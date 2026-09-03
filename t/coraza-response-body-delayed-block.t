#!/usr/bin/perl

# Tests for Coraza-nginx connector: a phase-4 RESPONSE_BODY intervention that
# fires WHILE the response headers are being delayed.
#
# With coraza_delay_response_headers on and SecResponseBodyAccess On, the body
# filter buffers the response and inspects it before the headers are sent.  When
# a RESPONSE_BODY rule matches, the intervention must be applied on the
# still-delayed headers path (ctx->headers_delayed branch in the body filter),
# turning the buffered 200 into the rule's status.  A control location without
# a matching body confirms the same delayed 200 is released untouched.
#
# A delayed DENY must reach the client as a real error page, which means a real
# ngx_http_filter_finalize_request(): it runs ngx_http_clean_header() +
# ngx_http_special_response_handler(), and that handler is what emits the
# status page.  Returning a bare status code from a body filter is not a
# finalize -- nginx propagates it up through ngx_http_output_filter() with no
# header ever written, so the client gets a truncated response or a reset.
# Asserting the status line alone cannot tell those two apart, so the blocked
# case below also asserts the error page BODY and asserts that the buffered
# origin body was discarded rather than leaked.
#
# A phase-4 REDIRECT while delayed takes the opposite exit and is covered too:
# there the finalize is the wrong move, because it would discard the Location
# header the intervention just installed.  Deny and redirect must diverge at
# this point, so both are pinned.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;
        default_type text/plain;

        # A custom 403 page is the sharpest oracle available here: only
        # ngx_http_special_response_handler() -- reached exclusively via
        # ngx_http_filter_finalize_request() -- consults error_page.  If the
        # delayed branch returns a bare status instead of finalizing, no
        # header and no page are written and this sentinel never appears.
        # Unlike nginx's built-in error HTML it does not depend on the
        # nginx version's markup.
        error_page 403 /denied-403.html;
        location = /denied-403.html {
            coraza off;
            internal;
        }

        # Blocked: RESPONSE_BODY rule matches while headers are delayed.
        location /block.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:300,phase:4,deny,log,status:403"
            ';
        }

        # A phase-4 REDIRECT while headers are delayed.  A deny wants the
        # error page a finalize builds, but a redirect must not be finalized:
        # ngx_http_coraza_process_intervention() has already installed
        # Location, and ngx_http_filter_finalize_request() would build a fresh
        # error page with fresh headers and drop it, leaving a 3xx pointing
        # nowhere.  The two intervention kinds have to part ways here.
        location /redirect.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:302,phase:4,log,status:302,redirect:http://www.example.com/blocked"
            ';
        }

        # The origin already carries a Location of its own, and the body then
        # trips a phase-4 DENY.  The deny must still win and produce the error
        # page: keying the redirect exit off r->headers_out.location alone
        # would mistake the origin's header for a redirect intervention and
        # answer with a header-only 403 pointing at the origin's target.
        location /origin-redirect.txt {
            coraza_delay_response_headers on;
            add_header Location http://origin.example.com/elsewhere always;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:303,phase:4,deny,log,status:403"
            ';
        }

        # Control: identical config, but the body does not contain the trigger,
        # so the delayed 200 is released intact.
        location /pass.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:301,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

my $clean = "harmless body, nothing matches\n";
my $origin = "leading text ... BLOCK ME ... trailing text\n";
my $denied = "DENIED-BY-PHASE4-ERROR-PAGE\n";
$t->write_file("/denied-403.html", $denied);
$t->write_file("/block.txt", $origin);
$t->write_file("/redirect.txt", $origin);
$t->write_file("/origin-redirect.txt", $origin);
$t->write_file("/pass.txt", $clean);

$t->run();
$t->todo_alerts();
$t->plan(11);

###############################################################################

my $blocked = http_get('/block.txt');

like($blocked, qr/^HTTP.*403/,
    'RESPONSE_BODY match while headers delayed -> blocked with rule status');

# The finalize path emits real response headers.  A bare status return from the
# body filter writes none at all, so the absence of a Content-Length here is
# the marker that separates the two -- status alone cannot.
like($blocked, qr/Content-Length: \d+/i,
    'delayed block emits real response headers, not a bare status');

# The sentinel only reaches the client through
# ngx_http_special_response_handler(), i.e. only if the delayed branch really
# finalized.  This is the assertion that fails if it returns a bare status.
like($blocked, qr/\Q$denied\E/,
    'delayed block emits the 403 error page body');

# The buffered origin body must be discarded, never leaked past the block.
unlike($blocked, qr/\QBLOCK ME\E/,
    'buffered origin body is not leaked on a delayed block');

# A delayed phase-4 redirect takes the other exit: it must reach the client as
# a real 3xx carrying Location, which a finalize would have thrown away along
# with the rest of the headers.
my $redirect = http_get('/redirect.txt');
like($redirect, qr/^HTTP.*302/,
    'RESPONSE_BODY redirect while headers delayed -> redirect status');
like($redirect, qr{Location: http://www\.example\.com/blocked},
    'delayed redirect keeps the Location header');
unlike($redirect, qr/\QBLOCK ME\E/,
    'buffered origin body is not leaked on a delayed redirect');

# A deny on a response that already has its own Location must still finalize.
my $origin_redir = http_get('/origin-redirect.txt');
like($origin_redir, qr/^HTTP.*403/,
    'deny beats a pre-existing origin Location');
like($origin_redir, qr/\Q$denied\E/,
    'deny on an origin redirect still emits the 403 error page body');

my $r = http_get('/pass.txt');
like($r, qr/^HTTP.*200/, 'non-matching delayed body -> released as 200');
like($r, qr/\Q$clean\E/, 'non-matching delayed body delivered intact');
