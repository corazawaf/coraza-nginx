#!/usr/bin/perl

# Tests for Coraza-nginx connector: the response body filter must not act on
# a fresh phase-4 intervention while nginx is already streaming the
# configured error_page's own body (r->error_page set).
#
# A phase-1 denial is routed through error_page into a second coraza-on
# location whose response BODY would trip a phase-4 RESPONSE_BODY rule if the
# connector re-inspected the error page's own content.  The body filter now
# carries the same r->error_page guard the rewrite, pre_access and
# header_filter poll sites already had (see
# ngx_http_coraza_body_filter.c: both poll_after_process consumers).  Without
# that guard the phase-4 rule below would fire on the error page's own body
# and finalize the request a second time, rewriting the status the client
# sees and risking a double-finalize on an already-erroring request.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

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
        default_type text/plain;

        coraza on;

        # A phase-1 denial whose 403 is routed into the coraza-on /denied
        # handler, forcing an internal error-page re-entry that streams a
        # response body through the body filter with r->error_page set.
        location /trigger {
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule ARGS:x "@streq boom" "id:600,phase:1,deny,log,status:403"
            ';
            error_page 403 = /denied;
            return 200 "should not reach";
        }

        # The error-page target is coraza-on with response-body access, and
        # its own body contains "forbidden" -- a string that WOULD trip the
        # phase-4 rule below (status 418) if the body filter re-inspected the
        # error page's own content instead of honoring r->error_page.
        location /denied {
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@contains forbidden" "id:601,phase:4,deny,log,status:418"
            ';
            return 403 "forbidden by coraza\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(4);

###############################################################################

# The denial is routed through the coraza-on error page; the phase-4 rule on
# the error page's own body must not re-fire and rewrite the status to 418.
my $r = http_get('/trigger?x=boom');
like($r, qr/^HTTP\S+ 403/,
    'error-page body filter did not re-finalize (still 403, not 418)');
like($r, qr/forbidden by coraza/, 'error_page handler body delivered intact');

# Control: a clean request never routes through the error page at all.
like(http_get('/trigger?x=safe'), qr/^HTTP\S+ 200/,
    'clean request passes without error-page re-entry (control)');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
