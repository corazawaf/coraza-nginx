#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed response-header path).
#
# Regression test for the truncation bug on the delayed-header path.  With
# SecResponseBodyAccess On the connector buffers the body and delays the
# response headers until phase 4 completes; it then forwards the headers and
# the accumulated pending_chain.  ngx_http_coraza_forward_header() bottoms out
# in the write filter, which returns NGX_AGAIN (not NGX_OK/NGX_ERROR) whenever
# the headers can't be fully flushed.  A buggy `if (rc != NGX_OK) return rc;`
# bailed out on that NGX_AGAIN before handing pending_chain to the body filter,
# so the body never entered r->out and was orphaned on the write retry ->
# truncated response / Content-Length mismatch.
#
# limit_rate triggers this deterministically: rate throttling makes the write
# filter return NGX_AGAIN via c->write->delayed even on an empty socket, so any
# inspected response on the delayed path with limit_rate set truncates every
# time.  The fix forwards pending_chain to the body filter regardless of the
# header filter's NGX_AGAIN, letting the body filter's return value carry the
# NGX_AGAIN up correctly.

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

        # Inspected response on the delayed-header path, throttled with
        # limit_rate so the write filter returns NGX_AGAIN via c->write->delayed.
        # The delay fires on the first flush whenever the body exceeds the rate
        # (regardless of how low the rate is), so a modest rate + body keeps the
        # whole transfer well under the test read timeout while still exercising
        # the NGX_AGAIN path.  Phase 4 does not intervene, so headers + the full
        # body must be forwarded, not stranded.
        location /delayed {
            default_type text/plain;
            limit_rate 32k;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 131072
                SecRule RESPONSE_BODY "@rx NEVER MATCHES THIS" "id:41,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

# 48 KB body @ 32k/s -> ~1.5 s: throttled across several write cycles (so a
# truncation on the delayed path is caught by the length assertion below) yet
# comfortably inside the harness read timeout.
my $body = "A" x (48 * 1024);
$t->write_file("/delayed", $body);

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

my $r = http_get('/delayed');

like($r, qr/^HTTP.*200/, 'delayed + limit_rate response returns 200');
like($r, qr/\Q$body\E/, 'delayed + limit_rate response body delivered intact');

# Explicit length guard: strip the headers and compare the body length so a
# short read (truncation) fails even if the head of the body still matches.
my ($got) = $r =~ /\r\n\r\n(.*)$/s;
is(length($got // ''), length($body),
    'delayed + limit_rate response body length matches (no truncation)');
