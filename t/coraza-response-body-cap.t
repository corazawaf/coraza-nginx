#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed-response buffering cap).
#
# The header filter delays response headers until phase 4 completes so a
# phase-4 rule can still return a clean error page.  While delayed, the body
# filter accumulates every response buffer into the request pool.  For a large
# or open-ended (streaming) response that buffering would grow without limit
# and OOM the worker.
#
# The fix caps the accumulation at NGX_HTTP_CORAZA_MAX_DELAYED_BODY (1 MiB by
# default): once exceeded, the delayed headers + everything buffered so far are
# flushed and the remainder streams through.  This test drives a response well
# past the cap (with SecResponseBodyAccess Off, so the body is still delayed
# and buffered but Coraza itself does not inspect/limit it) and asserts:
#   1. the response still completes with 200 and an intact body, and
#   2. the connector logged that it flushed early (the cap path executed).
# See src/ngx_http_coraza_body_filter.c (NGX_HTTP_CORAZA_MAX_DELAYED_BODY).

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

    error_log %%TESTDIR%%/cap.log warn;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        location /big {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }
    }
}
EOF

# 4 MiB response — comfortably past the 1 MiB default cap, delivered in many
# buffers so pending_bytes crosses the cap before last_buf arrives.
my $size = 4 * 1024 * 1024;
$t->write_file("/big", "Z" x $size);

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

my $r = http_get('/big');
like($r, qr/^HTTP.*200/, 'oversized delayed response still returns 200');

my ($body) = $r =~ /\r\n\r\n(.*)$/s;
is(length($body // ''), $size, 'oversized response body delivered intact');

$t->stop();
like($t->read_file('cap.log'), qr/flushing headers early/,
    'connector flushed delayed headers once the buffering cap was exceeded');
