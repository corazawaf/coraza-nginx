#!/usr/bin/perl

# Tests for Coraza-nginx connector (post-cap response body interventions).
#
# Once the delayed response-body cap is exceeded, the connector flushes headers
# early.  Any later disruptive response-body intervention cannot send a clean
# error page anymore, but it must still stop streaming the response promptly.

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

    error_log %%TESTDIR%%/cap-intervention.log warn;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /late-limit {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 1572864
                SecResponseBodyLimitAction Reject
            ';
        }
    }
}
EOF

my $size = 4 * 1024 * 1024;
$t->write_file('/late-limit', 'L' x $size);

$t->run();
$t->todo_alerts();
$t->plan(4);

###############################################################################

my $r = http_get('/late-limit');
like($r, qr/^HTTP\S+ 200/, 'oversized response starts before late intervention');

my ($body) = $r =~ /\r\n\r\n(.*)$/s;
ok(length($body // '') < 2_500_000,
    'post-flush intervention stops the response near the Coraza limit');
isnt(length($body // ''), $size,
    'post-flush intervention does not stream the complete response');

$t->stop();
like($t->read_file('cap-intervention.log'), qr/flushing headers early/,
    'connector flushed delayed headers before the intervention');
