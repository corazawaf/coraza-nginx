#!/usr/bin/perl

# (C) Andrei Belov

# Tests for Coraza-nginx connector (response body operations).

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

        location /body1 {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 128
                SecRule RESPONSE_BODY "@rx BAD BODY" "id:11,phase:4,deny,log,status:403"
            ';
        }

        location /body_access_off {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }
    }
}
EOF

$t->write_file("/body1", "BAD BODY");

# Create a ~100 KB file to verify that large responses are served without
# hanging when SecResponseBodyAccess is Off.  Prior to the fix the module
# would forward every byte through the Go FFI bridge even when body
# inspection was disabled, blocking the nginx worker for large responses.
my $large_body = "X" x (100 * 1024);
$t->write_file("/body_access_off", $large_body);

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

like(http_get('/body1'), qr/^HTTP.*403/, 'response body (block)');

my $r = http_get('/body_access_off');
like($r, qr/^HTTP.*200/, 'large response with SecResponseBodyAccess Off returns 200');
like($r, qr/\Q$large_body\E/, 'large response body delivered intact');

