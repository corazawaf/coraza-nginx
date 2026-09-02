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

        location /body_file_clean {
            default_type text/plain;
            directio 512;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 524288
            ';
        }

        location /body_file_block {
            default_type text/plain;
            directio 512;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 524288
                SecRule RESPONSE_BODY "@contains END-MARKER" "id:12,phase:4,deny,log,status:403,t:none"
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

# Static files arrive as file-backed buffers.  Put the rule marker beyond the
# first 64 KiB chunk so phase 4 proves all chunks were submitted.
my $file_body = ("R" x (256 * 1024)) . "END-MARKER";
$t->write_file("/body_file_clean", $file_body);
$t->write_file("/body_file_block", $file_body);

$t->run();
$t->todo_alerts();
$t->plan(7);

###############################################################################

like(http_get('/body1'), qr/^HTTP.*403/, 'response body (block)');

my $r = http_get('/body_access_off');
like($r, qr/^HTTP.*200/, 'large response with SecResponseBodyAccess Off returns 200');
like($r, qr/\Q$large_body\E/, 'large response body delivered intact');

$r = http_get('/body_file_clean');
like($r, qr/^HTTP.*200/, 'chunked file-backed response inspection allows clean body');
like($r, qr/\QEND-MARKER\E/, 'chunked inspected file body is delivered intact');

$r = http_get('/body_file_block');
like($r, qr/^HTTP.*403/,
    'phase 4 blocks on a marker beyond the first file chunk');
unlike($r, qr/\QEND-MARKER\E/,
    'clean phase-4 block does not leak the inspected file body');
