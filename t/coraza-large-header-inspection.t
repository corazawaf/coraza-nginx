#!/usr/bin/perl

# Tests for Coraza-nginx connector (cgo length-narrowing guard).
#
# The Coraza cgo boundary takes header/body lengths as int, so the connector
# now guards the size_t -> int narrowing and fails closed above INT_MAX. That
# ceiling is far larger than any header nginx will accept, so a normal large
# header (well below INT_MAX) must still be inspected as usual -- the guard must
# not clip or skip legitimate large headers.
# See the INT_MAX guards in ngx_http_coraza_{rewrite,header_filter,body_filter,
# pre_access}.c.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    large_client_header_buffers 4 32k;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /big {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Big "@contains attackpat" "id:40,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }
    }
}
EOF

$t->run();

###############################################################################

my $pad = 'a' x 16000;

my $attack = http(<<EOF);
GET /big HTTP/1.0
Host: localhost
X-Big: ${pad}attackpat

EOF
like($attack, qr!^HTTP/\S+ 403!, 'large header (16k) still inspected: attack blocked');

my $benign = http(<<EOF);
GET /big HTTP/1.0
Host: localhost
X-Big: ${pad}benign

EOF
like($benign, qr!^HTTP/\S+ 200!, 'large benign header passes');
