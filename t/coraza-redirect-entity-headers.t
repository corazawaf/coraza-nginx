#!/usr/bin/perl

# Tests for Coraza-nginx connector (RFC 9110 §15.4 redirect hygiene).
#
# When a phase-3 rule turns an already-populated 200 response into a 3xx
# redirect (redirect: action -> intervention with a Location), the connector
# synthesizes the Location + status but must also drop the entity/representation
# headers carried over from the discarded 200 response.  Otherwise the body-less
# redirect advertises Content-Type / Content-Length / Last-Modified / ETag /
# Accept-Ranges describing a representation it no longer sends -- a
# protocol-inconsistent response (RFC 9110 §15.4 / §8.3-8.8).
# See src/ngx_http_coraza_header_filter.c (redirect branch entity-header clear).

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location /static/ {
            alias %%TESTDIR%%/;

            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@rx ." "id:100,phase:3,status:302,redirect:http://example.org/blocked,log"
            ';
        }
    }
}
EOF

# A static file so the original 200 carries the full entity-header set
# (Content-Type, Content-Length, Last-Modified, ETag, Accept-Ranges).
$t->write_file('page.html', 'body content that is discarded by the redirect');

$t->run();

###############################################################################

my $r = http_get('/static/page.html');

like($r, qr!^HTTP/\S+ 302!, 'phase-3 redirect turns 200 into 302');
like($r, qr!Location: http://example\.org/blocked!, 'Location header present');

# The discarded 200 representation's entity headers must be gone.
unlike($r, qr/^Content-Type:/mi, 'Content-Type cleared on redirect');
unlike($r, qr/^Content-Length: \d/mi, 'Content-Length cleared on redirect');
unlike($r, qr/^Last-Modified:/mi, 'Last-Modified cleared on redirect');
unlike($r, qr/^ETag:/mi, 'ETag cleared on redirect');
unlike($r, qr/^Accept-Ranges:/mi, 'Accept-Ranges cleared on redirect');
