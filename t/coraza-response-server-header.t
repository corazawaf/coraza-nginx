#!/usr/bin/perl

# Tests for Coraza-nginx connector (synthetic Server response header).

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
        server_tokens off;

        coraza on;

        location /server_exact_pass {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Server "!@streq nginx" "id:61,phase:3,deny,log,status:403"
            ';
        }

        location /server_exact_block {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Server "@streq nginx" "id:62,phase:3,deny,log,status:403"
            ';
        }
    }
}
EOF

$t->write_file("/server_exact_pass", "server header must not include NUL");
$t->write_file("/server_exact_block", "server header matched");

$t->run();
$t->todo_alerts();
$t->plan(2);

###############################################################################

like(http_get('/server_exact_pass'), qr/^HTTP.*200/,
	'synthetic Server header is exactly nginx');

like(http_get('/server_exact_block'), qr/^HTTP.*403/,
	'exact synthetic Server header can be matched');
