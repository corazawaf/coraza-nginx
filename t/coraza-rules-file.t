#!/usr/bin/perl

# Tests for Coraza-nginx connector (coraza_rules_file directive).
#
# Existing tests use only inline `coraza_rules`. This drives the
# `coraza_rules_file <path>;` directive so ngx_conf_set_rules_file() executes
# and the referenced file's rules are loaded and enforced at runtime.

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

$t->write_file('my.rules', <<'RULES');
SecRuleEngine On
SecRule ARGS:q "@streq boom" "id:900,phase:1,deny,status:403,log"
RULES

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

        location / {
            default_type text/plain;
            coraza_rules_file %%TESTDIR%%/my.rules;
            return 200 "clean\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(2);

###############################################################################

like(http_get('/?q=boom'), qr!^HTTP\S+ 403!,
	'rule loaded from coraza_rules_file blocks attack');
like(http_get('/?q=safe'), qr!^HTTP\S+ 200!,
	'clean request passes with coraza_rules_file');
