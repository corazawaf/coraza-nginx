#!/usr/bin/perl

# Regression: coraza_transaction_id takes exactly one argument.
#
# The directive is declared with NGX_CONF_TAKE1. If it regresses to
# NGX_CONF_1MORE (its earlier value) nginx would silently accept a second
# argument and ignore it, so the effective transaction-id template would be
# whatever the first token happened to be. This test proves nginx refuses to
# start with a two-argument use and that the error names the directive.

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

my $t = Test::Nginx->new()->plan(2);

my $nginx = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY} : 'nginx';

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # Two arguments where exactly one is allowed.
    coraza_transaction_id "tid-A" "tid-B";

    server {
        listen       127.0.0.1:8080;
        server_name  server1;

        location / {
            coraza on;
        }
    }
}

EOF

# Config-test the written nginx.conf directly and capture the diagnostics.
# The arity error is emitted during config parse, before the error_log file
# is opened, so it lands on stderr -- capture combined output.
my $testdir = $t->testdir();
my $out = `$nginx -t -p $testdir/ -c nginx.conf 2>&1`;
my $rc = $?;

isnt($rc, 0, 'nginx rejects two-argument coraza_transaction_id');
like($out, qr/invalid number of arguments in "coraza_transaction_id"/,
	'error names coraza_transaction_id arity');

###############################################################################
