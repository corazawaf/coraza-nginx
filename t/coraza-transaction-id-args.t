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

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new();

my $nginx = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY} : 'nginx';

# The object's own nginx.conf is VALID and is actually started: this creates
# error.log and the prefix layout Test::Nginx's teardown expects, so the run
# tears down cleanly.  The arity check below runs `nginx -t` against a SEPARATE
# hand-written conf -- an invalid conf that never starts, so it must NOT be the
# object's conf (Test::Nginx would try to run it and its teardown would then
# fail to open error.log, exit 255 with the asserts already passed).
$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    coraza_transaction_id "tid-A";

    server {
        listen       127.0.0.1:8080;
        server_name  server1;

        location / {
            coraza on;
        }
    }
}

EOF

$t->run();
$t->plan(3);

my $testdir = $t->testdir();

# A second conf with two arguments where exactly one is allowed.  Expand
# %%TEST_GLOBALS%% so the coraza module is load_module'd -- otherwise nginx
# reports "unknown directive" instead of the arity error we assert on.
$t->write_file_expand('bad.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    # Two arguments where exactly one is allowed.
    coraza_transaction_id "tid-A" "tid-B";
}

EOF

# Config-test the bad conf and capture the diagnostics.  The arity error is
# emitted during config parse and lands on stderr -- capture combined output.
my $out = `$nginx -t -p $testdir/ -c bad.conf 2>&1`;
my $rc = $?;

isnt($rc, 0, 'nginx rejects two-argument coraza_transaction_id');
like($out, qr/invalid number of arguments in "coraza_transaction_id"/,
	'error names coraza_transaction_id arity');

###############################################################################

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
