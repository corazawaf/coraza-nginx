#!/usr/bin/perl

# (C) Coraza contributors

# Tests for Coraza-nginx connector: SecRemoteRules is rejected at `nginx -t`.
#
# The Coraza SecLang parser implements SecRemoteRules as a hard "not
# implemented" error, but rules only reach libcoraza in init_process, after
# fork. Before this check the directive passed `nginx -t` and every worker then
# failed to build its WAF (issue #139). Both entry points are covered: inline
# text and a rules file (top level, comments ignored, case-insensitive).

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

my $t = Test::Nginx->new();

my $nginx = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY} : 'nginx';

# The object's own nginx.conf is VALID and is started, so Test::Nginx's
# teardown finds the prefix layout it expects. The rejection cases below run
# `nginx -t` against separate hand-written confs that never start.
$t->write_file_expand('nginx.conf', <<'EOF_CONF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            coraza on;
            coraza_rules 'SecRuleEngine On';
        }
    }
}

EOF_CONF

$t->run();
$t->plan(6);

my $testdir = $t->testdir();

sub conf_test {
	my ($name, $body) = @_;
	$t->write_file_expand($name, <<"EOF_T");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
$body
}

EOF_T
	my $out = `$nginx -t -p $testdir/ -c $name 2>&1`;
	return ($?, $out);
}

# 1. inline
my ($rc, $out) = conf_test('inline.conf', <<'EOF_B');
    coraza on;
    coraza_rules 'SecRemoteRules https://example.org/rules.conf';
EOF_B
isnt($rc, 0, 'inline SecRemoteRules is rejected at nginx -t');
like($out, qr/"SecRemoteRules" is not implemented by the Coraza engine/,
	'inline rejection names the directive');

# 2. rules file, directive on line 3, indented and mixed case
$t->write_file('remote.rules', <<'RULES');
SecRuleEngine On
# a comment line, then the offending directive
    secRemoteRules https://example.org/rules.conf
RULES
($rc, $out) = conf_test('file.conf', <<'EOF_B');
    coraza on;
    coraza_rules_file %%TESTDIR%%/remote.rules;
EOF_B
isnt($rc, 0, 'SecRemoteRules in a rules file is rejected at nginx -t');
like($out, qr/"SecRemoteRules" \(.*remote\.rules:3\) is not implemented/,
	'file rejection names the file and the line');

# 3. controls: a commented-out SecRemoteRules must not trip the scan, and
#    SecRemoteRulesFailAction is an implemented directive that must still pass
$t->write_file('ok.rules', <<'RULES');
SecRuleEngine On
# SecRemoteRules https://example.org/rules.conf   -- commented out
SecRemoteRulesFailAction Abort
RULES
($rc, $out) = conf_test('ok.conf', <<'EOF_B');
    coraza on;
    coraza_rules_file %%TESTDIR%%/ok.rules;
    coraza_rules 'SecRemoteRulesFailAction Abort';
EOF_B
is($rc, 0, 'commented SecRemoteRules and SecRemoteRulesFailAction still pass nginx -t')
	or diag($out);
unlike($out, qr/not implemented by the Coraza engine/, 'no rejection message on the control');

###############################################################################
