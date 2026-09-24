#!/usr/bin/perl

# (C) Coraza contributors

# Tests for Coraza-nginx connector: SecRemoteRules is rejected at `nginx -t`.
#
# The Coraza SecLang parser implements SecRemoteRules as a hard "not
# implemented" error, but rules only reach libcoraza in init_process, after
# fork. Before this check the directive passed `nginx -t` and every worker then
# failed to build its WAF (issue #139). Both entry points are covered: inline
# text (any line of it) and a rules file (top level, comments ignored,
# case-insensitive, scanned through a small buffer so file size and long lines
# do not matter). Records are assembled the way coraza's parser does it, so
# backslash continuations and backtick action lists are neither bypass nor
# false positive.

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

my $nginx = $Test::Nginx::NGINX;

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
$t->plan(12);

my $testdir = $t->testdir();

# $t is passed in rather than captured: a named sub closing over it would keep
# it alive into global destruction, past Test::Builder, and lose the alerts
# and sanitizer checks that Test::Nginx runs when the object is destroyed.
sub conf_test {
	my ($t, $name, $body) = @_;
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
my ($rc, $out) = conf_test($t, 'inline.conf', <<'EOF_B');
    coraza on;
    coraza_rules 'SecRemoteRules https://example.org/rules.conf';
EOF_B
isnt($rc, 0, 'inline SecRemoteRules is rejected at nginx -t');
like($out, qr/"SecRemoteRules" \(coraza_rules text, line 1\) is not implemented/,
	'inline rejection names the directive and the line');

# 1b. inline, multi-line value: the offending directive is not on the first
#     line, and sits behind a comment and a blank line
($rc, $out) = conf_test($t, 'inline-multi.conf', <<'EOF_B');
    coraza on;
    coraza_rules '
        SecRuleEngine On
        # remote rules below

        SecRemoteRules https://example.org/rules.conf
    ';
EOF_B
isnt($rc, 0, 'SecRemoteRules on a later line of inline text is rejected');
like($out, qr/"SecRemoteRules" \(coraza_rules text, line 5\) is not implemented/,
	'multi-line inline rejection reports the right line');

# 2. rules file, directive on line 3, indented and mixed case
$t->write_file('remote.rules', <<'RULES');
SecRuleEngine On
# a comment line, then the offending directive
    secRemoteRules https://example.org/rules.conf
RULES
($rc, $out) = conf_test($t, 'file.conf', <<'EOF_B');
    coraza on;
    coraza_rules_file %%TESTDIR%%/remote.rules;
EOF_B
isnt($rc, 0, 'SecRemoteRules in a rules file is rejected at nginx -t');
like($out, qr/"SecRemoteRules" \(.*remote\.rules:3\) is not implemented/,
	'file rejection names the file and the line');

# 2b. rules file larger than the scan buffer, with a line longer than the
#     buffer before the directive, and the directive on the last line without
#     a trailing newline
my $big = "SecRuleEngine On\n";
$big .= "SecRule ARGS \"\@rx " . ('a' x 5000) . "\" \"id:1,phase:1,pass\"\n";
$big .= "# filler\n" x 800;
$big .= "SecRemoteRules https://example.org/rules.conf";
$t->write_file('big.rules', $big);
($rc, $out) = conf_test($t, 'big.conf', <<'EOF_B');
    coraza on;
    coraza_rules_file %%TESTDIR%%/big.rules;
EOF_B
isnt($rc, 0, 'SecRemoteRules past the read buffer is still rejected');
like($out, qr/"SecRemoteRules" \(.*big\.rules:803\) is not implemented/,
	'large-file rejection reports the right line (no trailing newline)');

# 2c. the directive name itself cut by a backslash continuation: coraza glues
#     the next (trimmed) line to this one, so the record still reads
#     "SecRemoteRules ..."; the report points at the line the record starts on
$t->write_file('split.rules', <<'RULES');
SecRuleEngine On
SecRemoteRul\
    es https://example.org/rules.conf
RULES
($rc, $out) = conf_test($t, 'split.conf', <<'EOF_B');
    coraza on;
    coraza_rules_file %%TESTDIR%%/split.rules;
EOF_B
isnt($rc, 0, 'SecRemoteRules split by a line continuation is rejected');
like($out, qr/"SecRemoteRules" \(.*split\.rules:2\) is not implemented/,
	'split-word rejection reports the line the record starts on');

# 3. controls: a commented-out SecRemoteRules must not trip the scan, and
#    SecRemoteRulesFailAction is an implemented directive that must still pass;
#    so must a longer word that merely starts with the directive name, and
#    the words "SecRemoteRules" at the start of a continuation line or of a
#    line inside a backtick action list, which belong to the record above
$t->write_file('ok.rules', <<'RULES');
SecRuleEngine On
# SecRemoteRules https://example.org/rules.conf   -- commented out
SecRemoteRulesFailAction Abort
SecRemoteRulesX not-a-real-directive-but-not-ours-to-refuse
SecRule ARGS "@rx foo" \
    # a comment inside a continued record is ignored, the record goes on

SecRemoteRules https://example.org/rules.conf is only text in this msg" \
    "id:2,phase:1,pass"
SecRule ARGS "@rx bar" `
SecRemoteRules https://example.org/rules.conf
    id:3,phase:1,pass
`
RULES
($rc, $out) = conf_test($t, 'ok.conf', <<'EOF_B');
    coraza on;
    coraza_rules_file %%TESTDIR%%/ok.rules;
    coraza_rules 'SecRemoteRulesFailAction Abort';
EOF_B
is($rc, 0, 'commented SecRemoteRules and SecRemoteRulesFailAction still pass nginx -t')
	or diag($out);
unlike($out, qr/not implemented by the Coraza engine/, 'no rejection message on the control');

###############################################################################
