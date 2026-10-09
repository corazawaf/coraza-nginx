#!/usr/bin/perl

# Tests for Coraza-nginx connector: which location's policy applies after
# ngx_http_rewrite_module moves a request to another location.
#
# nginx evaluates `rewrite ... last` in the REWRITE phase and then rematches
# the location, so a request can start in location A and finish in location
# B. The connector used to create its transaction in its own REWRITE-phase
# handler, which nginx runs before ngx_http_rewrite_module's handler, so the
# transaction was bound to A's `coraza_rules`/`coraza_transaction_id` even
# when B served the request: B's rules never ran and the audit entry carried
# A's transaction id. Each location below gets its own audit log, so the log
# that receives the entry identifies the policy that inspected the request.
#
# With the fix the transaction is created once routing has settled: in
# PREACCESS for an ordinary content response, in the response header filter
# for a rewrite-phase `return`/redirect that never reaches PREACCESS, and in
# LOG (audit only) for a headerless exit such as `return 444`.
#
# A phase-2 rule still cannot fire on a `return 200` location (see
# t/coraza-args-post-match.t): `return` finalizes the request in the REWRITE
# phase. The last case pins that this is unchanged.
#
# The cases encode the table from the PR discussion; one audit log per
# location, so the log that gains the entry names the policy that applied:
#
#   situation                                       | main           | fixed
#   ------------------------------------------------+----------------+---------------
#   A rewrites to B, deny rule only in B (c2)       | 200, logged A  | 403, logged B
#   A -> B -> C, deny rule only in C (c4e)          | 200, logged A  | 403, logged C
#   A phase-1 deny, rewrites to permissive B (c1a)  | 403 from A     | 200 from B
#   return 403, return 444, redirect, if+set        | one audit      | one audit
#     (c4a, c4b, c4d, c4c)                          | entry each     | entry each
#
# Every request produces exactly one audit entry on both trees; the counts
# pin that nothing is logged twice or lost. A subrequest issued by an enabled
# location (c5) never starts a transaction of its own in the header filter:
# the main request's transaction is the only one audited.

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

my $t = Test::Nginx->new()->has(qw/http rewrite auth_request/);

my $conf = <<'EOF';

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
        default_type text/plain;
        root %%TESTDIR%%;

        # control: no rewrite, phase-2 ARGS deny on static content
        location /c0 {
            coraza_transaction_id "c0-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:1,phase:2,deny,status:403,log"
                %%AUDIT(c0-A)%%
            ';
        }

        # A denies in phase 1 and rewrites to a permissive B: B's policy wins
        location /c1a {
            coraza_transaction_id "c1a-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecAction "id:101,phase:1,deny,status:403,log"
                %%AUDIT(c1a-A)%%
            ';
            rewrite ^ /c1a-b last;
        }
        location /c1a-b {
            coraza_transaction_id "c1a-B-$request_id";
            coraza_rules '
                SecRuleEngine On
                %%AUDIT(c1a-B)%%
            ';
        }

        # permissive A rewrites to a B that denies in phase 1
        location /c1b {
            coraza_transaction_id "c1b-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                %%AUDIT(c1b-A)%%
            ';
            rewrite ^ /c1b-b last;
        }
        location /c1b-b {
            coraza_transaction_id "c1b-B-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecAction "id:102,phase:1,deny,status:403,log"
                %%AUDIT(c1b-B)%%
            ';
        }

        # distinct rule sets: the phase-2 ARGS deny exists only in B
        location /c2 {
            coraza_transaction_id "c2-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:201,phase:2,pass,log"
                %%AUDIT(c2-A)%%
            ';
            rewrite ^ /c2-b last;
        }
        location /c2-b {
            coraza_transaction_id "c2-B-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:202,phase:2,deny,status:403,log"
                %%AUDIT(c2-B)%%
            ';
        }

        # rewrite-phase `return 403`: skips PREACCESS, binds in the header filter
        location /c4a {
            coraza_transaction_id "c4a-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains c4a" "id:401,phase:1,pass,log"
                %%AUDIT(c4a-A)%%
            ';
            return 403 "c4a\n";
        }

        # rewrite-phase `return 444`: no headers at all, binds in LOG
        location /c4b {
            coraza_transaction_id "c4b-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains c4b" "id:402,phase:1,pass,log"
                %%AUDIT(c4b-A)%%
            ';
            return 444;
        }

        # if/set in the rewrite phase without a rematch
        location /c4c {
            coraza_transaction_id "c4c-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:403,phase:2,deny,status:403,log"
                %%AUDIT(c4c-A)%%
            ';
            set $c4c_flag 0;
            if ($arg_x) {
                set $c4c_flag 1;
            }
        }

        # external redirect from the rewrite phase
        location /c4d {
            coraza_transaction_id "c4d-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains c4d" "id:404,phase:1,pass,log"
                %%AUDIT(c4d-A)%%
            ';
            rewrite ^ http://example.com/elsewhere redirect;
        }

        # nested chain A -> B -> C, phase-2 ARGS deny only in C
        location /c4e {
            coraza_transaction_id "c4e-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                %%AUDIT(c4e-A)%%
            ';
            rewrite ^ /c4e-b last;
        }
        location /c4e-b {
            coraza_transaction_id "c4e-B-$request_id";
            coraza_rules '
                SecRuleEngine On
                %%AUDIT(c4e-B)%%
            ';
            rewrite ^ /c4e-c last;
        }
        location /c4e-c {
            coraza_transaction_id "c4e-C-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:405,phase:2,deny,status:403,log"
                %%AUDIT(c4e-C)%%
            ';
        }

        # rewrite into a location where coraza is off
        location /c4f {
            coraza_transaction_id "c4f-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:406,phase:2,deny,status:403,log"
                %%AUDIT(c4f-A)%%
            ';
            rewrite ^ /c4f-b last;
        }
        location /c4f-b {
            coraza off;
        }

        # coraza off in A, rewrite into an enabled B
        location /c4g {
            coraza off;
            rewrite ^ /c4g-b last;
        }
        location /c4g-b {
            coraza_transaction_id "c4g-B-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:407,phase:2,deny,status:403,log"
                %%AUDIT(c4g-B)%%
            ';
        }

        # rewrite-phase `return 200` with a phase-2 deny: phase 2 never runs
        location /c4h {
            coraza_transaction_id "c4h-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:408,phase:2,deny,status:403,log"
                %%AUDIT(c4h-A)%%
            ';
            return 200 "c4h\n";
        }

        # auth_request subrequest into an enabled location that returns in the
        # rewrite phase: the subrequest reaches the header filter without a
        # context and must not bind a transaction of its own
        location /c5 {
            coraza_transaction_id "c5-A-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq evil" "id:501,phase:2,deny,status:403,log"
                %%AUDIT(c5-A)%%
            ';
            auth_request /c5-sub;
        }
        location = /c5-sub {
            internal;
            coraza_transaction_id "c5-S-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecAction "id:502,phase:1,deny,status:403,log"
                %%AUDIT(c5-S)%%
            ';
            return 204;
        }
    }
}
EOF

my @logs;
$conf =~ s{%%AUDIT\(([\w-]+)\)%%}{
    push @logs, $1;
    "SecAuditEngine On\n"
    . "                SecAuditLogParts ABFHZ\n"
    . "                SecAuditLogFormat JSON\n"
    . "                SecAuditLogType Serial\n"
    . "                SecAuditLog %%TESTDIR%%/audit-$1.log"
}ge;

$t->write_file_expand('nginx.conf', $conf);

for my $f (qw/c0 c1a-b c1b-b c2-b c4c c4e-c c4f-b c4g-b c5/) {
    $t->write_file($f, "$f\n");
}

$t->run()->plan(70);

###############################################################################

my $testdir = $t->testdir();

# control: the phase-2 rule fires where no rewrite is involved
my $a = audited('c0', '/c0?x=evil');
like($a->{response}, qr/^HTTP\S+ 403/, 'control: evil request denied');
is_deeply($a->{counts}, { 'c0-A' => 1 }, 'control: one audit entry in A');
is($a->{rule}, '1', 'control: rule 1 matched');

$a = audited('c0', '/c0?x=ok');
like($a->{response}, qr/^HTTP\S+ 200/, 'control: benign request served');
is_deeply($a->{counts}, { 'c0-A' => 1 }, 'control: benign request audited');
is($a->{rule}, undef, 'control: no rule matched');

# A denies in phase 1, then rewrites to B: the request is inspected by B
$a = audited('c1a', '/c1a');
like($a->{response}, qr/^HTTP\S+ 200/,
	'phase-1 deny in A does not apply after rewrite to B');
is_deeply($a->{counts}, { 'c1a-A' => 0, 'c1a-B' => 1 },
	'A->B: audit entry lands in B, none in A');
like($a->{txid}, qr/^c1a-B-/, 'A->B: transaction id comes from B');
is($a->{rule}, undef, 'A->B: A\'s rule 101 did not match');

# permissive A, B denies in phase 1: B's rule runs and blocks
$a = audited('c1b', '/c1b');
like($a->{response}, qr/^HTTP\S+ 403/, 'phase-1 deny in B applies after rewrite');
is_deeply($a->{counts}, { 'c1b-A' => 0, 'c1b-B' => 1 },
	'A->B deny: audit entry lands in B, none in A');
like($a->{txid}, qr/^c1b-B-/, 'A->B deny: transaction id comes from B');
is($a->{rule}, '102', 'A->B deny: rule 102 matched');

# distinct rule sets: B's phase-2 ARGS rule sees the request
$a = audited('c2', '/c2?x=evil');
like($a->{response}, qr/^HTTP\S+ 403/, 'phase-2 deny in B applies after rewrite');
is_deeply($a->{counts}, { 'c2-A' => 0, 'c2-B' => 1 },
	'A->B phase 2: audit entry lands in B, none in A');
like($a->{txid}, qr/^c2-B-/, 'A->B phase 2: transaction id comes from B');
is($a->{rule}, '202', 'A->B phase 2: rule 202 matched, not A\'s 201');

$a = audited('c2', '/c2?x=ok');
like($a->{response}, qr/^HTTP\S+ 200/, 'A->B phase 2: benign request served');
is_deeply($a->{counts}, { 'c2-A' => 0, 'c2-B' => 1 },
	'A->B phase 2: benign request audited by B');
is($a->{rule}, undef, 'A->B phase 2: no rule matched');

# rewrite-phase return 403: skips PREACCESS, still inspected and audited
$a = audited('c4a', '/c4a');
like($a->{response}, qr/^HTTP\S+ 403/, 'return 403 reaches the client');
is_deeply($a->{counts}, { 'c4a-A' => 1 }, 'return 403: one audit entry');
is($a->{rule}, '401', 'return 403: phase-1 rule matched');
is($a->{status}, 403, 'return 403: audit entry records status 403');

# rewrite-phase return 444: no response at all, audited in LOG with 444
$a = audited('c4b', '/c4b');
unlike($a->{response} // '', qr/^HTTP/, 'return 444 sends no status line');
is_deeply($a->{counts}, { 'c4b-A' => 1 }, 'return 444: one audit entry');
is($a->{rule}, '402', 'return 444: phase-1 rule matched');
is($a->{status}, 444, 'return 444: audit entry records status 444');

# if/set without a rematch: policy and transaction id unchanged
$a = audited('c4c', '/c4c?x=evil');
like($a->{response}, qr/^HTTP\S+ 403/, 'if/set: evil request denied');
is_deeply($a->{counts}, { 'c4c-A' => 1 }, 'if/set: one audit entry');
like($a->{txid}, qr/^c4c-A-/, 'if/set: transaction id from the same location');
is($a->{rule}, '403', 'if/set: rule 403 matched');

$a = audited('c4c', '/c4c?x=ok');
like($a->{response}, qr/^HTTP\S+ 200/, 'if/set: benign request served');
is_deeply($a->{counts}, { 'c4c-A' => 1 }, 'if/set: benign request audited');
is($a->{rule}, undef, 'if/set: no rule matched');

# external redirect from the rewrite phase
$a = audited('c4d', '/c4d');
like($a->{response}, qr/^HTTP\S+ 302/, 'rewrite redirect: 302 reaches the client');
like($a->{response}, qr!^Location: http://example\.com/elsewhere!m,
	'rewrite redirect: Location preserved');
is_deeply($a->{counts}, { 'c4d-A' => 1 }, 'rewrite redirect: one audit entry');
is($a->{rule}, '404', 'rewrite redirect: phase-1 rule matched');
is($a->{status}, 302, 'rewrite redirect: audit entry records status 302');

# nested chain A -> B -> C: only the final location inspects
$a = audited('c4e', '/c4e?x=evil');
like($a->{response}, qr/^HTTP\S+ 403/, 'A->B->C: C\'s phase-2 deny applies');
is_deeply($a->{counts}, { 'c4e-A' => 0, 'c4e-B' => 0, 'c4e-C' => 1 },
	'A->B->C: audit entry lands in C only');
like($a->{txid}, qr/^c4e-C-/, 'A->B->C: transaction id comes from C');
is($a->{rule}, '405', 'A->B->C: rule 405 matched');

$a = audited('c4e', '/c4e?x=ok');
like($a->{response}, qr/^HTTP\S+ 200/, 'A->B->C: benign request served');
is_deeply($a->{counts}, { 'c4e-A' => 0, 'c4e-B' => 0, 'c4e-C' => 1 },
	'A->B->C: benign request audited by C');
is($a->{rule}, undef, 'A->B->C: no rule matched');

# rewrite into `coraza off`: the final location's setting applies
$a = audited('c4f', '/c4f?x=evil');
like($a->{response}, qr/^HTTP\S+ 200/, 'rewrite into coraza off: not inspected');
is_deeply($a->{counts}, { 'c4f-A' => 0 }, 'rewrite into coraza off: no audit entry');

# `coraza off` in A, enabled B: B inspects
$a = audited('c4g', '/c4g?x=evil');
like($a->{response}, qr/^HTTP\S+ 403/, 'coraza off -> on: B\'s phase-2 deny applies');
is_deeply($a->{counts}, { 'c4g-B' => 1 }, 'coraza off -> on: one audit entry in B');
like($a->{txid}, qr/^c4g-B-/, 'coraza off -> on: transaction id comes from B');
is($a->{rule}, '407', 'coraza off -> on: rule 407 matched');

# rewrite-phase return 200: phase 2 never runs, the request is still audited
$a = audited('c4h', '/c4h?x=evil');
like($a->{response}, qr/^HTTP\S+ 200/, 'return 200: phase-2 rule cannot fire');
is_deeply($a->{counts}, { 'c4h-A' => 1 }, 'return 200: one audit entry');
is($a->{rule}, undef, 'return 200: no rule matched');
is($a->{status}, 200, 'return 200: audit entry records status 200');

$a = audited('c4h', '/c4h?x=ok');
like($a->{response}, qr/^HTTP\S+ 200/, 'return 200: benign request served');
is_deeply($a->{counts}, { 'c4h-A' => 1 }, 'return 200: benign request audited');

# auth_request subrequest into an enabled location: only the main request binds
$a = audited('c5', '/c5?x=ok');
like($a->{response}, qr/^HTTP\S+ 200/, 'subrequest: main request served');
is_deeply($a->{counts}, { 'c5-A' => 1, 'c5-S' => 0 },
	'subrequest: one audit entry for the main request, none for the subrequest');
like($a->{txid}, qr/^c5-A-/, 'subrequest: transaction id from the main location');
is($a->{rule}, undef, 'subrequest: the subrequest location\'s phase-1 deny never ran');

$a = audited('c5', '/c5?x=evil');
like($a->{response}, qr/^HTTP\S+ 403/,
	'subrequest: main location\'s phase-2 deny still applies');
is_deeply($a->{counts}, { 'c5-A' => 1, 'c5-S' => 0 },
	'subrequest: denial audited once, by the main location');
is($a->{rule}, '501', 'subrequest: rule 501 matched');

# every log received exactly as many entries as requests routed to it
is(entries('c1a-A') + entries('c1b-A') + entries('c2-A')
	+ entries('c4e-A') + entries('c4e-B') + entries('c4f-A'), 0,
	'no rewritten-away location ever audited a request');
is(entries('c1a-B') + entries('c1b-B') + entries('c2-B') + entries('c4e-C')
	+ entries('c4g-B'), 7, 'every final location audited each of its requests');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');

###############################################################################

# Serial JSON audit log: one line per transaction.
sub entries {
	my ($log) = @_;
	my $f = "$testdir/audit-$log.log";
	return 0 unless -e $f;
	open my $fh, '<', $f or die "open $f: $!";
	my $n = grep { /"transaction"/ } <$fh>;
	close $fh;
	return $n;
}

sub last_entry {
	my ($log) = @_;
	my $f = "$testdir/audit-$log.log";
	return undef unless -e $f;
	open my $fh, '<', $f or die "open $f: $!";
	my @lines = grep { /"transaction"/ } <$fh>;
	close $fh;
	return $lines[-1];
}

# Snapshot every audit log that belongs to a case before the request is
# sent, then report how many entries each gained, plus the transaction id,
# the matched rule id and the recorded response status of the newest entry.
# The log file is written after the response, so poll briefly for an
# entry instead of relying on a fixed delay.
sub audited {
	my ($case, $uri) = @_;
	my @mine = grep { /^\Q$case\E-/ } @logs;
	my %before = map { $_ => entries($_) } @mine;
	my $response = http_get($uri);
	my $expected_entry = $case ne 'c4f';

	for (1 .. 50) {
		last if !$expected_entry;
		last if grep { entries($_) > $before{$_} } @mine;
		select undef, undef, undef, 0.1;
	}
	select undef, undef, undef, 0.3 unless $expected_entry;

	my %counts = map { $_ => entries($_) - $before{$_} } @mine;
	my ($txid, $rule, $status);
	for my $log (@mine) {
		next unless $counts{$log};
		my $e = last_entry($log);
		($txid) = $e =~ /"id":"([^"]+)"/;
		($rule) = $e =~ /\[id \\"(\d+)\\"\]/;
		($status) = $e =~ /"response":\{[^{}]*?"status":(\d+)/;
	}
	return {
		response => $response,
		counts => \%counts,
		txid => $txid,
		rule => $rule,
		status => defined $status ? $status + 0 : undef,
	};
}

###############################################################################
