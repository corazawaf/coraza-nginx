#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 14;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '.';
use coraza_crash_check;

for my $line (
	'[alert] worker process 42 exited on signal 11',
	'worker process exited with fatal code 2',
	'ERROR: AddressSanitizer: heap-use-after-free',
	'UndefinedBehaviorSanitizer: undefined-behavior',
	'ERROR: LeakSanitizer: detected memory leaks',
	'runtime error: signed integer overflow',
	"panic: fatal libcoraza state\n",
	"fatal error: concurrent map writes\n",
) {
	like($line, $coraza_crash_check::CRASH_RE, "crash signature: $line");
}

unlike('[notice] worker process 42 exited with code 0',
	$coraza_crash_check::CRASH_RE, 'normal worker exit is not a crash');

{
	package FakeTest;
	sub new { bless { calls => [], delay => $_[1] // 0 }, $_[0] }
	sub stop_daemons { push @{$_[0]->{calls}}, 'daemons' }
	sub stop {
		push @{$_[0]->{calls}}, 'nginx';
		sleep $_[0]->{delay};
	}
}

my $normal = FakeTest->new();
is(coraza_crash_check::_stop_with_timeout($normal, 1), undef,
	'bounded shutdown succeeds');
is_deeply($normal->{calls}, [qw/daemons nginx/],
	'backend daemons stop before nginx');

my $slow = FakeTest->new(2);
like(coraza_crash_check::_stop_with_timeout($slow, 1), qr/shutdown timeout/,
	'bounded shutdown reports a stalled stop');

my $child = fork();
die "fork failed: $!" unless defined $child;
exit 0 if $child == 0;
ok(coraza_crash_check::_reap_with_timeout($child, 1),
	'forced-cleanup reap completes through the nonblocking helper');

my $live_child = fork();
die "fork failed: $!" unless defined $live_child;
if ($live_child == 0) {
	sleep 5;
	exit 0;
}
ok(!coraza_crash_check::_reap_with_timeout($live_child, 0.05),
	'forced-cleanup reap returns at its deadline for a live child');
kill 'KILL', $live_child;
waitpid($live_child, 0);
