#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 12;

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
