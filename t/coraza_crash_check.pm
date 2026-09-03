package coraza_crash_check;

# Shared worker-crash detector for the coraza-nginx prove suite.
#
# A test that only checks the HTTP status/body of the last request can pass
# even when the worker segfaulted mid-run and was silently respawned, or when
# an ASan build already unwound and logged a report -- neither shows up in the
# response. Every file that starts nginx must therefore also grep error.log
# for a crash signature before Test::Nginx tears the instance down.
#
# CI flattens this repo's t/ into nginx-tests' own directory with a
# non-recursive `cp ../t/* .` (see .github/workflows/build-test.yml), so this
# module MUST stay a flat file directly under t/ -- a t/lib/ subdirectory
# would silently fail to ship (cp refuses to copy directories without -r,
# and the workflow step runs under `set -euo pipefail`, so that would abort
# the whole prove run rather than just dropping the helper).
#
# Usage, right before/instead of the file's own $t->stop():
#
#   use lib '.';
#   use coraza_crash_check;
#
#   coraza_crash_check::assert_no_crash($t, 'no crash from <scenario>');
#
# assert_no_crash() calls $t->stop() itself (Test::Nginx::stop is safe to
# call more than once), then runs exactly one Test::More assertion, so add 1
# to the file's plan() count for each call.

use warnings;
use strict;

use Test::More;
use Time::HiRes qw/ sleep /;

# Matches what the three original crash-checking tests looked for
# (coraza-empty-header-value.t, coraza-request-body-chunked.t,
# coraza-deleted-headers.t), widened to every way a dead worker shows up in
# error.log:
#   * the master's "[alert] worker process N exited on signal S" for ANY
#     signal, not just 11 -- a Go panic inside libcoraza (cgo) aborts the
#     worker with signal 6, and SIGBUS/SIGILL are just as fatal;
#   * "exited with fatal code" (ngx_worker_process_exit on a fatal error);
#   * the sanitizer report headers (ASan/UBSan/LSan, plus UBSan's bare
#     "runtime error:" lines) -- nginx redirects the worker's stderr into
#     error.log, so these land there too;
#   * Go runtime crash banners ("panic:", "fatal error:") from libcoraza,
#     which reach error.log the same way before the worker dies.
# NOTE: /x strips literal whitespace from the pattern, so every space in a
# multi-word alternative MUST be written as \s (or the alternative silently
# becomes an unmatchable run-together token such as "exitedonsignal").
our $CRASH_RE = qr/exited\son\ssignal|exited\swith\sfatal\scode
	|SIGSEGV|SIGABRT|SIGBUS|AddressSanitizer|UndefinedBehaviorSanitizer
	|LeakSanitizer|runtime\serror:|^panic:\s|^fatal\serror:\s/mx;

# Hard ceiling, in seconds, on the whole shutdown.  Test::Nginx::stop() polls
# for the master with WNOHANG for 90s, then falls through to a BLOCKING
# waitpid($pid, 0) with no timeout at all -- so a master that will not exit
# wedges the file, and with it the entire prove run, forever.  Bounding it
# here converts that class of failure into a loud test failure instead of a
# CI slot burned to its 6-hour limit.
our $SHUTDOWN_TIMEOUT = 60;

sub assert_no_crash {
	my ($t, $name) = @_;

	$name = 'no worker crash in error.log' unless defined $name;

	# Order matters.  Test::Nginx::DESTROY tears down in the order
	# stop() then stop_daemons(), but "nginx -s quit" is a GRACEFUL
	# shutdown: a worker holding a live upstream connection will not
	# exit while that connection is still being written to.  A test whose
	# backend daemon streams forever (coraza-sse.t) therefore keeps the
	# worker alive, stop() exhausts its 90s poll, and the unbounded
	# waitpid() behind it blocks for good.  Reaping the daemons FIRST
	# closes the upstream side, so the graceful quit can actually finish.
	my $wedged = _stop_with_timeout($t, $SHUTDOWN_TIMEOUT);

	if (defined $wedged) {
		# Kill the master outright and clear _started, otherwise
		# Test::Nginx::DESTROY calls the very same unbounded stop()
		# again at process exit and re-wedges the run after the plan
		# has already been satisfied.
		my $pid = eval { $t->read_file('nginx.pid') };
		if (defined $pid && $pid =~ /^\s*(\d+)/) {
			my $master = $1;
			my @workers = _child_pids($master);
			kill 'TERM', @workers, $master;
			sleep 0.1;
			kill 'KILL', @workers, $master;
			waitpid($master, 0);
		}
		$t->{_started} = 0;

		fail($name);
		diag("nginx did not shut down within "
			. "${SHUTDOWN_TIMEOUT}s: $wedged");
		return;
	}

	unlike($t->read_file('error.log'), $CRASH_RE, $name);
}

sub _stop_with_timeout {
	my ($t, $timeout) = @_;
	my $wedged;

	eval {
		local $SIG{ALRM} = sub { die "shutdown timeout\n" };
		alarm($timeout);
		$t->stop_daemons();
		$t->stop();
		alarm(0);
		1;
	} or do {
		alarm(0);
		$wedged = $@;
	};

	return $wedged;
}

sub _child_pids {
	my ($parent) = @_;
	my @children;

	open my $ps, '-|', 'ps', '-eo', 'pid=,ppid='
		or return @children;
	while (my $line = <$ps>) {
		my ($pid, $ppid) = $line =~ /^\s*(\d+)\s+(\d+)\s*$/;
		push @children, $pid
			if defined $pid && defined $ppid && $ppid == $parent;
	}
	close $ps;

	return @children;
}

1;
