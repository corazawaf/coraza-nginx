#!/usr/bin/perl

# Tests for Coraza-nginx connector (persistent upstream, interim/no-body
# statuses, misleading framing).
#
# With `keepalive` on the upstream block nginx reuses ONE TCP connection to
# the origin across requests, for as long as nginx's own upstream code
# considers that connection trustworthy. Three status classes never carry a
# body the connector's phase-4 body filter can wait on:
#
#   * 103 Early Hints followed by the real final response on the SAME
#     connection -- the connector must not treat the 103 as the final
#     header set and must not stall waiting for a body that belongs to the
#     103.
#   * 204 No Content -- must never carry a body per RFC 9110 regardless of
#     what Content-Length/Transfer-Encoding the origin (misleadingly) sends.
#   * 304 Not Modified -- same body-less contract, tested with the same
#     misleading framing.
#
# Each is sent with a Content-Length that lies about a body actually being
# present, and the 204 is additionally sent with `Transfer-Encoding: chunked`
# framing a chunked body, so both framing forms the origin could lie with
# are covered. Verified against this worktree's build (nginx 1.31.3): the
# well-formed 103-then-final handoff genuinely reuses the SAME upstream
# connection (proven via a per-connection id the origin logs alongside
# every URI it serves -- see conn-log below), matching the design intent
# above. For /no-content and /not-modified, nginx's own upstream layer logs
# "upstream sent more data than specified in Content-Length" and CLOSES
# that connection rather than risk misreading the surplus bytes as the
# start of the next response -- it does NOT keep reusing a connection it
# has just observed lying about its own framing. That closed-not-reused
# outcome, not blanket reuse, IS the anti-contamination guarantee for a
# connection an origin has shown to misreport Content-Length: nginx trades
# the (now-tainted) connection for provable safety instead of gambling on
# resynchronizing it. The oracle: no delayed-header stall (bounded read
# completes within the alarm), the body-less contract holds regardless of
# which connection serves the response, and the request that follows --
# on whichever connection nginx chooses -- is the correct, uncontaminated
# one, never bytes leaked from an earlier case.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use constant CRLF => "\x0d\x0a";

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(17);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream backend {
        server 127.0.0.1:%%PORT_8081%%;
        keepalive 4;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@contains BADBODY" "id:7400,phase:4,t:none,deny,log,status:403"
            ';
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}
EOF

# Captured as a plain string before the daemon forks: a named sub closing
# over $t (rather than a plain string) keeps $t's refcount alive until
# global destruction, which shifts Test::Nginx's DESTROY-time "no
# alerts"/"no sanitizer errors" checks past Test::Builder's own end-of-run
# plan verification and produces a spurious "planned N tests but ran N-2"
# diagnostic with a nonzero exit despite every subtest passing.
my $testdir = $t->testdir();

$t->run_daemon(\&origin_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# One client connection to nginx, kept open across all three cases plus a
# trailing control request -- proves neither a stalled header delay nor
# leftover bytes from a body-less status corrupt the NEXT response read off
# the same connection.

my $s = IO::Socket::INET->new(
	Proto => 'tcp',
	PeerAddr => '127.0.0.1:' . port(8080),
) or die "Can't connect to nginx: $!\n";
$s->autoflush(1);

# --- case 1: 103 Early Hints then the final response ----------------------

my $r103 = client_request($s, '/early-hints');
unlike($r103, qr/^$/, '103-then-final: response received without a delayed-header stall');
like($r103, qr!^HTTP/1\.1 200!,
	'103-then-final: client sees the FINAL status, not the interim 103');
unlike($r103, qr!^HTTP/1\.1 103!m,
	'103-then-final: the 103 status line itself is not surfaced to the client');

# --- case 2: 204 No Content with misleading framing ------------------------

my $r204 = client_request($s, '/no-content');
like($r204, qr!^HTTP/1\.1 204!, '204: status line passed through');
unlike($r204, qr!BADBODY!,
	'204: no body delivered to the client despite the origin sending one');

# --- case 3: 304 Not Modified with misleading framing -----------------------

my $r304 = client_request($s, '/not-modified');
like($r304, qr!^HTTP/1\.1 304!, '304: status line passed through');
unlike($r304, qr!BADBODY!,
	'304: no body delivered to the client despite the origin sending one');

# --- case 3b: 204 No Content with chunked Transfer-Encoding framing -------

my $r204c = client_request($s, '/no-content-chunked');
like($r204c, qr!^HTTP/1\.1 204!,
	'204 (chunked framing): status line passed through');
unlike($r204c, qr!BADBODY|Transfer-Encoding!i,
	'204 (chunked framing): neither the chunked body nor the '
	. 'Transfer-Encoding header reaches the client');

# --- control: the connection is still usable for a plain request afterward -

my $rctrl = client_request($s, '/plain');
like($rctrl, qr!^HTTP/1\.1 200!,
	'control: connection still serves a correct response after three '
	. 'body-less/interim statuses (no contamination, no stall)');
like($rctrl, qr!PLAIN-OK!,
	'control: the plain response body is exactly the next response, not '
	. 'leftover bytes from an earlier case');

close $s;

$t->stop();

is(origin_saw('unexpected'), 0,
	'origin never received a request URI other than the five sent '
	. '(rules out request-side desync from the misleading responses)');

# Every request-bearing accepted connection logs its (monotonically
# assigned) connection id next to each URI it served, in
# <testdir>/conn-log. The earlier response-content assertions do not, by
# themselves, prove which connection served which request -- nginx could
# silently reconnect after any response and every prior assertion would
# still pass. Verified separately (see header comment): reuse across the
# 103-then-final handoff is the real, observed behavior for THIS worktree's
# build, so that is what gets asserted; nginx closing the connection after
# /no-content or /not-modified (both of which lied about Content-Length) is
# also real, observed, and correct, so it is asserted as a close, not a gap
# papered over with a reuse claim that is not true.
my @conn_log = split /\n/, $t->read_file('conn-log');
my %conn_for_uri;
for my $line (@conn_log) {
	my ($id, $uri) = split /\s+/, $line, 2;
	next unless defined $uri;
	$conn_for_uri{$uri} = $id unless exists $conn_for_uri{$uri};
}

is($conn_for_uri{'/no-content'} // 'missing:/no-content',
	$conn_for_uri{'/early-hints'} // 'missing:/early-hints',
	'103-then-final and the immediately following request are served on '
	. 'the SAME persistent upstream connection (real reuse, not a fresh '
	. 'connect per request)');

isnt($conn_for_uri{'/not-modified'}, $conn_for_uri{'/no-content'},
	'nginx closes (does not keep reusing) the connection right after an '
	. 'origin response that lied about its own Content-Length, rather '
	. 'than gambling on resynchronizing a connection of provably '
	. 'untrustworthy framing');

isnt($conn_for_uri{'/no-content-chunked'}, $conn_for_uri{'/not-modified'},
	'nginx also closes the connection after the misleading 304 (the '
	. 'request after it lands on a fresh upstream connection)');

isnt($conn_for_uri{'/plain'}, $conn_for_uri{'/no-content-chunked'},
	'nginx closes the connection after a 204 whose surplus bytes were '
	. 'chunked-framed, exactly as it does for the Content-Length lie');

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling interim/no-body statuses on a persistent upstream');

###############################################################################

sub client_request {
	my ($sock, $uri) = @_;

	print $sock "GET $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF . CRLF;

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(5);
		# Read until we have a full status-line + headers block; for the
		# body-less cases that IS the whole response, for /plain and the
		# early-hints case we also drain the Content-Length body so the
		# next read on the connection starts at the next response.
		while (1) {
			my $buf;
			my $n = sysread($sock, $buf, 4096);
			last unless $n;
			$reply .= $buf;
			last if response_complete($reply);
		}
		alarm(0);
	};
	# Swallowing a SIGALRM timeout here would let client_request return ''
	# (or a partial buffer) silently on a real stall, and the "no
	# delayed-header stall" assertion below would then pass on a hang
	# instead of on an observed response. Cancel any pending alarm and
	# rethrow so a genuine timeout fails loudly.
	if (my $err = $@) {
		alarm(0);
		die $err;
	}
	return $reply;
}

# Heuristic completion check good enough for this fixture's small, known
# response shapes: headers terminated, and if a Content-Length is present
# the body has fully arrived.
sub response_complete {
	my ($buf) = @_;

	return 0 unless $buf =~ /\r\n\r\n/;

	my ($head, $rest) = split /\r\n\r\n/, $buf, 2;
	$rest //= '';

	if ($head =~ /^HTTP\/1\.1 (204|304)/) {
		return 1;
	}

	if ($head =~ /Content-Length:\s*(\d+)/i) {
		return length($rest) >= $1;
	}

	# No Content-Length and not body-less: treat headers-complete as done
	# for this fixture (used only by the 103 case, whose final response
	# below always sets Content-Length).
	return 1;
}

sub origin_saw {
	my ($tag) = @_;
	my $file = $testdir . "/seen-$tag";
	return -f $file ? 1 : 0;
}

# --- origin daemon: persistent connections, five sequential requests ------

sub origin_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	# Accept connections in a loop, not once: Test::Nginx's own
	# waitforsocket() readiness probe opens and immediately closes a
	# connection before the real client ever connects, and nginx itself may
	# open a fresh upstream connection if it does not keep the first one
	# alive. A single accept() would consume the probe's connection and
	# leave the real traffic unserved. Each accepted connection is served
	# until the peer stops sending requests (EOF), then we accept the next.
	#
	# Every accepted connection gets a monotonically increasing id, logged
	# to <testdir>/conn-log alongside each URI it serves, so the parent can
	# tell which of the five requests shared a connection: reuse across the
	# 103-then-final handoff, and a fresh connection after each response
	# that misreported its own framing.
	my $conn_id = 0;

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		$conn_id++;
		my $this_conn = $conn_id;

		while (1) {
			my $headers = '';
			while (<$client>) {
				$headers .= $_;
				last if (/^\x0d?\x0a?$/);
			}

			last unless length($headers);

			my ($uri) = $headers =~ /^\S+\s+(\S+)/;
			$uri //= '';

			if (length($uri)) {
				open(my $fh, '>>', $testdir . "/conn-log");
				print $fh "$this_conn $uri\n";
				close($fh);
			}

			if ($uri eq '/early-hints') {
				# Interim 103 first, no body, then the real final response
				# -- both on the same connection, back to back.
				print $client "HTTP/1.1 103 Early Hints\r\n"
					. "Link: </style.css>; rel=preload\r\n\r\n";
				print $client "HTTP/1.1 200 OK\r\n"
					. "Content-Length: 7\r\n\r\n"
					. "EH-DONE";
			} elsif ($uri eq '/no-content') {
				# 204 must never carry a body; send misleading framing
				# headers plus a body anyway to prove nginx/coraza strip it
				# regardless.
				print $client "HTTP/1.1 204 No Content\r\n"
					. "Content-Length: 7\r\n\r\n"
					. "BADBODY";
			} elsif ($uri eq '/not-modified') {
				print $client "HTTP/1.1 304 Not Modified\r\n"
					. "Content-Length: 7\r\n\r\n"
					. "BADBODY";
			} elsif ($uri eq '/no-content-chunked') {
				# Same body-less contract, chunked framing: the
				# surplus is a well-formed chunked body nginx must
				# neither forward nor treat as the next response.
				print $client "HTTP/1.1 204 No Content\r\n"
					. "Transfer-Encoding: chunked\r\n\r\n"
					. "7\r\nBADBODY\r\n0\r\n\r\n";
			} elsif ($uri eq '/plain') {
				my $body = "PLAIN-OK\n";
				print $client "HTTP/1.1 200 OK\r\n"
					. "Content-Length: " . length($body) . "\r\n\r\n"
					. $body;
			} else {
				open(my $fh, '>', $testdir . "/seen-unexpected");
				close($fh);
				print $client "HTTP/1.1 500 Internal Server Error\r\n"
					. "Content-Length: 0\r\n\r\n";
			}
		}

		close $client;
	}
}

###############################################################################
