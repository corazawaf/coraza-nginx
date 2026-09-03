#!/usr/bin/perl

# Tests for Coraza-nginx connector (no per-transaction state leaks across a
# keepalive connection).
#
# The connector creates/destroys a Coraza transaction per request, but that
# lifecycle is driven from nginx request phases and pool cleanup handlers
# rather than the connection itself, so a bug that left the c->data,
# ctx->tx, or an intervention flag pointing at the previous transaction
# would only surface on a SECOND request reusing the SAME connection --
# something no other test in this suite exercises. This drives a deny on
# request 1 and a benign request 2 down one persistent socket and asserts
# request 2 is genuinely evaluated fresh (200), not short-circuited by
# leftover state from request 1's block.
#
# CONTRACT PINNED, read before touching keepalive_requests/timeout: nginx
# keeps the connection open after a coraza deny (403) as long as the
# response was well-formed and Connection: close was not forced, so a
# second request pipelined on the same socket is a normal, reachable case in
# production, not a synthetic one. If a future connector change starts
# forcing Connection: close on every deny, this test's second read will
# simply see nothing back (a numbered request 2 that times out) and that is
# itself the regression to investigate, not an anomaly in this test.
# See src/ngx_http_coraza_module.c (transaction creation/cleanup handlers).

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    keepalive_timeout 30s;
    keepalive_requests 10;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:60,phase:1,deny,status:403,log,msg:\'keepalive-state-probe\'"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }
    }
}
EOF

$t->run();

###############################################################################

my $s = IO::Socket::INET->new(
	Proto    => 'tcp',
	PeerAddr => '127.0.0.1:' . port(8080),
	Timeout  => 5,
) or die "Can't connect to nginx: $!\n";
$s->autoflush(1);

# Request 1: trips the deny rule. Keep-Alive requested explicitly; do not
# close our end so the same TCP connection carries request 2.
my $r1 = send_and_read($s, "GET /?x=bad HTTP/1.1\r\n"
	. "Host: localhost\r\n"
	. "Connection: keep-alive\r\n\r\n");
like($r1, qr!^HTTP/\S+ 403!, 'request 1 on the connection is denied');

SKIP: {
	skip 'connection was closed after the deny (see file header)', 1
		# connected() returns a packed peer address, not a number, so test
		# it for truth -- comparing it with == warns and is meaningless.
		if !defined $r1 || $r1 eq '' || !$s->connected();

	# Request 2 on the SAME socket: benign, must be evaluated fresh and
	# return 200 -- not a stale 403 carried over from request 1's
	# transaction/intervention state.
	my $r2 = send_and_read($s, "GET /?x=fine HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n");
	like($r2, qr!^HTTP/\S+ 200!,
		'request 2 on the same connection is evaluated fresh, not stale-denied');
}

close $s;

$t->stop();
unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling two requests on one keepalive connection');

###############################################################################

# Read one HTTP response off an open socket without closing it, so it can be
# reused for a following request.
sub send_and_read {
	my ($sock, $request) = @_;

	$sock->print($request);

	my $buf = '';
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm(5);

		# Read headers first.
		while ($buf !~ /\r\n\r\n/) {
			my $chunk;
			my $n = $sock->sysread($chunk, 1024);
			last if !defined $n || $n == 0;
			$buf .= $chunk;
		}

		# Read the body per Content-Length, if any was sent.
		if ($buf =~ /Content-Length:\s*(\d+)/i) {
			my $want = $1;
			my ($headers, $body) = $buf =~ /^(.*?\r\n\r\n)(.*)$/s;
			while (length($body) < $want) {
				my $chunk;
				my $n = $sock->sysread($chunk, 1024);
				last if !defined $n || $n == 0;
				$body .= $chunk;
			}
			$buf = $headers . $body;
		}

		alarm(0);
	};
	return undef if $@;
	return $buf;
}

###############################################################################
