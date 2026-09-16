#!/usr/bin/perl

# Tests for Coraza-nginx connector (hostile request framing, on/off
# differential).
#
# nginx's core HTTP parser is the first line of defense against request
# smuggling and framing attacks: conflicting Content-Length/Transfer-Encoding,
# malformed chunk sizes, trailing garbage after the terminal chunk, and a body
# that does not match its declared Content-Length. The connector must never
# make nginx's own verdict on these WORSE -- a request core nginx rejects must
# never reach the proxied origin, whether coraza is on or off, and turning
# coraza on must not relax a rejection into a pass.
#
# Design: an origin daemon marks every request it actually receives by
# writing a line to a marker file per case. Each hostile case is sent to a
# pair of locations that are identical except for `coraza on|off`. The oracle
# is (a) the response is never the origin's 200 OK-off-limits marker leaking
# through as a successful smuggled request, and (b) the origin is not invoked
# at all for input nginx's own parser rejects -- checked identically for both
# locations. Where nginx's parser accepts and forwards the request (case is
# framing-ambiguous but not core-rejected), coraza on must reject at least as
# often as coraza off; it must never be the on-side that lets through what the
# off-side blocked.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(34);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location /off/ {
            coraza off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%/;
        }

        location /on/ {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecResponseBodyAccess On
                SecAction "id:7300,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule RESPONSE_BODY "@contains BADBODY" "id:7301,phase:4,t:none,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%/;
        }
    }
}
EOF

# Captured as a plain string, not the $t object itself, and BEFORE the daemon
# is forked: a named sub closing over $t keeps its refcount alive until
# global destruction, which shifts Test::Nginx's DESTROY-time "no
# alerts"/"no sanitizer errors" checks past Test::Builder's own end-of-run
# plan verification and produces a spurious "planned N tests but ran N-2"
# diagnostic with a nonzero exit despite every subtest passing. The forked
# daemon also needs the plain string, since it must be set before fork().
my $testdir = $t->testdir();

$t->run_daemon(\&origin_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# --- case 1: conflicting Content-Length vs Transfer-Encoding --------------
#
# Smuggling-classic: two framing headers that disagree on where the body
# ends. nginx's core must reject this outright (400) for both on and off --
# it must never reach the origin under either.

for my $loc (qw(off on)) {
	my $r = raw_request(
		"POST /$loc/clte HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: 5" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "3" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF
	);
	like($r, qr!^HTTP/1\.1 400!,
		"conflicting Content-Length/Transfer-Encoding rejected by core ($loc)");
}

# --- case 2: malformed / truncated chunk size ------------------------------

for my $loc (qw(off on)) {
	my $r = raw_request(
		"POST /$loc/badchunk HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "ZZZ" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF
	);
	unlike($r, qr!^HTTP/1\.1 200!,
		"malformed chunk size never yields 200 ($loc)");
}

# --- case 3: chunk trailers and surplus bytes after the final chunk -------
#
# Well-formed terminal chunk plus a trailer section, followed by extra bytes
# shaped like a second request. The request itself is legitimate (RFC 9112
# allows trailers), so it MUST be served and reach the origin exactly like a
# plain request -- a connector that rejected the whole request would pass a
# check that only looks for the absence of the surplus. The surplus bytes
# must never be routed as a request of their own: the request carries
# `Connection: close`, so nginx must discard anything after the terminal
# chunk and trailers instead of pipelining it, and the origin must never see
# `/smuggled`.

for my $loc (qw(off on)) {
	my $r = raw_request(
		"POST /$loc/trailer HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "3" . CRLF . "abc" . CRLF . "0" . CRLF
		. "X-Trailer: yes" . CRLF . CRLF
		. "GET /$loc/smuggled HTTP/1.1" . CRLF . "Host: localhost" . CRLF . CRLF
	);
	like($r, qr!^HTTP/1\.1 200!,
		"legitimate chunked request with a trailer section is served ($loc)");
	is(scalar(() = $r =~ m!^HTTP/1\.1 !mg), 1,
		"exactly one response: surplus bytes after the final chunk are not pipelined ($loc)");
}

# --- case 4: Content-Length vs actual body length mismatch ----------------
#
# Declared length longer than the bytes actually sent before the peer closes:
# nginx must not proxy a short/truncated body as if it were complete, and
# must not hang past the read timeout in a way that yields a 200.

for my $loc (qw(off on)) {
	my $r = short_body_request($loc);
	unlike($r, qr!^HTTP/1\.1 200!,
		"Content-Length longer than actual body never yields 200 ($loc)");
}

# --- case 5: stacked/unknown Content-Encoding under response body access --
#
# The /on/ location above already runs with SecResponseBodyAccess On, so it
# is reused directly here -- no second config/reload needed. Neither nginx
# nor the connector decodes response content codings, so an origin response
# advertising a chain nginx/coraza cannot decode (gzip+br stacked, or an
# unknown token) is passed through as opaque bytes. A 200 alone would not
# prove that: a regression that stripped the Content-Encoding header or
# rewrote the body would still return one. Each case therefore also asserts
# that the header arrives with its exact value and that the payload arrives
# byte for byte.

for my $enc ('gzip,br', 'unknown-codec', 'identity,gzip,unknown') {
	for my $loc (qw(off on)) {
		my $r = stacked_encoding_request($loc, $enc);
		like($r, qr!^HTTP/1\.1 200!,
			"stacked/unknown Content-Encoding '$enc' passes through undecoded, no hang ($loc)");
		like($r, qr!\r\nContent-Encoding:\s*\Q$enc\E\r\n!i,
			"Content-Encoding '$enc' reaches the client unchanged ($loc)");
		like($r, qr!\r\n\r\npayload\z!,
			"the opaque encoded payload reaches the client unchanged ($loc)");
	}
}

$t->stop();

is(origin_saw('clte'), 0,
	'origin never invoked for the Content-Length vs Transfer-Encoding conflict (core rejects before proxy_pass)');
is(origin_saw('badchunk'), 0,
	'origin never invoked for a malformed chunk size');
is(origin_saw('trailer'), 1,
	'origin received the legitimate trailer-carrying request (the reject '
	. 'of the surplus did not also reject the request in front of it)');
is(origin_saw('smuggled'), 0,
	'origin never invoked via bytes smuggled past the terminal chunk');
is(origin_saw('short'), 0,
	'origin never invoked for the truncated body (nginx does not proxy a '
	. 'request whose declared Content-Length was never fully received)');

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling hostile request framing');

###############################################################################

sub raw_request {
	my ($request) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s $request;

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(5);
		local $/;
		$reply = <$s> // '';
		alarm(0);
	};
	# A SIGALRM stores "timeout\n" in $@ via die; swallowing it would let
	# raw_request return '' silently, and every unlike(..., qr!^HTTP/1\.1
	# 200!) below would then pass vacuously on a hung connection instead of
	# on an observed rejection. Cancel any pending alarm and rethrow so a
	# real hang fails the test loudly instead of faking a pass.
	if (my $err = $@) {
		alarm(0);
		close $s;
		die $err;
	}
	close $s;
	return $reply;
}

# Send a Content-Length declaring more bytes than are actually written, then
# half-close the write side and close -- the classic truncated-body case.
# Half-closing (not just close()) is what actually signals "no more bytes
# coming" to nginx while the read side stays open long enough to receive a
# reply; a plain close() can leave nginx seeing a live, merely slow request
# instead of the peer-closed truncation this case is meant to exercise.
sub short_body_request {
	my ($loc) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "POST /$loc/short HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: 100" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "short";
	shutdown($s, 1) or die "Can't half-close request socket: $!\n";

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(3);
		local $/;
		$reply = <$s> // '';
		alarm(0);
	};
	if (my $err = $@) {
		alarm(0);
		close $s;
		die $err;
	}
	close $s;
	return $reply;
}

sub stacked_encoding_request {
	my ($loc, $enc) = @_;

	return raw_request(
		"GET /$loc/enc/$enc HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF . CRLF
	);
}

# --- origin daemon: records which URIs it actually received ---------------

sub origin_saw {
	my ($tag) = @_;
	my $file = $testdir . "/seen-$tag";
	return -f $file ? 1 : 0;
}

sub origin_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my ($uri) = $headers =~ /^\S+\s+(\S+)/;
		$uri //= '';

		for my $tag (qw(clte badchunk smuggled short trailer)) {
			if ($uri =~ /\Q$tag\E/) {
				open(my $fh, '>', $testdir . "/seen-$tag");
				close($fh);
			}
		}

		if ($uri =~ m{/enc/([^/\s]+)}) {
			my $enc = $1;
			my $body = "payload";
			print $client "HTTP/1.1 200 OK\r\n"
				. "Content-Encoding: $enc\r\n"
				. "Content-Length: " . length($body) . "\r\n"
				. "Connection: close\r\n\r\n"
				. $body;
		} else {
			my $body = "TEST-OK\n";
			print $client "HTTP/1.1 200 OK\r\n"
				. "Content-Length: " . length($body) . "\r\n"
				. "Connection: close\r\n\r\n"
				. $body;
		}

		close $client;
	}
}

###############################################################################
