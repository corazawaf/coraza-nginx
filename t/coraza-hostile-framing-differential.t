#!/usr/bin/perl

# Differential corpus for hostile HTTP framing: conflicting Content-Length /
# Transfer-Encoding, malformed and truncated chunked bodies, trailers, a
# Content-Length longer than the transmitted body, and stacked/unknown
# Content-Encoding under
# SecResponseBodyAccess On.
#
# Only t/coraza-request-body-chunked.t exercises chunking today, and only
# well-formed chunked bodies; "trailer" appears only in
# t/coraza-bulk-headers.t as a header name, never as a framing case.  No
# existing test compares Coraza on against Coraza off for the same hostile
# input.
#
# The point of this file is the PAIRED comparison, not an absolute status
# code check on the coraza-on config alone.  Every case is sent to a
# coraza-on location and a coraza-off location that otherwise share the same
# proxy_pass target, and both responses are inspected for two invariants:
#
#   1. Input nginx core itself rejects at the framing layer must never reach
#      the origin, on OR off.  The origin marks every response it produces
#      with an ORIGIN-HIT body so "did this reach the origin" is directly
#      observable in the reply, not inferred from a status code alone.
#   2. Coraza on must not be WEAKER than Coraza off: whatever core (or
#      Coraza) does when the request is off must not become a clean
#      pass-through when Coraza is turned on for the same bytes.

###############################################################################

use warnings;
use strict;

use IO::Socket::INET;
use Test::More;

use constant CRLF => "\x0d\x0a";

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        # coraza on: SecRuleEngine On with a body rule, so a request that
        # frames cleanly and carries no marker sails through, but the
        # location is still a real WAF, not a pass-through shim.
        location /on {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecResponseBodyAccess On
                SecAction "id:7300,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@contains BADBODY" "id:7301,phase:2,deny,log,status:403,t:none"
            ';
            rewrite ^/on(/.*)$ $1 break;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /off {
            coraza off;
            rewrite ^/off(/.*)$ $1 break;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  localhost;
        access_log   %%TESTDIR%%/origin.log;

        # Every reply from the real origin carries this marker so a test can
        # tell "the origin answered" from "nginx or Coraza answered instead"
        # by inspecting the body, independent of the status line.
        location / {
            return 200 "ORIGIN-HIT\n";
        }

        # Stacked / unknown Content-Encoding, for the SecResponseBodyAccess On
        # response-side cases below.
        location /stacked {
            add_header Content-Encoding "gzip, br";
            return 200 "ORIGIN-HIT-ENCODED\n";
        }

        location /unknown {
            add_header Content-Encoding "x-unknown-encoding";
            return 200 "ORIGIN-HIT-ENCODED\n";
        }
    }
}

EOF

$t->try_run('no coraza');
$t->plan(51);
our $origin_log = $t->testdir() . '/origin.log';

###############################################################################

# --- helpers ----------------------------------------------------------------

# Send raw bytes and read whatever comes back, with a bounded timeout; never
# use http_get/http(), which build well-formed request lines and would
# normalize away the very malformations under test.
sub raw {
	my ($bytes, %opt) = @_;

	my $s = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect: $!\n";
	$s->autoflush(1);

	local $SIG{ALRM} = sub { die "timeout\n" };
	my $reply = '';
	eval {
		alarm(5);
		$s->print($bytes) or die "Can't write request: $!\n";
		if ($opt{half_close}) {
			shutdown($s, 1)
				or die "Can't half-close request stream: $!\n";
		}
		my $buf;
		while (1) {
			my $n = sysread($s, $buf, 65536);
			die "Can't read response: $!\n" unless defined $n;
			last if $n == 0;
			$reply .= $buf;
		}
		alarm(0);
	};
	my $err = $@;
	alarm(0);
	$s->close();
	die $err if $err;
	return $reply;
}

sub status_of {
	my ($reply) = @_;
	return 'NONE' unless defined $reply and length $reply;
	return $1 if $reply =~ m!^HTTP/1\.[01]\s+(\d\d\d)!;
	return 'MALFORMED';
}

sub reached_origin {
	my ($reply) = @_;
	return defined $reply && $reply =~ /ORIGIN-HIT/;
}

sub origin_requests {
	return 0 unless -f $origin_log;
	open my $log, '<', $origin_log
		or die "Can't read $origin_log: $!\n";
	my $count = 0;
	$count++ while <$log>;
	close $log or die "Can't close $origin_log: $!\n";
	return $count;
}

# Run one malformed case against both /on and /off. Nginx core must refuse it
# before proxying, with Coraza on or off.
sub differential {
	my ($name, $request, %opt) = @_;

	my $before = origin_requests();
	my $on = raw($request =~ s!^(\S+ )/!${1}/on!mr,
		half_close => $opt{half_close});
	my $after_on = origin_requests();
	my $off = raw($request =~ s!^(\S+ )/!${1}/off!mr,
		half_close => $opt{half_close});
	my $after_off = origin_requests();

	my $on_status  = status_of($on);
	my $off_status = status_of($off);

	ok($off_status !~ /^2/,
		"$name: core rejects malformed framing (coraza off: $off_status)");
	ok($on_status !~ /^2/,
		"$name: coraza-on is not weaker than coraza-off ($on_status)");
	is($after_on, $before,
		"$name: malformed request never reaches origin (coraza on)");
	is($after_off, $after_on,
		"$name: malformed request never reaches origin (coraza off)");

}

###############################################################################
# --- conflicting framing: Content-Length vs Transfer-Encoding --------------

# RFC 9112 6.1: a message with both headers is invalid and must be rejected
# or the Transfer-Encoding header stripped and the message treated as
# malformed -- either way the origin must never see it as a valid request.
differential('conflicting Content-Length and Transfer-Encoding headers',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Content-Length: 5" . CRLF
	. "Transfer-Encoding: chunked" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "3" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF);

# --- malformed / truncated chunked bodies -----------------------------------

# Non-hex chunk size.
differential('non-hex chunk size',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Transfer-Encoding: chunked" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "zzzz" . CRLF . "abcd" . CRLF . "0" . CRLF . CRLF);

# Missing terminating CRLF after the chunk data.
differential('missing chunk terminator',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Transfer-Encoding: chunked" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "3" . CRLF . "abcXXXX" . CRLF . "0" . CRLF . CRLF);

# Negative-looking (signed) chunk size.
differential('negative chunk size',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Transfer-Encoding: chunked" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "-3" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF);

# Absurdly huge chunk size that cannot exist on the wire; the connection must
# be refused/truncated rather than nginx blocking waiting for it, and the
# origin must not see it.
differential('huge chunk size',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Transfer-Encoding: chunked" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "FFFFFFFFFFFFFFFF" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF);

# Truncated body: declares a chunk but the connection is closed before the
# chunk data or the final "0" chunk ever arrives.
differential('truncated chunked body',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Transfer-Encoding: chunked" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "a" . CRLF . "abc",
	half_close => 1);

# --- trailers ---------------------------------------------------------------

# A well-formed trailer section is legal chunked framing (RFC 9112 7.1.2);
# this is the well-formed control showing legitimate trailers are not
# themselves treated as malformed by either config.
{
	my $body = "3" . CRLF . "abc" . CRLF . "0" . CRLF
		. "X-Trailer: legit" . CRLF . CRLF;
	my $req = "POST / HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. $body;

	my $on  = raw($req =~ s!^(\S+ )/!${1}/on!mr);
	my $off = raw($req =~ s!^(\S+ )/!${1}/off!mr);

	is(status_of($on), '200',
		'well-formed trailer: coraza-on passes clean chunked body');
	is(status_of($off), '200',
		'well-formed trailer: coraza-off passes clean chunked body');
}

# --- Content-Length vs actual body length mismatch --------------------------

# Declares more bytes than are ever sent, then closes -- must not block
# waiting forever nor forward a short body as if it were complete.
differential('Content-Length longer than actual body',
	"POST / HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Content-Length: 100" . CRLF
	. "Connection: close" . CRLF . CRLF
	. "short",
	half_close => 1);

###############################################################################
# --- negative control: benign well-formed request reaches the origin ------

{
	my $on  = raw("GET /on HTTP/1.1" . CRLF . "Host: localhost" . CRLF
		. "Connection: close" . CRLF . CRLF);
	my $off = raw("GET /off HTTP/1.1" . CRLF . "Host: localhost" . CRLF
		. "Connection: close" . CRLF . CRLF);

	like($on, qr/^HTTP\/1\.1 200/, 'control: benign request passes coraza-on');
	ok(reached_origin($on), 'control: benign request reaches origin (coraza on)');
	like($off, qr/^HTTP\/1\.1 200/, 'control: benign request passes coraza-off');
	ok(reached_origin($off), 'control: benign request reaches origin (coraza off)');
}

# --- Coraza's own rule still fires on well-formed input --------------------
#
# The differential cases above are all about FRAMING invariants that nginx
# core enforces regardless of Coraza.  This case is the complement: proof
# that Coraza's own SecRule ("id:7301", REQUEST_BODY contains BADBODY) still
# blocks a well-formed request on /on while /off lets the identical bytes
# through to the origin -- so a differential run that (incorrectly) always
# treated "on" and "off" as equally strict would still be caught here.
{
	my $body = 'field=BADBODY';
	my $req = "POST / HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: " . length($body) . CRLF
		. "Connection: close" . CRLF . CRLF
		. $body;

	my $on  = raw($req =~ s!^(\S+ )/!${1}/on!mr);
	my $off = raw($req =~ s!^(\S+ )/!${1}/off!mr);

	like($on, qr/^HTTP\/1\.1 403/,
		"Coraza's own rule blocks a well-formed BADBODY request (coraza on)");
	ok(!reached_origin($on),
		"Coraza's own rule keeps a blocked BADBODY request from the origin (coraza on)");
	like($off, qr/^HTTP\/1\.1 200/,
		'well-formed BADBODY request passes through when coraza is off (control)');
	ok(reached_origin($off),
		'well-formed BADBODY request reaches origin when coraza is off (control)');
}

###############################################################################
# --- stacked / unknown Content-Encoding under SecResponseBodyAccess On -----
#
# These exercise the response side: the origin sends back a body under a
# Content-Encoding Coraza cannot necessarily decode, with
# SecResponseBodyAccess On already set in the /on location.  Coraza must not
# crash or corrupt the passthrough; nginx core still owns whether the encoded
# bytes are forwarded unchanged.

for my $path (qw(/on/stacked /off/stacked /on/unknown /off/unknown)) {
	my $r = http_get($path);
	my $encoding = $path =~ /stacked/ ? 'gzip, br' : 'x-unknown-encoding';
	like($r, qr/^HTTP\/1\.[01] 200/,
		"stacked/unknown Content-Encoding: $path does not crash the proxy");
	like($r, qr/^Content-Encoding: \Q$encoding\E\r?$/mi,
		"stacked/unknown Content-Encoding: $path preserves the header");
	like($r, qr/\r\n\r\nORIGIN-HIT-ENCODED\n\z/,
		"stacked/unknown Content-Encoding: $path preserves the body");
}

$t->stop();

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling hostile HTTP framing, trailers, or stacked Content-Encoding');

###############################################################################
