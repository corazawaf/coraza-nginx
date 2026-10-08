#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed response headers vs Range).
#
# coraza_delay_response_headers returns NGX_OK from the Coraza header filter
# instead of calling the next header filter, so every header filter below this
# module is skipped at ngx_http_send_header() time and only runs later, from
# the body filter.  Before the header filter moved below gzip and range, that
# skipped ngx_http_range_header_filter too: the body passed the range BODY
# filter before the range header filter had created its context, so it was
# never sliced, and the range header filter then stamped 206 + Content-Range +
# a short Content-Length onto a full-length body.  The framing on the wire no
# longer matched the declared Content-Length -- a response-smuggling primitive
# and, on a large file, a large amplification.
#
# With the header filter registered after range processing the range context
# exists before the body is produced, and a delayed 206 is a genuine slice.
# These tests assert the wire truth for the delayed path: the status is 206,
# Content-Range describes the slice, the body bytes actually sent equal the
# declared Content-Length, and they are the requested bytes -- for both a
# single range and a multipart/byteranges response.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

use constant CRLF => "\x0d\x0a";

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(18);

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

        # Delay is ON here (the shipped default): this is the path under test.
        # The phase-4 rule proves the delay is in force on this location: a
        # deny after the body has been seen can only come back as a clean 403
        # if the headers were still being held.
        location /delayed {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule ARGS:block "@streq 1" "id:1001,phase:4,deny,status:403"
            ';
        }

        # Negative control: identical location with the delay switched OFF.
        # Range handling is nginx's own here, so a failure in this location
        # means the rig is broken, not the module.
        location /nodelay {
            default_type text/plain;
            coraza on;
            coraza_delay_response_headers off;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
            ';
        }
    }
}

EOF

# 61 bytes exactly.
my $BODY = 'RANGE-DESYNC-CANARY-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-END';
die "fixture must be 61 bytes, got " . length($BODY) if length($BODY) != 61;

$t->write_file('/delayed', $BODY);
$t->write_file('/nodelay', $BODY);

$t->run();
$t->todo_alerts();

###############################################################################

# --- single range, delay ON ---------------------------------------------------

my $r = raw_request("GET /delayed HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-9" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 206 !,
	'single range: delayed path returns 206');
like($r, qr!^Content-Range:\s*bytes 0-9/61\s*$!mi,
	'single range: Content-Range describes the slice');

my ($content_length, $body) = split_response($r);
cmp_ok(defined $content_length ? $content_length : -1, '>', 0,
	'single range: response declares a Content-Length');
is(length($body), $content_length,
	'single range: body bytes on the wire equal Content-Length');
is($body, substr($BODY, 0, 10),
	'single range: body is the requested slice, not the whole entity');

# --- multipart range, delay ON ------------------------------------------------

$r = raw_request("GET /delayed HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-4,10-14" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 206 !,
	'multipart range: delayed path returns 206');
like($r, qr!^Content-Type:\s*multipart/byteranges!mi,
	'multipart range: delayed path emits multipart/byteranges');

($content_length, $body) = split_response($r);
is(length($body), $content_length,
	'multipart range: body bytes on the wire equal Content-Length');
# Each part carries its own Content-Range and exactly its slice; a body that
# passed the range body filter unsliced would carry neither.
like($body, qr!Content-Range:\s*bytes 0-4/61\s*\r\n\r\nRANGE\r\n!i,
	'multipart range: first part is framed and holds bytes 0-4');
like($body, qr!Content-Range:\s*bytes 10-14/61\s*\r\n\r\nNC-CA\r\n!i,
	'multipart range: second part is framed and holds bytes 10-14');

# --- the delay really is in force on /delayed ---------------------------------

# A phase-4 deny on a Range request.  With the headers held this is a clean
# 403; had the 206 headers already gone out the deny would meet "header
# already sent" and the client would see an aborted 206 instead.
$r = raw_request("GET /delayed?block=1 HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-9" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 403 !,
	'delayed path: phase-4 deny on a Range request is a clean 403');
($content_length, $body) = split_response($r);
is(length($body), $content_length,
	'delayed path: the 403 body equals its Content-Length');

# --- negative control: same requests with the delay OFF ---------------------

$r = raw_request("GET /nodelay HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-9" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 206 !,
	'negative control (delay off), single range: 206');
like($r, qr!^Content-Range:\s*bytes 0-9/61\s*$!mi,
	'negative control (delay off), single range: Content-Range describes the slice');
($content_length, $body) = split_response($r);
is($body, substr($BODY, 0, 10),
	'negative control (delay off), single range: body is the slice');

$r = raw_request("GET /nodelay HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-4,10-14" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 206 !,
	'negative control (delay off), multipart range: 206');
like($r, qr!^Content-Type:\s*multipart/byteranges!mi,
	'negative control (delay off), multipart range: emits multipart/byteranges');
($content_length, $body) = split_response($r);
is(length($body), $content_length,
	'negative control (delay off), multipart range: body equals Content-Length');

###############################################################################

# Split a raw response into its declared Content-Length and the bytes that
# actually followed the header terminator.  Returns (undef, '') when there is
# no Content-Length, so the caller's cmp_ok above fails loudly rather than
# comparing against an accidental 0.
sub split_response {
	my ($raw) = @_;
	my $sep = index($raw, CRLF . CRLF);
	return (undef, '') if $sep < 0;
	my $head = substr($raw, 0, $sep);
	my $body = substr($raw, $sep + 4);
	my ($len) = $head =~ /^Content-Length:\s*(\d+)\s*$/mi;
	return ($len, $body);
}

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
		alarm(10);
		local $/;
		$reply = <$s> // '';
		alarm(0);
	};
	# Rethrow a timeout instead of returning '': a silent '' would make the
	# length comparisons above pass vacuously (0 == 0) on a hung connection.
	if (my $err = $@) {
		alarm(0);
		close $s;
		die $err;
	}
	close $s;
	return $reply;
}

###############################################################################
