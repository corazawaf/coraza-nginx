#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed response headers vs 304).
#
# Content handlers read r->header_only AFTER ngx_http_send_header() returns,
# and that flag is set by nginx's own final header filter.  When
# coraza_delay_response_headers returns NGX_OK instead of calling the next
# header filter, that final filter never runs at send_header() time, so
# r->header_only is still 0 when the static handler resumes -- and the handler
# streams the whole file for a response that must carry no body at all.
# The connector then buffers it and flushes the 304 headers followed by the
# body (RFC 9110 section 15.4.5: a 304 transfers no content).
#
# The HEAD case of exactly this mechanism was already anticipated and excluded
# in the header filter; 304 and 204 were not.  t/coraza-head-no-body.t covers
# the HEAD half; this file covers the status-code half.
#
# The assertion is on the raw wire response: everything after the header
# terminator must be zero bytes.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(6);

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
        location /delayed {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
            ';
        }

        # Negative control: identical location with the delay switched OFF.
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

my $BODY = 'NOT-MODIFIED-CANARY-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-END';
# The unlike(NOT-MODIFIED-CANARY) assertion below is only meaningful while the
# fixture actually contains that substring; if it is ever edited out the check
# passes vacuously.  Fail loudly here instead.
die "fixture must contain the NOT-MODIFIED-CANARY marker"
	if index($BODY, 'NOT-MODIFIED-CANARY') < 0;

$t->write_file('/delayed', $BODY);
$t->write_file('/nodelay', $BODY);

$t->run();
$t->todo_alerts();

###############################################################################

# Learn the validator from an unconditional GET, then replay it.  Using the
# server's own ETag keeps this independent of clock skew and of how the
# fixture's mtime was set.
my $etag = etag_of('/delayed');
ok(defined $etag && length $etag, 'delayed location returns an ETag to revalidate');

my $r = raw_request("GET /delayed HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "If-None-Match: $etag" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 304!, '304 Not Modified for a matching If-None-Match');
is(body_bytes($r), 0, '304 response carries zero body bytes on the wire');
unlike($r, qr/\QNOT-MODIFIED-CANARY\E/,
	'304 response does not leak file content');

# --- negative control: same exchange with the delay OFF ---------------------

my $cetag = etag_of('/nodelay');
my $c = raw_request("GET /nodelay HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "If-None-Match: $cetag" . CRLF
	. "Connection: close" . CRLF . CRLF);

# There is no "other path" marker to assert here the way the range control can
# assert 206/Content-Range: with the delay off the 304 is simply a correct 304,
# and a correct 304 is byte-for-byte what the fixed delayed path also produces.
# The one thing worth pinning is that this control really revalidated, so the
# zero-body check cannot pass against a 200 whose body happened to be absent.
like($c, qr!^HTTP/1\.1 304!,
	'negative control (delay off): really revalidated to 304');
is(body_bytes($c), 0,
	'negative control (delay off): 304 carries zero body bytes');

###############################################################################

sub etag_of {
	my ($uri) = @_;

	my $raw = raw_request("GET $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF . CRLF);

	my ($e) = $raw =~ /^ETag:\s*(\S+)\s*$/mi;
	return $e;
}

# Count the bytes that followed the header terminator.  Returns -1 when no
# terminator was seen, so a truncated or empty reply fails the is(..., 0)
# assertions above instead of passing vacuously.
sub body_bytes {
	my ($raw) = @_;

	my $sep = index($raw, CRLF . CRLF);
	return -1 if $sep < 0;

	return length(substr($raw, $sep + 4));
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
	# Rethrow a timeout instead of returning '': a silent '' would make
	# body_bytes() return -1 and the assertions fail loudly, but the die
	# reports the real cause rather than a confusing -1.
	if (my $err = $@) {
		alarm(0);
		close $s;
		die $err;
	}
	close $s;
	return $reply;
}

###############################################################################
