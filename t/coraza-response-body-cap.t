#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed-response buffering cap).
#
# The header filter delays response headers until phase 4 completes so a
# phase-4 rule can still return a clean error page.  While delayed, the body
# filter accumulates every response buffer into the request pool.  For a large
# or open-ended (streaming) response that buffering would grow without limit
# and OOM the worker.
#
# The fix caps the accumulation at NGX_HTTP_CORAZA_MAX_DELAYED_BODY (1 MiB by
# default): once exceeded, the delayed headers + everything buffered so far are
# flushed and the remainder streams through.  This test drives a response well
# past the cap (with SecResponseBodyAccess Off, so the body is still delayed
# and buffered but Coraza itself does not inspect/limit it) and asserts:
#   1. the response still completes with 200 and an intact body, and
#   2. the connector logged that it flushed early (the cap path executed).
# See src/ngx_http_coraza_body_filter.c (NGX_HTTP_CORAZA_MAX_DELAYED_BODY).
#
# The /big case above only exercises the fail-open half of the cap: nothing
# in that body should ever match, so it cannot tell a real "still inspects
# up to the cap" connector apart from one that stopped inspecting on the
# first delayed buffer. Two more locations close that gap with
# SecResponseBodyAccess On:
#   * /before-cap serves a body that stays wholly under the cap with the
#     matching marker in its first bytes -- deny must still fire and 403,
#     proving buffered content is genuinely inspected while delayed, not
#     just passed through.
# Both new locations must set two directives explicitly or they prove
# nothing:
#   * SecResponseBodyMimeType application/octet-stream -- Coraza inspects a
#     response body only when its Content-Type is in that list, and the
#     default list does not contain application/octet-stream, so without it
#     neither rule below ever sees a byte.
#   * SecResponseBodyLimit 4194304 -- Coraza's own response-body limit
#     (512 KiB, ProcessPartial by default) would truncate inspection well
#     before the connector's 1 MiB delayed-body cap, so the pair would
#     measure Coraza's limit rather than the cap. Raised past the cap, the
#     connector flush is the only thing that can stop inspection.
#
#   * /after-cap places the marker only past the 1 MiB cap. Once flushed,
#     headers and preceding bytes have already reached the client, but Coraza
#     continues inspecting subsequent chunks. A late deny therefore resets
#     the response instead of replacing it with a clean error page. The
#     declared Content-Length is intentionally left unsatisfied and the
#     matching final chunk must not reach the client.

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

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_log %%TESTDIR%%/cap.log warn;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        location /big {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }

        location /before-cap {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType application/octet-stream
                SecResponseBodyLimit 4194304
                SecRule RESPONSE_BODY "@contains EARLY-MARKER" "id:451,phase:4,deny,log,status:403,t:none"
            ';
        }

        location /after-cap {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType application/octet-stream
                SecResponseBodyLimit 4194304
                SecRule RESPONSE_BODY "@contains LATE-MARKER" "id:452,phase:4,deny,log,status:403,t:none"
            ';
        }
    }
}
EOF

# 4 MiB response — comfortably past the 1 MiB default cap, delivered in many
# buffers so pending_bytes crosses the cap before last_buf arrives.
my $size = 4 * 1024 * 1024;
$t->write_file("/big", "Z" x $size);

# Marker in the first bytes of a body that stays entirely under the 1 MiB
# cap, so the whole response is still buffered when phase 4 runs and the deny
# can still produce a clean 403. The body must be under the cap, not merely
# the marker: once total pending bytes cross the cap the connector flushes
# the headers and a later deny can no longer change the status, whatever the
# marker position was.
$t->write_file("/before-cap", "EARLY-MARKER" . ("Y" x (512 * 1024)));

# Marker placed only after the 1 MiB cap: by the time these bytes arrive the
# connector has already flushed and stopped collecting, so it must NOT be
# seen (must NOT block) even though the rule would clearly match it if
# inspection continued past the cap.
my $pad = 2 * 1024 * 1024;
$t->write_file("/after-cap", ("X" x $pad) . "LATE-MARKER");

$t->run();
$t->todo_alerts();
$t->plan(9);

###############################################################################

my $r = http_get('/big');
like($r, qr/^HTTP.*200/, 'oversized delayed response still returns 200');

my ($body) = $r =~ /\r\n\r\n(.*)$/s;
is(length($body // ''), $size, 'oversized response body delivered intact');

# A marker well before the cap must still be inspected and blocked: this is
# the deny-side control that /big's fail-open assertions above cannot
# provide, since nothing in /big's body can ever match.
my $r_early = http_get('/before-cap');
like($r_early, qr/^HTTP.*403/,
    'rule match before the buffering cap still blocks (deny is not bypassed by delayed buffering)');

# A marker placed only past the cap is still inspected. Since the 200 headers
# are already on the wire, the late deny cannot replace them with a 403; it
# aborts the response before the matching final chunk is forwarded instead.
my ($r_late, $expected_late) = http_get_until_close('/after-cap');
like($r_late, qr/^HTTP.*200/,
	'late intervention preserves the status whose headers were already sent');
unlike($r_late, qr/LATE-MARKER/,
	'late matching chunk is not forwarded after the intervention');
cmp_ok(length($r_late), '<', $expected_late,
	'late intervention closes the response before its declared Content-Length');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
like($t->read_file('cap.log'), qr/flushing headers early/,
    'connector flushed delayed headers once the buffering cap was exceeded');
like($t->read_file('cap.log'), qr/header already sent/,
	'late phase-4 intervention reached the post-flush finalization path');

sub http_get_until_close {
	my ($uri) = @_;
	my $reply = '';
	my $s;
	my $error;
	my $expected;
	eval {
		local $SIG{ALRM} = sub { die "response read timeout\n" };
		alarm(10);
		$s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1:' . port(8080),
		) or die "Can't connect to nginx: $!\n";
		$s->autoflush(1);
		print $s "GET $uri HTTP/1.1" . CRLF
			. "Host: localhost" . CRLF
			. "Connection: close" . CRLF . CRLF;

		while (1) {
			my $n = sysread($s, my $chunk, 64 * 1024);
			die "Can't read nginx response: $!\n" unless defined $n;
			last if $n == 0;
			$reply .= $chunk;
			die "nginx response exceeded 8 MiB\n"
				if length($reply) > 8 * 1024 * 1024;
			if (!defined $expected && $reply =~ /\A(.*?)\r\n\r\n/s) {
				my $headers = $1;
				$expected = length($headers) + 4 + $1
					if $headers =~ /Content-Length:\s*(\d+)/i;
			}
		}
		die "nginx response omitted Content-Length\n"
			unless defined $expected;
		alarm(0);
		1;
	} or do {
		alarm(0);
		$error = $@;
	};
	close $s if defined $s;
	die $error if defined $error;
	return ($reply, $expected);
}
