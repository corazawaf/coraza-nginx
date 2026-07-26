#!/usr/bin/perl

# Tests for Coraza-nginx connector (Server-Sent Events, text/event-stream).
#
# Regression test for issue #81: the connector delays response headers until
# phase-4 body inspection completes at last_buf, but an SSE stream emits events
# indefinitely and never sends a last_buf, so the headers (and every event)
# were held forever and the client received 0 bytes -- even in DetectionOnly.
# The header filter now skips the delay for Content-Type: text/event-stream,
# exactly as it does for a 101 upgrade.
#
# The upstream daemon streams heartbeat events until the client disconnects
# and never closes the connection on its own, so the delayed-header path can
# never be rescued by an upstream-close last_buf flush: only prompt delivery
# passes the positive assertions (the test fails on the pre-fix code).
#
# Near-miss content types ("text/event-streamx", "text/event-stream junk")
# must NOT get the exemption: those requests assert that nothing reaches the
# client early, i.e. the phase-4 header delay is still in force.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(10);

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

        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecResponseBodyAccess On
            ';
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 5s;
            proxy_buffering off;
        }

        # Control: the SSE exemption must not disable the WAF on the stream.
        # Phase 1 still evaluates and still blocks -- what the exemption gives
        # up is only the phase-4 clean-error-page path, not inspection itself.
        location /guarded {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule ARGS "@streq attack" "id:181,phase:1,status:403,deny,log"
            ';
            proxy_pass http://127.0.0.1:8081/events;
            proxy_read_timeout 5s;
            proxy_buffering off;
        }
    }
}

EOF

$t->run_daemon(\&sse_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# The SSE response headers and first events must reach the client promptly.
# Previously they were delayed until a last_buf that never comes, so the
# client saw nothing before the read timeout.
my ($status, $body) = sse_read('/events');

like($status, qr!HTTP/1\.1 200!, 'SSE response headers arrive');
like($status, qr!text/event-stream!i, 'content-type is text/event-stream');
like($body, qr/data: event-1/, 'first SSE event delivered');

# Media-type variants that are still SSE must also skip the delay.
($status, $body) = sse_read('/charset');
like($body, qr/data: event-1/, 'SSE with "; charset=utf-8" delivered');

($status, $body) = sse_read('/tab');
like($body, qr/data: event-1/, 'SSE with HTAB OWS before ";" delivered');

($status, $body) = sse_read('/mixedcase');
like($body, qr/data: event-1/, 'SSE with mixed-case media type delivered');

# Near-miss content types must NOT get the exemption: the phase-4 header
# delay stays in force, so the client receives nothing early.
($status, $body) = sse_read('/nearmiss', 2);
is($status . $body, '', 'near-miss "text/event-streamx" stays delayed');

($status, $body) = sse_read('/notsse', 2);
is($status . $body, '', 'malformed "text/event-stream junk" stays delayed');

# The exemption skips the header DELAY, not the WAF.  A phase-1 rule must
# still block an SSE request, otherwise this change would be a bypass rather
# than a streaming fix.
($status, $body) = sse_read('/guarded?q=attack', 2);
like($status, qr!HTTP/1\.1 403!, 'phase-1 rule still blocks an SSE request');

# ...and a clean SSE request through the same guarded location still streams.
($status, $body) = sse_read('/guarded?q=fine');
like($body, qr/data: event-1/, 'guarded SSE location still streams when allowed');

###############################################################################

# Read the status line + whatever early body arrives, then bail without
# waiting for the (never-ending) stream to close.
sub sse_read {
	my ($uri, $deadline) = @_;

	$deadline ||= 4;

	my $s = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
		Timeout  => 5,
	) or return ('', '');

	$s->print("GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n");

	my $buf = '';
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm($deadline);
		# Stop as soon as we have headers plus the first event.
		# sysread(): return as soon as any bytes arrive; read() would
		# block for the full requested length, which a trickling stream
		# never delivers.
		while ($buf !~ /data: event-1/) {
			my $chunk;
			my $n = $s->sysread($chunk, 1024);
			last if !defined $n || $n == 0;
			$buf .= $chunk;
		}
		alarm(0);
	};
	alarm(0);
	close($s);

	my ($head, $body) = split /\r\n\r\n/, $buf, 2;
	$head = '' unless defined $head;
	$body = '' unless defined $body;
	return ($head, $body);
}

sub sse_daemon {
	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen    => 5,
		Reuse     => 1,
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	my %ct = (
		'/events'    => "text/event-stream",
		'/charset'   => "text/event-stream; charset=utf-8",
		'/tab'       => "text/event-stream\t; charset=utf-8",
		'/mixedcase' => "Text/Event-Stream",
		'/nearmiss'  => "text/event-streamx",
		'/notsse'    => "text/event-stream junk",
	);

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $uri = '/events';
		my $headers = '';
		while (<$client>) {
			$uri = $1 if /^GET\s+(\S+)/;
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my $type = $ct{$uri} || $ct{'/events'};

		# Stream events with no Content-Length and never close on our own:
		# a low-volume, never-terminating SSE endpoint.  The loop ends only
		# when the client goes away (print to a dead socket fails), so the
		# delayed-header path can never be rescued by an upstream close.
		print $client "HTTP/1.1 200 OK\r\n"
			. "Content-Type: $type\r\n"
			. "Cache-Control: no-cache\r\n"
			. "Connection: keep-alive\r\n\r\n";

		my $i = 1;
		while (print $client "data: event-$i\n\n") {
			$i++;
			select(undef, undef, undef, 0.2);
		}

		close $client;
	}
}

###############################################################################
