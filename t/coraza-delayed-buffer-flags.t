#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed-header buffer chains).
#
# t/coraza-delayed-file-buffer.t covers the uninspected file-backed clone
# branch (large file, sendfile off, phase-4 pass). t/coraza-response-body-
# trailing-buf.t covers the one-shot phase-4 gate on a trailing buffer.
# Three things those files do not exercise, all on the delayed-header path
# in src/ngx_http_coraza_body_filter.c:
#
#   (a) many recycled, non-final in-memory buffers. Small proxy_buffers make
#       nginx hand the body filter a long chain of buffers it wants to reuse
#       rather than one big buffer, so every one of them must be deep-copied
#       into r->pool before it is queued on pending_chain. A copy that
#       dropped, duplicated or reordered a buffer shows up as a response
#       body that differs from what the origin sent.
#   (b) a response far larger than the proxy buffers, read slowly by the
#       client, so the delayed-header path crosses the connector's 1 MiB
#       cap (NGX_HTTP_CORAZA_MAX_DELAYED_BODY), flushes, and streams the
#       remainder while buffers keep being recycled underneath it.
#   (c) a client that disconnects while the response is still being written.
#       The aborted transaction must not wedge the worker: a later request
#       has to be served normally.
#
# NOT COVERED: buffers that arrive from a spilled proxy temp file
# (ngx_buf_in_memory() false, temp_file set), which the clone branch
# excludes deliberately because upstream owns that file's lifetime. Forcing
# a spill was attempted and does not work from this harness: with a Perl
# origin on loopback and a deliberately slow client, nginx never wrote a
# temp file even with proxy_buffers as small as 4x4k and coraza off
# entirely, because the origin cannot outrun the reader far enough to
# exhaust them. An assertion here would have passed without ever touching
# the path, so the case is stated as a gap instead. Covering it needs an
# origin that can saturate the buffers (a real upstream, or a fixture that
# writes without a reader draining it).
#
# The oracle for (a) and (b) is a byte-exact comparison of the whole
# response body against what the origin sent, so a truncation, a duplicated
# buffer or a corrupted copy all fail. Reading the body to completion
# matters: http_get() returns only whatever the first reads delivered, so
# comparing its result would pass on a truncated response.
#
# This file deliberately contains no assertions about the SHAPE of the C
# source. Source-text greps do not exercise the code and go red on
# behaviour-preserving refactors; the repo keeps them in lint/ instead.

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

# Ten assertions below; plan() adds Test::Nginx's own two teardown checks.
my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(10);
my $testdir = $t->testdir();

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

        # Small proxy buffers force nginx to hand the body filter several
        # recycled, non-final in-memory buffers instead of one big buffer --
        # this drives the in-memory copy branch on more than the trivial
        # single-buffer case. SecResponseBodyMimeType must name the type
        # this location actually serves: Coraza inspects a response body
        # only for a Content-Type in that list.
        location /recycled {
            default_type text/plain;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_buffering on;
            proxy_buffer_size 512;
            proxy_buffers 8 512;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 262144
                SecRule RESPONSE_BODY "@rx NEVER MATCHES THIS" "id:171,phase:4,deny,log,status:403,t:none"
            ';
        }

        # A response far larger than the proxy buffers, read slowly by the
        # client: the delayed-header path crosses the connector's 1 MiB cap,
        # flushes the headers, and streams the rest while nginx keeps
        # recycling buffers underneath. SecResponseBodyAccess is On so the
        # response really does travel the delayed path rather than streaming
        # straight through.
        location /large {
            default_type text/plain;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 4 4k;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule RESPONSE_BODY "@rx NEVER MATCHES THIS" "id:172,phase:4,deny,log,status:403,t:none"
            ';
        }

        # Client that disconnects mid-transfer on the delayed-header path,
        # followed by a healthy request to prove the worker still serves.
        location /slow {
            default_type text/plain;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_buffering off;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
            ';
        }

        location /healthy {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
            return 200 "HEALTHY-OK";
        }
    }
}
EOF

# Non-uniform payloads: a same-length response with corrupted, duplicated or
# reordered content must not compare equal, which a run of one repeated byte
# could not detect.
my $recycled_body = join('', map { sprintf("recycled-line-%05d\n", $_) } 1 .. 400);
# Well past the connector's 1 MiB delayed-body cap
# (NGX_HTTP_CORAZA_MAX_DELAYED_BODY), so the response is forced through the
# flush-then-stream half of the delayed path rather than being held whole.
my $large_body = join('', map { sprintf("large-line-%06d\n", $_) } 1 .. 80000);

# Large enough that the kernel socket buffers cannot swallow the whole thing,
# so output is provably still pending when the client below disconnects.
my $slow_body = join('', map { sprintf("slow-line-%06d\n", $_) } 1 .. 80000);

$t->run_daemon(\&http_daemon, port(8081), $recycled_body, $large_body,
    $slow_body);

$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# Recycled in-memory buffers: the full body must arrive byte for byte.
my ($status, $body) = read_full_response('/recycled');
like($status, qr/^HTTP\S+ 200/, 'recycled small-proxy-buffer response returns 200');
is(length($body), length($recycled_body),
    'recycled small-proxy-buffer response body length matches exactly');
is($body, $recycled_body,
    'recycled small-proxy-buffer response body bytes match exactly');

# Past the cap, read slowly: same byte-exact oracle. A response that flushed
# early and then streamed must still arrive complete and in order.
($status, $body) = read_full_response('/large', slow => 1);
like($status, qr/^HTTP\S+ 200/, 'over-cap response returns 200');
is(length($body), length($large_body),
    'over-cap response body length matches exactly');
is($body, $large_body,
    'over-cap response body bytes match exactly');

# Client disconnects while the response is still being written: read one
# short prefix, then close with the rest of the body still in flight.
my $prefix = disconnect_mid_response('/slow');
cmp_ok($prefix, '>', 0,
    'disconnecting client received part of the response before closing');
cmp_ok($prefix, '<', length($slow_body),
    'disconnecting client closed while response output was still pending '
    . '(the aborted transfer is a real abort, not a completed one)');

like(http_get('/healthy'), qr/HEALTHY-OK/,
    'a fresh request after the aborted transfer still succeeds');

$t->stop();

# The connector logs the cap flush at [warn]. Without it the /large case
# above would have proven only that a normal buffered response survives,
# never reaching the flush-then-stream half of the delayed path.
like($t->read_file('error.log'), qr/flushing headers early/,
    'the over-cap response actually crossed the delayed-body cap and flushed');

###############################################################################

# Read a complete response: headers, then exactly the announced
# Content-Length bytes. Returns (status line + headers, body). With slow => 1
# the body is read in small, paced chunks so recycled output buffers stay
# under pressure after the delayed-header cap flushes.
sub read_full_response {
    my ($uri, %opt) = @_;

    my $s = IO::Socket::INET->new(
        Proto    => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
        Timeout  => 5,
    ) or die "Can't connect to nginx: $!\n";

    $s->print("GET $uri HTTP/1.0\r\n"
        . "Host: localhost\r\n\r\n");

    my $buf = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(30);

        # Headers first, so Content-Length says how much body to expect.
        while ($buf !~ /\r\n\r\n/) {
            my $chunk;
            my $n = $s->sysread($chunk, 16384);
            last if !defined $n || $n == 0;
            $buf .= $chunk;
        }

        my ($head, $rest) = split /\r\n\r\n/, $buf, 2;
        $rest = '' unless defined $rest;
        my ($len) = $head =~ /Content-Length:\s*(\d+)/i;

        if ($opt{slow}) {
            # Pause before draining so the upstream body arrives with no
            # reader downstream and puts pressure on the recycled proxy
            # buffers.
            select undef, undef, undef, 0.5;
        }

        while (!defined $len || length($rest) < $len) {
            my $chunk;
            my $n = $s->sysread($chunk, $opt{slow} ? 4096 : 65536);
            last if !defined $n || $n == 0;
            $rest .= $chunk;
            select undef, undef, undef, 0.01 if $opt{slow};
        }

        $buf = $head . "\r\n\r\n" . $rest;
        alarm(0);
    };
    my $err = $@;
    alarm(0);
    close $s;
    die $err if $err;

    my ($head, $body) = split /\r\n\r\n/, $buf, 2;
    return ($head, defined $body ? $body : '');
}

# Read one short prefix of the response, then close with the remainder still
# unread, so nginx is writing into a socket whose peer has gone away.
# Returns the number of body bytes read before closing.
sub disconnect_mid_response {
    my ($uri) = @_;

    my $s = IO::Socket::INET->new(
        Proto    => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
        Timeout  => 5,
    ) or die "Can't connect to nginx: $!\n";

    $s->print("GET $uri HTTP/1.0\r\n"
        . "Host: localhost\r\n\r\n");

    my $buf = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(10);
        # Just past the headers plus a little body, then stop reading. The
        # body is far larger than the socket buffers can hold, so the rest
        # is provably still pending when the socket closes below.
        while (length($buf) < 8192) {
            my $chunk;
            my $n = $s->sysread($chunk, 1024);
            last if !defined $n || $n == 0;
            $buf .= $chunk;
        }
        alarm(0);
    };
    my $err = $@;
    alarm(0);
    wait_for_marker('slow-holding');
    close $s;
    release_marker('slow-release');
    die $err if $err;

    my (undef, $body) = split /\r\n\r\n/, $buf, 2;
    return defined $body ? length($body) : 0;
}

sub http_daemon {
    my ($port, $recycled_body, $large_body, $slow_body) = @_;

    my $server = IO::Socket::INET->new(
        Proto     => 'tcp',
        LocalPort => $port,
        Listen    => 5,
        Reuse     => 1,
    )
        or die "Can't create listening socket: $!\n";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $uri = '/recycled';
        while (<$client>) {
            $uri = $1 if /^GET\s+(\S+)/;
            last if (/^\x0d?\x0a?$/);
        }

        my $body = ($uri =~ m{^/large}) ? $large_body
            : ($uri =~ m{^/slow}) ? $slow_body : $recycled_body;
        my $type = 'text/plain';

        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Type: $type\r\n"
            . "Content-Length: " . length($body) . "\r\n"
            . "Connection: close\r\n\r\n";

        # /recycled is written in small chunks so nginx's proxy buffering
        # sees the body arrive across several reads rather than one syscall,
        # producing distinct recycled buffers on the way out.
        #
        # /large is written as fast as the socket accepts it, so the body
        # reaches the connector well ahead of the slow reader and the cap is
        # crossed while output is still in flight.
        my $chunk_size = ($uri =~ m{^/(?:large|slow)}) ? 65536 : 256;
        for (my $off = 0; $off < length($body); $off += $chunk_size) {
            my $chunk = substr($body, $off, $chunk_size);
            last unless print $client $chunk;

            if ($uri =~ m{^/slow} && $off + length($chunk) >= 1100000
                && !-e "$testdir/slow-holding")
            {
                open my $fh, '>', "$testdir/slow-holding"
                    or die "Can't write slow-response marker: $!\n";
                print $fh "holding\n";
                close $fh;

                my $released = 0;
                for (1 .. 500) {
                    if (-e "$testdir/slow-release") {
                        $released = 1;
                        last;
                    }
                    select undef, undef, undef, 0.01;
                }
                die "timeout waiting for slow-release\n" unless $released;
            }
        }

        close $client;
    }
}

sub wait_for_marker {
    my ($name) = @_;

    for (1 .. 500) {
        return if -e "$testdir/$name";
        select undef, undef, undef, 0.01;
    }

    die "timeout waiting for marker $name\n";
}

sub release_marker {
    my ($name) = @_;

    open my $fh, '>', "$testdir/$name"
        or die "Can't write release marker: $!\n";
    print $fh "go\n";
    close $fh;
}

###############################################################################
