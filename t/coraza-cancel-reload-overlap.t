#!/usr/bin/perl

# Tests for Coraza-nginx connector: client cancellation and `nginx -s reload`
# overlapping an in-flight transaction.
#
# ngx_http_coraza_cleanup() (src/ngx_http_coraza_module.c) is registered on
# r->pool and is the only place coraza_free_transaction() is called; nginx
# runs pool cleanups exactly once when the request pool is destroyed,
# regardless of whether the request finished normally, was aborted by the
# client, or its worker is draining after a reload. So the oracle for "no
# double free / no WAF free-before-transaction" is: the worker does not
# crash (no SIGSEGV/ASan/UBSan mark in error.log) and, since a double-free or
# use-after-free inside libcoraza's transaction free path would either abort
# the process or corrupt the allocator that later requests depend on, the
# server must also go on to serve a completely unrelated follow-up request
# correctly afterward.
#
# Coverage:
#   (1) client cancellation mid deferred-request-body -- the client sends
#       part of the body then closes, so ngx_http_coraza_pre_access.c is
#       sitting in the NGX_AGAIN / waiting_more_body path when the pool is
#       destroyed.
#   (2) client cancellation mid delayed-response -- coraza_delay_response_headers
#       holds response headers back for a phase-4 rule while a slow upstream
#       body is in flight; the client closes before any byte of the response
#       reaches it, so cleanup runs with the transaction mid response-phase.
#   (3) `nginx -s reload` while a request is in flight, at three phases:
#       deferred request body, delayed response headers/body, and an
#       intervention (phase-4 deny). The reload sends the old worker
#       QUIT-on-drain (it keeps serving in-flight connections while the new
#       worker takes new ones), so the in-flight transaction's cleanup runs
#       during worker shutdown instead of during normal request completion.
#
# COVERAGE GAP: reload changes the pid nginx.pid records to the new worker's
# master-tracked pid immediately, but the OLD worker (the one whose pool
# cleanup we care about) keeps running until it drains. Test::Nginx's
# reload() only sends SIGHUP and returns; it has no hook to observe when the
# specific old worker PID that held our transaction has actually exited, so
# these tests cannot assert "the old worker's cleanup ran" as a directly
# observed event distinct from "the response came back correctly and the
# server kept working" -- they rely on the crash oracle plus the successful
# follow-up request as the closest available proxy. A tighter test would need
# a way to pin/observe the specific worker pid across the reload, which this
# harness does not expose.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF MSG_PEEK /;
use IO::Socket::INET;
use Time::HiRes qw/ sleep /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(9);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
master_process on;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        coraza on;

        # Deferred request body: no Content-Length is available at preread
        # time because the client sends the headers and a partial body then
        # stalls/closes, forcing ngx_http_coraza_pre_access.c into the
        # NGX_AGAIN / waiting_more_body branch.
        location /body {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Delayed response: phase-4 rule forces coraza_delay_response_headers
        # to hold the response until the upstream body (deliberately slow) is
        # in.  The transaction is alive and mid response-phase when the
        # client cancels.
        location /slow-response {
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq observe" "id:170,phase:4,pass,log,t:none"
                SecRule ARGS "@streq block" "id:171,phase:4,deny,log,status:403,t:none"
            ';
            proxy_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Plain follow-up target used after every cancellation/reload case to
        # prove the worker is still healthy and serving new transactions
        # correctly -- the strongest available proxy for "exactly one
        # transaction cleanup ran and nothing corrupted the allocator".
        location /healthy {
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq attack" "id:172,phase:1,deny,status:403,log,t:none"
            ';
            return 200 "HEALTHY-OK";
        }
    }
}
EOF

my $testdir = $t->testdir();

$t->run_daemon(\&slow_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# --- (1) client cancellation mid deferred request body --------------------

{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    # Content-Length announces more body than we will ever send, so the
    # request stays in the deferred/waiting_more_body state until we close.
    print $s "POST /body HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Expect: 100-continue" . CRLF
        . "Content-Type: application/x-www-form-urlencoded" . CRLF
        . "Content-Length: 65536" . CRLF . CRLF;

    wait_for_continue($s);
    print $s "x=partial-and-never-finished";
    close $s;
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker survives client cancel mid deferred request body '
    . '(single transaction cleanup, no crash)');

# --- (2) client cancellation mid delayed response --------------------------

{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /slow-response?q=observe&id=cancel HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    # Deterministic sync: the daemon writes a marker once it is blocked
    # holding the response body back, i.e. the coraza transaction is
    # definitely alive and mid response-phase server-side, before we cancel.
    wait_for_marker('slow-response-holding-cancel');
    close $s;

    # The daemon observes nginx closing its upstream socket before it can
    # finish this response. This proves nginx processed the downstream FIN;
    # a fixed sleep followed by an unconditional release would not.
    wait_for_marker('slow-response-aborted-cancel');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker survives client cancel mid delayed response '
    . '(single transaction cleanup, no crash)');

# --- (3) reload overlapping an in-flight transaction ------------------------

# (3a) deferred request body in flight across a reload.
{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "POST /body HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Expect: 100-continue" . CRLF
        . "Content-Type: application/x-www-form-urlencoded" . CRLF
        . "Content-Length: 17" . CRLF . CRLF;

    wait_for_continue($s);
    print $s "x=abc";

    my $log_offset = -s $t->testdir() . '/error.log';
    $t->reload();
    wait_for_reload($t, $log_offset);

    print $s "defghijklmno";

    my $reply = read_reply($s);
    close $s;

    like($reply, qr/^HTTP\S+ 200.*BODY-OK/s,
        'in-flight deferred request body completes across a reload');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker healthy after reload overlapping deferred request body');

# (3b) delayed response headers/body in flight across a reload.
{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /slow-response?q=observe&id=reload HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    wait_for_marker('slow-response-holding-reload');

    my $log_offset = -s $t->testdir() . '/error.log';
    $t->reload();
    wait_for_reload($t, $log_offset);

    release_marker('slow-response-release-reload');

    my $reply = read_reply($s);
    close $s;

    like($reply, qr/^HTTP\S+ 200.*SLOW-BODY-DONE/s,
        'in-flight delayed response completes across a reload');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker healthy after reload overlapping a delayed response');

# (3c) reload overlapping an intervention (phase-4 deny).
{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /slow-response?q=block&id=reload_intervention HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    wait_for_marker('slow-response-holding-reload_intervention');
    my $log_offset = -s $t->testdir() . '/error.log';
    $t->reload();
    wait_for_reload($t, $log_offset);
    release_marker('slow-response-release-reload_intervention');

    my $reply = read_reply($s);
    close $s;

    like($reply, qr/^HTTP\S+ 403/,
        'in-flight intervention still cleanly blocks across a reload');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker healthy after reload overlapping an intervention');

# --- crash oracle ------------------------------------------------------------

$t->stop();

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer|UndefinedBehaviorSanitizer|double free|invalid free/,
    'no crash or double-free signature across cancellation/reload overlap');

# Run Test::Nginx's DESTROY checks before Test::Builder validates the plan.
# The named wait helpers close over this lexical, so global destruction is
# otherwise too late to emit "no alerts" and "no sanitizer errors".
undef $t;

###############################################################################

sub http_get_healthy {
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /healthy HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    my $reply = read_reply($s);
    close $s;

    return $reply;
}

sub read_reply {
    my ($s) = @_;

    local $SIG{ALRM} = sub { die "timeout\n" };
    my $reply = '';
    eval {
        alarm(8);
        local $/;
        $reply = $s->getline() // '';
        alarm(0);
    };
    my $err = $@;
    alarm(0);
    die $err if $err;

    return $reply;
}

sub wait_for_continue {
    my ($s) = @_;

    local $SIG{ALRM} = sub { die "timeout waiting for 100 Continue\n" };
    my $head = '';
    eval {
        alarm(8);
        while ($head !~ /\r\n\r\n/) {
            my $line = $s->getline();
            last unless defined $line;
            $head .= $line;
        }
        alarm(0);
    };
    my $err = $@;
    alarm(0);
    die $err if $err;
    die "expected 100 Continue, got: $head\n"
        unless $head =~ m{^HTTP/1\.1 100 Continue\r\n}i;
}

sub wait_for_marker {
    my ($name) = @_;
    my $marker = "$testdir/$name";

    for (1 .. 500) {
        return if -e $marker;
        sleep 0.01;
    }

    die "timeout waiting for marker $marker\n";
}

sub release_marker {
    my ($name) = @_;

    open my $fh, '>', "$testdir/$name"
        or die "Can't write release marker: $!\n";
    print $fh "go\n";
    close $fh;
}

sub wait_for_reload {
    my ($test, $offset) = @_;
    my $log = $test->testdir() . '/error.log';
    my $deadline = time() + 10;

    while (time() < $deadline) {
        open my $fh, '<', $log or die "Can't read $log: $!\n";
        seek $fh, $offset, 0 or die "Can't seek $log: $!\n";
        local $/;
        my $new_log = <$fh> // '';
        close $fh;

        return if $new_log =~ /reconfiguring/;
        sleep 0.05;
    }

    die "nginx did not log reload reconfiguration within 10 seconds\n";
}

# A slow upstream: sends response headers immediately, then blocks holding the
# body back (writing a "holding" marker as soon as it starts blocking) until
# the "release" marker file appears, then finishes the body and writes a
# "done" marker.  Used for /slow-response, which delays forwarding headers to
# the client behind a phase-4 rule -- the client sees nothing until the
# marker is released.  Every marker name carries the request's id= query
# parameter so two /slow-response cases can never satisfy each other's
# waits.
sub slow_daemon {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => '127.0.0.1:' . port(8081),
        Listen => 5,
        Reuse => 1
    ) or die "Can't create listening socket: $!\n";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $request = <$client>;
        if (!defined $request) {
            close $client;
            next;
        }

        my ($uri) = $request =~ /^\S+\s+(\S+)/;
        my ($id) = (defined $uri && $uri =~ /[?&]id=(\w+)/) ? $1 : 'none';

        my $headers = $request;
        while (<$client>) {
            $headers .= $_;
            last if (/^\x0d?\x0a?$/);
        }

        if (defined $uri && $uri =~ m{^/body}) {
            # Drain the forwarded request body before responding so nginx's
            # upstream write completes; otherwise the proxy round-trip races
            # on an unread socket (see coraza-request-body-deferred.t).
            if ($headers =~ /Content-Length:\s*(\d+)/i) {
                my $need = $1;
                my $got = 0;
                while ($got < $need) {
                    my $buf;
                    my $n = read($client, $buf, $need - $got);
                    last if !defined $n || $n == 0;
                    $got += $n;
                }
            }

            print $client "HTTP/1.1 200 OK" . CRLF;
            print $client "Content-Length: 7" . CRLF;
            print $client "Connection: close" . CRLF . CRLF;
            print $client "BODY-OK";
            close $client;
            next;
        }

        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Length: 14\r\n"
            . "Content-Type: text/plain\r\n\r\n";

        open my $fh, '>', "$testdir/slow-response-holding-$id"
            or die "Can't write holding marker: $!\n";
        print $fh "holding\n";
        close $fh;

        my $release = "$testdir/slow-response-release-$id";
        my $released = 0;
        my $aborted = 0;
        for (1 .. 800) {
            if (-e $release) {
                $released = 1;
                last;
            }

            my $readable = '';
            vec($readable, fileno($client), 1) = 1;
            if (select($readable, undef, undef, 0.01) > 0) {
                my $peek = '';
                my $peer = recv($client, $peek, 1, MSG_PEEK);
                if (!defined $peer || length($peek) == 0) {
                    $aborted = 1;
                    last;
                }
            }
        }

        if ($aborted) {
            open $fh, '>', "$testdir/slow-response-aborted-$id"
                or die "Can't write abort marker: $!\n";
            print $fh "aborted\n";
            close $fh;
            close $client;
            next;
        }

        die "timeout waiting for release marker $release\n" unless $released;

        print $client "SLOW-BODY-DONE";
        close $client;

        open $fh, '>', "$testdir/slow-response-done-$id"
            or die "Can't write done marker: $!\n";
        print $fh "done\n";
        close $fh;
    }
}

###############################################################################
