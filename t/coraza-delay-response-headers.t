#!/usr/bin/perl

# Tests for Coraza-nginx connector (configurable response-header delay).
#
# By default the connector delays response headers until phase 4 completes so a
# response-body or late non-body phase-4 intervention can still return a clean
# error page.  coraza_delay_response_headers off lets operators with no phase-4
# response rules opt out and stream headers immediately.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(8);

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
        postpone_output 1;

        location /delay-off {
            coraza on;
            coraza_delay_response_headers off;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
            proxy_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /delay-default {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
            proxy_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /delay-on {
            coraza on;
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
            proxy_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /block-default {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq block" "id:151,phase:4,deny,log,status:403"
            ';
        }

        location /block-on {
            default_type text/plain;
            coraza on;
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq block" "id:152,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

$t->write_file('/block-default', 'ORIGINAL-BODY');
$t->write_file('/block-on', 'ORIGINAL-BODY');
my $testdir = $t->testdir();

$t->run_daemon(\&delayed_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

my ($early, $full) = timed_get('/delay-off');
like($early, qr/^HTTP\S+ 200.*X-Delayed-Upstream: yes/s,
    'delay off forwards response headers before upstream body');
unlike($early, qr/DELAYED-BODY/,
    'delay off early read contains headers but not the delayed body');
like($full, qr/DELAYED-BODY/, 'delay off still forwards the body');

($early, $full) = timed_get('/delay-default');
is($early, '', 'default response-body delay withholds headers until body');
like($full, qr/^HTTP\S+ 200.*DELAYED-BODY/s,
    'default response-body delay eventually forwards response');

($early, $full) = timed_get('/delay-on');
is($early, '', 'explicit response-body delay on withholds headers until body');

like(http_get('/block-default?q=block'), qr/^HTTP\S+ 403/,
    'default delay preserves clean phase-4 non-body block');

like(http_get('/block-on?q=block'), qr/^HTTP\S+ 403/,
    'explicit delay on preserves clean phase-4 non-body block');

###############################################################################

sub timed_get {
    my ($uri) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET $uri HTTP/1.1\r\n"
        . "Host: localhost\r\n"
        . "Connection: close\r\n\r\n";

    # Deterministic sync: the daemon writes the "headers-" marker right after it
    # has sent the response headers upstream, then blocks on the "release-"
    # marker before sending the body.  So between wait_for_upstream_headers()
    # returning and release_body() being called, nginx has upstream headers but
    # no body -- whatever the client has received in that window is purely the
    # forwarded-header state, with no wall-clock guessing.
    wait_for_upstream_headers($uri);

    # Drain everything the client can see WHILE the body is still withheld.
    # Loop until the socket goes idle (no bytes for a full poll interval) so a
    # slow header-forward under CI load still lands in $early; the body cannot
    # race in because the daemon is blocked on the release marker.
    my $early = drain_pending($s);

    release_body($uri);

    my $full = $early;
    local $SIG{ALRM} = sub { die "timeout\n" };
    eval {
        alarm(5);
        while (sysread($s, my $chunk, 4096)) {
            $full .= $chunk;
        }
        alarm(0);
    };
    alarm(0);
    close $s;

    return ($early, $full);
}

sub drain_pending {
    my ($s) = @_;

    my $data = '';
    my $rin = '';
    vec($rin, fileno($s), 1) = 1;

    # Read until the socket is idle for a full interval.  While the daemon holds
    # the body back (release marker not yet written) an idle socket means "all
    # currently-forwarded bytes captured", not "body might still arrive".
    while (select(my $rout = $rin, undef, undef, 0.3) > 0) {
        my $n = sysread($s, my $chunk, 4096);
        last if !$n;            # peer closed / error
        $data .= $chunk;
    }

    return $data;
}

sub release_body {
    my ($uri) = @_;

    open my $fh, '>', "$testdir/release-" . marker_key($uri)
        or die "Can't write release marker: $!\n";
    print $fh "go\n";
    close $fh;
}

sub wait_for_upstream_headers {
    my ($uri) = @_;
    my $marker = "$testdir/headers-" . marker_key($uri);

    for (1 .. 300) {
        return if -e $marker;
        select undef, undef, undef, 0.01;
    }

    die "timeout waiting for upstream headers marker $marker\n";
}

sub marker_key {
    my ($uri) = @_;

    $uri =~ s/\?.*//;
    $uri =~ s/[^A-Za-z0-9]+/-/g;
    $uri =~ s/^-//;
    $uri =~ s/-$//;

    return $uri;
}

sub delayed_daemon {
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

        while (<$client>) {
            last if (/^\x0d?\x0a?$/);
        }

        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Length: 12\r\n"
            . "Content-Type: text/plain\r\n"
            . "X-Delayed-Upstream: yes\r\n\r\n";

        my $key = marker_key($uri // 'unknown');

        open my $fh, '>', "$testdir/headers-" . $key
            or die "Can't write upstream marker: $!\n";
        print $fh "sent\n";
        close $fh;

        # Block until the client side signals it has captured the pre-body state
        # (release marker).  This replaces a fixed sleep, so the body can never
        # race into the "early" read regardless of CI scheduling latency.
        my $release = "$testdir/release-" . $key;
        for (1 .. 500) {
            last if -e $release;
            select undef, undef, undef, 0.01;
        }

        print $client "DELAYED-BODY";
        close $client;
    }
}
