#!/usr/bin/perl

# Run from nginx-tests with t/* copied alongside Test::Nginx.
# The producer cannot complete until the client has captured the early result.
# Open streams never send a terminating chunk, including on the release signal.
use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;
use lib '.';
use coraza_crash_check;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(39);
my $dir = $t->testdir();
my $locations = '';
for my $mode (qw/off mime inspected/) {
    my $access = $mode eq 'off' ? 'Off' : 'On';
    my $mime = $mode eq 'mime' ? 'text/html' : 'text/plain';
    $locations .= <<"CONF";
        location /$mode/ {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess $access
                SecResponseBodyMimeType $mime
                SecRule ARGS:deny_args "\@streq 1" "id:801,phase:4,t:none,deny,status:403"
                SecRule ARGS:deny_tx "\@streq 1" "id:802,phase:3,t:none,pass,nolog,setvar:tx.outbound=1"
                SecRule TX:outbound "\@eq 1" "id:803,phase:4,t:none,deny,status:403"
                SecRule RESPONSE_STATUS "\@eq 503" "id:804,phase:4,t:none,deny,status:403"
                SecRule RESPONSE_HEADERS:X-Policy "\@streq deny" "id:805,phase:4,t:none,deny,status:403"
                SecRule RESPONSE_BODY "\@contains BLOCK-LATER" "id:806,phase:4,t:none,deny,status:403"
            ';
            proxy_buffering off;
            proxy_read_timeout 15s;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
CONF
}
$t->write_file_expand('nginx.conf', <<"CONF");
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name localhost;
        postpone_output 1;
$locations
    }
}
CONF
$t->run_daemon(\&producer);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

for my $mode (qw/off mime/) {
    for my $kind (qw/finite open/) {
        my ($early, $full) = request("/$mode/$kind");
        like($early, qr/^HTTP\S+ 200/, "$mode $kind: headers arrive before completion");
        like($early, qr/FIRST-CHUNK/, "$mode $kind: first chunk arrives before completion");
        if ($kind eq 'finite') {
            like($full, qr/LAST-CHUNK/, "$mode finite: final chunk survives");
        } else {
            unlike($early, qr/LAST-CHUNK/, "$mode open: no final chunk was sent");
        }
    }
}
my ($early, $full) = request('/inspected/finite');
is($early, '', 'inspected finite: headers and first chunk stay held');
like($full, qr/^HTTP\S+ 200/, 'inspected finite: clean result released');
like($full, qr/FIRST-CHUNK.*LAST-CHUNK/s, 'inspected finite: body survives delay');
($early, $full) = request('/inspected/open');
is($early, '', 'inspected open: response stays held');
is($full, '', 'inspected open: client abort does not synthesize a response');

for my $mode (qw/off mime/) {
    for my $variable (qw/args tx status headers/) {
        ($early, $full) = request("/$mode/open?deny_$variable=1");
        like($early, qr/^HTTP\S+ 403/, "$mode: phase-4 $variable denies before completion");
        unlike($full, qr/FIRST-CHUNK/, "$mode: phase-4 $variable withholds producer body");
    }
}
($early, $full) = request('/inspected/finite?bodyblock=1');
is($early, '', 'inspected body decision waits for final chunk');
like($full, qr/^HTTP\S+ 403/, 'inspected final body rule denies cleanly');

# A clean request after both cancellation and intervention checks cleanup.
($early, $full) = request('/off/finite?after=1');
like($early, qr/^HTTP\S+ 200/, 'request after abort and denial starts cleanly');
like($early, qr/FIRST-CHUNK/, 'request after abort and denial still streams');
like($full, qr/LAST-CHUNK/, 'request after abort and denial completes');
coraza_crash_check::assert_no_crash($t, 'no worker crash during stream cleanup');

sub key {
    my ($uri) = @_;
    $uri =~ s/[^a-zA-Z0-9]/_/g;
    return $uri;
}

sub mark {
    my ($name) = @_;
    open my $fh, '>', "$dir/$name" or die "marker $name: $!";
    print $fh "ready\n";
    close $fh or die "close marker: $!";
}

sub wait_marker {
    my ($name) = @_;
    for (1 .. 1000) {
        return if -e "$dir/$name";
        select undef, undef, undef, 0.01;
    }
    die "producer synchronization failed: $name";
}

sub request {
    my ($uri) = @_;
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . port(8080),
        Proto => 'tcp', Timeout => 5) or die "connect: $!";
    $s->autoflush(1);
    print $s "GET $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    my $key = key($uri);
    wait_marker("ready$key");
    my $early = '';
    my $bits = '';
    vec($bits, fileno($s), 1) = 1;
    while (select(my $ready = $bits, undef, undef, 1) > 0) {
        my $n = sysread($s, my $chunk, 8192);
        die "early read: $!" unless defined $n;
        last unless $n;
        $early .= $chunk;
    }
    my $full = $early;
    if ($uri =~ m{/open}) {
        close $s;
        mark("release$key");
    } else {
        mark("release$key");
        local $SIG{ALRM} = sub { die "finite response did not finish\n" };
        alarm 10;
        while (1) {
            my $n = sysread($s, my $chunk, 8192);
            die "final read: $!" unless defined $n;
            last unless $n;
            $full .= $chunk;
        }
        alarm 0;
        close $s;
    }
    wait_marker("done$key");
    return ($early, $full);
}

sub producer {
    my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
        LocalPort => port(8081), Proto => 'tcp', Listen => 10, ReuseAddr => 1)
        or die "listen: $!";
    local $SIG{PIPE} = 'IGNORE';
    while (my $s = $server->accept()) {
        $s->autoflush(1);
        my $line = <$s>;
        if (!defined $line) { close $s; next; }
        my ($uri) = $line =~ /^GET (\S+)/;
        while (<$s>) { last if /^\r?\n$/; }
        my $key = key($uri);
        my $status = $uri =~ /deny_status/ ? '503 Unavailable' : '200 OK';
        my $policy = $uri =~ /deny_headers/ ? 'deny' : 'allow';
        print $s "HTTP/1.1 $status\r\nContent-Type: text/plain\r\n"
            . "Transfer-Encoding: chunked\r\nX-Policy: $policy\r\n\r\n"
            . "B\r\nFIRST-CHUNK\r\n";
        mark("ready$key");
        wait_marker("release$key");
        if ($uri !~ m{/open}) {
            my $tail = $uri =~ /bodyblock/ ? 'BLOCK-LATER' : 'LAST-CHUNK';
            printf $s "%X\r\n%s\r\n0\r\n\r\n", length($tail), $tail;
        }
        close $s;
        mark("done$key");
    }
}
