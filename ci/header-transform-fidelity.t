#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use Test::More;
use IO::Socket::INET;
BEGIN {
    my $root = $ENV{CORAZA_NGINX_TEST_ROOT} // "$FindBin::Bin/../nginx-tests";
    chdir $root or die "nginx test harness required: $!";
}
use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;
use Test::Nginx::HTTP3;
use lib '.';
use coraza_crash_check;

my $t = Test::Nginx->new()->has(qw/http proxy gzip http_v2 http_v3 cryptx/)->has_daemon('openssl');
my $body = 'F07-body-marker-' x 8;
my @cases = (
    ['gzip', 'gzip on;', 'text/plain', 200, $body],
    ['off', 'gzip off;', 'text/plain', 200, $body],
    ['vary-off', 'gzip on; gzip_vary off;', 'text/plain', 200, $body],
    ['short', 'gzip on;', 'text/plain', 200, 'x' x 19],
    ['boundary', 'gzip on;', 'text/plain', 200, 'x' x 20],
    ['type', 'gzip on;', 'application/octet-stream', 200, $body],
    ['forbidden', 'gzip on;', 'text/plain', 403, $body],
    ['notfound', 'gzip on;', 'text/plain', 404, $body],
    ['created', 'gzip on;', 'text/plain', 201, $body],
    ['no-content', 'gzip on;', 'text/plain', 204, ''],
    ['not-modified', 'gzip on;', 'text/plain', 304, ''],
    ['trailers', 'gzip off; add_trailer X-F07 trailer;', 'text/plain', 200, $body],
    ['chunk-off', 'gzip on; chunked_transfer_encoding off;', 'text/plain', 200, $body],
    ['unknown', 'gzip off;', 'text/plain', 200, $body, 'unknown'],
    ['unknown-off', 'gzip off; chunked_transfer_encoding off;', 'text/plain', 200, $body, 'unknown'],
    ['upstream', 'gzip on;', 'text/plain', 200, $body, 'encoded'],
);
my @fields = qw(Transfer-Encoding Vary Content-Encoding Content-Length Connection Keep-Alive);
$t->plan(scalar(@cases) * 12 * (1 + 3 * scalar(@fields)) - 36 + 1);
my $locations = '';
my $id = 7300;
for my $case (@cases) {
    my ($name, $config, $type, $status, $data, $origin) = @$case;
    my $serve = $origin ? "proxy_pass http://127.0.0.1:%%PORT_8081%%/$origin;"
        : "default_type $type; return $status '$data';";
    $locations .= "location /wire/$name { coraza off; $config $serve }\n";
    for my $field (@fields) {
        my ($value_id, $absent_id) = ($id + 1, $id + 2);
        $id += 2;
        $locations .= "location /inspect/$name/$field { coraza on; $config $serve\n"
            . "coraza_rules 'SecRuleEngine On\nSecResponseBodyAccess Off\n"
            . "SecRule RESPONSE_HEADERS:$field \"\@streq %{REQUEST_HEADERS.X-Expected}\" \"id:"
            . $value_id . ",phase:3,t:none,deny,status:418,log\"\n"
            . "SecRule &RESPONSE_HEADERS:$field \"\@eq 0\" \"id:"
            . $absent_id . ",phase:3,t:none,deny,status:418,log,chain\"\n"
            . "SecRule REQUEST_HEADERS:X-Expected \"\@streq ABSENT\" \"t:none\"'; }\n";
    }
}
$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    gzip_types text/plain;
    gzip_min_length 20;
    gzip_vary on;
    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;
    server {
        listen 127.0.0.1:%%PORT_8080%%;
        listen 127.0.0.1:%%PORT_8082%% http2;
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        $locations
    }
}
EOF
$t->write_file('openssl.conf', "[ req ]\ndistinguished_name = dn\n[ dn ]\n");
my $dir = $t->testdir();
system('openssl', 'req', '-x509', '-new', '-nodes', '-newkey', 'rsa:2048',
    '-config', "$dir/openssl.conf", '-subj', '/CN=localhost/',
    '-out', "$dir/localhost.crt", '-keyout', "$dir/localhost.key") == 0
    or die 'certificate creation failed';
$t->run_daemon(\&origin);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
for my $version ('1.0', '1.1', '2', '3') {
    for my $encoding ('gzip', 'identity', 'gzip;q=0') {
        for my $case (@cases) {
            my ($name, undef, undef, $status) = @$case;
            my $wire = request("/wire/$name", $version, $encoding, 'unused');
            like($wire, qr/^HTTP\S+ $status/, "$name $version $encoding wire status");
            # 204 Content-Length normalization is an existing separate defect:
            # the terminal nginx filter clears it after either collector order.
            for my $field (grep { $status != 204 || $_ ne 'Content-Length' } @fields) {
                my ($value) = $wire =~ /^\Q$field\E: ([^\r\n]*)/mi;
                $value //= 'ABSENT';
                my $match = request("/inspect/$name/$field", $version, $encoding, $value);
                like($match, qr/^HTTP\S+ 418/, "$name $version $encoding rule sees $field=$value");
                my $benign = request("/inspect/$name/$field", $version, $encoding, 'f07-never-matches');
                like($benign, qr/^HTTP\S+ $status/, "$name $version $encoding $field benign status");
                my ($observed) = $benign =~ /^\Q$field\E: ([^\r\n]*)/mi;
                is($observed // 'ABSENT', $value, "$name $version $encoding $field benign wire parity");
            }
        }
    }
}
coraza_crash_check::assert_no_crash($t, 'no worker crash');


sub request {
    my ($path, $version, $encoding, $expected) = @_;
    if ($version eq '2' || $version eq '3') {
        my $socket = $version eq '2' ? Test::Nginx::HTTP2->new(8082)
            : Test::Nginx::HTTP3->new();
        my $mode = $version eq '2' ? 2 : 4;
        my $scheme = $version eq '2' ? 'http' : 'https';
        my $stream = $socket->new_stream({ headers => [
            { name => ':method', value => 'GET', mode => $mode },
            { name => ':scheme', value => $scheme, mode => $mode },
            { name => ':path', value => $path, mode => $mode },
            { name => ':authority', value => 'localhost', mode => $mode },
            { name => 'accept-encoding', value => $encoding, mode => $mode },
            { name => 'x-expected', value => $expected, mode => $mode },
        ] });
        my $frames = $socket->read(all => [{ sid => $stream, fin => 1 }]);
        my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
        return '' unless $frame;
        my $headers = $frame->{headers};
        return "HTTP/$version $headers->{':status'}\r\n"
            . join('', map { "$_: $headers->{$_}\r\n" }
                grep { $_ ne ':status' } sort keys %$headers) . "\r\n";
    }
    return http("GET $path HTTP/$version\r\nHost: localhost\r\nConnection: close\r\nAccept-Encoding: $encoding\r\nX-Expected: $expected\r\n\r\n");
}

sub origin {
    my $socket = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
        LocalPort => port(8081), Listen => 5, ReuseAddr => 1) or die $!;
    while (my $client = $socket->accept()) {
        $client->autoflush(1);
        my $request = '';
        while (my $line = <$client>) {
            $request .= $line;
            last if $line eq "\r\n";
        }
        my $extra = $request =~ m{GET /encoded }
            ? "Content-Encoding: br\r\nVary: Origin\r\nContent-Length: " . length($body) . "\r\n" : '';
        print {$client} "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n${extra}Connection: close\r\n\r\n$body";
        close $client;
    }
}
