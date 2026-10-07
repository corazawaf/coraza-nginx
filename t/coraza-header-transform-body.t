#!/usr/bin/perl

# Tests for Coraza-nginx connector (response header and body transforms): gzip,
# Vary and delayed response headers under phase-3 and phase-4 rules over HTTP/1, HTTP/2 and HTTP/3.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;
use Test::Nginx::HTTP3;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http gzip http_v2 http_v3 cryptx/)->has_daemon('openssl')->plan(73);
my $payload = 'F07-body-marker-' x 20;
my $locations = '';
for my $mode (qw(phase3 phase4 benign)) {
    my $rule = $mode eq 'phase3'
        ? 'SecRule RESPONSE_HEADERS:Vary "@streq accept-encoding" "id:7901,phase:3,t:lowercase,deny,status:403"'
        : $mode eq 'phase4'
        ? 'SecRule RESPONSE_BODY "@contains F07-body-marker" "id:7902,phase:4,deny,status:403"'
        : 'SecRule RESPONSE_BODY "@contains never-match-f07" "id:7903,phase:4,deny,status:403"';
    $locations .= "location /$mode { coraza on; default_type text/plain; return 200 '$payload';\n"
        . "coraza_delay_response_headers on; coraza_rules 'SecRuleEngine On\n"
        . "SecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n$rule'; }\n";
}
$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    gzip on;
    gzip_types text/plain;
    gzip_http_version 1.0;
    gzip_min_length 0;
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
$t->run();
for my $version ('1.0', '1.1', '2', '3') {
    for my $encoding ('gzip', 'identity') {
        for my $mode (qw(phase3 phase4 benign)) {
            my $wire = request("/$mode", $version, $encoding);
            my $status = $mode eq 'benign' ? 200 : 403;
            like($wire, qr/^HTTP\S+ $status/, "$mode $version $encoding status before body");
            my ($headers, $body) = split /\r\n\r\n/, $wire // '', 2;
            $body //= '';
            if ($headers =~ /Transfer-Encoding: chunked/i) {
                my $decoded = '';
                while ($body =~ s/^([0-9a-f]+)[^\r\n]*\r\n//i) {
                    my $length = hex $1;
                    last if !$length;
                    $decoded .= substr($body, 0, $length, '');
                    $body =~ s/^\r\n// or die 'invalid chunk framing';
                }
                $body = $decoded;
            }
            if ($headers =~ /Content-Encoding: gzip/i) {
                my $decoded;
                gunzip(\$body => \$decoded) or die "gunzip: $GunzipError";
                $body = $decoded;
            }
            if ($mode eq 'benign') {
                is($body, $payload, "$mode $version $encoding delayed body preserved");
            } else {
                unlike($body, qr/F07-body-marker/, "$mode $version $encoding denied body absent");
            }
            my $compressed = $headers =~ /Content-Encoding: gzip/i ? 1 : 0;
            is($compressed, $encoding eq 'gzip' ? 1 : 0, "$mode $version $encoding representation remains valid");
        }
    }
}
coraza_crash_check::assert_no_crash($t, 'no worker crash');

sub request {
    my ($path, $version, $encoding) = @_;
    return http("GET $path HTTP/$version\r\nHost: localhost\r\nConnection: close\r\nAccept-Encoding: $encoding\r\n\r\n")
        if $version eq '1.0' || $version eq '1.1';
    my $socket = $version eq '2' ? Test::Nginx::HTTP2->new(8082)
        : Test::Nginx::HTTP3->new();
    my $mode = $version eq '2' ? 2 : 4;
    my $stream = $socket->new_stream({ headers => [
        { name => ':method', value => 'GET', mode => $mode },
        { name => ':scheme', value => 'http', mode => $mode },
        { name => ':path', value => $path, mode => $mode },
        { name => ':authority', value => 'localhost', mode => $mode },
        { name => 'accept-encoding', value => $encoding, mode => $mode },
    ] });
    my $frames = $socket->read(all => [{ sid => $stream, fin => 1 }]);
    my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
    return '' unless $frame;
    my $headers = $frame->{headers};
    my $body = join '', map { $_->{data} } grep { $_->{type} eq 'DATA' } @$frames;
    return "HTTP/$version $headers->{':status'}\r\n"
        . join('', map { "$_: $headers->{$_}\r\n" }
            grep { $_ ne ':status' } sort keys %$headers) . "\r\n" . $body;
}
