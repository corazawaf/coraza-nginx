#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use lib 'lib';
use Test::Nginx;

# Run from the project's pinned nginx-tests directory, like t/coraza*.t.
# SSI consumes comment-only input buffers and emits empty sync markers before
# later literal data. Small copy buffers ensure some markers are nonfinal.
my $t = Test::Nginx->new()->has(qw/http ssi/)->plan(17);
$t->write_file_expand('nginx.conf', <<'CONF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        root %%TESTDIR%%;
        default_type text/html;
        sendfile off;
        output_buffers 1 64;
        ssi on;
        coraza on;
        coraza_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/html
            SecRule RESPONSE_BODY "@contains unused-sentinel" "id:606,phase:4,t:none,deny,status:403"
        ';
        location /plain { ssi off; }
        location /nonchunked { chunked_transfer_encoding off; }
    }
}
CONF
my $body = "start:0123456789:middle:abcdefghijklmnopqrstuvwxyz:end\n";
my $comments = '<!--# set var="x" value="a" -->' x 256;
$t->write_file('chunked', $comments . $body);
$t->write_file('nonchunked', $comments . $body);
$t->write_file('empty', $comments);
$t->write_file('plain', $body);
$t->run();

for my $path (qw(chunked nonchunked empty plain)) {
    my $response = http("GET /$path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    like($response, qr/^HTTP\/1\.1 200 /, "$path status");
    my ($headers, $wire) = split /\r\n\r\n/, $response, 2;
    $headers //= '';
    $wire //= '';
    my $decoded = $wire;
    if ($path eq 'chunked' || $path eq 'empty') {
        like($headers, qr/Transfer-Encoding: chunked/i, "$path uses chunking");
        $decoded = '';
        my $final = 0;
        # Consume every chunk including its terminator; a prefix or a short
        # body must not pass the full-response oracle.
        while ($wire =~ s/^([0-9a-fA-F]+)\r\n//) {
            my $size = hex $1;
            if ($size == 0) {
                $final = 1;
                last;
            }
            die "truncated chunk\n" if length($wire) < $size + 2;
            $decoded .= substr($wire, 0, $size, '');
            die "invalid chunk terminator\n" unless $wire =~ s/^\r\n//;
        }
        ok($final, "$path has final chunk");
        is($wire, "\r\n", "$path has no trailing bytes");
    } else {
        unlike($headers, qr/Transfer-Encoding:/i, "$path is nonchunked");
    }
    is($decoded, $path eq 'empty' ? '' : $body, "$path complete exact body");
}
$t->stop();
unlike($t->read_file('error.log'), qr/zero size buf in writer|\[alert\]|\[emerg\]/,
    'no writer alert or fatal nginx error');
