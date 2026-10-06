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
use lib '.';
use coraza_crash_check;

my $t = Test::Nginx->new()->has(qw/http proxy charset/)->plan(44);
my @cases = (
    ['off', 'Server', 'server_tokens off; default_type text/plain; return 200 "ok";'],
    ['on', 'Server', 'server_tokens on; default_type text/plain; return 200 "ok";'],
    ['build', 'Server', 'server_tokens build; default_type text/plain; return 200 "ok";'],
    ['charset', 'Content-Type', 'charset utf-8; default_type text/plain; return 200 "ok";'],
    ['plain', 'Content-Type', 'charset off; default_type text/plain; return 200 "ok";'],
    ['parameter', 'Content-Type', 'charset off; default_type "text/plain; format=flowed"; return 200 "ok";'],
    ['upstream-server', 'Server', 'server_tokens off; proxy_pass_header Server; proxy_pass http://127.0.0.1:%%PORT_8081%%;'],
    ['upstream-charset', 'Content-Type', 'charset utf-8; override_charset off; proxy_pass http://127.0.0.1:%%PORT_8081%%;'],
);
my $locations = '';
my $id = 7100;
for my $case (@cases) {
    my ($path, $field, $config) = @$case;
    $locations .= "location /wire/$path { coraza off; $config }\n";
    $locations .= "location /inspect/$path { coraza on; $config\n"
        . "coraza_rules 'SecRuleEngine On\nSecResponseBodyAccess Off\n"
        . 'SecRule RESPONSE_HEADERS:' . $field
        . ' "@streq %{REQUEST_HEADERS.X-Expected}" "id:' . ++$id
        . ',phase:3,t:none,deny,status:418,log"' . "'; }\n";
}
$t->write_file_expand('nginx.conf', <<EOF_CONF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name localhost;
        $locations
    }
}
EOF_CONF
$t->run_daemon(\&origin);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
for my $case (@cases) {
    my ($path, $field) = @$case;
    my $wire = http_get("/wire/$path");
    like($wire, qr/^HTTP\S+ 200/, "$path ordinary response");
    my ($value) = $wire =~ /^\Q$field\E: ([^\r\n]*)/mi;
    ok(defined $value && length $value, "$path wire oracle exists");
    $value //= '';
    my $matched = http("GET /inspect/$path HTTP/1.0\r\nHost: localhost\r\nX-Expected: $value\r\n\r\n");
    like($matched, qr/^HTTP\S+ 418/, "$path rule sees exact ordinary $field");
    my $benign = http("GET /inspect/$path HTTP/1.0\r\nHost: localhost\r\nX-Expected: never-matches-f07\r\n\r\n");
    like($benign, qr/^HTTP\S+ 200/, "$path benign nonmatch passes");
    like($benign, qr/^\Q$field: $value\E\r?$/mi, "$path inspection preserves wire value");
    if ($path eq 'charset') {
        is($value, 'text/plain; charset=utf-8', 'charset appended once');
    } elsif ($path eq 'upstream-server') {
        is($value, 'origin-f07', 'explicit upstream Server preserved');
    } elsif ($path eq 'upstream-charset') {
        is($value, 'text/plain; charset=iso-8859-1', 'explicit upstream charset preserved');
    }
}
coraza_crash_check::assert_no_crash($t, 'no worker crash');

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
        print {$client} "HTTP/1.1 200 OK\r\nServer: origin-f07\r\n"
            . "Content-Type: text/plain; charset=iso-8859-1\r\n"
            . "Content-Length: 2\r\nConnection: close\r\n\r\nok";
        close $client;
    }
}
