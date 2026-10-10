#!/usr/bin/perl

# Tests for Coraza-nginx connector (Location replacement on policy redirect).
#
# A benign upstream Location must be replaced, not appended to, when a rule
# issues a policy redirect: the response carries exactly one Location header.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/);
$t->write_file_expand('nginx.conf', <<'CONF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:action "@streq redirect" "id:501,phase:3,t:none,status:302,redirect:https://policy.example/new,log"
                SecRule ARGS:action "@streq deny" "id:502,phase:3,t:none,status:403,deny,log"
            ';
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 2s;
        }
    }
}
CONF
$t->todo_alerts();
$t->run_daemon(\&upstream);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(13);

my $clean = http_get('/?action=clean');
like($clean, qr/^HTTP\S+ 302/, 'clean preserves upstream redirect status');
my @clean_locations = $clean =~ /^Location:\s*([^\r\n]*)/img;
is_deeply(\@clean_locations, ['https://origin.example/old'], 'clean preserves upstream destination');
for my $path ('/?action=redirect', '/no-location?action=redirect') {
    my $response = http_get($path);
    like($response, qr/^HTTP\S+ 302/, "$path policy redirect status");
    my @locations = $response =~ /^Location:\s*([^\r\n]*)/img;
    is_deeply(\@locations, ['https://policy.example/new'],
        "$path emits exactly one policy destination");
    unlike($response, qr/origin\.example/, "$path does not emit stale destination");
}
my $denied = http_get('/?action=deny');
like($denied, qr/^HTTP\S+ 403/, 'deny overrides origin redirect');
unlike($denied, qr/^Location:/im, 'deny does not send origin redirect');
my $ordinary = http_get('/no-location?action=clean');
like($ordinary, qr/^HTTP\S+ 200/, 'ordinary response passes through');
unlike($ordinary, qr/^Location:/im, 'ordinary response has no Location');
coraza_crash_check::assert_no_crash($t, 'no worker crash');

sub upstream {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp', LocalHost => '127.0.0.1:' . port(8081),
        Listen => 5, Reuse => 1
    ) or die "listen: $!";
    local $SIG{PIPE} = 'IGNORE';
    while (my $client = $server->accept()) {
        $client->autoflush(1);
        my $headers = '';
        while (<$client>) {
            $headers .= $_;
            last if /^\r?\n$/;
        }
        my $no_location = $headers =~ m{^GET /no-location};
        print {$client} $no_location ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 302 Found\r\n";
        print {$client} "Location: https://origin.example/old\r\n" unless $no_location;
        print {$client} "Content-Length: 0\r\nConnection: close\r\n\r\n";
        close $client;
    }
}
