#!/usr/bin/perl

# Tests for Coraza-nginx connector (WebSocket / 101 Switching Protocols).
#
# Regression test for the fix that lets protocol-upgrade responses pass
# through. The connector delays response headers until phase-4 body
# inspection completes, but a 101 response has no HTTP body to trigger
# that flush, so the upgrade handshake was held forever and WebSocket
# connections timed out (even in DetectionOnly).

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;
use Digest::SHA qw/sha1/;
use MIME::Base64 qw/encode_base64/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
            ';
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 1.1;
            proxy_set_header Upgrade    $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 2s;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# WebSocket upgrade must complete with a 101 (the header was previously
# delayed and never sent, so the handshake timed out).
my $status = ws_handshake('/chat');
like($status, qr!HTTP/1\.1 101!, 'websocket upgrade returns 101');

# Control: a normal request is still proxied (and inspected) as usual.
like(http_get('/'), qr/200 OK/, 'normal request still proxied');

###############################################################################

sub ws_handshake {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
		Timeout  => 5,
	) or return '';

	my $key = encode_base64(pack('N4', $$, time(), 0, 0), '');
	$s->print("GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Upgrade: websocket\r\n"
		. "Connection: Upgrade\r\n"
		. "Sec-WebSocket-Key: $key\r\n"
		. "Sec-WebSocket-Version: 13\r\n\r\n");

	my $buf = '';
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm(5);
		while ($buf !~ /\r\n\r\n/) {
			my $chunk;
			my $n = $s->read($chunk, 1024);
			last if !defined $n || $n == 0;
			$buf .= $chunk;
		}
		alarm(0);
	};
	return '' if $@;

	my ($line) = split /\r\n/, $buf, 2;
	return $line;
}

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen    => 5,
		Reuse     => 1,
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		if ($headers =~ /Upgrade:\s*websocket/i) {
			my ($key) = $headers =~ /Sec-WebSocket-Key:\s*(\S+)/i;
			my $accept = encode_base64(
				sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), '');

			print $client "HTTP/1.1 101 Switching Protocols\r\n"
				. "Upgrade: websocket\r\n"
				. "Connection: Upgrade\r\n"
				. "Sec-WebSocket-Accept: $accept\r\n\r\n";

			# Echo whatever arrives over the upgraded tunnel.
			while (my $n = $client->read(my $b, 1024)) {
				print $client $b;
			}
		} else {
			print $client "HTTP/1.1 200 OK\r\n"
				. "Connection: close\r\n\r\n"
				. "TEST-OK-IF-YOU-SEE-THIS";
		}

		close $client;
	}
}

###############################################################################
