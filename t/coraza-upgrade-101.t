#!/usr/bin/perl

# Tests for Coraza-nginx connector (101 Switching Protocols passthrough).
#
# Regression test for the fix that lets a 101 Switching Protocols response
# (WebSocket / protocol upgrade) pass through the header filter unharmed.
# The connector forces Connection: upgrade for status 101 and must not block
# or corrupt the handshake while still allowing phase-3 rules to run.
# See src/ngx_http_coraza_header_filter.c (NGX_HTTP_SWITCHING_PROTOCOLS).

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                # A benign phase-3 rule: must NOT match the 101 handshake, so
                # the upgrade passes through with the WAF active.
                SecRule RESPONSE_HEADERS:X-Block "@streq yes" "id:54,phase:3,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 1s;
        }
    }
}
EOF

$t->run_daemon(\&upgrade_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

my $r = upgrade_request();
like($r, qr/^HTTP\S+ 101/, '101 Switching Protocols passes through the WAF');
like($r, qr/Upgrade: websocket/i, 'Upgrade header preserved');
like($r, qr/Connection: upgrade/i, 'Connection: upgrade forced by connector');

###############################################################################

sub upgrade_request {
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "GET / HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Upgrade: websocket\r\n"
		. "Connection: upgrade\r\n\r\n";

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(3);
		while (<$s>) {
			$reply .= $_;
			last if /^\x0d?\x0a$/ && $reply =~ /\r\n\r\n/;
		}
		alarm(0);
	};
	close $s;
	return $reply;
}

sub upgrade_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		while (<$client>) {
			last if (/^\x0d?\x0a?$/);
		}

		print $client "HTTP/1.1 101 Switching Protocols\r\n"
			. "Upgrade: websocket\r\n"
			. "Connection: upgrade\r\n\r\n";

		# Keep the socket briefly open like a real upgraded stream.
		select undef, undef, undef, 0.2;
		close $client;
	}
}
