#!/usr/bin/perl

# Tests for Coraza-nginx connector: request body inspection when the body is
# buffered to a temporary FILE rather than kept in memory.
#
# With client_body_in_file_only nginx always spills the request body to a temp
# file; the pre-access handler then feeds Coraza via
# coraza_request_body_from_file() (the temp_file branch) instead of the
# in-memory chain walk.  A phase-2 REQUEST_BODY rule proves the file-backed
# body is still inspected and blocked.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/);

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

        coraza on;

        location /body {
            # Force the request body onto disk so the temp-file inspection
            # path (coraza_request_body_from_file) is exercised.
            client_body_in_file_only on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx BAD BODY" "id:500,phase:2,deny,status:403,log"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(2);

###############################################################################

# File-backed body carrying the attack token must be blocked.
like(http_req_body('POST', '/body', 'x=VERY BAD BODY value'),
    qr/^HTTP\S+ 403/, 'file-backed request body inspected and blocked');

# Positive control: a clean file-backed body passes through to the upstream.
like(http_req_body('POST', '/body', 'x=totally harmless value'),
    qr/TEST-OK-IF-YOU-SEE-THIS/, 'clean file-backed request body allowed');

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
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

		# Drain the forwarded request body so nginx's upstream write
		# completes; responding before reading it leaves bytes in the
		# socket and makes the proxy round-trip race (intermittent 502).
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
		print $client "Content-Length: 23" . CRLF;
		print $client "Connection: close" . CRLF . CRLF;
		print $client "TEST-OK-IF-YOU-SEE-THIS"
			unless $headers =~ /^HEAD/i;

		close $client;
	}
}

sub http_req_body {
	my ($method, $uri, $body) = @_;
	return http(
		"$method $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Type: application/x-www-form-urlencoded" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	);
}

###############################################################################
