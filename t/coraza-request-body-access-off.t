#!/usr/bin/perl

# Request-body fast path for SecRequestBodyAccess Off.
#
# The connector must not preread or submit body bytes when Coraza says they are
# inaccessible, but it must still execute phase 2.  The first test sends only
# one byte of a declared body and requires a phase-2 header rule to deny before
# the rest arrives.  It fails if the connector waits for the body, and also if
# coraza_process_request_body() is incorrectly skipped.  The other tests prove
# that an allowed body still reaches the upstream intact and that the normal
# body-inspection path remains active when access is on.

###############################################################################

use warnings;
use strict;

use IO::Select;
use IO::Socket::INET;
use Socket qw/ CRLF /;
use Test::More;
use Time::HiRes qw/ time /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(4);

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

        location /off {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:700,phase:1,pass,nolog,t:none,ctl:requestBodyAccess=Off"
                SecRule REQUEST_HEADERS:X-Phase2 "@streq blockme" "id:701,phase:2,deny,status:403,log,t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /on {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:702,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@contains blockme" "id:703,phase:2,deny,status:403,log,t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(
	early_phase2_response(),
	qr/^HTTP\S+ 403/,
	'phase 2 runs without waiting for an inaccessible request body'
);

my $body = 'body reaches upstream byte-for-byte';
like(
	http_req_body('/off', $body, 'safe'),
	qr/\Q$body\E\z/s,
	'inaccessible request body is still forwarded intact'
);

like(
	http_req_body('/on', 'x=blockme', 'safe'),
	qr/^HTTP\S+ 403/,
	'control: accessible request body remains inspected'
);

###############################################################################

sub early_phase2_response {
	my $client = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1:' . port(8080),
		Proto => 'tcp',
	) or die "connect to nginx: $!\n";

	$client->autoflush(1);
	print $client 'POST /off HTTP/1.0' . CRLF
		. 'Host: localhost' . CRLF
		. 'X-Phase2: blockme' . CRLF
		. 'Content-Length: 65536' . CRLF . CRLF
		. 'x';

	my $deadline = time() + ($ENV{TEST_NGINX_TIMEOUT} // 5);
	my $select = IO::Select->new($client);
	my $response = '';
	while ($response !~ /\r?\n/ && length($response) < 4096) {
		my $remaining = $deadline - time();
		last if $remaining <= 0;

		my @ready = $select->can_read($remaining);
		last if !@ready;

		my $chunk = '';
		my $peer = recv($client, $chunk, 4096 - length($response), 0);
		last if !defined $peer || $chunk eq '';
		$response .= $chunk;
	}

	close $client;
	return $response;
}

sub http_req_body {
	my ($uri, $body, $phase2) = @_;
	return http(
		'POST ' . $uri . ' HTTP/1.0' . CRLF
		. 'Host: localhost' . CRLF
		. 'X-Phase2: ' . $phase2 . CRLF
		. 'Content-Type: application/x-www-form-urlencoded' . CRLF
		. 'Content-Length: ' . length($body) . CRLF . CRLF
		. $body
	);
}

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1,
	) or die "create backend socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if /^\x0d?\x0a?$/;
		}

		my $body = '';
		if ($headers =~ /Content-Length:\s*(\d+)/i) {
			my $need = $1;
			while (length($body) < $need) {
				my $chunk = '';
				my $n = read($client, $chunk, $need - length($body));
				last if !defined $n || $n == 0;
				$body .= $chunk;
			}
		}

		print $client 'HTTP/1.1 200 OK' . CRLF;
		print $client 'Content-Length: ' . length($body) . CRLF;
		print $client 'Connection: close' . CRLF . CRLF;
		print $client $body;
		close $client;
	}
}

###############################################################################

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
