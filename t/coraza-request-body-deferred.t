#!/usr/bin/perl

# Tests for Coraza-nginx connector: request body that is NOT fully preread when
# the pre-access handler first runs.  ngx_http_read_client_request_body()
# returns NGX_AGAIN, the handler sets ctx->waiting_more_body and returns
# NGX_DONE; when the rest of the body arrives the request_read callback clears
# waiting_more_body and re-runs the phase engine.  This exercises the deferred
# body-read path (NGX_AGAIN branch + request_read resume) that a fully-preread
# body never touches.

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
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx BAD BODY" "id:600,phase:2,deny,status:403,log"
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

# Send the body in two parts with a delay so it is not available at preread
# time: this forces the NGX_AGAIN / waiting_more_body deferred read path.
# The full body carries the attack token and must still be blocked.
like(
	http(
		'POST /body HTTP/1.0' . CRLF
		. 'Host: localhost' . CRLF
		. 'Content-Type: application/x-www-form-urlencoded' . CRLF
		. 'Content-Length: 26' . CRLF . CRLF
		. 'x=VERY ',
		sleep => 0.2,
		body => 'BAD BODY value here'
	),
	qr/^HTTP\S+ 403/,
	'deferred (split) request body inspected and blocked'
);

# Positive control: a clean split body reaches the upstream unblocked.
like(
	http(
		'POST /body HTTP/1.0' . CRLF
		. 'Host: localhost' . CRLF
		. 'Content-Type: application/x-www-form-urlencoded' . CRLF
		. 'Content-Length: 27' . CRLF . CRLF
		. 'x=nice ',
		sleep => 0.2,
		body => 'GOOD BODY value here'
	),
	qr/TEST-OK-IF-YOU-SEE-THIS/,
	'clean deferred request body allowed'
);

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

		# Drain the forwarded request body before responding so nginx's
		# upstream write completes; otherwise the proxy round-trip races
		# on an unread socket (intermittent 502).
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

###############################################################################
