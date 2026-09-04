#!/usr/bin/perl

# Tests for Coraza-nginx connector: request body inspection when the proxied
# location uses "proxy_request_buffering off".
#
# The pre-access handler always calls ngx_http_read_client_request_body()
# itself before the proxy module's content-phase handler ever runs, and does
# so without setting r->request_body_no_buffering.  Once r->request_body is
# populated, nginx core's ngx_http_read_client_request_body() short-circuits
# any later caller (see the r->request_body check at its top) and clears
# request_body_no_buffering back to 0, so the proxy module's own streaming
# path never activates.  This test proves the full body is still inspected
# and blocked when "proxy_request_buffering off" is set, with a benign body
# of the same shape passing through -- i.e. the directive is a no-op for
# Coraza's inspection guarantee, not a bypass.

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
my $good_body = 'GOOD BODY' x 40;
my $bad_body = $good_body . 'BAD BODY';

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

        location /nobuffering {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx BAD BODY" "id:11,phase:2,deny,log,status:403,t:none"
            ';
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /nobuffering_detectiononly {
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx BAD BODY" "id:12,phase:2,deny,log,auditlog,status:403,msg:\'no-buffering-detectiononly\',t:none"
                SecAuditEngine On
                SecAuditLogParts ABKZ
                SecAuditLog %%TESTDIR%%/auditlog-detectiononly.txt
                SecAuditLogType Serial
            ';
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

$t->plan(4);

###############################################################################

# Benign body of the same shape still passes with buffering off.
like(http_req_body('POST', '/nobuffering', $good_body),
	qr/\Q$good_body\E\z/,
	'proxy_request_buffering off, benign body, pass');

# A body Coraza's rule blocks under normal (buffered) inspection is still
# blocked with proxy_request_buffering off -- the full streamed body reached
# the engine, not a truncated prefix.
like(http_req_body('POST', '/nobuffering', $bad_body),
	qr/^HTTP.*403/,
	'proxy_request_buffering off, malicious body, block');

# Negative control: with the same request-buffering-off streaming path but
# SecRuleEngine DetectionOnly, the same malicious body is NOT blocked. This
# proves the block above comes from the engine actually evaluating the body,
# not from some unrelated 403 (e.g. a body-limit or protocol error).
like(http_req_body('POST', '/nobuffering_detectiononly', $bad_body),
	qr/\Q$bad_body\E\z/,
	'proxy_request_buffering off, malicious body, DetectionOnly control passes through');

$t->stop();

like($t->read_file('auditlog-detectiononly.txt'),
	qr/no-buffering-detectiononly/,
	'DetectionOnly rule evaluated the full request body');

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

		my ($content_length) = $headers =~ /^Content-Length:\s*(\d+)/mi;
		my $body = '';
		while (defined $content_length && length($body) < $content_length) {
			my $n = read($client, my $chunk, $content_length - length($body));
			last unless defined $n && $n > 0;
			$body .= $chunk;
		}
		my $response_body = defined $content_length
			&& length($body) == $content_length ? $body : 'TRUNCATED';

		print $client "HTTP/1.1 200 OK\r\n"
			. "Connection: close\r\n"
			. "Content-Length: " . length($response_body) . "\r\n\r\n"
			. $response_body;

		close $client;
	}
}

sub http_req_body {
	my ($method, $uri, $body) = @_;
	return http(
		"$method $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	);
}

###############################################################################
