#!/usr/bin/perl

# Tests for Coraza-nginx connector (chunked and temp-file request bodies).
#
# Two request-body paths that the rest of the suite never exercises:
#
#   * Chunked transfer encoding.  Every other body test sends a
#     Content-Length, so the chunked path -- which changes whether nginx
#     buffers to a temp file and whether the body arrives across multiple
#     reads -- had no coverage at all.
#
#   * Temp-file bodies.  ngx_http_coraza_pre_access.c has a whole branch for
#     r->request_body->temp_file that hands the file PATH to Coraza
#     (coraza_request_body_from_file) instead of appending buffers.  Every
#     existing body test sends a few hundred bytes and stays in memory, so
#     that branch was never entered.  client_body_buffer_size here is small
#     enough to force the spill.
#
# The adversarial case that matters for the temp-file path: a payload split
# across the buffer boundary must still be inspected as one body.  If only
# the first in-memory buffer were fed to the engine, a marker straddling the
# boundary would slip through -- so the test places it deliberately.

###############################################################################

use warnings;
use strict;

use Test::More;

use constant CRLF => "\x0d\x0a";

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(7);

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

        location /body {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:7200,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@contains BADBODY" "id:7201,phase:2,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # client_body_buffer_size 1k forces anything larger to a temp file, so
        # this location drives the coraza_request_body_from_file branch.
        # SecRequestBodyLimit must stay above the payload or Coraza would
        # reject it before the branch is reached.
        location /body-file {
            client_body_buffer_size 1k;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 1048576
                SecRequestBodyNoFilesLimit 1048576
                SecAction "id:7203,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@contains BADBODY" "id:7202,phase:2,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  localhost;

        location / {
            return 200 "TEST-OK\n";
        }
    }
}

EOF

$t->run();

###############################################################################

# --- chunked bodies -------------------------------------------------------

like(chunked_post('/body', ['BAD', 'BODY']),
	qr!^HTTP/1.1 403!,
	'chunked body inspected (marker split across two chunks)');

like(chunked_post('/body', ['harmless', 'payload']),
	qr!^HTTP/1.1 200!,
	'control: clean chunked body passes');

# --- temp-file bodies -----------------------------------------------------

# Well over client_body_buffer_size, marker near the end: proves the whole
# spilled body is inspected, not just the first buffered kilobyte.
my $tail = ('A' x 8192) . 'BADBODY' . ('B' x 64);
like(post('/body-file', $tail), qr!^HTTP/1.1 403!,
	'temp-file body inspected (marker past the buffer boundary)');

# Marker straddling the 1k boundary itself: the byte range Coraza sees must be
# contiguous across the spill, not two independently-scanned pieces.
my $straddle = ('A' x 1021) . 'BADBODY' . ('B' x 4096);
like(post('/body-file', $straddle), qr!^HTTP/1.1 403!,
	'temp-file body inspected (marker straddling the buffer boundary)');

# Control: same size, no marker -- proves the 403s above are the rule matching
# and not the temp-file path failing closed on every large body.
like(post('/body-file', 'C' x 9000), qr!^HTTP/1.1 200!,
	'control: clean temp-file body passes');

# A large chunked body also spills to a temp file: both paths at once.
like(chunked_post('/body-file', ['D' x 4096, 'BADBODY', 'E' x 4096]),
	qr!^HTTP/1.1 403!,
	'chunked body spilled to a temp file is inspected');

$t->stop();

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling chunked or temp-file bodies');

###############################################################################

sub post {
	my ($uri, $payload) = @_;

	return http("POST $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: " . length($payload) . CRLF
		. "Connection: close" . CRLF . CRLF
		. $payload);
}

# Send the body as chunked transfer-encoding, one chunk per list element, so
# the marker can be split across chunk boundaries.
sub chunked_post {
	my ($uri, $chunks) = @_;

	my $body = '';
	for my $c (@$chunks) {
		$body .= sprintf("%x", length($c)) . CRLF . $c . CRLF;
	}
	$body .= '0' . CRLF . CRLF;

	return http("POST $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. $body);
}

###############################################################################
