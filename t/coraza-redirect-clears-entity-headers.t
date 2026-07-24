#!/usr/bin/perl

# Tests for Coraza-nginx connector: a phase-3 (response-header) redirect
# intervention must strip the entity/representation headers carried over from
# the original upstream response so the synthesized 3xx is not
# protocol-inconsistent (RFC 9110 15.4 / 8.3-8.8): a body-less redirect must
# not advertise Content-Length, Content-Encoding, Last-Modified, ETag or
# Accept-Ranges that describe the representation being discarded.
#
# These headers only exist as real ngx_table_elt_t pointers
# (headers_out.content_length / .last_modified / .content_encoding / .etag)
# when they arrive from an upstream over the proxy module -- a static-file
# response uses the integer content_length_n / last_modified_time fields and
# never populates the pointers, so the pointer-clearing branch is reachable
# only via proxy.

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

        location /redir {
            coraza on;
            # Phase-3 redirect fires AFTER the upstream response headers
            # (Content-Length, Content-Encoding, Last-Modified, ETag) are in
            # place, so the redirect branch must clear those table entries.
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq go" "id:400,phase:3,status:302,redirect:http://example.org/moved,log"
            ';
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 2s;
        }
    }
}
EOF

$t->todo_alerts();
$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(14);

###############################################################################

# Trigger the phase-3 redirect over the entity-header-rich upstream response.
my $r = http_get('/redir?x=go');

like($r, qr!^HTTP\S+ 302!, 'phase-3 redirect status emitted over proxied response');
like($r, qr!Location: http://example.org/moved!, 'Location present');

# The entity headers describing the discarded representation must be gone.
unlike($r, qr!^Content-Length: \d!im, 'Content-Length cleared on redirect');
unlike($r, qr!^Content-Type:!im, 'Content-Type cleared on redirect');
unlike($r, qr!^Content-Encoding:!im, 'Content-Encoding cleared on redirect');
unlike($r, qr!^Last-Modified:!im, 'Last-Modified cleared on redirect');
unlike($r, qr!^ETag:!im, 'ETag cleared on redirect');
unlike($r, qr!^Accept-Ranges:!im, 'Accept-Ranges cleared on redirect');

# Positive control: a clean request passes the upstream response through WITH
# its entity headers intact (proves the assertions above are not vacuous).
my $clean = http_get('/redir?x=safe');
like($clean, qr!^HTTP\S+ 200!, 'clean request 200 (control)');
like($clean, qr!^Content-Type: text/plain!im, 'clean keeps Content-Type (control)');
like($clean, qr!^Content-Encoding: gzip!im, 'clean keeps Content-Encoding (control)');
like($clean, qr!^Last-Modified: !im, 'clean keeps Last-Modified (control)');
like($clean, qr!^ETag: !im, 'clean keeps ETag (control)');
like($clean, qr!^Accept-Ranges: bytes!im, 'clean keeps Accept-Ranges (control)');

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

		# Emit a representation-rich response so nginx populates the
		# headers_out.* table-entry pointers the redirect branch clears.
		my $body = "the original representation body\n";
		print $client "HTTP/1.1 200 OK\r\n";
		print $client "Content-Type: text/plain\r\n";
		print $client "Content-Length: " . length($body) . "\r\n";
		print $client "Content-Encoding: gzip\r\n";
		print $client "Last-Modified: Wed, 01 Jan 2025 00:00:00 GMT\r\n";
		print $client "ETag: \"deadbeef\"\r\n";
		print $client "Accept-Ranges: bytes\r\n";
		print $client "Connection: close\r\n";
		print $client "\r\n";
		print $client $body unless $headers =~ /^HEAD/i;

		close $client;
	}
}

###############################################################################
