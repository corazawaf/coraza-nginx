#!/usr/bin/perl

# Tests for Coraza-nginx connector: ARGS_POST matching.
#
# No pre-existing test demonstrated a rule actually matching against
# ARGS_POST. t/coraza-request-body.t's /nobodyaccess location has an
# ARGS_POST rule, but every probe against it is a benign pass -- it never
# proves the rule can fire.
#
# Two earlier attempts at such an oracle failed for reasons that are NOT
# connector defects, and both are recorded here so they are not re-derived:
#
#   1. t/coraza-request-body-single-submit.t's attempt sent a malformed
#      probe body (it omitted the "=" from the urlencoded pair), so no POST
#      arg named "val" was ever parsed out of it.
#
#   2. This file's first version sent a well-formed "val=one" body with the
#      correct Content-Type but served the location with `return 200`.
#      `return` belongs to ngx_http_rewrite_module and is evaluated in the
#      REWRITE phase; the connector's request-body handler is registered in
#      the PREACCESS phase (ngx_http_coraza_module.c, postconfiguration:
#      NGX_HTTP_PREACCESS_PHASE), which runs *after* REWRITE. A `return`
#      location therefore finalizes the request before phase 2 is ever
#      evaluated, so NO phase-2 rule can fire there -- not one on ARGS_POST,
#      not one on REQUEST_BODY, not even one on a plain request header.
#      Phase-1 rules are unaffected (they run in the REWRITE handler), which
#      is why t/coraza-phase1-addr-uri-deny.t blocks fine with `return 200`.
#
# The working idiom for any phase-2 assertion is therefore a location served
# by an upstream (proxy_pass), as every passing body test in this suite uses.
# This test sends a well-formed "val=one"/"val=two" urlencoded pair with the
# required Content-Type to such a location and asserts that ARGS_POST:val
# matches and blocks the former while a benign control passes.
#
# The ARGS_POST rule here deliberately carries NO
# ctl:requestBodyProcessor=URLENCODED. The other body tests set it
# explicitly; this one pins the contract that Coraza selects the URLENCODED
# body processor from the Content-Type request header on its own, which
# requires the connector to have fed that header to the engine before
# ProcessRequestBody runs.

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

$t->write_file_expand('nginx.conf', <<'EOF2');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        coraza on;

        location /argspost {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule ARGS_POST:val "@rx ^one$" "id:51,phase:2,deny,log,status:403,t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF2

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

$t->plan(2);

###############################################################################

like(http_post_form('/argspost', 'val=one'), qr/^HTTP.*403/,
    'ARGS_POST:val matches a well-formed urlencoded pair and blocks');

like(http_post_form('/argspost', 'val=two'), qr/TEST-OK-IF-YOU-SEE-THIS/,
    'ARGS_POST:val benign control (non-matching value) passes');

###############################################################################

sub http_post_form {
	my ($uri, $body) = @_;
	return http(
		"POST $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Type: application/x-www-form-urlencoded" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	);
}

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
