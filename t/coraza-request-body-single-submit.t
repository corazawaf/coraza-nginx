#!/usr/bin/perl

# Tests for Coraza-nginx connector: the request body must be submitted to the
# engine exactly once per request.
#
# ngx_http_coraza_pre_access_handler's body-submit block used to be guarded
# only by `waiting_more_body == 0`. If the PREACCESS phase were re-entered on
# the same request after the body had already been appended and processed
# (e.g. a second PREACCESS-phase handler runs after coraza), the handler had
# no record that submission already happened and would walk
# r->request_body->bufs again, re-call coraza_append_request_body() and
# re-call coraza_process_request_body(). Symptoms: REQUEST_BODY becomes
# "BAD BODYBAD BODY", ARGS_POST gains duplicate params, and
# SecRequestBodyLimit trips at half the configured size (spurious 413).
#
# A genuine second PREACCESS-phase nginx module is not available in the test
# module set here (see t/README.md / `has(qw/.../)` across this suite: no
# module other than coraza itself hooks PREACCESS). auth_request only proves
# the pre_access ACCESS-adjacent re-entry pattern via a different phase
# (t/coraza-request-body.t's /useauth case), so it cannot exercise this
# handler being invoked twice. This test instead pins the observable
# contract on the single normal invocation, via SecRequestBodyLimit: the body
# is sized so one submission fits comfortably under the limit while a doubled
# one would exceed it and Reject with 413. See the GAP note below the
# assertion for the ARGS_POST check that is deliberately not made here.

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

        location /singlesubmit {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRequestBodyLimit 20
                SecRequestBodyLimitAction Reject
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

$t->plan(1);

###############################################################################

# SecRequestBodyLimit is 20 (exclusive: the limit itself already trips
# Reject, per t/coraza-request-body.t's /bodylimitreject pair where 129
# passes at 128 bytes and blocks at 132). The body here is 12 bytes --
# comfortably under 20 for a single submission, but a doubled submission
# (24 bytes effective) would exceed 20 and Reject with 413.
like(http_req_body('POST', '/singlesubmit', '123456789012'), qr/TEST-OK-IF-YOU-SEE-THIS/,
    "POST body submitted once stays within SecRequestBodyLimit");

# GAP: an ARGS_POST-based duplication check would be the sharper oracle --
# a single submission gives val="one" (matching ^one$) while a doubled one
# gives "oneone" (matching one.*one), so the two are distinguishable by
# status alone. It is not asserted here because the ARGS_POST rule did not
# fire against this connector in CI (the request returned 200 with the rule
# never matching), and the cause was not established. The only existing
# ARGS_POST case in the suite, t/coraza-request-body.t's /nobodyaccess, runs
# with SecRequestBodyAccess Off and asserts a pass, so it does not
# demonstrate ARGS_POST matching either. Resolving that is its own task;
# a decorative assertion here would be worse than the stated gap.

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

		print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
		print $client "TEST-OK-IF-YOU-SEE-THIS"
			unless $headers =~ /^HEAD/i;

		close $client;
	}
}

sub http_req_body {
	my $method = shift;
	my $uri = shift;
	my $body = shift;
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
