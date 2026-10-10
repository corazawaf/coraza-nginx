#!/usr/bin/perl

# Phase 4 must be finalised BEFORE the headers of a bodyless (204 / 304)
# response go out, even when the Content-Type is listed in
# SecResponseBodyMimeType.
#
# An nginx-generated 304 never carries a Content-Type (the not-modified
# filter clears it), so it was always finalised on the headers alone.  A
# proxied origin, however, may answer "304 Not Modified" or "204 No Content"
# WITH a Content-Type.  Such a response is "processable" to coraza, yet nginx
# sets r->header_only once its headers are sent and the only body-filter call
# is the upstream's last_buf, AFTER the headers are on the wire.  Phase 4 run
# from there is too late: a deny meets "header already sent" and the client
# receives an aborted response instead of a clean 403.
#
# This file fails on a tree that merely excludes 204/304 from the header
# delay without finalising phase 4 for them (tests 4 and 7: no status line,
# plus the "header already sent" alert), and passes once the header filter
# finalises phase 4 for bodyless statuses before forwarding the headers.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF2');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # Origin: bodyless statuses that still carry a listed Content-Type.
    server {
        listen       127.0.0.1:8081;
        server_name  origin;

        location /nm304 {
            add_header Content-Type text/plain always;
            return 304;
        }

        location /nc204 {
            add_header Content-Type text/plain always;
            return 204;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        # Delay is ON (the shipped default): the path under test.
        location /delayed/ {
            proxy_pass http://127.0.0.1:8081/;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule ARGS "@streq block" "id:901,phase:4,deny,log,status:403,t:none"
            ';
        }

        # Positive control: an nginx-generated 304 has no Content-Type and
        # was finalised on the headers alone all along.
        location /static {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule ARGS "@streq block" "id:903,phase:4,deny,log,status:403,t:none"
            ';
        }
    }
}

EOF2

$t->write_file('/static', 'STATIC-CANARY-BODY');
$t->run();

###############################################################################

# Precondition: the origin really emits Content-Type on its 304.  Without it
# the response is not "processable" and this file would test nothing.
my $o = http("GET /nm304 HTTP/1.0\r\nHost: origin\r\n\r\n",
	socket => IO::Socket::INET->new(Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8081)));
like($o, qr/^Content-Type: text\/plain/mi,
	'precondition: origin 304 carries Content-Type: text/plain');

for my $case ([ 'nm304', 304 ], [ 'nc204', 204 ]) {
	my ($path, $code) = @$case;
	my $r;

	$r = http_get("/delayed/$path?x=ok");
	is(status($r), $code, "$path: clean request passes through as $code");
	is(body($r), '', "$path: clean request carries no body");

	$r = http_get("/delayed/$path?x=block");
	is(status($r), 403, "$path: phase-4 ARGS deny answers a clean 403");
}

my $first = http_get('/static');
my ($etag) = $first =~ /^ETag:\s*(\S+)\s*$/mi;
ok(defined $etag, 'static: ETag present to revalidate');

my $r = http("GET /static?x=block HTTP/1.0\r\nHost: localhost\r\n"
	. "If-None-Match: $etag\r\n\r\n");
is(status($r), 403, 'static 304 path: phase-4 ARGS deny answers 403');

$r = http("GET /static?x=ok HTTP/1.0\r\nHost: localhost\r\n"
	. "If-None-Match: $etag\r\n\r\n");
is(status($r), 304, 'static conditional GET revalidates to 304');
is(body($r), '', 'static 304 carries no body');

###############################################################################

sub status {
	my ($r) = @_;
	my ($s) = $r =~ m!^HTTP/1\.[01] (\d{3})!;
	return defined $s ? $s : 'NONE';
}

sub body {
	my ($r) = @_;
	my $i = index($r, "\x0d\x0a\x0d\x0a");
	# undef, not '', so a response without a header terminator cannot pass
	# an "empty body" check
	return $i < 0 ? undef : substr($r, $i + 4);
}

###############################################################################
