#!/usr/bin/perl

# Tests for Coraza-nginx connector (phase 4 for header_only responses).
#
# ngx_http_dav_module's PUT handler sets 201 Created or 204 No Content and
# r->header_only = 1 BEFORE it calls ngx_http_send_header(), then finalises
# the request.  No body-filter call follows, so phase 4 cannot run from the
# body filter's last_buf: it has to be finalised in the header filter, before
# the headers go out.  Without that, a phase-4 deny on ARGS is silently
# skipped for every DAV PUT and the client gets 201/204.
#
# Tests 3 and 4 fail on a tree whose header filter excludes header_only
# responses from the phase-4 finalisation; tests 1, 2 and 5 pin that clean
# PUTs keep their status and carry no body.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(5);

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

        # Delay is ON (the shipped default): the path under test.
        location /dav/ {
            root %%TESTDIR%%;
            dav_methods PUT;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule ARGS "@streq block" "id:911,phase:4,deny,log,status:403,t:none"
            ';
        }
    }
}
EOF

mkdir($t->testdir() . '/dav');

$t->run();

###############################################################################

my $r = put('/dav/a.txt');
is(status($r), 201, 'clean PUT of a new file answers 201');

$r = put('/dav/a.txt');
is(status($r), 204, 'clean PUT replacing the file answers 204');

$r = put('/dav/a.txt?x=block');
is(status($r), 403, 'PUT 204 path: phase-4 ARGS deny answers 403');

$r = put('/dav/b.txt?x=block');
is(status($r), 403, 'PUT 201 path: phase-4 ARGS deny answers 403');

$r = put('/dav/a.txt');
like($r, qr/\x0d\x0a\x0d\x0a\z/, 'clean 204 carries no body');

###############################################################################

sub put {
	my ($uri) = @_;

	return http(<<EOR . 'abc');
PUT $uri HTTP/1.0
Host: localhost
Content-Length: 3

EOR
}

sub status {
	my ($raw) = @_;

	return 0 unless defined $raw;
	my ($s) = $raw =~ m!^HTTP/1\.[01] (\d{3})!;
	return $s // 0;
}

###############################################################################
