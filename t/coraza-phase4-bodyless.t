#!/usr/bin/perl

# Tests for Coraza-nginx connector (phase 4 for bodyless responses, issues
# #165 and #166).
#
# Phase 4 runs either from the header filter, before the headers go out, or
# from the body filter on last_buf.  A HEAD request, a 204, a 304 and a
# response the handler already marked header_only (WebDAV PUT) never get a
# body-filter call, so phase 4 can only come from the header filter -- and it
# must come in both coraza_delay_response_headers modes: with the delay off
# nothing is held back anyway, and with it on there is nothing to hold.
#
# Before the fix, HEAD was excluded from both header-filter branches (#165)
# and the finalise-before-headers branch was gated on the delay (#166), so a
# phase-4 deny on ARGS was silently skipped for every such response: the
# client got the normal 200/201/204/304 and nothing was audited.
#
# Oracle: the wire status, plus one JSON audit log per location whose last
# entry must be the blocked request, carrying the rule id and status 403.

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

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(33);

my $conf = <<'EOF';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        default_type text/plain;

        # Delay OFF: phase 4 used to run only from the body filter, which
        # bodyless responses never reach (#166).
        location /off/ {
            coraza_delay_response_headers off;
            alias %%TESTDIR%%/files/;
            coraza on;
            coraza_rules '%%RULES(921)%%';
        }
        location /off/dav/ {
            coraza_delay_response_headers off;
            root %%TESTDIR%%;
            dav_methods PUT;
            coraza on;
            coraza_rules '%%RULES(922)%%';
        }
        location = /off/nocontent {
            coraza_delay_response_headers off;
            coraza on;
            coraza_rules '%%RULES(923)%%';
            return 204;
        }
        location /off/cond/ {
            coraza_delay_response_headers off;
            alias %%TESTDIR%%/files/;
            # nginx applies add_header to 304, which makes the response
            # body-processable: the delay-on form of this is the body leak
            # covered by t/coraza-delayed-not-modified.t
            add_header Content-Type text/plain;
            coraza on;
            coraza_rules '%%RULES(924)%%';
        }

        # Delay ON (the shipped default): HEAD was excluded from the
        # finalise-before-headers branch too (#165).
        location /on/ {
            alias %%TESTDIR%%/files/;
            coraza on;
            coraza_rules '%%RULES(931)%%';
        }
        location /on/dav/ {
            root %%TESTDIR%%;
            dav_methods PUT;
            coraza on;
            coraza_rules '%%RULES(932)%%';
        }
    }
}
EOF

my @ids;
$conf =~ s{%%RULES\((\d+)\)%%}{
    push @ids, $1;
    "\n                SecRuleEngine On\n"
    . "                SecResponseBodyAccess On\n"
    . "                SecResponseBodyMimeType text/plain\n"
    . "                SecRule ARGS:x \"\@streq block\" \"id:$1,phase:4,deny,log,status:403,t:none\"\n"
    . "                SecAuditEngine On\n"
    . "                SecAuditLogParts ABFHZ\n"
    . "                SecAuditLogFormat JSON\n"
    . "                SecAuditLogType Serial\n"
    . "                SecAuditLog %%TESTDIR%%/audit-$1.log\n"
    . "            "
}ge;

$t->write_file_expand('nginx.conf', $conf);

my $testdir = $t->testdir();

mkdir("$testdir/files");
mkdir("$testdir/on");
mkdir("$testdir/on/dav");
mkdir("$testdir/off");
mkdir("$testdir/off/dav");
$t->write_file('files/static', 'STATIC-CANARY-BODY');

$t->run();

###############################################################################

# --- delay off ---------------------------------------------------------------

my $r = http_head('/off/static');
is(status($r), 200, 'off: clean HEAD answers 200');
unlike($r, qr/STATIC-CANARY-BODY/, 'off: clean HEAD carries no body');

$r = http_head('/off/static?x=block');
is(status($r), 403, 'off: HEAD with a phase-4 ARGS deny answers 403');

$r = put('/off/dav/a.txt');
is(status($r), 201, 'off: clean PUT of a new file answers 201');

$r = put('/off/dav/a.txt');
is(status($r), 204, 'off: clean PUT replacing the file answers 204');
like($r, qr/\x0d\x0a\x0d\x0a\z/, 'off: clean PUT 204 carries no body');

$r = put('/off/dav/a.txt?x=block');
is(status($r), 403, 'off: PUT 204 with a phase-4 ARGS deny answers 403');

$r = put('/off/dav/b.txt?x=block');
is(status($r), 403, 'off: PUT 201 with a phase-4 ARGS deny answers 403');

$r = http_get('/off/nocontent');
is(status($r), 204, 'off: clean return 204 answers 204');
like($r, qr/\x0d\x0a\x0d\x0a\z/, 'off: clean 204 carries no body');

$r = http_get('/off/nocontent?x=block');
is(status($r), 403, 'off: return 204 with a phase-4 ARGS deny answers 403');

my $first = http_get('/off/cond/static');
my ($etag) = $first =~ /^ETag:\s*(\S+)\s*$/mi;
ok(defined $etag, 'off: ETag present to revalidate');

$r = http(<<EOF);
GET /off/cond/static HTTP/1.0
Host: localhost
If-None-Match: $etag

EOF
is(status($r), 304, 'off: conditional GET revalidates to 304');
unlike($r, qr/STATIC-CANARY-BODY/, 'off: clean 304 carries no body');

$r = http(<<EOF);
GET /off/cond/static?x=block HTTP/1.0
Host: localhost
If-None-Match: $etag

EOF
is(status($r), 403, 'off: 304 with a phase-4 ARGS deny answers 403');

# --- delay on ----------------------------------------------------------------

$r = http_head('/on/static');
is(status($r), 200, 'on: clean HEAD answers 200');
unlike($r, qr/STATIC-CANARY-BODY/, 'on: clean HEAD carries no body');

$r = http_head('/on/static?x=block');
is(status($r), 403, 'on: HEAD with a phase-4 ARGS deny answers 403');

$r = put('/on/dav/a.txt');
is(status($r), 201, 'on: clean PUT of a new file answers 201');

$r = put('/on/dav/a.txt?x=block');
is(status($r), 403, 'on: PUT 204 with a phase-4 ARGS deny answers 403');

# --- the denies were phase-4 matches: last audit entry per location --------

for my $id (@ids) {
	my $e;
	for (1 .. 50) {
		$e = last_entry($id);
		last if defined $e && $e =~ /\[id \\"$id\\"\]/;
		select undef, undef, undef, 0.1;
	}
	$e = '' unless defined $e;
	like($e, qr/\[id \\"$id\\"\]/, "rule $id: blocked request audited with its rule id");
	like($e, qr/"response":\{[^{}]*?"status":403/, "rule $id: audit entry records status 403");
}

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');

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

sub last_entry {
	my ($id) = @_;
	my $f = "$testdir/audit-$id.log";
	return undef unless -e $f;
	open my $fh, '<', $f or die "open $f: $!";
	my @lines = grep { /"transaction"/ } <$fh>;
	close $fh;
	return $lines[-1];
}

###############################################################################
