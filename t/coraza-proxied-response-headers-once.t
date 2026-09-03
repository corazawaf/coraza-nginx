#!/usr/bin/perl

# Tests for Coraza-nginx connector (proxied response headers submitted once).
#
# ngx_http_coraza_header_filter() submits response headers to Coraza in two
# passes: a lookup table over the dedicated headers_out struct fields
# (Server, Date, Last-Modified, ...), then a walk over the raw
# r->headers_out.headers list. On a proxied response nginx's upstream module
# points r->headers_out.server / .date / .last_modified at the very same
# ngx_table_elt_t entries that also live in that list, so a naive second pass
# resubmits them -- a SecRule that counts RESPONSE_HEADERS:Server hits would
# see it twice.
#
# The oracle counts submissions with tx.hits=+1 on every match of
# RESPONSE_HEADERS:Server / :Date / :Last-Modified and denies only when a
# header was seen MORE than once. A passing 200 proves single submission; a
# regression to double submission would flip this to 403.
#
# That oracle only works if the underlying selector actually counts repeat
# submissions of the same header name rather than collapsing/overwriting them
# -- nothing else in t/ establishes that append semantics for
# RESPONSE_HEADERS:Name. /control below is a positive control that proves the
# counting mechanism itself: it hits a location whose backend sends the SAME
# custom header name (X-Dup) TWICE as genuinely separate header lines on the
# wire, and which nginx does NOT hoist into any dedicated headers_out slot --
# so both wire copies reach the header list, and are expected (correctly, not
# a bug) to be forwarded to Coraza individually. If the collection selector
# cannot distinguish "matched twice" from "matched once", tx.hits for X-Dup
# stays 1 and /control comes back 200 instead of 403, and that result must be
# read as "the counting oracle above is vacuous, use a different oracle" --
# not patched around.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location /proxied {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule RESPONSE_HEADERS:Server "@rx ." "id:401,phase:3,pass,log,setvar:tx.hits=+1"
                SecRule RESPONSE_HEADERS:Date "@rx ." "id:402,phase:3,pass,log,setvar:tx.hits=+1"
                SecRule RESPONSE_HEADERS:Last-Modified "@rx ." "id:403,phase:3,pass,log,setvar:tx.hits=+1"
                SecRule TX:HITS "@gt 3" "id:499,phase:3,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Positive control: proves the counting mechanism itself can see a
        # header name matched more than once. X-Dup is sent twice on the wire
        # by the backend below and is not one of nginx's dedicated
        # headers_out slots, so both copies legitimately reach the header
        # list and both must legitimately reach Coraza -- expecting a deny
        # here at count > 1 is the correct, intended behavior, not the bug
        # under test in /proxied.
        location /control {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule RESPONSE_HEADERS:X-Dup "@rx ." "id:411,phase:3,pass,log,setvar:tx.dup_hits=+1"
                SecRule TX:DUP_HITS "@gt 1" "id:498,phase:3,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

like(http_get('/proxied'), qr/^HTTP\S+ 200/,
    'proxied Server/Date/Last-Modified each counted at most once (tx.hits <= 3)');

my $log = $t->read_file('error.log');
unlike($log, qr/id "499"/,
    'the double-submission guard rule (id:499) never fired');

like(http_get('/control'), qr/^HTTP\S+ 403/,
    'control: a genuinely-duplicated wire header (X-Dup) is counted twice, '
    . 'proving the tx.hits mechanism can detect a real double submission');

###############################################################################

sub http_daemon {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => '127.0.0.1:' . port(8081),
        Listen => 5,
        Reuse => 1
    ) or die "Can't create listening socket: $!\n";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $headers = '';
        while (<$client>) {
            $headers .= $_;
            last if (/^\x0d?\x0a?$/);
        }

        my ($uri) = $headers =~ /^\S+\s+(\S+)/;
        $uri //= '';

        if ($uri eq '/control') {
            print $client "HTTP/1.1 200 OK\r\n"
                . "X-Dup: a\r\n"
                . "X-Dup: b\r\n"
                . "Content-Length: 2\r\n"
                . "Connection: close\r\n\r\n"
                . "ok";
        } else {
            print $client "HTTP/1.1 200 OK\r\n"
                . "Server: upstream-origin/1.0\r\n"
                . "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
                . "Last-Modified: Mon, 01 Jan 2029 00:00:00 GMT\r\n"
                . "Content-Length: 2\r\n"
                . "Connection: close\r\n\r\n"
                . "ok";
        }

        close $client;
    }
}
