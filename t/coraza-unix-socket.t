#!/usr/bin/perl

# Tests for Coraza-nginx connector (unix domain socket connection info).
#
# Regression test for the fix that passes a conventional "unix" address to the
# WAF for AF_UNIX connections instead of a socket file path / bogus value.
# Previously ngx_str_to_char was called on a unix sockaddr, so REMOTE_ADDR /
# SERVER_ADDR seen by the engine were unusable and rules could not match.
# See src/ngx_http_coraza_rewrite.c (sa_family == AF_UNIX -> "unix").

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::UNIX;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http unix/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       unix:%%TESTDIR%%/unix.sock;
        server_name  localhost;

        coraza on;

        # Deny when the connection's client address is reported as the
        # conventional "unix" string.  This only fires if the connector mapped
        # the AF_UNIX sockaddr to "unix" rather than a socket path / garbage.
        location / {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule REMOTE_ADDR "@streq unix" "id:41,phase:1,deny,log,status:403"
            ';
            return 200 "ok\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(1);

###############################################################################

my $path = $t->testdir() . '/unix.sock';

my $s = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => $path,
) or die "Can't connect to unix socket $path: $!\n";

$s->autoflush(1);
print $s "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";

my $reply = '';
while (<$s>) { $reply .= $_; }
close $s;

like($reply, qr/^HTTP\S+ 403/, 'AF_UNIX connection reported as REMOTE_ADDR "unix"');
