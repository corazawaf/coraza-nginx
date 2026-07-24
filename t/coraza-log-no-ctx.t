#!/usr/bin/perl

# Tests for Coraza-nginx connector: the log-phase handler must tolerate a request
# that reached the LOG phase without a Coraza context ever being created
# (ngx_http_coraza_log.c: the ctx == NULL guard).  This happens when nginx
# rejects a request before the rewrite phase (where the context is allocated),
# e.g. a client error such as a request whose URI/header is too large.  The
# handler must return without dereferencing a NULL context.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

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
        default_type text/plain;

        coraza on;
        coraza_rules '
            SecRuleEngine On
        ';

        # Small header buffers so an oversized request line is rejected with a
        # client error BEFORE the rewrite phase runs -> no Coraza context.
        large_client_header_buffers 2 512;

        location / {
            return 200 "ok";
        }
    }
}
EOF

$t->run();
$t->plan(2);

###############################################################################

# An oversized request line is rejected (414) before the rewrite phase, so the
# log handler runs with ctx == NULL.  A clean worker (no crash on the next
# request) proves the NULL-context path was handled gracefully.
my $big = '/' . ('a' x 2048);
like(http_get($big), qr/^HTTP\S+ 414/,
    'oversized request line rejected before rewrite (no Coraza context at log)');

# The worker survived the NULL-context log path and still serves normally.
like(http_get('/'), qr/^HTTP\S+ 200/,
    'worker healthy after logging a context-less request');
