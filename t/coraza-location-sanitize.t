#!/usr/bin/perl

# Tests for Coraza-nginx connector (Location sanitization, no-regression).
#
# ngx_http_coraza_process_intervention copies intervention->data into the
# Location header on a redirect, now truncating at the first control byte to
# defend against CR/LF response splitting should that data ever carry
# client-controlled bytes.  A clean redirect target contains no control bytes,
# so it must pass through byte-for-byte unchanged.
#
# NOTE: libcoraza 1.4 does not macro-expand the redirect: target (verified: a
# %{ARGS.x} target reaches Location literally), so client data cannot reach
# intervention->data through a normal rule today -- the sanitization is
# defense-in-depth for future/dynamic sources and cannot be positively
# exercised for the injection case through the rule engine.  This test pins the
# no-regression behaviour.
# See src/ngx_http_coraza_module.c (ngx_http_coraza_process_intervention).

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(2);

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
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq go" "id:30,phase:1,status:302,redirect:http://example.org/clean/path?a=b,log"
            ';
        }
    }
}
EOF

$t->run();

###############################################################################

my $r = http_get('/redir?x=go');

like($r, qr!^HTTP/\S+ 302!, 'clean redirect returns 302');
like($r, qr!Location: http://example\.org/clean/path\?a=b\r?\n!,
    'clean Location passes through unchanged (no truncation)');
