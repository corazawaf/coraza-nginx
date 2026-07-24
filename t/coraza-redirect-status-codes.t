#!/usr/bin/perl

# Tests for Coraza-nginx connector (redirect: interventions with non-302
# status codes 303/307/308).
#
# The intervention redirect block in src/ngx_http_coraza_module.c only emits a
# Location header for a recognised redirect status. Existing tests exercise
# status:302 only; this exercises the later `||` terms (303 SEE_OTHER,
# 307 TEMPORARY_REDIRECT) so those comparisons execute at runtime.
#
# NOTE: status:308 is deliberately not tested. libcoraza 1.4 normalises a
# redirect intervention with status 308 down to 302 before the connector sees
# it (verified: the wire response is "302 Moved Temporarily"), so the
# `intervention->status == 308` term is not reachable through this harness.

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

        coraza on;

        location /r303 {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq go" "id:303,phase:1,status:303,redirect:http://example.org/p,log"
            ';
            return 200 "clean\n";
        }

        location /r307 {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq go" "id:307,phase:1,status:307,redirect:http://example.org/p,log"
            ';
            return 200 "clean\n";
        }

    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(5);

###############################################################################

my $r303 = http_get('/r303?x=go');
like($r303, qr!^HTTP\S+ 303!, 'redirect status 303 emitted');
like($r303, qr!Location: http://example.org/p!, 'Location present for 303');

my $r307 = http_get('/r307?x=go');
like($r307, qr!^HTTP\S+ 307!, 'redirect status 307 emitted');
like($r307, qr!Location: http://example.org/p!, 'Location present for 307');

# Positive control: a clean request must NOT redirect.
like(http_get('/r303?x=safe'), qr!^HTTP\S+ 200!, 'clean request not redirected');
