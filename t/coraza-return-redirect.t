#!/usr/bin/perl

# Tests for Coraza-nginx connector (nginx `return` in a location).
#
# Regression test for upstream issue #46: with `coraza on`, a plain nginx
# `return 301 ...` / `return 404` in a location closed the connection without
# sending the status line or body (the header filter finalized the request and
# discarded the response). The fix routes header-only / redirect responses
# through the normal filter chain.
# See src/ngx_http_coraza_header_filter.c (r->header_only / location handling).

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(4);

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
        coraza_rules '
            SecRuleEngine On
        ';

        # nginx return-redirect with the WAF active: must reach the client
        # with the status + Location, not a closed/empty response.
        location = /redir {
            return 301 /wiki/Main_Page;
        }

        # nginx return with a status only.
        location = /notfound {
            return 404;
        }

        # nginx return with an inline body.
        location = /gone {
            return 410 "gone body\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();

###############################################################################

my $r = http_get('/redir');
like($r, qr/^HTTP\S+ 301/, 'return 301 reaches client with coraza on');
# nginx (absolute_redirect on, the default) rewrites the relative target to an
# absolute URL, e.g. "http://localhost:8080/wiki/Main_Page"; accept either form
# so the test asserts the path survives the WAF, not nginx's URL normalization.
like($r, qr!Location: \S*/wiki/Main_Page!, 'Location header preserved on return 301');

like(http_get('/notfound'), qr/^HTTP\S+ 404/, 'return 404 reaches client with coraza on');

like(http_get('/gone'), qr/gone body/, 'return with inline body reaches client');
