#!/usr/bin/perl

# Tests for Coraza-nginx connector: when a Coraza denial is routed through an
# error_page into another coraza-on location, nginx re-runs the rewrite and
# pre-access phases for the internal error-page request.  On that second pass
# the connector must NOT re-inspect: the rewrite handler returns NGX_DECLINED
# because r->error_page is set (rewrite.c), and the pre-access handler returns
# NGX_DECLINED because ctx->intervention_triggered is already set
# (pre_access.c).  Re-inspection would either double-process the transaction or
# loop.
#
# The observable contract: the client receives the error_page's body served
# under the denial status, and the worker stays healthy.

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

        # A phase-1 denial whose 403 is routed into the coraza-on /denied
        # handler, forcing an internal error-page re-entry through the
        # rewrite + pre-access phases.
        location /trigger {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule ARGS:x "@streq boom" "id:500,phase:1,deny,log,status:403"
            ';
            error_page 403 = /denied;
            return 200 "should not reach";
        }

        # The error-page target is also coraza-on, so the internal request
        # re-runs the connector phases with r->error_page / intervention set.
        location /denied {
            coraza_rules '
                SecRuleEngine On
            ';
            return 403 "denied by coraza\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

# The denial is routed through the coraza-on error page; the re-entry paths
# return NGX_DECLINED instead of re-inspecting, and the handler body is served.
my $r = http_get('/trigger?x=boom');
like($r, qr/^HTTP\S+ 403/, 'coraza denial served through the error_page handler');
like($r, qr/denied by coraza/, 'error_page handler body delivered on re-entry');

# Control: a clean request is not denied and never triggers the error page.
like(http_get('/trigger?x=safe'), qr/^HTTP\S+ 200/,
    'clean request passes without error-page re-entry (control)');
