#!/usr/bin/perl

# Tests for Coraza-nginx connector: a transaction the WAF interrupts in phase 2
# must still produce an audit record when the denial status is routed through an
# error_page.
#
# nginx wipes r->ctx on every internal redirect (ngx_http_internal_redirect(),
# ngx_http_named_location()), so the LOG-phase handler finds no Coraza context
# for the request that was actually blocked -- and if the error location is
# `coraza off`, mcf->enable is 0 there too.  Either way the handler bails and
# ProcessLogging is never called, silently dropping the audit record for the
# request that was blocked.  Phases 2..4 are affected; the request-headers poll
# passes early_log=1 and is not.
#
# ngx_http_coraza_cleanup() (registered on r->pool, which nginx destroys after
# ngx_http_log_request()) runs ProcessLogging as a fallback when ctx->logged is
# still unset, and the LOG handler sets ctx->logged so the record is never
# written twice.
#
# Note: the blocked locations serve a static file rather than `return 200`.
# ngx_http_rewrite_module handles `return` in the REWRITE phase and finalizes
# the request there, so PREACCESS -- where the connector runs Coraza phase 2 --
# would never be reached.

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

my $t = Test::Nginx->new()->has(qw/http/);

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
        default_type text/plain;
        root         %%TESTDIR%%;

        coraza on;
        coraza_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecAuditEngine On
            SecAuditLogParts ABZ
            SecAuditLogType Serial
            SecAuditLog %%TESTDIR%%/audit.txt
            SecRule ARGS:x "@streq boom" "id:900,phase:2,deny,log,auditlog,status:403"
        ';

        # Denied in phase 2, then sent through an internal redirect, which
        # clears r->ctx before the LOG phase runs.
        location = /page-ep.html {
            error_page 403 /denied.html;
        }

        # Same rule, no error_page: the LOG-phase handler still finds the ctx.
        # Guards the fallback against logging that transaction a second time.
        location = /page-plain.html {
        }

        # The error-page target has the WAF off, so no second transaction is
        # created for the internal request.
        location = /denied.html {
            coraza off;
            return 403 "denied\n";
        }
    }
}
EOF

$t->write_file('page-ep.html', 'should not reach');
$t->write_file('page-plain.html', 'should not reach');

$t->run();
$t->todo_alerts();
$t->plan(6);

###############################################################################

my $d = $t->testdir();

# Blocked in phase 2; the response body comes from the error_page.
my $r = http_get('/page-ep.html?x=boom');
like($r, qr/^HTTP\S+ 403/, 'phase-2 denial routed through error_page keeps 403');
like($r, qr/denied/, 'error_page body served');

# The same rule without an error_page: the ordinary LOG-phase path.
like(http_get('/page-plain.html?x=boom'), qr/^HTTP\S+ 403/,
    'phase-2 denial without error_page');

# Control: a request matching nothing is served normally.
like(http_get('/page-plain.html?x=safe'), qr/^HTTP\S+ 200/,
    'clean request is served');

my $audit = do {
    local $/ = undef;
    open my $fh, '<', "$d/audit.txt" or die "could not open audit log: $!";
    <$fh>;
};

# Without the pool-cleanup fallback the first count is 0: the record for the
# blocked request is lost.  The second count guards against the fallback
# duplicating a transaction the LOG handler already logged.
my @counts = (
    scalar(() = $audit =~ m!/page-ep\.html\?x=boom!g),
    scalar(() = $audit =~ m!/page-plain\.html\?x=boom!g),
);
is_deeply(\@counts, [1, 1],
    'exactly one audit record per denial, with and without error_page');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
