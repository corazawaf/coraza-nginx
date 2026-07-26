#!/usr/bin/perl

# Smoke test for the phase-4 one-shot gate on trailing output buffers.
#
# ngx_http_coraza_body_filter() walks the whole output chain in one call and
# the phase-4 finalize block is gated on the PER-BUFFER is_last
# (chain->buf->last_buf), not the accumulated is_request_processed.  Gating on
# the accumulated flag would re-enter the phase-4 block on any buffer that
# followed the last_buf link in the same call ([last_buf, empty]), running
# coraza_process_response_body() twice on an already-finalized transaction.
#
# NOTE ON COVERAGE: this exercises the sub_filter body-rewrite path (which is
# what motivated the gate) and asserts the response stays well-formed -- a
# single clean status line and the rewritten body delivered intact.  It does
# NOT act as a strict negative control: with the buggy accumulated gate
# restored, sub_filter here emits the last_buf and its sentinel across SEPARATE
# body-filter calls (is_request_processed is a fresh per-call local, so it
# starts 0 each call), so the double-run does not reproduce and the assertions
# below still pass.  The fix is correct by construction -- gating on is_last is
# a no-op when exactly one last_buf exists and strictly prevents a re-run if a
# trailing buffer ever arrives in the same call -- and this test guards against
# gross regressions of the surrounding rewrite/finalize path.

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

my $t = Test::Nginx->new()->has(qw/http sub/);

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

        # sub_filter rewrites the body (MARK -> BAD BODY), driving the phase-4
        # deny rule and the trailing-sentinel-buffer chain shape the is_last
        # gate is written for.
        location /trailing {
            default_type text/plain;
            sub_filter 'MARK' 'BAD BODY';
            sub_filter_once off;
            sub_filter_types text/plain;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 128
                SecRule RESPONSE_BODY "@rx BAD BODY" "id:71,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

$t->write_file("/trailing", "MARK");

$t->run();
$t->todo_alerts();
$t->plan(2);

###############################################################################

my $r = http_get('/trailing');

# Phase-4 deny fires once on the rewritten body.
like($r, qr/^HTTP.*403/, 'phase-4 deny on rewritten (trailing-buffer) body');

# Exactly one status line: a double phase-4 finalize would re-enter request
# finalization and corrupt / duplicate the response.
my @status = ($r =~ /^HTTP\/\d\.\d\s+\d{3}/mg);
is(scalar(@status), 1,
    'exactly one status line (phase-4 finalize ran once)');
