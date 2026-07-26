#!/usr/bin/perl

# Tests for Coraza-nginx connector (SecResponseBodyAccess Off fast path).
#
# Regression test for the fix that stops routing response bodies through the
# Go FFI when body inspection is disabled (prevents the large-response hang):
#   * With SecResponseBodyAccess Off a RESPONSE_BODY rule can NOT match, because
#     the body is never appended to the transaction, and the body is served
#     intact.
#   * Phase-4 evaluation still runs on the last buffer, so a phase-4 rule on a
#     non-body variable (ARGS, TX, ...) still fires even with access Off.
#   * Control: with SecResponseBodyAccess On the RESPONSE_BODY rule matches.
# See src/ngx_http_coraza_body_filter.c (ctx->response_body_processable).

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(5);

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

        # SecResponseBodyMimeType text/plain whitelists this response for body
        # inspection, so SecResponseBodyAccess Off is the ONLY reason the body is
        # not inspected (without it Coraza skips text/plain regardless and the
        # test would pass vacuously).
        # SecResponseBodyAccess Off: body inspection disabled. The FFI append
        # is skipped, so RESPONSE_BODY rules can never match and the body is
        # forwarded untouched.
        location /off {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyMimeType text/plain
                SecResponseBodyAccess Off
                SecRule RESPONSE_BODY "@rx SECRET" "id:421,phase:4,deny,log,status:403"
            ';
        }

        # Phase 4 still runs on non-body variables even when access is Off.
        location /off-args {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq boom" "id:422,phase:4,deny,log,status:403"
            ';
        }

        # Upstream issue #41: a large (>60KB) response with access Off used to
        # hang/timeout because the body was still routed through the Go FFI.
        # With the fast path it must serve promptly and intact.
        location /big {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyMimeType text/plain
                SecResponseBodyAccess Off
            ';
        }

        # Control: with access On the same RESPONSE_BODY rule matches.
        location /on {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyMimeType text/plain
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx SECRET" "id:423,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

$t->write_file("/off", "top SECRET body");
$t->write_file("/off-args", "harmless body");
$t->write_file("/on", "top SECRET body");
# >60KB body to reproduce the issue #41 large-response hang.
$t->write_file("/big", "A" x (128 * 1024));

$t->run();
$t->todo_alerts();

###############################################################################

like(http_get('/off'), qr/^HTTP\S+ 200/,
	'RESPONSE_BODY not inspected when SecResponseBodyAccess Off');
like(http_get('/off'), qr/SECRET/,
	'body forwarded intact when body inspection disabled');

like(http_get('/off-args?q=boom'), qr/^HTTP\S+ 403/,
	'phase-4 ARGS rule still fires with SecResponseBodyAccess Off');

like(http_get('/on'), qr/^HTTP\S+ 403/,
	'control: RESPONSE_BODY inspected when SecResponseBodyAccess On');

# issue #41: large body with access Off must not hang. http_get has the
# harness timeout; a hang shows up as a failed/empty match here.
my $big = http_get('/big');
like($big, qr/^HTTP\S+ 200.*AAAA/s,
	'large (>60KB) response served promptly with SecResponseBodyAccess Off');
