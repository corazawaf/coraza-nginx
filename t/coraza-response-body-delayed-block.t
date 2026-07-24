#!/usr/bin/perl

# Tests for Coraza-nginx connector: a phase-4 RESPONSE_BODY intervention that
# fires WHILE the response headers are being delayed.
#
# With coraza_delay_response_headers on and SecResponseBodyAccess On, the body
# filter buffers the response and inspects it before the headers are sent.  When
# a RESPONSE_BODY rule matches, the intervention must be applied on the
# still-delayed headers path (ctx->headers_delayed branch in the body filter),
# turning the buffered 200 into the rule's status.  A control location without
# a matching body confirms the same delayed 200 is released untouched.

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
        default_type text/plain;

        # Blocked: RESPONSE_BODY rule matches while headers are delayed.
        location /block.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:300,phase:4,deny,log,status:403"
            ';
        }

        # Control: identical config, but the body does not contain the trigger,
        # so the delayed 200 is released intact.
        location /pass.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:301,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

my $clean = "harmless body, nothing matches\n";
$t->write_file("/block.txt", "leading text ... BLOCK ME ... trailing text\n");
$t->write_file("/pass.txt", $clean);

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

like(http_get('/block.txt'), qr/^HTTP.*403/,
    'RESPONSE_BODY match while headers delayed -> blocked with rule status');

my $r = http_get('/pass.txt');
like($r, qr/^HTTP.*200/, 'non-matching delayed body -> released as 200');
like($r, qr/\Q$clean\E/, 'non-matching delayed body delivered intact');
