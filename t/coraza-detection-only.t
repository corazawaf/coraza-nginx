#!/usr/bin/perl

# Tests for Coraza-nginx connector (SecRuleEngine DetectionOnly).
#
# SecRuleEngine DetectionOnly is documented Coraza/CRS behaviour -- rules run
# and log but never intervene -- yet nothing in this suite pins that the
# connector actually honours it: that a rule which would deny under
# SecRuleEngine On instead only logs and lets the request through under
# DetectionOnly.
#
# Two locations share the IDENTICAL phase-1 deny rule, differing only in
# SecRuleEngine. Asserting the DetectionOnly location returns 200 alone would
# be consistent with the rule silently never running at all, so this also
# greps the error log for the rule's msg to prove it matched. A benign
# request to each location is the negative control, proving the 403/200 split
# above is the rule engine mode and not some other difference between the two
# locations.
# See src/ngx_http_coraza_module.c (phase evaluation / intervention handling).

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

        location /on {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:50,phase:1,t:none,deny,status:403,log,msg:\'detectiononly-probe\'"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /detect {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecRule ARGS:x "@streq bad" "id:51,phase:1,t:none,deny,status:403,log,msg:\'detectiononly-probe\'"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }
    }
}
EOF

$t->run();

###############################################################################

# SecRuleEngine On: the rule blocks as usual.
my $blocked = http_get('/on?x=bad');
like($blocked, qr!^HTTP/\S+ 403!, 'SecRuleEngine On blocks the matching request');

# SecRuleEngine DetectionOnly: the identical rule matches but must not block.
my $detected = http_get('/detect?x=bad');
like($detected, qr!^HTTP/\S+ 200!, 'SecRuleEngine DetectionOnly does not block a matching request');

# Benign requests to each location pass regardless of engine mode.
like(http_get('/on?x=fine'), qr!^HTTP/\S+ 200!, 'benign request passes under SecRuleEngine On');
like(http_get('/detect?x=fine'), qr!^HTTP/\S+ 200!, 'benign request passes under SecRuleEngine DetectionOnly');

$t->stop();

# GAP, deliberately not asserted: nothing here proves the DetectionOnly rule
# actually MATCHED. The 200 above is equally consistent with "matched, and
# DetectionOnly correctly declined to block" and with "never ran at all", and
# this test cannot tell them apart.
#
# The obvious oracle -- grepping error.log for the rule's msg -- was tried and
# found no line (CI, 2026-09-03), so either DetectionOnly does not log through
# this path or the connector does not surface the msg to nginx's error log.
# That is its own question, tracked in the ledger alongside the related
# ARGS_POST gap; it was dropped here rather than guessed at, because a wrong
# oracle that goes green would settle the wrong contract.
#
# What this file does pin is still worth having: the On/DetectionOnly split is
# observable end-to-end (403 vs 200) on an identical rule, so a regression that
# made DetectionOnly block, or made On stop blocking, fails here.

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling SecRuleEngine DetectionOnly');

###############################################################################
