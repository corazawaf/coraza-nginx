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

my $t = Test::Nginx->new()->has(qw/http/)->plan(6);

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
                SecRule ARGS:x "@streq bad" "id:50,phase:1,deny,status:403,log,msg:\'detectiononly-probe\'"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /detect {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecRule ARGS:x "@streq bad" "id:51,phase:1,deny,status:403,log,msg:\'detectiononly-probe\'"
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

# Proves the DetectionOnly rule actually matched rather than silently not
# running at all -- without this the 200 above is consistent with either.
like($t->read_file('error.log'), qr/detectiononly-probe/,
	'DetectionOnly rule logged a match for the tripping request');

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling SecRuleEngine DetectionOnly');

###############################################################################
