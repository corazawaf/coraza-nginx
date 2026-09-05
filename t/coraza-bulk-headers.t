#!/usr/bin/perl

# Tests for the Coraza-nginx bulk-header submission path (libcoraza >= 1.7).
#
# The connector packs every request / response header into a single buffer and
# hands the whole set to Coraza in one cgo crossing via
# coraza_add_request_headers() / coraza_add_response_headers(), instead of one
# crossing per header.  libcoraza >= 1.7 is a hard floor and both bulk symbols
# are mandatory, so there is no capability fallback left.  Three runtime
# conditions still select the per-header path: the collector allocation
# failing (ngx_array_create in the header filter, ngx_palloc of the pair array
# in rewrite.c), the pack failing on an over-range header length, and the
# submit returning CORAZA_ERROR.
#
# Correctness requirement: whichever path is taken, EVERY header must still be
# inspected exactly once.  These tests drive a request carrying many request
# headers and a response carrying a synthesized header, with rules that match
# on both a request header and a response header, and assert the rules fire.
# See the bulk path in ngx_http_coraza_{rewrite,header_filter}.c and the
# packer in ngx_http_coraza_utils.c.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(6);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    large_client_header_buffers 8 32k;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        # Request-header inspection across many headers (exercises the packed
        # bulk request-header path; the match must land on a header that is not
        # first or last in the set).
        location /req {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe "@streq blockme" "id:100,phase:1,deny,status:403,log,t:none"
            ';
            return 200 "ok";
        }

        # Response-header inspection (exercises the packed bulk response-header
        # path). add_header injects a header into headers_out that the bulk
        # collector must forward for phase-3 evaluation.
        location /resp {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Secret "@streq leak" "id:200,phase:3,deny,status:403,log,t:none"
            ';
            add_header X-Secret "leak";
            return 200 "ok";
        }

        # Benign control: same ruleset, non-matching values must pass so the
        # rules above are proven to be doing real work (negative control).
        location /benign {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe "@streq blockme" "id:100,phase:1,deny,status:403,log,t:none"
                SecRule RESPONSE_HEADERS:X-Secret "@streq leak" "id:200,phase:3,deny,status:403,log,t:none"
            ';
            add_header X-Secret "safe";
            return 200 "ok";
        }
    }
}
EOF

$t->run();

###############################################################################

# Many request headers surrounding the one that matters, so a bug that drops
# or misorders headers in the packed buffer would miss the match.
my $many = join('', map { "X-Fill-$_: filler-value-$_\n" } (1 .. 30));

my $req_block = http(<<EOF);
GET /req HTTP/1.0
Host: localhost
${many}X-Probe: blockme
X-Trailer: last

EOF
like($req_block, qr!^HTTP/\S+ 403!,
    'bulk request headers: match on a middle header blocks');

my $req_pass = http(<<EOF);
GET /req HTTP/1.0
Host: localhost
${many}X-Probe: allowme
X-Trailer: last

EOF
like($req_pass, qr!^HTTP/\S+ 200!,
    'bulk request headers: non-matching value passes (control)');

my $resp_block = http_get('/resp');
like($resp_block, qr!^HTTP/\S+ 403!,
    'bulk response headers: match on synthesized header blocks');

my $benign = http(<<EOF);
GET /benign HTTP/1.0
Host: localhost
X-Probe: allowme

EOF
like($benign, qr!^HTTP/\S+ 200!,
    'bulk path: benign request+response passes both rules');

my $log = $t->read_file('error.log');

# Rule out the one path-selection cause a black-box test can rule out: the
# bulk entry points being absent.  They are mandatory symbols, so a successful
# load proves they resolved.
#
# This is a proxy, not a path trace.  It does not prove the collector
# allocation succeeded, and under memory pressure the connector would take the
# per-header path and still satisfy every assertion above.  That is by design:
# the point of the assertions is that both paths inspect every header exactly
# once, so either one passing is the correct outcome.  Distinguishing them
# would need a pool-allocation failure injection hook, which does not exist,
# or a log line emitted purely for the test.
if ($log =~ /coraza: \S+ loaded via dynlib_open \(libcoraza (\d+)\.(\d+)\.\d+\)/) {
    ok($1 > 1 || ($1 == 1 && $2 >= 7),
        "libcoraza $1.$2 loaded (>= 1.7): bulk-header symbols resolved");
} else {
    fail('connector did not log the libcoraza version at load');
}

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
