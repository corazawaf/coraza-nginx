#!/usr/bin/perl

# Negative-control tests for the intervention-poll reduction.
#
# Two optimizations are guarded here (see ngx_http_coraza_common.h
# ngx_http_coraza_poll_after_process() and the removed polls in
# ngx_http_coraza_rewrite.c):
#
#  (A) The coraza_intervention() polls that used to run right after
#      coraza_process_connection() and coraza_process_uri() were removed: those
#      calls only populate connection/URI variables and run no rule phase, so the
#      poll was provably always NULL. A phase-1 rule matching REMOTE_ADDR or
#      REQUEST_URI does NOT fire there — it fires at ProcessRequestHeaders. If the
#      removal were wrong (a rule COULD interrupt at connection/URI), these denies
#      would stop blocking. They must still return 403.
#
#  (B) The post-phase polls (request-headers, request-body, response-headers,
#      response-body) now skip the CGO intervention fetch when the running
#      libcoraza is 1.6+ AND the process fn returned != CORAZA_INTERRUPTION. On an
#      older library the return value is not a reliable interruption signal, so
#      the connector falls back to an unconditional poll (fail-closed). Whichever
#      path runs, a deny in each phase must still return 403.
#
# Every deny below is paired with a benign control that must pass, so a rule that
# silently stopped matching cannot masquerade as a working negative control
# (feedback-negative-control-or-it-isnt-a-test).

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(14);

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

        # (A) phase-1 REMOTE_ADDR deny. The client is 127.0.0.1; the rule denies
        # it. Populated by coraza_process_connection but only evaluated at
        # ProcessRequestHeaders, so removing the connection-phase poll must not
        # regress this.
        location /addr {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "id:100,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }

        # (A) phase-1 REQUEST_URI deny. Populated by coraza_process_uri, evaluated
        # at ProcessRequestHeaders. Removing the URI-phase poll must not regress.
        location /uri {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains blockme" "id:101,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }

        # (A) controls: same rules, non-matching subject must pass.
        location /addr-ok {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:100,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }
        location /uri-ok {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains blockme" "id:101,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }

        # (B) phase-1 request-header deny (poll gated on process_request_headers).
        location /reqhdr {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe "@streq blockme" "id:200,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }

        # (B) phase-2 request-body deny (poll gated on process_request_body).
        # ctl:requestBodyProcessor forces REQUEST_BODY population, and the handler
        # must actually READ the body — a return-only location makes nginx skip
        # the body preread, leaving REQUEST_BODY empty. proxy_pass to the backend
        # forces the read (mirrors t/coraza-request-body.t). The deny fires in
        # pre_access (phase 2) before the proxy runs; the control reaches the
        # backend.
        location /reqbody {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:210,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@contains blockme" "id:201,phase:2,deny,status:403,log"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # (B) phase-3 response-header deny (poll gated on
        # process_response_headers).
        location /resphdr {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Secret "@streq leak" "id:202,phase:3,deny,status:403,log"
            ';
            add_header X-Secret "leak";
            return 200 "ok";
        }

        # (B) phase-4 response-body deny (poll gated on process_response_body).
        location /respbody {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule RESPONSE_BODY "@contains leakme" "id:203,phase:4,deny,status:403,log"
            ';
            default_type text/plain;
            return 200 "leakme now";
        }

        # (B) one benign control per phase, same ruleset, non-matching subject.
        location /reqhdr-ok {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe "@streq blockme" "id:200,phase:1,deny,status:403,log"
            ';
            return 200 "ok";
        }
        location /respbody-ok {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecRule RESPONSE_BODY "@contains leakme" "id:203,phase:4,deny,status:403,log"
            ';
            default_type text/plain;
            return 200 "all safe";
        }
        location /resphdr-ok {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Secret "@streq leak" "id:202,phase:3,deny,status:403,log"
            ';
            add_header X-Secret "safe";
            return 200 "ok";
        }
    }

    # Backend for /reqbody: a location whose only job is to read the proxied
    # request body and answer 200, so the phase-2 body rule has a real body to
    # inspect (a return-only frontend location skips the body preread).
    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  localhost;
        location / {
            return 200 "backend ok";
        }
    }
}
EOF

$t->run();

###############################################################################

# (A) phase-1 REMOTE_ADDR / REQUEST_URI denies still block after the
# connection/uri poll removal.
like(http_get('/addr'), qr!^HTTP/\S+ 403!,
    'A: phase-1 REMOTE_ADDR deny still blocks');
like(http_get('/addr-ok'), qr!^HTTP/\S+ 200!,
    'A: REMOTE_ADDR control (non-matching ip) passes');

like(http_get('/uri?blockme'), qr!^HTTP/\S+ 403!,
    'A: phase-1 REQUEST_URI deny still blocks');
like(http_get('/uri-ok?allow'), qr!^HTTP/\S+ 200!,
    'A: REQUEST_URI control (non-matching uri) passes');

# (B) each phase deny still blocks with the gate active.
my $reqhdr = http(<<'EOF');
GET /reqhdr HTTP/1.0
Host: localhost
X-Probe: blockme

EOF
like($reqhdr, qr!^HTTP/\S+ 403!,
    'B: request-header deny still blocks (gated poll)');

my $reqhdr_ok = http(<<'EOF');
GET /reqhdr-ok HTTP/1.0
Host: localhost
X-Probe: allowme

EOF
like($reqhdr_ok, qr!^HTTP/\S+ 200!,
    'B: request-header control passes');

my $reqbody = http(<<'EOF');
POST /reqbody HTTP/1.0
Host: localhost
Content-Length: 7

blockme
EOF
like($reqbody, qr!^HTTP/\S+ 403!,
    'B: request-body deny still blocks (gated poll)');

my $reqbody_ok = http(<<'EOF');
POST /reqbody HTTP/1.0
Host: localhost
Content-Length: 6

benign
EOF
like($reqbody_ok, qr!^HTTP/\S+ 200!,
    'B: request-body control passes');

like(http_get('/resphdr'), qr!^HTTP/\S+ 403!,
    'B: response-header deny still blocks (gated poll)');
like(http_get('/resphdr-ok'), qr!^HTTP/\S+ 200!,
    'B: response-header control passes');

like(http_get('/respbody'), qr!^HTTP/\S+ 403!,
    'B: response-body deny still blocks (gated poll)');
like(http_get('/respbody-ok'), qr!^HTTP/\S+ 200!,
    'B: response-body control passes');

# libcoraza >= 1.7 is required, so the OK-path poll gate is always active.
# Confirm the library loaded so a green result is interpretable.
my $log = $t->read_file('error.log');
if ($log =~ /coraza: \S+ loaded via dynlib_open \(libcoraza (\d+)\.(\d+)\.\d+\)/) {
    ok($1 > 1 || ($1 == 1 && $2 >= 7),
        "connector loaded libcoraza $1.$2 (>= 1.7; poll gate active on the "
        . 'required ABI)');
} else {
    fail('connector did not log the libcoraza version at load');
}

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
