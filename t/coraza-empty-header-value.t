#!/usr/bin/perl

# Tests for Coraza-nginx connector (empty / zero-length value handling).
#
# Covers the empty-value boundary on the request path: a present-but-empty
# header value, and an empty query string.  Both must be inspected normally
# and neither may wedge or crash the worker.
#
# Scope note, so the next reader does not overestimate these tests: header
# values do NOT flow through ngx_str_to_char().  ngx_http_coraza_rewrite.c
# passes header key/value to coraza_add_request_header() as explicit
# (ptr, len) pairs, so these assertions pass both before and after the
# ngx_str_to_char zero-length fix -- they pin the engine-visible behaviour,
# they are not a regression guard for that fix.
#
# ngx_str_to_char()'s zero-length path (which used to yield *str = NULL) is
# reached only by the connection address, URI, method and request-body temp
# file path -- see the call sites in src/ngx_http_coraza_rewrite.c and
# src/ngx_http_coraza_pre_access.c.  None of those can be empty on a request
# nginx has already accepted and routed, which is why this file asserts the
# empty-value contract behaviourally rather than claiming to regress the fix.

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

        # An empty header VALUE must still be inspected.  "@rx ^$" matches only
        # if the engine received an empty string; a NULL would drop the header
        # from the transaction entirely and the rule could never fire.
        location /empty-header {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe "@rx ^$" "id:7001,phase:1,deny,log,status:403"
            ';
            return 200 "TEST-OK\n";
        }

        # Control for /empty-header: the same rule must NOT fire when the
        # header carries a value, proving the 403 above is driven by the empty
        # value and not by the header merely being present.
        location /nonempty-header {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe "@rx ^$" "id:7002,phase:1,deny,log,status:403"
            ';
            return 200 "TEST-OK\n";
        }

        # An empty query string ("/q?") must not crash the connector or wedge
        # the worker: the URI still has to be processed and the request served.
        location /q {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq boom" "id:7003,phase:1,deny,log,status:403"
            ';
            return 200 "TEST-OK\n";
        }
    }
}

EOF

$t->run();

###############################################################################

# Present-but-empty header value: the engine must see "" and the rule fires.
my $empty = http(<<EOF);
GET /empty-header HTTP/1.0
Host: localhost
X-Probe:

EOF
like($empty, qr!^HTTP/1.1 403!, 'empty header value is inspected (matches "^\$")');

# Negative control: same rule, non-empty value, must not match.
my $filled = http(<<EOF);
GET /nonempty-header HTTP/1.0
Host: localhost
X-Probe: something

EOF
like($filled, qr!^HTTP/1.1 200!, 'non-empty header value does not match "^\$"');
like($filled, qr/TEST-OK/, 'non-empty header request served normally');

# Empty query string: served, worker survives.
like(http_get('/q?'), qr!^HTTP/1.1 200!, 'empty query string served');

# The worker is still healthy afterwards -- a NULL deref would have killed it
# and this follow-up request would fail rather than 403.  Note ARGS holds
# parameter VALUES, so the payload must be "x=boom": a bare "?boom" is a key
# with an empty value and @streq boom would not match it.
like(http_get('/q?x=boom'), qr!^HTTP/1.1 403!,
	'rule still enforced after empty-value requests (worker healthy)');

$t->stop();

unlike($t->read_file('error.log'), qr/\[emerg\]|signal 11|SIGSEGV/,
	'no crash from empty-string conversions');

###############################################################################
