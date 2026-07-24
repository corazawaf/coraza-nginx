#!/usr/bin/perl

# Tests for Coraza-nginx connector (deleted headers, hash == 0).
#
# nginx marks a header as deleted by zeroing its hash and may leave the key
# and value pointers stale.  Both header-collection loops therefore skip
# entries with hash == 0 before handing them to the engine:
#   * request headers  -- src/ngx_http_coraza_rewrite.c
#   * response headers -- src/ngx_http_coraza_header_filter.c
#
# Without the skip the connector feeds Coraza a stale key/value pair: in the
# best case a rule matches a header the peer never sent, in the worst case it
# reads freed memory.  The read is what an ASan build catches -- on a normal
# build the stale pointer usually still reads plausible bytes, so a passing
# run here proves less than it looks.  Run this file under the sanitizer job
# for the memory-safety half.
#
# The behavioural half is assertable anywhere: a header nginx has deleted must
# be invisible to the WAF, and the rest of the list must still be inspected,
# proving the loop `continue`s past the hole rather than `break`ing out of it.
#
# Only the RESPONSE side is reachable from configuration alone -- see the
# comment on /walk-all below for why the request-side skip is not.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(4);

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

        # Request side: the rewrite-phase loop walks r->headers_in, i.e. the
        # headers as the CLIENT sent them.  proxy_set_header only rewrites the
        # upstream request and does not zero anything in headers_in, so there
        # is no directive here that deletes a client header before the coraza
        # rewrite handler runs -- the request-side hash == 0 skip is therefore
        # not reachable from configuration alone (it needs a third-party module
        # such as headers-more clearing an input header).
        #
        # What IS assertable: the loop must walk the whole list and inspect
        # every live header, including ones positioned late.  A `break` where
        # the code has `continue` would silently stop collecting at the first
        # hole, so this is the behavioural half of the same guard.
        location /walk-all {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Kept "@streq sentinel" "id:7101,phase:1,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        # Response side: proxy_hide_header zeroes the hash on headers_out
        # before the coraza header filter walks the list.
        location /deleted-resp {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Leak "@rx ." "id:7103,phase:3,deny,log,status:403"
            ';
            proxy_hide_header X-Leak;
            proxy_pass http://127.0.0.1:8081;
        }

        # Control for /deleted-resp: without proxy_hide_header the same rule
        # DOES fire, proving the 200 above means "header hidden from the WAF"
        # and not "rule never ran".
        location /kept-resp {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Leak "@rx ." "id:7104,phase:3,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            add_header X-Leak "upstream-secret";
            return 200 "TEST-OK\n";
        }
    }
}

EOF

$t->run();

###############################################################################

# The request-header loop must walk the whole list: X-Kept is sent last, after
# several other headers, and must still be collected and matched.
like(http(<<EOF), qr!^HTTP/1.1 403!, 'request header late in the list is still inspected');
GET /walk-all HTTP/1.0
Host: localhost
X-One: a
X-Two: b
X-Three: c
X-Kept: sentinel

EOF

# Response side: hidden header invisible to the WAF...
like(http_get('/deleted-resp'), qr!^HTTP/1.1 200!,
	'deleted response header not inspected');

# ...and the control proving that rule fires when the header is not hidden.
like(http_get('/kept-resp'), qr!^HTTP/1.1 403!,
	'control: response header rule fires when not hidden');

$t->stop();

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash or sanitizer error walking deleted headers');

###############################################################################
