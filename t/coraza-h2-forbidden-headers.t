#!/usr/bin/perl

# Tests for Coraza-nginx connector (HTTP/2 hop-by-hop header hygiene).
#
# The connector synthesizes a Connection response header (and, when
# keepalive_timeout carries a header timeout, a Keep-Alive header) and feeds it
# to the WAF for inspection.  HTTP/2 (RFC 9113 §8.2.2) and HTTP/3 (RFC 9114
# §4.2) both forbid these connection-specific header fields, and nginx never
# emits them on an h2 stream or an h3 request, so they must NOT be synthesized
# for the WAF either -- otherwise a rule on RESPONSE_HEADERS:Connection
# false-positives on every HTTP/2 and HTTP/3 response.
#
# The guard is a version check (r->http_version >= NGX_HTTP_VERSION_20), which
# covers h2 and h3 alike -- r->stream is h2-only and NULL for h3.  This test
# exercises the h1-vs-h2 boundary; h3 shares the identical code path and is not
# separately scaffolded here (the harness has no QUIC/TLS setup).
#
# The same location is reachable over HTTP/1.1 (port 8080) and HTTP/2
# (port 8081).  A phase-3 deny rule keyed on the synthetic Connection header
# must fire over h1 (the header is present) but not over h2 (the header must be
# absent from the WAF's view).  Connection is always synthesized, so it
# exercises the version guard directly; the same early return also suppresses
# the Keep-Alive synthesis.
# See src/ngx_http_coraza_header_filter.c (resolv_header_connection version guard).

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2/)->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:8081 http2;
        server_name  localhost;

        location /conn {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Connection "@rx .+" "id:20,phase:3,deny,status:403,log"
            ';
            return 200 "ok";
        }
    }
}
EOF

$t->run();

###############################################################################

# HTTP/1.1: the synthetic Connection header is present, so the phase-3 rule
# matches and blocks with 403.
like(http_get('/conn'), qr!^HTTP/\S+ 403!, 'h1: synthetic Connection seen by WAF');

# HTTP/2: Connection is forbidden and must not be synthesized, so the rule does
# not match and the request passes.
my $s = Test::Nginx::HTTP2->new(8081);
my $sid = $s->new_stream({ path => '/conn' });
my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
is($frame->{headers}->{':status'}, 200, 'h2: no synthetic Connection, request passes');
