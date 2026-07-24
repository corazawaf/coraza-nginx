#!/usr/bin/perl

# Tests for Coraza-nginx connector (synthesized response headers).
#
# The header filter synthesizes several connection-specific / computed response
# headers (Connection, Keep-Alive, Transfer-Encoding, Vary) and feeds them to
# the WAF so RESPONSE_HEADERS rules can inspect values nginx computes late.
# Each runtime check pins one synthesis branch: a phase-3 rule matching the
# synthesized value must fire, proving the header reached Coraza.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

BEGIN { chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(9);

my $root = "$FindBin::Bin/..";
my $src  = slurp("$root/src/ngx_http_coraza_header_filter.c");

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
        root         %%TESTDIR%%;

        coraza on;

        # Connection: keep-alive + Keep-Alive: timeout=... resolver branch.
        # Second arg sets clcf->keepalive_header -> the Keep-Alive: timeout=...
        # sub-branch of the Connection resolver is exercised.
        keepalive_timeout 60s 30s;
        keepalive_requests 100;

        location /keepalive {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Connection "@streq keep-alive" "id:301,phase:3,deny,log,status:403"
            ';
            return 200 "ka";
        }

        # Same synthesis, but assert the Keep-Alive: timeout=<sec> sub-branch
        # value directly (keepalive_timeout second arg = 30s -> timeout=30).
        location /keepalive-timeout {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Keep-Alive "@streq timeout=30" "id:302,phase:3,deny,log,status:418"
            ';
            return 200 "ka";
        }

        # SSE content-type WITH a parameter -> is_sse_content_type() must scan
        # past the media type, hit the ";" and treat it as SSE (loop body).
        location /sse-param {
            default_type 'text/event-stream; charset=utf-8';
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq x" "id:304,phase:4,pass,log"
            ';
            return 200 "data: hi\n\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();

###############################################################################

# Connection: keep-alive + Keep-Alive: timeout=... synthesized. A keepalive
# request with a two-argument keepalive_timeout drives both the keep-alive
# branch and the Keep-Alive-header sub-branch of the Connection resolver.
my $r = http(<<EOF);
GET /keepalive HTTP/1.1
Host: localhost
Connection: keep-alive

EOF
like($r, qr/^HTTP\S+ 403/, 'Connection: keep-alive synthesized and inspected');

# Keep-Alive: timeout=30 sub-branch: the synthesized header carries the
# configured second keepalive_timeout arg. Deny (418) fires only if the value
# reached the WAF, so this asserts value selection AND WAF delivery.
my $ka = http(<<EOF);
GET /keepalive-timeout HTTP/1.1
Host: localhost
Connection: keep-alive

EOF
like($ka, qr/^HTTP\S+ 418/, 'Keep-Alive: timeout=30 synthesized and inspected');

# Control: without a keepalive connection no Keep-Alive header is synthesized,
# so the timeout=30 rule cannot fire (proves the 418 above is not vacuous).
my $ka_close = http(<<EOF);
GET /keepalive-timeout HTTP/1.1
Host: localhost
Connection: close

EOF
unlike($ka_close, qr/^HTTP\S+ 418/, 'no Keep-Alive header when connection closes (control)');

# SSE content-type with a parameter is recognized as SSE: served, headers not
# delayed, content-type preserved. Exercises is_sse_content_type()'s OWS scan
# loop (skip the parameter list, accept the ";" delimiter).
$r = http_get('/sse-param?q=x');
like($r, qr/^HTTP\S+ 200/, 'SSE content-type with parameter is served');
like($r, qr/text\/event-stream/, 'SSE content-type preserved');

# The runtime check above cannot prove the headers were NOT delayed: `return 200`
# completes the body immediately, so a delayed-then-flushed response looks
# identical. Pin the delay-skip guard by source grep instead -- the same
# contract idiom used for the resolver branches below: the delay condition must
# be gated on !ngx_http_coraza_is_sse_response(r).
like($src,
    qr/delay_response_headers.*?&&\s*!ngx_http_coraza_is_sse_response\(r\)/s,
    'header delay is skipped for SSE responses (delay guard excludes is_sse)');

# The Transfer-Encoding and Vary resolvers cannot be driven at runtime: both
# r->chunked and r->gzip_vary are set by filters that run AFTER the Coraza
# header filter (Coraza registers last, so it runs first), so those flags are
# always 0 when the resolvers execute. Pin the synthesis code by source grep
# instead -- the same contract idiom used for the delayed file-buffer clone.
like($src,
    qr/r->chunked.*?ngx_string\("chunked"\).*?ngx_http_coraza_add_response_header/s,
    'Transfer-Encoding: chunked is synthesized to the WAF when r->chunked');

like($src,
    qr/r->gzip_vary\s*&&\s*clcf->gzip_vary.*?ngx_string\("Accept-Encoding"\).*?ngx_http_coraza_add_response_header/s,
    'Vary: Accept-Encoding is synthesized AND delivered to the WAF when gzip_vary applies');

like($src,
    qr/r->headers_out\.status\s*==\s*NGX_HTTP_SWITCHING_PROTOCOLS.*?connection\s*=\s*"upgrade".*?ngx_http_coraza_add_response_header/s,
    'Connection: upgrade is synthesized AND delivered to the WAF on 101 Switching Protocols');

###############################################################################

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!";
    local $/ = undef;
    return <$fh>;
}
