#!/usr/bin/perl

# Tests for Coraza-nginx connector: every disruptive intervention blocks,
# regardless of the status the rule happens to carry.
#
# ngx_http_coraza_process_intervention() used to decide "was this request
# blocked?" from intervention->status (`if (intervention->status != 200)`) and
# return that status raw, while every caller tests `if (ret > 0)`. That is not
# a block decision, and two disruptive SecLang actions fell straight through it
# to the origin:
#
#   * a bare `drop` yields status 0. 0 is NGX_OK, so `ret > 0` was false, the
#     rewrite handler returned NGX_DECLINED and nginx proxied the request
#     upstream. Worse, status 0 still satisfied `!= 200`, so on the way out the
#     connector called coraza_update_status_code(tx, 0), logged
#     "Access denied with code 0" and ran the logging phase -- the operator's
#     audit trail claimed a block for a request that was actually served.
#     CRS uses bare `drop` for several paranoia-level and anomaly actions, so
#     any ruleset relying on those was not enforcing them.
#
#   * `deny,status:200` yields status 200, which `!= 200` excluded outright, so
#     the request was served with no audit record at all.
#
# intervention->disruptive is not a usable signal either: libcoraza 1.7.0
# leaves it 0 even for a plain `deny,status:403`.
#
# The fix derives blocked-ness from the intervention's existence -- libcoraza
# only allocates one for a disruptive action, and `allow`, `pass` and every
# rule under SecRuleEngine DetectionOnly yield NULL -- and maps the status the
# way Coraza's own reference middleware does (coraza/v3 http/middleware.go,
# obtainStatusCodeFromInterruptionOrDefault): honour ->status for `deny`, and
# for `drop` close the connection (NGX_HTTP_CLOSE).
#
# Each location below proxies to a real origin server whose access log is the
# oracle for "did this request reach the origin?". Asserting the client-visible
# status alone is not enough: a 403 error page and a genuinely-blocked request
# look the same from the client if the origin was hit anyway, and for `drop`
# the client sees a closed connection either way only if nothing was forwarded.
#
# See src/ngx_http_coraza_module.c (ngx_http_coraza_process_intervention).

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(59);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format origin_hit '$uri';

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        # The connector's "Access denied with code N" line is emitted only
        # when a transaction id is configured. It is the audit record under
        # test below: before the fix a bare `drop` logged "code 0" for a
        # request that was then served by the origin.
        coraza_transaction_id "tid-$request_id";

        # Bare `drop`: no status at all. Must close the connection and must
        # never reach the origin.
        location /drop {
            coraza on;
            coraza_transaction_id "drop-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8100,phase:1,drop,log,msg:\'drop-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # `deny` with an explicitly non-disruptive-looking status. Still a
        # disruptive action, so it must block and must not reach the origin.
        location /deny200 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8101,phase:1,deny,status:200,log,msg:\'deny200-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Ordinary deny. Pins that the fix did not change normal 403 handling.
        location /deny403 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8102,phase:1,deny,status:403,log,msg:\'deny403-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Negative control: identical drop rule, but the request below does
        # not match it. Its own location (and therefore its own URI in the
        # origin access log) keeps the "/drop never reached the origin" oracle
        # unambiguous.
        location /control {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8104,phase:1,drop,log,msg:\'control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # DetectionOnly with the same drop rule: must still be allowed through
        # to the origin. This is the regression guard against turning
        # detection into blocking.
        location /detect {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecRule ARGS:x "@streq bad" "id:8103,phase:1,drop,log,msg:\'detect-drop-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
        # --- phase:3 (RESPONSE_HEADERS) bare `drop` -------------------------
        #
        # This is a HEADER-FILTER site, not a rule-phase handler, and it is a
        # different code path from /drop above.  A phase handler returns
        # NGX_HTTP_CLOSE into ngx_http_finalize_request(), which special-cases
        # it and terminates.  The header filter instead finalizes through
        # ngx_http_filter_finalize_request() -> ngx_http_special_response_handler(),
        # where NGX_HTTP_CLOSE is not special at all: 444 matches none of the
        # error-page ranges (NGX_HTTP_NGINX_CODES is 494) and nginx emits a
        # well-formed zero-body `HTTP/1.1 444 ` response on a KEPT-ALIVE
        # connection -- the opposite of `drop`.  The assertions below are
        # written against that failure mode specifically.
        location /drop-p3 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8110,phase:3,drop,log,msg:\'drop-p3-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # phase:3 negative control: same rule, origin sends a non-matching
        # header, so the response must come back intact.
        location /drop-p3-control {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8111,phase:3,drop,log,msg:\'drop-p3-control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- phase:4 (RESPONSE_BODY) bare `drop` ----------------------------
        #
        # A BODY-FILTER site, reached through
        # ngx_http_coraza_body_filter_finalize().  Same NGX_HTTP_CLOSE problem
        # as phase:3.  Headers are delayed here so the drop is taken on the
        # delayed-headers branch -- the branch that would otherwise have a
        # clean error page available and is therefore most likely to emit a
        # tidy 444 instead of dropping.
        location /drop-p4 {
            coraza on;
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx DROPME" "id:8112,phase:4,drop,log,msg:\'drop-p4-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # phase:4 negative control: same rule, body does not match.
        location /drop-p4-control {
            coraza on;
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx DROPME" "id:8113,phase:4,drop,log,msg:\'drop-p4-control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- phase:4 bare `drop` with the body NOT inspected -----------------
        #
        # SecResponseBodyAccess Off sends phase 4 through the HEADER filter's
        # early finalisation instead of the body filter, so this is a third
        # filter site and must drop the same way, not serve a tidy 444.
        location /drop-p4-noinspect {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS:x "@streq bad" "id:8117,phase:4,drop,log,msg:\'drop-p4-noinspect-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- deny,status:444 must NOT be treated as a drop ------------------
        #
        # 444 is a status an operator can legitimately ask for with `deny`,
        # and it is also the value NGX_HTTP_CLOSE happens to have.  Pins that
        # the connector keys the connection teardown on the ACTION being
        # `drop`, not on the resulting number, so this still produces an
        # ordinary response rather than a reset.
        location /deny444-p3 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8114,phase:3,deny,status:444,log,msg:\'deny444-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- deny,status:200 at a rule PHASE --------------------------------
        #
        # The /deny200 case above probes this rule over `Connection: close`,
        # where "blocked" and "wrote nothing and kept the socket" are
        # indistinguishable -- an empty reply satisfies both.  This location
        # exists to be probed over a KEPT-ALIVE pipelined pair instead.
        #
        # A phase handler returns the mapped status straight into
        # ngx_http_finalize_request().  For rc == 200 that value is not
        # >= NGX_HTTP_SPECIAL_RESPONSE (300) and is neither NGX_HTTP_CREATED
        # (201) nor NGX_HTTP_NO_CONTENT (204), so it misses the special-response
        # block entirely, sets r->done = 1 and falls through to
        # ngx_http_finalize_connection() -- zero bytes written and the socket
        # returned to keep-alive state.  The client gets a hung/empty reply on
        # a reusable connection rather than a clean block.
        #
        # The connector serves such a `deny` as 403 -- in every phase, so a
        # rule means the same thing wherever it fires -- and the assertion is
        # that a real 403 response comes back.
        location /deny200-p1 {
            coraza on;
            coraza_transaction_id "deny200p1-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8115,phase:1,deny,status:200,log,msg:\'deny200-p1-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- phase:2 (REQUEST_BODY) bare `drop` -----------------------------
        #
        # The request-body handler is the third kind of site: ngx_http_coraza_
        # pre_access.c polls after coraza_process_request_body() and, while
        # feeding the body, after every chunk.  /drop-p2 keeps the body in
        # memory; /drop-p2-file forces it into a temp file so the drop is
        # taken after the file reader has fed the body.  Both are phase sites
        # and must tear the connection down with nothing written, like /drop.
        location /drop-p2 {
            coraza on;
            coraza_transaction_id "dropp2-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx DROPME" "id:8118,phase:2,drop,log,msg:\'drop-p2-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /drop-p2-file {
            coraza on;
            client_body_in_file_only clean;
            coraza_transaction_id "dropp2file-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx DROPME" "id:8119,phase:2,drop,log,msg:\'drop-p2-file-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # phase:2 negative controls: same rules, benign body.  Separate
        # locations so the origin-log oracle for the two above stays exact.
        location /drop-p2-control {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx DROPME" "id:8120,phase:2,drop,log,msg:\'drop-p2-control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /drop-p2-file-control {
            coraza on;
            client_body_in_file_only clean;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx DROPME" "id:8121,phase:2,drop,log,msg:\'drop-p2-file-control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- deny,status:200 in phase:2 and at a FILTER site ----------------
        #
        # The sub-300 remap is not a phase:1 special case: the same rule in
        # the request-body phase and in the response-header filter must be
        # served and recorded as 403 too.
        location /deny200-p2 {
            coraza on;
            coraza_transaction_id "deny200p2-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx DROPME" "id:8122,phase:2,deny,status:200,log,msg:\'deny200-p2-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /deny200-p3 {
            coraza on;
            coraza_transaction_id "deny200p3-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8123,phase:3,deny,status:200,log,msg:\'deny200-p3-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- deny,status:444 at a rule PHASE --------------------------------
        #
        # The /deny444-p3 case above is a FILTER site, where 444 is served as
        # an ordinary zero-body response.  A PHASE site is different: the raw
        # 444 reaches ngx_http_finalize_request(), where NGX_HTTP_CLOSE is
        # special-cased inside the rc >= NGX_HTTP_SPECIAL_RESPONSE block and
        # tears the connection down exactly like `drop`.  That is accepted as
        # correct -- 444 is nginx's own "close without response" convention --
        # and this case pins it so the two sites' divergence is deliberate and
        # observed rather than assumed.
        location /deny444-p1 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8116,phase:1,deny,status:444,log,msg:\'deny444-p1-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }

    # The origin. Its access log is the oracle for "was the request forwarded".
    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  origin;

        access_log %%TESTDIR%%/origin.log origin_hit;

        location / {
            return 200 "ORIGIN-REACHED";
        }

        # Origin arm for the phase:3 cases: emits the response header the
        # RESPONSE_HEADERS rule keys on. The value is taken from the query
        # argument so the matching and control requests differ only in that
        # one byte string and share every other code path.
        location /drop-p3 {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }
        location /drop-p3-control {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }
        location /deny444-p3 {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }
        location /deny200-p3 {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }

        # Origin arm for the phase:4 cases: the body carries the token the
        # RESPONSE_BODY rule keys on. text/plain so it passes
        # SecResponseBodyMimeType and is actually inspected.
        location /drop-p4 {
            default_type text/plain;
            return 200 "ORIGIN-REACHED-DROPME-PAYLOAD";
        }
        location /drop-p4-control {
            default_type text/plain;
            return 200 "ORIGIN-REACHED-BENIGN-PAYLOAD";
        }
    }
}

EOF

$t->run();

###############################################################################

# Read until nginx closes the socket. A stalled connection must fail the test,
# not look like the empty response expected from `drop`.
sub read_response {
	my ($s, $deadline) = @_;
	$deadline //= 5;
	my $resp;
	eval {
		local $SIG{ALRM} = sub { die "Timed out reading nginx response\n" };
		alarm $deadline;
		local $/ = undef;
		$resp = <$s>;
		alarm 0;
		1;
	} or do {
		my $error = $@;
		alarm 0;
		die $error;
	};
	return defined $resp ? $resp : '';
}

# Raw-socket GET. Returns the bytes nginx sent back, which is the empty string
# when the connection was closed without a response -- the observable that
# distinguishes a `drop` from anything that produces a status line.
sub raw_get {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n";

	my $resp = read_response($s);
	close $s;

	return $resp;
}

# Two PIPELINED keep-alive requests on ONE socket, returning both replies.
#
# This is the oracle that separates a real `drop` from nginx serving a tidy
# zero-body 444: ngx_http_special_response_handler() leaves the connection
# reusable, so the broken path answers the second request too. A dropped
# connection cannot answer it, so the second reply is empty.
#
# Both requests are written before reading anything, so the second is already
# in the socket buffer when nginx decides what to do with the first -- nginx
# cannot "not have received it yet", and an empty second reply means the
# connection really was torn down rather than merely slow.
sub raw_get_keepalive_pair {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	# Request 1 keeps the connection open; request 2 is the reuse probe and
	# targets a location that is always benign, so anything coming back for
	# it is proof the socket survived request 1.
	print $s "GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n\r\n"
		. "GET /control?x=fine HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n";

	my $resp = read_response($s);
	close $s;

	# Split on the second status line, if there is one.
	my @parts = split /(?=HTTP\/1\.[01] )/, $resp;
	my $first  = defined $parts[0] ? $parts[0] : '';
	my $second = defined $parts[1] ? join('', @parts[1 .. $#parts]) : '';

	return ($first, $second);
}

# Raw-socket POST with a body, `Connection: close`.  Same observable as
# raw_get(): the empty string means the connection was closed without a
# response.
sub raw_post {
	my ($uri, $body) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "POST $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Content-Length: " . length($body) . "\r\n"
		. "Connection: close\r\n\r\n"
		. $body;

	my $resp = read_response($s);
	close $s;

	return $resp;
}

# POST variant of raw_get_keepalive_pair(): the body-carrying request first,
# the benign reuse probe pipelined behind it on the same socket.
sub raw_post_keepalive_pair {
	my ($uri, $body) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "POST $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Content-Length: " . length($body) . "\r\n\r\n"
		. $body
		. "GET /control?x=fine HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n";

	my $resp = read_response($s);
	close $s;

	my @parts = split /(?=HTTP\/1\.[01] )/, $resp;
	my $first  = defined $parts[0] ? $parts[0] : '';
	my $second = defined $parts[1] ? join('', @parts[1 .. $#parts]) : '';

	return ($first, $second);
}

# --- bare `drop` -------------------------------------------------------------

my $drop = raw_get('/drop?x=bad');

# Expected: nothing at all on the wire (NGX_HTTP_CLOSE terminates the
# connection without writing a response).
# Observed before the fix: "HTTP/1.1 200 OK ... ORIGIN-REACHED" -- the request
# was proxied and the origin's response came back.
unlike($drop, qr!ORIGIN-REACHED!,
	'bare drop does not return the origin response');
unlike($drop, qr!^HTTP/\S+ 200!,
	'bare drop does not return 200');
is($drop, '',
	'bare drop closes the connection without sending a response');

# --- deny,status:200 ---------------------------------------------------------

my $deny200 = raw_get('/deny200?x=bad');

# Expected: blocked -- the origin's body must not come back. Returning 200 from
# a phase handler makes ngx_http_finalize_request() finalize the connection
# without ever running the content phase, so the client gets an empty 200.
# Observed before the fix: "ORIGIN-REACHED".
unlike($deny200, qr!ORIGIN-REACHED!,
	'deny,status:200 does not return the origin response');

# --- ordinary deny (must not regress) ----------------------------------------

my $deny403 = raw_get('/deny403?x=bad');
like($deny403, qr!^HTTP/\S+ 403!,
	'deny,status:403 still returns 403');
unlike($deny403, qr!ORIGIN-REACHED!,
	'deny,status:403 does not return the origin response');

# --- DetectionOnly (must not regress into blocking) --------------------------

my $detect = raw_get('/detect?x=bad');
like($detect, qr!^HTTP/\S+ 200!,
	'DetectionOnly does not block a matching drop rule');
like($detect, qr!ORIGIN-REACHED!,
	'DetectionOnly forwards the matching request to the origin');

# --- negative control --------------------------------------------------------
#
# A benign request to the same drop location, differing only in the argument
# value so the rule does not match. This proves the three assertions above are
# the rule firing and not the location being broken, unreachable, or
# misconfigured in a way that would close every connection.

my $benign = raw_get('/control?x=fine');
like($benign, qr!^HTTP/\S+ 200!,
	'negative control: non-matching request to the drop location returns 200');
like($benign, qr!ORIGIN-REACHED!,
	'negative control: non-matching request to the drop location reaches the origin');


# --- phase:3 / phase:4 bare `drop` -------------------------------------------
#
# These are the two FILTER sites. They do not share the rewrite handler's
# teardown: a phase handler hands NGX_HTTP_CLOSE to
# ngx_http_finalize_request(), which special-cases it
# (`if (rc == NGX_HTTP_CLOSE) { c->timedout = 1; ngx_http_terminate_request(); }`)
# and really drops the connection. A filter finalizes through
# ngx_http_filter_finalize_request() -> ngx_http_special_response_handler(),
# which has no NGX_HTTP_CLOSE case at all, so 444 is handled as an ordinary
# error status, matches none of the error-page ranges (NGX_HTTP_NGINX_CODES is
# 494) and falls through to `err = 0`. nginx then writes a well-formed
# zero-body response whose status line is the literal "HTTP/1.1 444 " (444 is
# absent from ngx_http_status_lines[]) and KEEPS THE CONNECTION ALIVE.
#
# So the assertions are written against that exact failure mode: no status
# line of any kind, and the connection must not survive to serve a second
# request on the same socket.

my $drop_p3 = raw_get('/drop-p3?p=bad');

unlike($drop_p3, qr!ORIGIN-REACHED!,
	'phase:3 drop does not return the origin response body');
unlike($drop_p3, qr!^HTTP/!,
	'phase:3 drop writes no status line at all');
unlike($drop_p3, qr!\b444\b!,
	'phase:3 drop does not emit a 444 status line');
is($drop_p3, '',
	'phase:3 drop closes the connection without sending a response');

my $drop_p4 = raw_get('/drop-p4');

unlike($drop_p4, qr!ORIGIN-REACHED!,
	'phase:4 drop does not return the origin response body');
unlike($drop_p4, qr!^HTTP/!,
	'phase:4 drop writes no status line at all');
unlike($drop_p4, qr!\b444\b!,
	'phase:4 drop does not emit a 444 status line');
is($drop_p4, '',
	'phase:4 drop closes the connection without sending a response');

# --- keep-alive reuse oracle -------------------------------------------------
#
# The sharpest discriminator between "dropped" and "served a tidy 444".
# ngx_http_special_response_handler() leaves the connection reusable, so the
# broken behaviour answers a SECOND pipelined request on the same socket. A
# real drop cannot: the connection is gone after the first.

# Only the first reply is bound: the second is deliberately not examined,
# for the reason spelled out below.
my ($p3_first) = raw_get_keepalive_pair('/drop-p3?p=bad');

# Assert on the FIRST reply, not merely on the absence of a second.
#
# Asserting only that the second reply is empty would be vacuous here, and was
# observed to be so: the broken build answers request 1 with a 444 carrying
# `Connection: close`, so it does not serve request 2 either and an
# empty-second-reply assertion passes on BOTH the broken and the fixed build.
# What actually differs is whether anything was written at all, so that is
# what is asserted -- with the pipelined second request still present to prove
# the socket was readable and the emptiness is nginx's choice, not a race.
is($p3_first, '',
	'phase:3 drop writes nothing even with a second request already queued');

# Only the first reply is bound; see the phase:3 case above.
my ($p4_first) = raw_get_keepalive_pair('/drop-p4');
is($p4_first, '',
	'phase:4 drop writes nothing even with a second request already queued');

# Phase 4 on an uninspected body runs from the header filter, before any
# header is sent; a drop there must still write nothing.
my ($p4n_first) = raw_get_keepalive_pair('/drop-p4-noinspect?x=bad');
is($p4n_first, '',
	'phase:4 drop on an uninspected body writes nothing with a second request queued');

# --- phase:3 / phase:4 negative controls -------------------------------------
#
# Same locations, same rules, non-matching data. Proves the assertions above
# are the rule firing and not the location being broken in a way that would
# close every connection.

my $p3_ok = raw_get('/drop-p3-control?p=fine');
like($p3_ok, qr!ORIGIN-REACHED!,
	'negative control: non-matching phase:3 response is returned intact');

my $p4_ok = raw_get('/drop-p4-control');
like($p4_ok, qr!ORIGIN-REACHED-BENIGN-PAYLOAD!,
	'negative control: non-matching phase:4 response is returned intact');

my $p4n_ok = raw_get('/drop-p4-noinspect?x=fine');
like($p4n_ok, qr!ORIGIN-REACHED!,
	'negative control: non-matching phase:4 uninspected response is returned intact');

# --- deny,status:444 is not a drop -------------------------------------------
#
# 444 is both a status an operator may legitimately request with `deny` and
# the numeric value of NGX_HTTP_CLOSE. The connector must key the connection
# teardown on the ACTION, so this one still produces an ordinary response.

my $deny444 = raw_get('/deny444-p3?p=bad');
like($deny444, qr!^HTTP/!,
	'deny,status:444 is answered with a response, not a dropped connection');
unlike($deny444, qr!ORIGIN-REACHED!,
	'deny,status:444 still blocks the origin body');

# --- deny,status:200 at a rule PHASE, over a KEPT-ALIVE connection -----------
#
# The /deny200 probe earlier in this file uses `Connection: close`, where an
# empty reply is indistinguishable from a proper block -- so the defect this
# case pins passed green there.  Here the pair is pipelined on one socket:
# both requests are written before anything is read, so nginx has request 2
# buffered when it decides what to do with request 1.
#
# Broken behaviour: rc == 200 misses ngx_http_finalize_request()'s
# special-response block (not >= 300, not 201, not 204), so nothing is ever
# written and the connection is returned to keep-alive state.  The first reply
# is empty and the SECOND request is then answered normally -- zero bytes for
# the block, a live socket afterwards.
#
# Correct behaviour: a `deny` whose status cannot be served as a special
# response is mapped to 403, so request 1 gets a real, well-formed 403 body.
my ($deny200_p1_first, $deny200_p1_second) =
	raw_get_keepalive_pair('/deny200-p1?x=bad');

isnt($deny200_p1_first, '',
	'deny,status:200 at a phase site writes a response rather than nothing');
like($deny200_p1_first, qr!^HTTP/\S+ 403!,
	'deny,status:200 at a phase site is served as a 403 block');
unlike($deny200_p1_first, qr!ORIGIN-REACHED!,
	'deny,status:200 at a phase site does not return the origin response');

# The socket is deliberately still probed for reuse.  A 403 from
# ngx_http_special_response_handler() leaves the connection usable, so the
# second reply is expected to arrive -- this asserts the pipelined probe is
# live and that an empty FIRST reply above would have been nginx's choice
# rather than a dead socket or a race.
like($deny200_p1_second, qr!^HTTP/!,
	'the pipelined reuse probe is live after a phase-site deny,status:200');

# --- phase:2 bare `drop`, in-memory and file-backed body ---------------------
#
# The request-body handler returns NGX_HTTP_CLOSE into
# ngx_http_finalize_request() like the phase:1 site, so the observable is the
# same: nothing on the wire, even with a second request already queued.

my $drop_p2 = raw_post('/drop-p2', 'DROPME-PAYLOAD');
is($drop_p2, '',
	'phase:2 drop closes the connection without sending a response');
unlike($drop_p2, qr!ORIGIN-REACHED!,
	'phase:2 drop does not return the origin response');

my ($p2_first) = raw_post_keepalive_pair('/drop-p2', 'DROPME-PAYLOAD');
is($p2_first, '',
	'phase:2 drop writes nothing even with a second request already queued');

my $drop_p2_file = raw_post('/drop-p2-file', 'DROPME-PAYLOAD');
is($drop_p2_file, '',
	'phase:2 drop on a file-backed body closes the connection without a response');
unlike($drop_p2_file, qr!ORIGIN-REACHED!,
	'phase:2 drop on a file-backed body does not return the origin response');

my ($p2f_first) = raw_post_keepalive_pair('/drop-p2-file', 'DROPME-PAYLOAD');
is($p2f_first, '',
	'phase:2 drop on a file-backed body writes nothing with a second request queued');

# phase:2 negative controls: same rules, benign body, origin reached.
like(raw_post('/drop-p2-control', 'BENIGN-PAYLOAD'), qr!ORIGIN-REACHED!,
	'negative control: non-matching phase:2 request body reaches the origin');
like(raw_post('/drop-p2-file-control', 'BENIGN-PAYLOAD'), qr!ORIGIN-REACHED!,
	'negative control: non-matching file-backed phase:2 request body reaches the origin');

# --- deny,status:200 in phase:2 and at a FILTER site -------------------------
#
# Same oracle as the phase:1 case above: a real 403 on the wire, the socket
# still usable afterwards.
my ($deny200_p2_first, $deny200_p2_second) =
	raw_post_keepalive_pair('/deny200-p2', 'DROPME-PAYLOAD');

like($deny200_p2_first, qr!^HTTP/\S+ 403!,
	'deny,status:200 in phase:2 is served as a 403 block');
unlike($deny200_p2_first, qr!ORIGIN-REACHED!,
	'deny,status:200 in phase:2 does not return the origin response');
like($deny200_p2_second, qr!^HTTP/!,
	'the pipelined reuse probe is live after a phase:2 deny,status:200');

# At the header-filter site nginx could have served a zero-body 200 through
# ngx_http_special_response_handler(); the connector remaps there too so the
# rule means the same thing in every phase.
my $deny200_p3 = raw_get('/deny200-p3?p=bad');
like($deny200_p3, qr!^HTTP/\S+ 403!,
	'deny,status:200 at a filter site is served as a 403 block');
unlike($deny200_p3, qr!ORIGIN-REACHED!,
	'deny,status:200 at a filter site does not return the origin response body');

# --- deny,status:444 at a rule PHASE -----------------------------------------
#
# Deliberately NOT the same as the filter-site /deny444-p3 case above.  At a
# phase site the raw 444 is NGX_HTTP_CLOSE and ngx_http_finalize_request()
# tears the connection down with nothing written -- identical to `drop`.  That
# is accepted: 444 is nginx's own "close without response" convention, so an
# operator writing `deny,status:444` in a request phase is asking for exactly
# that.  This pins the behaviour rather than leaving it unverified, and the
# README and the ngx_http_coraza_process_intervention() comment are written to
# match.
#
# Note 444 >= NGX_HTTP_SPECIAL_RESPONSE, so it is untouched by the sub-300
# remap that the deny,status:200 case above exercises.
my ($deny444_p1_first) = raw_get_keepalive_pair('/deny444-p1?x=bad');

is($deny444_p1_first, '',
	'deny,status:444 at a phase site closes the connection without a response');

my $deny444_p1 = raw_get('/deny444-p1?x=bad');
unlike($deny444_p1, qr!ORIGIN-REACHED!,
	'deny,status:444 at a phase site does not return the origin response');

$t->stop();

###############################################################################

# The origin's own access log is the authoritative record of what was actually
# forwarded. Checking the client-visible response alone cannot distinguish
# "blocked" from "forwarded, and the origin's reply happened to look like a
# block".
my $origin_log = $t->read_file('origin.log');
$origin_log = '' unless defined $origin_log;

unlike($origin_log, qr!^/drop$!m,
	'no dropped request ever reached the origin');
unlike($origin_log, qr!^/deny200$!m,
	'no deny,status:200 request ever reached the origin');
unlike($origin_log, qr!^/drop-p2$!m,
	'no phase:2 dropped request ever reached the origin');
unlike($origin_log, qr!^/drop-p2-file$!m,
	'no file-backed phase:2 dropped request ever reached the origin');
unlike($origin_log, qr!^/deny200-p2$!m,
	'no phase:2 deny,status:200 request ever reached the origin');

# The audit trail must not claim a block with a status the client never got.
# Before the fix a bare `drop` produced exactly this line and then served the
# request from the origin anyway, so an operator reading the log saw a block
# that never happened.
my $errlog = $t->read_file('error.log');
$errlog = '' unless defined $errlog;

unlike($errlog, qr/Access denied with code 0\b/,
	'no request is logged as denied with the bogus status 0');

# The drop that really was blocked is recorded with the status the connector
# actually enforced (444, nginx's "connection closed without response").
# /drop carries its own transaction-id prefix because the deny,status:444
# locations also log "code 444"; without it this would pass on their lines.
like($errlog, qr/Access denied with code 444, unique_id "drop-/,
	'a dropped request is logged as denied with the status it was blocked with');
like($errlog, qr/Access denied with code 444, unique_id "dropp2-/,
	'a phase:2 dropped request is logged as denied with 444');
like($errlog, qr/Access denied with code 444, unique_id "dropp2file-/,
	'a file-backed phase:2 dropped request is logged as denied with 444');

# --- the audit record must agree with the wire -------------------------------
#
# The point of this whole file is that what the operator reads in the log is
# what the client actually got.  A `deny,status:200` is served as a 403 (see
# the /deny200-p1, /deny200-p2 and /deny200-p3 cases above, which assert the
# wire side), so the connector must RECORD 403 too.
#
# Regression pinned: the remap once happened in the caller, AFTER
# ngx_http_coraza_process_intervention() had already called
# coraza_update_status_code() and emitted this line with the rule's raw status.
# The client got 403 while the audit log and the error log both said 200 --
# the same "logged a block that does not match what was served" defect as the
# original "Access denied with code 0", just with a different number.
#
# Every `status:200` rule in this file is remapped, so a "code 200" line can
# only be this mismatch.
unlike($errlog, qr/Access denied with code 200\b/,
	'no deny is logged with a status the client was not served');

# Matched on each location's own prefix: /deny403 also logs "code 403".
like($errlog, qr/Access denied with code 403, unique_id "deny200p1-/,
	'a phase:1 deny,status:200 is logged with the 403 it was served as');
like($errlog, qr/Access denied with code 403, unique_id "deny200p2-/,
	'a phase:2 deny,status:200 is logged with the 403 it was served as');
like($errlog, qr/Access denied with code 403, unique_id "deny200p3-/,
	'a filter-site deny,status:200 is logged with the 403 it was served as');

# Drop one known-benign nginx-core UBSan diagnostic before the crash gate.
#
# The deny,status:200 keep-alive case above pipelines a second request that
# nginx actually parses -- the first test in this suite to do so, because the
# other pipelined probes drop the connection before request 2 is read. Parsing
# a request method goes through ngx_http_parse.c's ngx_str3_cmp(), which is a
# deliberate unaligned `*(uint32_t *) m` load compiled in only when
# NGX_HAVE_NONALIGNED says the platform allows it. UBSan's alignment check
# reports it as "runtime error: load of misaligned address ... for type
# 'uint32_t'", and coraza_crash_check's $CRASH_RE matches any "runtime error:".
#
# This is nginx core, not this module: the identical diagnostic reproduces
# from a pipelined pair against a plain `return 200` location with the coraza
# module not loaded at all. It cannot be turned off at runtime either --
# UBSan's check selection is a compile-time flag, and GCC's runtime honours
# neither UBSAN_OPTIONS=alignment=0 nor a suppressions file for it.
#
# So exactly this one line is filtered, matched on both the check and the
# nginx source file that raises it, and only ngx_http_parse.c is allowed. Any
# other runtime error, any sanitizer report from the connector, and every
# crash signal still reach the assertion unchanged. The shared helper is left
# alone so no other test's gate is weakened.
{
	my $log = $t->read_file('error.log');
	$log = '' unless defined $log;

	my $filtered = join '', grep {
		$_ !~ m{^src/http/ngx_http_parse\.c:\d+:\d+:
			\sruntime\serror:\sload\sof\smisaligned\saddress
			\s\S+\sfor\stype\s'uint32_t'}x
	} split /(?<=
)/, $log;

	if ($filtered ne $log) {
		$t->write_file('error.log', $filtered);
	}
}

coraza_crash_check::assert_no_crash($t,
	'no crash handling drop and deny,status:200 interventions');

###############################################################################
