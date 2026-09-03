#!/usr/bin/perl

# Tests for Coraza-nginx connector: a request body carried through an
# error_page re-entry into a coraza-on named location.
#
# When a non-Coraza error (here a plain 404) is routed through error_page,
# nginx re-runs the rewrite and pre-access phases for the internal request
# with r->error_page set.  On that second pass the pre-access handler must
# yield at every intervention poll -- the final poll, and the in-loop polls
# in both the in-memory and the file-buffered body paths -- rather than
# finalizing the request a second time on top of the error page nginx is
# already serving.  Phase-2 processing never runs on that pass, so a body
# rule in the error_page location must not turn the 404 into a 403.
#
# The large body is bigger than client_body_buffer_size (temp file) and
# bigger than the 64 KiB file chunk, so the file loop takes more than one
# iteration and its in-loop poll site is actually exercised.
#
# The direct POST controls prove the body rule and both body paths work when
# no error_page is involved, so the 404 outcomes above are not vacuous.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Socket qw/ CRLF /;
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
        client_body_buffer_size 8k;
        client_max_body_size 1m;

        # Everything proxies to the backend below so the request reaches the
        # content phase: `return` answers in the rewrite phase, before
        # pre-access ever reads the body, and would make all of this vacuous.
        # The URLENCODED body processor is what populates REQUEST_BODY.

        # First pass: body is read and inspected clean, then the backend
        # answers 404, which proxy_intercept_errors + error_page route into
        # @fallback.
        location /missing {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 1048576
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
            ';
            proxy_intercept_errors on;
            error_page 404 = @fallback;
            proxy_pass http://127.0.0.1:8081;
        }

        # Second pass, r->error_page set.  The body rule here would fire if
        # the connector re-inspected the body instead of yielding.
        location @fallback {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 1048576
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx TRIGGER-BODY" "id:600,phase:2,deny,log,status:403"
            ';
            rewrite ^ /fallback break;
            proxy_pass http://127.0.0.1:8081;
        }

        # Control: the same rule with no error_page in the way.
        location /direct {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 1048576
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule REQUEST_BODY "@rx TRIGGER-BODY" "id:601,phase:2,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  backend;

        coraza off;
        default_type text/plain;

        location /missing  { return 404; }
        location /fallback { return 404 "fallback page\n"; }
        location /direct   { return 200 "direct ok\n"; }
    }
}

EOF

$t->run();
$t->todo_alerts();
$t->plan(9);

###############################################################################

sub post {
    my ($uri, $body) = @_;
    return http(
        "POST $uri HTTP/1.0" . CRLF
        . "Host: localhost" . CRLF
        . "Content-Type: application/x-www-form-urlencoded" . CRLF
        . "Content-Length: " . length($body) . CRLF . CRLF
        . $body
    );
}

my $small = "a=leading+TRIGGER-BODY+trailing";
my $large = "a=" . ("x" x 65536) . "TRIGGER-BODY" . ("y" x 131072);  # ~192 KiB

# Controls first: the rule and both body paths work without error_page.
like(post('/direct', $small), qr/^HTTP\S+ 403/,
    'control: in-memory body trips the phase-2 rule on a direct request');
like(post('/direct', $large), qr/^HTTP\S+ 403/,
    'control: file-buffered multi-chunk body trips the phase-2 rule');
like(post('/direct', "a=harmless"), qr/^HTTP\S+ 200/,
    'control: clean body passes the direct location');

# error_page re-entry, in-memory body.
my $r = post('/missing', $small);
like($r, qr/^HTTP\S+ 404/,
    'in-memory body: error_page re-entry keeps the 404, not a second finalize');
like($r, qr/fallback page/,
    'in-memory body: error_page location body delivered on re-entry');

# error_page re-entry, file-buffered body spanning more than one chunk.
$r = post('/missing', $large);
like($r, qr/^HTTP\S+ 404/,
    'file body: error_page re-entry keeps the 404 across in-loop polls');
like($r, qr/fallback page/,
    'file body: error_page location body delivered on re-entry');

# Worker survived all of it.
like(http_get('/direct'), qr/^HTTP\S+ 200/, 'worker still serving afterwards');

my $log = $t->read_file('error.log');
unlike($log, qr/signal 11|SIGSEGV|AddressSanitizer/,
    'no crash or sanitizer report in error.log');

###############################################################################
