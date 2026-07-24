#!/usr/bin/perl

# Tests for Coraza-nginx connector: phase-1 request denial driven by the
# REMOTE_ADDR (@ipMatch) and REQUEST_URI (@contains) variables -- rule-variable
# types not otherwise exercised by the suite.  Both are evaluated by libcoraza
# when process_request_headers runs and are enforced through the rewrite-phase
# intervention path.

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

        # Denies on the client address -- evaluated right after
        # coraza_process_connection(), before URI/headers.
        location /byaddr {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "id:700,phase:1,deny,status:403,log"
            ';
            return 200 "clean\n";
        }

        # Denies on the request URI -- evaluated right after
        # coraza_process_uri(), still before request headers.
        location /byuri {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains /forbidden" "id:701,phase:1,deny,status:403,log"
            ';
            return 200 "clean\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

# Connection-info intervention: any request from 127.0.0.1 is blocked.
like(http_get('/byaddr'), qr/^HTTP\S+ 403/,
    'phase-1 REMOTE_ADDR intervention (post process_connection)');

# URI intervention: the forbidden path is blocked.
like(http_get('/byuri/forbidden/x'), qr/^HTTP\S+ 403/,
    'phase-1 REQUEST_URI intervention (post process_uri)');

# Positive control: a non-matching URI on the same location passes.
like(http_get('/byuri/allowed'), qr/^HTTP\S+ 200/,
    'non-matching URI not blocked (control)');
