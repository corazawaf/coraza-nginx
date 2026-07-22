#!/usr/bin/perl

# Tests for Coraza-nginx connector (HEAD responses).
#
# The header filter delays response headers until the body filter reaches
# last_buf.  For HEAD requests nginx normally sets r->header_only in its final
# header filter; if Coraza delays before that point, static handlers continue as
# if this were a GET and pass the file body into the body filter.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(2);

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

        location /head {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }
    }
}
EOF

$t->write_file('/head', 'HEAD-MUST-NOT-LEAK-BODY');

$t->run();
$t->todo_alerts();

###############################################################################

my $r = http_head('/head');
like($r, qr/^HTTP\S+ 200/, 'HEAD response succeeds with Coraza enabled');
unlike($r, qr/HEAD-MUST-NOT-LEAK-BODY/, 'HEAD response does not include body');
