#!/usr/bin/perl

# Tests for Coraza-nginx connector (Content-Length response header).
#
# Regression test for the fix that forwards a zero-length Content-Length
# response header to the WAF.  Previously the connector only passed
# Content-Length to Coraza when content_length_n > 0, so a legitimate
# Content-Length: 0 body was never surfaced and could not be matched by a
# RESPONSE_HEADERS rule.

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

        # Deny when the response carries Content-Length: 0.  This only fires
        # if the connector forwarded the zero-length Content-Length header to
        # the engine.
        location /empty {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Content-Length "@streq 0" "id:31,phase:3,deny,log,status:403"
            ';
        }

        # Control: a non-zero Content-Length must not match the rule above.
        location /nonempty {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Content-Length "@streq 0" "id:32,phase:3,deny,log,status:403"
            ';
        }
    }
}
EOF

$t->write_file("/empty", "");
$t->write_file("/nonempty", "hello");

$t->run();
$t->todo_alerts();
$t->plan(2);

###############################################################################

like(http_get('/empty'), qr/^HTTP.*403/,
	'Content-Length: 0 response header inspected (block)');

like(http_get('/nonempty'), qr/^HTTP.*200/,
	'non-zero Content-Length does not match the zero-length rule');
