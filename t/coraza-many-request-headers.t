#!/usr/bin/perl

# Tests for Coraza-nginx connector (request-header list spanning multiple
# ngx_list parts).
#
# r->headers_in.headers is an ngx_list; each part holds ~20 entries. Sending
# many (40) distinct request headers makes the list span multiple parts, so the
# `part = part->next` traversal in src/ngx_http_coraza_rewrite.c executes while
# forwarding headers to Coraza.

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

        # allow lots of request headers
        large_client_header_buffers 8 16k;

        coraza on;

        location / {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Probe-39 "@streq boom" "id:940,phase:1,deny,status:403,log"
            ';
            return 200 "clean\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(2);

###############################################################################

sub many_headers {
	my ($probe_val) = @_;
	my $req = "GET / HTTP/1.0\r\nHost: localhost\r\n";
	for my $i (0 .. 39) {
		my $v = ($i == 39) ? $probe_val : "v$i";
		$req .= "X-Probe-$i: $v\r\n";
	}
	$req .= "\r\n";
	return http($req);
}

like(many_headers("clean"), qr!^HTTP\S+ 200!,
	'40-header request traverses multi-part list and passes');
like(many_headers("boom"), qr!^HTTP\S+ 403!,
	'header in a later list part is inspected and blocks');
