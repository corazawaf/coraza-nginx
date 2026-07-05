#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed file-backed response buffers).
#
# When response body inspection is disabled, delayed pure file-backed buffers
# can be replayed as file ranges instead of being read and copied into r->pool.
# The runtime checks below pin the behaviour that optimization must preserve.

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

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_body_filter.c");
my $t = Test::Nginx->new()->has(qw/http/)->plan(6);

like($src,
    qr/!\s*ctx->response_body_processable\s*&&\s*!\s*ngx_buf_in_memory\(chain->buf\)\s*&&\s*chain->buf->in_file\s*&&\s*!\s*chain->buf->temp_file.*?\*b\s*=\s*\*chain->buf/s,
    'uninspected non-temp file-backed delayed buffers are cloned without body copy');

like($src,
    qr/\*b\s*=\s*\*chain->buf;.*?chain->buf->file_pos\s*=\s*chain->buf->file_last/s,
    'cloned file-backed source buffers are still marked consumed');

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
        sendfile     on;

        location /file-pass {
            default_type application/octet-stream;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }

        location /file-block {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq block" "id:161,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

my $size = 128 * 1024;
$t->write_file('/file-pass', 'F' x $size);
$t->write_file('/file-block', 'ORIGINAL-FILE-BODY');

$t->run();
$t->todo_alerts();

###############################################################################

my $r = http_get('/file-pass');
like($r, qr/^HTTP\S+ 200/, 'uninspected delayed file response returns 200');

my ($body) = $r =~ /\r\n\r\n(.*)$/s;
is(length($body // ''), $size,
    'uninspected delayed file response body is delivered intact');

$r = http_get('/file-block?q=block');
like($r, qr/^HTTP\S+ 403/,
    'phase-4 non-body rule still cleanly blocks delayed file response');
unlike($r, qr/ORIGINAL-FILE-BODY/,
    'clean phase-4 block does not leak original file response body');

###############################################################################

sub slurp {
    my ($path) = @_;

    open my $fh, '<', $path or die "open $path: $!";
    local $/ = undef;
    return <$fh>;
}
