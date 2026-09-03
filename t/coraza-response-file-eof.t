#!/usr/bin/perl

# Executable unit test for file-backed response reads.  The production source
# is included directly; unused filter sections are discarded by the linker.

use warnings;
use strict;

use Test::More;
use File::Temp qw(tempdir);
use FindBin;

my $nginx = $ENV{TEST_NGINX_SOURCE};

# Walk up looking for the module source tree.  CI copies t/* into an unpacked
# nginx-tests directory and proves from there, so $FindBin::Bin/../src is the
# workspace root rather than this repository.  Matches find_root() in
# coraza-h3-protocol-map.t.
sub find_root {
    my $dir = $FindBin::Bin;

    for (0 .. 4) {
        return $dir if -f "$dir/src/ngx_http_coraza_common.h";
        $dir = "$dir/..";
    }

    return undef;
}

my $root = find_root();

# Every directory below is passed to the compiler as an -I path.  ngx_http.h
# pulls in the v2, v3 and QUIC headers whenever those modules are configured,
# so a tree missing any of them fails during compilation rather than skipping.
my @needed = qw(
    src/core
    src/event
    src/event/modules
    src/event/quic
    src/os/unix
    src/http
    src/http/modules
    src/http/v2
    src/http/v3
    objs
);

plan skip_all => 'TEST_NGINX_SOURCE must name the nginx source tree'
    unless defined $nginx;

for my $dir (@needed) {
    plan skip_all => "TEST_NGINX_SOURCE is missing $dir"
        unless -d "$nginx/$dir";
}

plan skip_all => 'module source tree not found'
    unless defined $root;
plan skip_all => 'coraza headers not available'
    unless -f '/usr/local/include/coraza/coraza.h';

plan tests => 3;

my $tmp = tempdir(CLEANUP => 1);
my $source = "$tmp/response-file-eof.c";
my $binary = "$tmp/response-file-eof";

open my $fh, '>', $source or die "open $source: $!";
print {$fh} <<'EOF';
#include <stdlib.h>
#include <string.h>

#include "ngx_http_coraza_common.h"

#define static
#include "ngx_http_coraza_body_filter.c"
#undef static

static int force_eof;

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    (void) file;
    (void) offset;

    if (force_eof) {
        return 0;
    }

    memset(buf, 'A', size);
    return (ssize_t) size;
}

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level;
    (void) log;
    (void) err;
    (void) fmt;
}

int
main(void)
{
    ngx_http_request_t  request;
    ngx_connection_t    connection;
    ngx_pool_t          pool;
    ngx_log_t           log;
    ngx_buf_t           buffer;
    ngx_file_t          file;
    u_char             *data;
    size_t              len;

    memset(&request, 0, sizeof(request));
    memset(&connection, 0, sizeof(connection));
    memset(&pool, 0, sizeof(pool));
    memset(&log, 0, sizeof(log));
    memset(&buffer, 0, sizeof(buffer));
    memset(&file, 0, sizeof(file));

    request.pool = &pool;
    request.connection = &connection;
    connection.log = &log;
    buffer.in_file = 1;
    buffer.file = &file;
    buffer.file_pos = 0;
    buffer.file_last = 18;

    force_eof = 1;
    if (ngx_http_coraza_read_body_data(&request, &buffer, &data, &len)
        != NGX_ERROR)
    {
        return 1;
    }

    force_eof = 0;
    if (ngx_http_coraza_read_body_data(&request, &buffer, &data, &len)
        != NGX_OK || len != 18)
    {
        return 2;
    }

    return 0;
}
EOF
close $fh or die "close $source: $!";

my $cc = $ENV{CC} || 'cc';
my @includes = map { "-I$_" } (
    "$nginx/src/core",
    "$nginx/src/event",
    "$nginx/src/event/modules",
    "$nginx/src/event/quic",
    "$nginx/src/os/unix",
    "$nginx/src/http",
    "$nginx/src/http/modules",
    "$nginx/src/http/v2",
    "$nginx/src/http/v3",
    "$nginx/objs",
    '/usr/local/include',
    "$root/src",
);

is(system($cc, '-D_GNU_SOURCE', '-O2', '-ffunction-sections', '-fdata-sections',
          '-Werror', '-Wno-unused-function', @includes, $source,
          '-Wl,--gc-sections', '-o', $binary), 0,
    'compiled production response-file reader harness');

is(system($binary), 0,
    'premature file EOF fails closed and a complete file buffer succeeds');

ok(-x $binary, 'focused harness is executable');
