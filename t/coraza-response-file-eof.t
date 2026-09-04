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
# CI installs libcoraza under /usr/local; a distribution package lands in
# /usr.  Probe both so the harness is not silently skipped on either.
my ($coraza_inc) = grep { -f "$_/coraza/coraza.h" }
    qw(/usr/local/include /usr/include);

plan skip_all => 'coraza headers not available'
    unless defined $coraza_inc;

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

/*
 * Physical end of the backing file.  0 means "the file is as long as the
 * buffer claims"; a positive value models a response file truncated after
 * buf->file_last was already recorded, so a read at or past it returns 0.
 */
static off_t truncate_at;

/* Bytes handed to coraza_append_response_body() across the whole range. */
static size_t appended_total;
static int    append_calls;
static int    append_fail;

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}

/*
 * The fixture leaves buf->file->directio unset, so these are never reached;
 * they exist only to satisfy the linker on a tree built with
 * NGX_HAVE_ALIGNED_DIRECTIO.
 */
ngx_int_t
ngx_directio_off(ngx_fd_t fd)
{
    (void) fd;
    return 0;
}

ngx_int_t
ngx_directio_on(ngx_fd_t fd)
{
    (void) fd;
    return 0;
}

ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    (void) file;

    if (force_eof) {
        return 0;
    }

    if (truncate_at > 0) {
        if (offset >= truncate_at) {
            return 0;
        }

        if (offset + (off_t) size > truncate_at) {
            size = (size_t) (truncate_at - offset);
        }
    }

    memset(buf, 'A', size);
    return (ssize_t) size;
}

int
coraza_append_response_body(coraza_transaction_t t, unsigned char *data,
    int length)
{
    (void) t;
    (void) data;

    append_calls++;
    appended_total += (size_t) length;

    return append_fail ? -1 : 0;
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
    ngx_http_coraza_ctx_t  ctx;
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

    /*
     * Bounded chunked reader, ngx_http_coraza_append_response_body_file().
     * The range spans more than one 64 KiB chunk so the loop iterates, and
     * the backing file is short of buf->file_last -- the shape a response
     * temp/static file takes when it is truncated after the buffer recorded
     * its length.  The second ngx_read_file() therefore returns 0.
     */
    memset(&ctx, 0, sizeof(ctx));
    buffer.file_pos = 0;
    buffer.file_last = 3 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;

    truncate_at = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;
    appended_total = 0;
    append_calls = 0;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
        != NGX_ERROR)
    {
        /* premature EOF mid-range must fail closed, not report success */
        return 3;
    }

    if (!ctx.intervention_triggered) {
        return 4;
    }

    /* Only the bytes that really existed were inspected. */
    if (appended_total != NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE
        || append_calls != 1)
    {
        return 5;
    }

    /* Negative control: an intact multi-chunk range succeeds in full. */
    memset(&ctx, 0, sizeof(ctx));
    truncate_at = 0;
    appended_total = 0;
    append_calls = 0;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
        != NGX_OK)
    {
        return 6;
    }

    if (appended_total
            != (size_t) (3 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE)
        || append_calls != 3)
    {
        return 7;
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
    $coraza_inc,
    "$root/src",
);

is(system($cc, '-D_GNU_SOURCE', '-O2', '-ffunction-sections', '-fdata-sections',
          '-Werror', '-Wno-unused-function', @includes, $source,
          '-Wl,--gc-sections', '-o', $binary), 0,
    'compiled production response-file reader harness');

ok(-x $binary, 'focused harness is executable');

# The harness exits with the number of the scenario that failed, so a red
# result names the branch that regressed instead of just "non-zero".
my %scenario = (
    1 => 'whole-range reader: premature EOF must fail closed',
    2 => 'whole-range reader: intact file buffer must succeed',
    3 => 'chunked reader: premature EOF mid-range must fail closed',
    4 => 'chunked reader: premature EOF must set intervention_triggered',
    5 => 'chunked reader: only the bytes that existed are inspected',
    6 => 'chunked reader: intact multi-chunk range must succeed',
    7 => 'chunked reader: intact range inspects every 64 KiB chunk',
);

my $status = system($binary);
my $code = $status == -1 ? -1 : $status >> 8;

is($code, 0, 'file-backed response readers fail closed on premature EOF')
    or diag($scenario{$code}
        ? "failing scenario $code: $scenario{$code}"
        : "harness exited with unmapped status $status");
