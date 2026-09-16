#!/usr/bin/perl

# Executable unit test for file-backed response reads.  The production source
# is included directly; unused filter sections are discarded by the linker.

use warnings;
use strict;

use Test::More;
use File::Temp qw(tempdir);
use FindBin;

my $nginx = $ENV{TEST_NGINX_SOURCE};
# CI installs libcoraza under /usr/local; a distribution package lands in
# /usr.  Probe both so the harness is not silently skipped on either.  An
# explicit TEST_LIBCORAZA_INCLUDE always wins; otherwise the first hit wins
# deliberately -- that mirrors the linker's own search order, so a host with
# stale headers under /usr/local and the real library under /usr still
# compiles against the same set the linker would resolve against.
my ($coraza_include) = grep { -f "$_/coraza/coraza.h" }
    ($ENV{TEST_LIBCORAZA_INCLUDE} ? ($ENV{TEST_LIBCORAZA_INCLUDE})
                                  : qw(/usr/local/include /usr/include));

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
    unless defined $coraza_include;

plan tests => 11;

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
static off_t  truncate_at;
static size_t appended_total;
static int    append_calls;
static int    alloc_calls;
static int    alloc_fail;
static int    append_fail;
static int    force_error;
static int    read_calls;
static int    short_read;
static int fail_chain_link;
static int fail_pcalloc;
static int fail_pnalloc;
static int finalize_calls;
static ngx_int_t finalized_status;
static ngx_chain_t allocated_chain;
static ngx_buf_t allocated_buffer;

ngx_module_t ngx_http_coraza_module;

ngx_int_t
ngx_http_coraza_is_redirect_status(ngx_int_t status)
{
    (void) status;
    return 0;
}

void
ngx_http_coraza_prepare_redirect(ngx_http_request_t *r, ngx_int_t status)
{
    (void) r;
    (void) status;
}

ngx_int_t
ngx_http_coraza_forward_header(ngx_http_request_t *r)
{
    (void) r;
    return NGX_OK;
}

ngx_int_t
ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_module_t *m,
    ngx_int_t status)
{
    (void) r;
    (void) m;
    finalize_calls++;
    finalized_status = status;
    return status;
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    if (fail_pnalloc) {
        return NULL;
    }
    return malloc(size);
}

void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    (void) size;
    if (fail_pcalloc) {
        return NULL;
    }
    memset(&allocated_buffer, 0, sizeof(allocated_buffer));
    return &allocated_buffer;
}

ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    (void) pool;
    if (fail_chain_link) {
        return NULL;
    }
    memset(&allocated_chain, 0, sizeof(allocated_chain));
    return &allocated_chain;
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;

    alloc_calls++;

    if (alloc_fail) {
        return NULL;
    }

    return malloc(size);
}

ngx_int_t
ngx_directio_off(ngx_fd_t fd)
{
    (void) fd;
    return NGX_OK;
}

ngx_int_t
ngx_directio_on(ngx_fd_t fd)
{
    (void) fd;
    return NGX_OK;
}

int
ngx_http_coraza_bulk_headers_available(void)
{
    return 0;
}

int
coraza_append_response_body(coraza_transaction_t transaction,
    unsigned char *data, int length)
{
    (void) transaction;
    (void) data;

    append_calls++;
    appended_total += (size_t) length;

    return append_fail ? -1 : 0;
}

int
coraza_process_response_body(coraza_transaction_t transaction)
{
    (void) transaction;
    return 0;
}

ngx_int_t
ngx_http_coraza_process_intervention(ngx_http_coraza_ctx_t *ctx,
    ngx_http_request_t *r, ngx_int_t early_log)
{
    (void) ctx;
    (void) r;
    (void) early_log;
    return NGX_OK;
}

ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    (void) file;

    read_calls++;

    if (force_eof) {
        return 0;
    }

    if (force_error) {
        return NGX_ERROR;
    }

    if (truncate_at > 0) {
        if (offset >= truncate_at) {
            return 0;
        }

        if (offset + (off_t) size > truncate_at) {
            size = (size_t) (truncate_at - offset);
        }
    }

    /*
     * Short reads are the ordinary pread()/signal case.  Halving each read
     * keeps the loop honest: the reader must advance by what it actually got
     * and submit only those bytes, never the full requested size.
     */
    if (short_read && size > 1) {
        size /= 2;
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

static int
run_chunked_reader_cases(void)
{
    ngx_http_coraza_ctx_t  ctx;
    ngx_http_request_t  request;
    ngx_connection_t    connection;
    ngx_pool_t          pool;
    ngx_log_t           log;
    ngx_buf_t           buffer;
    ngx_file_t          file;

    memset(&request, 0, sizeof(request));
    memset(&connection, 0, sizeof(connection));
    memset(&pool, 0, sizeof(pool));
    memset(&log, 0, sizeof(log));
    memset(&buffer, 0, sizeof(buffer));
    memset(&file, 0, sizeof(file));

    request.pool = &pool;
    request.connection = &connection;
    connection.log = &log;

    /*
     * Bounded chunked reader, ngx_http_coraza_append_response_body_file().
     * The range spans more than one 64 KiB chunk so the loop iterates, and
     * the backing file is short of buf->file_last -- the shape a response
     * temp/static file takes when it is truncated after the buffer recorded
     * its length.  The second ngx_read_file() therefore returns 0.
     */
    memset(&ctx, 0, sizeof(ctx));
    memset(&buffer, 0, sizeof(buffer));
    buffer.in_file = 1;
    buffer.file = &file;
    buffer.file_pos = 0;

    /*
     * Deliberately NOT a whole multiple of the chunk size: the final chunk is
     * short, so the clamp's else-branch (size = file_last - offset) is
     * exercised rather than every read being a full 64 KiB.
     */
    buffer.file_last = 3 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE + 100;

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
            != (size_t) (3 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE
                         + 100)
        || append_calls != 4)
    {
        return 7;
    }

    /*
     * Coraza rejects an intact chunk (append_fail): the chunked reader must
     * fail closed and flag intervention, exercising body_filter.c:190.
     */
    memset(&ctx, 0, sizeof(ctx));
    truncate_at = 0;
    appended_total = 0;
    append_calls = 0;
    append_fail = 1;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
        != NGX_ERROR)
    {
        return 8;
    }

    if (!ctx.intervention_triggered) {
        return 9;
    }

    append_fail = 0;

    /*
     * Short reads: every byte of the range must still be inspected, and the
     * reader must advance by what ngx_read_file() returned rather than by the
     * size it asked for.  Advancing by the requested size would skip the
     * unread remainder past the WAF.
     */
    memset(&ctx, 0, sizeof(ctx));
    truncate_at = 0;
    appended_total = 0;
    append_calls = 0;
    short_read = 1;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
        != NGX_OK)
    {
        return 10;
    }

    if (appended_total
        != (size_t) (3 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE + 100))
    {
        return 11;
    }

    short_read = 0;

    /*
     * A mid-file range: the reader must start at buf->file_pos, not at 0.
     * Response chains routinely describe a window into a larger file.
     */
    memset(&ctx, 0, sizeof(ctx));
    truncate_at = 0;
    appended_total = 0;
    append_calls = 0;

    buffer.file_pos = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;
    buffer.file_last = 3 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
        != NGX_OK)
    {
        return 12;
    }

    if (appended_total
            != (size_t) (2 * NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE)
        || append_calls != 2)
    {
        return 13;
    }

    /* An empty range must return early without reading anything. */
    memset(&ctx, 0, sizeof(ctx));
    appended_total = 0;
    append_calls = 0;

    buffer.file_pos = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;
    buffer.file_last = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
        != NGX_OK
        || append_calls != 0)
    {
        return 14;
    }

    /* A read error must fail closed after one attempted read. */
    memset(&ctx, 0, sizeof(ctx));
    alloc_calls = 0;
    appended_total = 0;
    append_calls = 0;
    read_calls = 0;
    force_error = 1;

    buffer.file_pos = 0;
    buffer.file_last = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
            != NGX_ERROR
        || !ctx.intervention_triggered
        || alloc_calls != 1
        || read_calls != 1
        || append_calls != 0)
    {
        return 15;
    }

    force_error = 0;

    /* An inverted range must be rejected before allocation or I/O. */
    memset(&ctx, 0, sizeof(ctx));
    alloc_calls = 0;
    append_calls = 0;
    read_calls = 0;

    buffer.file_pos = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;
    buffer.file_last = 0;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
            != NGX_ERROR
        || !ctx.intervention_triggered
        || alloc_calls != 0
        || read_calls != 0
        || append_calls != 0)
    {
        return 16;
    }

    /* Scratch-buffer allocation failure must stop before read or append. */
    memset(&ctx, 0, sizeof(ctx));
    alloc_calls = 0;
    append_calls = 0;
    read_calls = 0;
    alloc_fail = 1;

    buffer.file_pos = 0;
    buffer.file_last = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE;

    if (ngx_http_coraza_append_response_body_file(&ctx, &request, &buffer)
            != NGX_ERROR
        || !ctx.intervention_triggered
        || alloc_calls != 1
        || read_calls != 0
        || append_calls != 0)
    {
        return 17;
    }

    return 0;
}

static int
run_filter_case(const char *name)
{
    ngx_http_request_t  request;
    ngx_connection_t    connection;
    ngx_pool_t          pool;
    ngx_log_t           log;
    ngx_buf_t           buffer;
    ngx_file_t          file;
    ngx_chain_t         pending;
    ngx_chain_t         input;
    ngx_http_coraza_ctx_t ctx;
    void               *request_ctx[1];
    u_char               payload[18];
    ngx_int_t            rc;

    memset(&request, 0, sizeof(request));
    memset(&connection, 0, sizeof(connection));
    memset(&pool, 0, sizeof(pool));
    memset(&log, 0, sizeof(log));
    memset(&buffer, 0, sizeof(buffer));
    memset(&file, 0, sizeof(file));
    memset(&pending, 0, sizeof(pending));
    memset(&input, 0, sizeof(input));
    memset(&ctx, 0, sizeof(ctx));
    memset(request_ctx, 0, sizeof(request_ctx));
    memset(payload, 'A', sizeof(payload));

    request.pool = &pool;
    request.connection = &connection;
    request.ctx = request_ctx;
    connection.log = &log;
    ngx_http_coraza_module.ctx_index = 0;
    request_ctx[0] = &ctx;

    buffer.temporary = 1;
    buffer.pos = payload;
    buffer.last = payload + sizeof(payload);
    input.buf = &buffer;

    ctx.headers_delayed = 1;
    ctx.pending_chain = &pending;
    ctx.pending_chain_last = &pending.next;
    ctx.pending_bytes = 18;

    force_eof = 0;
    fail_chain_link = 0;
    fail_pcalloc = 0;
    fail_pnalloc = 0;
    finalize_calls = 0;
    finalized_status = 0;

    if (strcmp(name, "chain-link") == 0) {
        fail_chain_link = 1;
    } else if (strcmp(name, "stable-buffer") == 0) {
        buffer.temporary = 0;
        buffer.in_file = 1;
        buffer.file = &file;
        buffer.file_last = 18;
        fail_pcalloc = 1;
    } else if (strcmp(name, "file-read") == 0) {
        buffer.temporary = 0;
        buffer.in_file = 1;
        buffer.temp_file = 1;
        buffer.file = &file;
        buffer.file_last = 18;
        force_eof = 1;
    } else if (strcmp(name, "copy-buffer") == 0) {
        fail_pcalloc = 1;
    } else if (strcmp(name, "copy-data") == 0) {
        fail_pnalloc = 1;
    } else if (strcmp(name, "success-stable") == 0) {
        buffer.temporary = 0;
        buffer.in_file = 1;
        buffer.file = &file;
        buffer.file_last = 18;
    } else if (strcmp(name, "success-memory") != 0) {
        return 90;
    }

    rc = ngx_http_coraza_body_filter(&request, &input);

    if (strncmp(name, "success-", 8) == 0) {
        if (rc != NGX_OK || finalize_calls != 0 || !ctx.headers_delayed
            || ctx.intervention_triggered || ctx.pending_chain != &pending
            || pending.next != &allocated_chain
            || allocated_chain.buf != &allocated_buffer
            || ctx.pending_bytes != 36)
        {
            return 91;
        }
        return 0;
    }

    if (rc != NGX_HTTP_INTERNAL_SERVER_ERROR
        || !ctx.intervention_triggered || ctx.headers_delayed
        || ctx.pending_chain != NULL
        || ctx.pending_chain_last != &ctx.pending_chain
        || ctx.pending_bytes != 0 || finalize_calls != 1
        || finalized_status != NGX_HTTP_INTERNAL_SERVER_ERROR)
    {
        return 92;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    ngx_http_request_t request;
    ngx_connection_t   connection;
    ngx_pool_t         pool;
    ngx_log_t          log;
    ngx_buf_t          buffer;
    ngx_file_t         file;
    u_char            *data;
    size_t             len;

    if (argc == 2) {
        if (strcmp(argv[1], "chunked-reader") == 0) {
            return run_chunked_reader_cases();
        }
        return run_filter_case(argv[1]);
    }

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
    $coraza_include,
    "$root/src",
);

is(system($cc, '-D_GNU_SOURCE', '-O2', '-ffunction-sections', '-fdata-sections',
          '-Werror', '-Wno-unused-function', @includes, $source,
          '-Wl,--gc-sections', '-o', $binary), 0,
    'compiled production response-file reader harness');

is(system($binary), 0, 'file EOF fails closed');

for my $case (qw(chain-link stable-buffer file-read copy-buffer copy-data)) {
    is(system($binary, $case), 0,
        "$case failure finalizes HTTP 500 and clears pending buffers");
}

is(system($binary, 'chunked-reader'), 0,
    'bounded chunked response-file reader enforces range and failure paths');

for my $case (qw(success-stable success-memory)) {
    is(system($binary, $case), 0,
        "$case control retains the delayed response");
}

ok(-x $binary, 'focused harness is executable');
