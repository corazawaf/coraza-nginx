#!/usr/bin/perl

# Static contract checks for bounded file-backed response-body inspection.

use warnings;
use strict;

use Test::More;
use FindBin;

my $root = "$FindBin::Bin/..";
my $body_filter = slurp("$root/src/ngx_http_coraza_body_filter.c");

like($body_filter,
    qr/#define NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE \(64 \* 1024\)/,
    'file-backed response inspection uses 64 KiB chunks');

like($body_filter,
    qr/file_last - offset\s*>\s*\(off_t\) NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE.*?size = NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE/s,
    'file read size is capped before allocation and read');

like($body_filter,
    qr/ngx_alloc\(NGX_HTTP_CORAZA_RESPONSE_BODY_FILE_CHUNK_SIZE,.*?while \(offset < buf->file_last\).*?ngx_read_file\(buf->file, data, size, offset\).*?coraza_append_response_body.*?ngx_free\(data\)/s,
    'one scratch buffer is reused and released across file chunks');

like($body_filter,
    qr/if \(buf->file->directio\).*?ngx_directio_off\(buf->file->fd\).*?while \(offset < buf->file_last\).*?ngx_read_file\(buf->file, data, size, offset\).*?if \(directio_disabled\).*?ngx_directio_on\(buf->file->fd\)/s,
    'direct I/O is disabled around reads into the reusable scratch buffer');

like($body_filter,
    qr/if \(!ngx_buf_in_memory\(chain->buf\).*?ngx_http_coraza_append_response_body_file\(ctx, r,\s*chain->buf\)/s,
    'file-backed response buffers use the bounded reader');

like($body_filter,
    qr/ngx_http_coraza_append_response_body_file\(ctx, r,\s*chain->buf\) != NGX_OK\).*?headers_delayed = 0;.*?NGX_HTTP_INTERNAL_SERVER_ERROR.*?ngx_http_filter_finalize_request/s,
    'file inspection failures use the normal fail-closed response path');

like($body_filter,
    qr/if \(!ngx_buf_in_memory\(chain->buf\)\s*&& chain->buf->in_file\s*&& chain->buf->file != NULL\s*&& !chain->buf->temp_file\).*?\*b = \*chain->buf/s,
    'stable delayed file ranges are retained without a body-sized pool copy');

like($body_filter,
    qr/if \(is_last\).*?coraza_process_response_body\(ctx->coraza_transaction\)/s,
    'last file buffer still finalizes phase-4 inspection');

done_testing();

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!";
    local $/ = undef;
    return <$fh>;
}
