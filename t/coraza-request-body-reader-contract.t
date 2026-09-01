#!/usr/bin/perl

# Static contract checks for the connector-owned temp-file request-body reader.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";

my $pre_access = slurp("$root/src/ngx_http_coraza_pre_access.c");
my $dl = slurp("$root/src/ngx_http_coraza_dl.c");

like($pre_access,
	qr/#define NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE \(64 \* 1024\)/,
	'temp-file reader uses 64 KiB chunks');

like($pre_access,
	qr/body_size - offset\s*> \(off_t\) NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE\).*?size = NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE/s,
	'read size is capped by the 64 KiB chunk constant');

like($pre_access,
	qr/while \(offset < body_size\).*?ngx_read_file\(&file, data, size, offset\).*?coraza_append_request_body/s,
	'temp-file reader appends each bounded file chunk');

like($pre_access,
	qr/while \(offset < body_size\).*?coraza_append_request_body.*?ngx_http_coraza_process_intervention/s,
	'temp-file reader stops promptly on an intervention');

like($pre_access,
	qr/ngx_alloc\(NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE,.*?while \(offset < body_size\).*?ngx_free\(data\)/s,
	'temp-file reader reuses and releases one chunk buffer');

unlike($pre_access, qr/\bcoraza_request_body_from_file\b/,
	'pre-access path no longer delegates file reads to libcoraza');

unlike($dl, qr/\b(?:fn_|dl_)?coraza_request_body_from_file\b/,
	'unused libcoraza file-reader symbol is not required at runtime');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
