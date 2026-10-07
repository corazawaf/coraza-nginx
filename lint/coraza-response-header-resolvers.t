#!/usr/bin/perl

# Static regression checks for the response-header resolvers that synthesize
# values nginx computes late (Server, Content-Type, Transfer-Encoding, Vary).
# Source-text assertions only: they pin the synthesis code and the error
# contracts (allocation, overflow and collector failures return NGX_ERROR).
# Runtime coverage of these headers is in
# t/coraza-header-transform-fidelity.t and t/coraza-header-fidelity.t.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_header_filter.c");

my $fn_will_chunk = func($src, 'will_chunk');
my $fn_server = func($src, 'resolv_header_server');
my $fn_ctype = func($src, 'resolv_header_content_type');
my $fn_te = func($src, 'resolv_header_transfer_encoding');
my $fn_vary = func($src, 'resolv_header_vary');

my $collect = qr/return\s+ngx_http_coraza_add_response_header\s*\(\s*r\s*,\s*ctx\s*,\s*&name\s*,\s*&value\s*\)\s*;/;

# Synthesis (moved from t/coraza-synth-response-headers.t).

like($fn_te,
	qr/ngx_http_coraza_will_chunk\(r\).*?ngx_string\("chunked"\).*?ngx_http_coraza_add_response_header/s,
	'Transfer-Encoding: chunked is synthesized to the WAF when the response will be chunked');

like($fn_vary,
	qr/r->gzip_vary\s*&&\s*clcf->gzip_vary.*?ngx_string\("Accept-Encoding"\).*?ngx_http_coraza_add_response_header/s,
	'Vary: Accept-Encoding is synthesized AND delivered to the WAF when gzip_vary applies');

# will_chunk returns a flag: NGX_ERROR (-1) would read as true.

ok(length($fn_will_chunk) && $fn_will_chunk !~ /NGX_ERROR|NGX_DECLINED|NGX_AGAIN/,
	'will_chunk never returns an ngx_int_t error code from a flag function');

like($fn_will_chunk,
	qr/NGX_HTTP_VERSION_11.*?NGX_HTTP_NO_CONTENT.*?NGX_HTTP_NOT_MODIFIED.*?NGX_HTTP_HEAD.*?NGX_HTTP_CONNECT.*?return 0;/s,
	'will_chunk rejects non-HTTP/1.1, 204, 304, HEAD and CONNECT before choosing chunked');

like($fn_will_chunk, qr/r\s*!=\s*r->main/,
	'will_chunk rejects subrequests');

like($fn_will_chunk,
	qr/chunked_transfer_encoding\s*&&\s*\(\s*r->headers_out\.content_length_n\s*==\s*-1\s*\|\|\s*r->expect_trailers\s*\)/,
	'will_chunk requires chunked_transfer_encoding and an unknown length or trailers');

# Collector failures are propagated by every resolver.

like($fn_server, $collect,
	'Server resolver returns the collector result');
like($fn_te, qr/return\s+ngx_http_coraza_add_response_header\s*\(/,
	'Transfer-Encoding resolver returns the collector result');
like($fn_vary, qr/return\s+ngx_http_coraza_add_response_header\s*\(/,
	'Vary resolver returns the collector result');
like($fn_ctype,
	qr/return\s+ngx_http_coraza_add_response_header\s*\(\s*r\s*,\s*ctx\s*,\s*&name\s*,\s*&value\s*\)/,
	'Content-Type resolver returns the collector result');

# Content-Type charset composition: overflow and allocation failures.

like($fn_ctype,
	qr/NGX_MAX_SIZE_T_VALUE.*?\)\s*\{\s*return NGX_ERROR;\s*\}.*?ngx_pnalloc/s,
	'Content-Type length overflow returns NGX_ERROR before allocating');

like($fn_ctype,
	qr/value\.data\s*=\s*ngx_pnalloc\(.*?\);\s*if\s*\(value\.data\s*==\s*NULL\)\s*\{\s*return NGX_ERROR;\s*\}/s,
	'Content-Type allocation failure returns NGX_ERROR');

like($fn_ctype,
	qr/if\s*\(r->headers_out\.content_type\.len\s*>\s*0\)/,
	'Content-Type resolver skips an empty content type');

unlike($fn_ctype, qr/headers_out\.content_type\s*=[^=]/,
	'Content-Type resolver does not modify headers_out.content_type');

done_testing();

###############################################################################

sub func {
	my ($code, $name) = @_;

	my @m = $code =~ /(^static\s+ngx_(?:int|flag)_t\s+ngx_http_coraza_\Q$name\E\s*\([^;{]*?\)\s*\{.*?^\})/msg;

	return $m[0] if @m == 1;
	diag("expected exactly one $name definition, found " . scalar(@m));
	return '';
}

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
