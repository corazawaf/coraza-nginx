#!/usr/bin/perl

# Static regression checks for response-header insertion error handling.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_header_filter.c");

my @raw_calls = $src =~ /\bcoraza_add_response_header\s*\(/g;
is(scalar @raw_calls, 1,
	'raw coraza_add_response_header call is confined to the checked helper');

like($src,
	qr/static ngx_int_t\s+ngx_http_coraza_add_response_header.*?<\s*0.*?return NGX_ERROR.*?return NGX_OK/s,
	'checked helper maps Coraza header-add failures to NGX_ERROR');

like($src,
	qr/rc\s*=\s*ngx_http_coraza_headers_out\[i\]\.resolver\(.*?if\s*\(rc\s*!=\s*NGX_OK\)\s*\{\s*return rc;/s,
	'built-in response-header resolver failures are propagated');

like($src,
	qr/rc\s*=\s*ngx_http_coraza_add_response_header\(r,\s*ctx,\s*&data\[i\]\.key,\s*&data\[i\]\.value\).*?if\s*\(rc\s*!=\s*NGX_OK\)\s*\{\s*return rc;/s,
	'dynamic response-header list insertion failures are propagated');

unlike($src,
	qr/^\s*ngx_http_coraza_headers_out\[i\]\.resolver\(/m,
	'resolver return values are not discarded');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
