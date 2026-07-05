#!/usr/bin/perl

# Static contract checks for the libcoraza dlopen boundary.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";

my $dl = slurp("$root/src/ngx_http_coraza_dl.c");

my ($close_body) = $dl =~
	qr/ngx_http_coraza_dl_close\s*\([^)]*\)\s*\{(.*?)\n\}/s;

ok(defined $close_body, 'found ngx_http_coraza_dl_close body');

unlike($close_body, qr/\bdynlib_close\b/,
	'worker exit does not unload the Go-backed libcoraza handle');

unlike($close_body, qr/\bdl_handle\s*=\s*NULL\b/,
	'worker exit keeps the loaded libcoraza handle intact');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
