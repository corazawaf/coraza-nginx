#!/usr/bin/perl

# Static contract checks for the libcoraza dlopen boundary.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";

my $control = slurp("$root/debian/control");
my $dl = slurp("$root/src/ngx_http_coraza_dl.c");

like($control, qr/\blibcoraza1\s+\(>=\s*1\.7\)/,
	'Debian package pins the libcoraza runtime ABI');

unlike($dl, qr/Optional.*coraza_is_response_body_processable/s,
	'response-body helper is not documented as optional');

unlike($dl, qr/libcoraza\s*<\s*1\.4/,
	'loader comments do not advertise pre-1.4 compatibility');

like($dl, qr/DL_SYM\(dl_is_response_body_processable,\s*coraza_is_response_body_processable\)/s,
	'response-body helper is resolved as a required symbol');

like($dl, qr/DL_SYM\(dl_is_request_body_accessible,\s*coraza_is_request_body_accessible\)/s,
	'request-body helper is resolved as a required symbol');

like($dl, qr/return\s+dl_is_request_body_accessible\(t\)/,
	'request-body helper wrapper calls the resolved symbol');

# The bulk-header wrappers dereference these pointers unconditionally -- the
# NULL guards were removed once >= 1.7 became a hard floor -- so a downgrade to
# DL_SYM_OPT would turn the first header-bearing request into a NULL call.
like($dl, qr/DL_SYM\(dl_add_request_headers,\s*coraza_add_request_headers\)/s,
	'bulk request-header entry point is resolved as a required symbol');

like($dl, qr/DL_SYM\(dl_add_response_headers,\s*coraza_add_response_headers\)/s,
	'bulk response-header entry point is resolved as a required symbol');

unlike($dl, qr/DL_SYM_OPT\([^,]+,\s*coraza_add_(?:request|response)_headers\)/s,
	'bulk header entry points are not downgraded to optional symbols');

unlike($dl, qr/DL_SYM\([^,]+,\s*coraza_rules_merge\)/,
	'dead coraza_rules_merge symbol is not required at startup');

unlike($dl, qr/DL_SYM\([^,]+,\s*coraza_add_get_args\)/,
	'dead coraza_add_get_args symbol is not required at startup');

unlike($dl, qr/\bfn_coraza_(?:rules_merge|add_get_args)\b/,
	'dead Coraza function pointer typedefs are removed');

unlike($dl, qr/\bdl_(?:rules_merge|add_get_args)\b/,
	'dead Coraza function pointers are removed');

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
