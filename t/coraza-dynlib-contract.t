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

unlike($dl, qr/DL_SYM\([^,]+,\s*coraza_rules_merge\)/,
	'dead coraza_rules_merge symbol is not required at startup');

unlike($dl, qr/DL_SYM\([^,]+,\s*coraza_add_get_args\)/,
	'dead coraza_add_get_args symbol is not required at startup');

unlike($dl, qr/\bfn_coraza_(?:rules_merge|add_get_args)\b/,
	'dead Coraza function pointer typedefs are removed');

unlike($dl, qr/\bdl_(?:rules_merge|add_get_args)\b/,
	'dead Coraza function pointers are removed');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
