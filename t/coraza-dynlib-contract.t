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

like($control, qr/\blibcoraza1\s+\(>=\s*1\.4\.0\)/,
	'Debian package pins the libcoraza runtime ABI');

unlike($dl, qr/Optional.*coraza_is_response_body_processable/s,
	'response-body helper is not documented as optional');

unlike($dl, qr/libcoraza\s*<\s*1\.4/,
	'loader comments do not advertise pre-1.4 compatibility');

like($dl, qr/DL_SYM\(dl_is_response_body_processable,\s*\n\s*coraza_is_response_body_processable\)/,
	'response-body helper is resolved as a required symbol');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
