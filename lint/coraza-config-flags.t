#!/usr/bin/perl

# Static regression checks for nginx addon config flags.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $config = slurp("$root/config");

unlike($config, qr/ngx_module_incs=.*-L/,
	'linker search paths are not placed in ngx_module_incs');

like($config, qr/ngx_module_libs="-ldl"/,
	'dynamic module links against libdl');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
