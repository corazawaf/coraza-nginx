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

# The static-build filter reorder runs as shell; execute the block from config
# against synthetic HTTP_FILTER_MODULES lists.  CI only builds the dynamic
# module, so this is the only coverage of the static path.

my ($reorder) = $config =~ /^(if test "\$ngx_module_link" != DYNAMIC; then\n.*?^fi\n)/ms;
ok(defined $reorder, 'static-build filter reorder block found in config');

my $C = 'ngx_http_coraza_module';
my $H = 'ngx_http_coraza_headers_module';
my $R = 'ngx_http_range_header_filter_module';
my $G = 'ngx_http_gzip_filter_module';
my $W = 'ngx_http_write_filter_module';

is_deeply(reorder('', "$W $R $G $C"), { list => "$W $H $R $G $C", out => '' },
	'old-style static: companion registered just before the range header filter');

is_deeply(reorder('ADDON', "$W $R $G $C $H"),
	{ list => "$W $H $R $G $C", out => '' },
	'ADDON static: companion moved before range, not duplicated');

my $miss = reorder('', "$W $G $C");
is($miss->{list}, "$W $G $C $H",
	'range anchor missing: companion still registered (appended last)');
like($miss->{out}, qr/warning: $R not found/,
	'range anchor missing: configure prints a warning');

is(reorder('', '')->{list}, $H, 'empty filter list: companion still registered');

is_deeply(reorder('DYNAMIC', "$W $R $G $C"), { list => "$W $R $G $C", out => '' },
	'dynamic build: HTTP_FILTER_MODULES left untouched');

done_testing();

###############################################################################

sub reorder {
	my ($link, $modules) = @_;
	my $script = "ngx_module_link='$link'\nHTTP_FILTER_MODULES='$modules'\n"
		. $reorder . 'echo "LIST=$HTTP_FILTER_MODULES"' . "\n";
	open my $fh, '-|', 'sh', '-c', $script or die "sh: $!";
	my @lines = <$fh>;
	close $fh;
	die "reorder script failed: $?" if $?;
	my ($list) = map { /^LIST=(.*)/ ? $1 : () } @lines;
	my $out = join '', grep { !/^LIST=/ } @lines;
	$list =~ s/^\s+|\s+$//g;
	$list =~ s/\s+/ /g;
	return { list => $list, out => $out };
}

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
