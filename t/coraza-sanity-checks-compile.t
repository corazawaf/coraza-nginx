#!/usr/bin/perl

# Compile regression for the CORAZA_SANITY_CHECKS debug macro.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;
use File::Temp qw/tempdir/;

###############################################################################

my $root = "$FindBin::Bin/..";
my $nginx = "$root/nginx-1.28.0";

plan skip_all => 'cc not found' unless command_exists('cc');
plan skip_all => 'nginx build tree not available'
	unless -f "$nginx/objs/ngx_auto_config.h";
plan skip_all => 'coraza headers not available'
	unless -f '/usr/local/include/coraza/coraza.h';

my $tmp = tempdir(CLEANUP => 1);
my @includes = map { "-I$_" } (
	'/usr/local/include',
	"$nginx/src/core",
	"$nginx/src/event",
	"$nginx/src/event/modules",
	"$nginx/src/event/quic",
	"$nginx/src/os/unix",
	"$nginx/objs",
	"$nginx/src/http",
	"$nginx/src/http/modules",
	"$nginx/src/http/v2",
);

compile_ok('src/ngx_http_coraza_module.c', "$tmp/module.o");
compile_ok('src/ngx_http_coraza_header_filter.c', "$tmp/header_filter.o");

done_testing();

###############################################################################

sub compile_ok {
	my ($source, $object) = @_;
	my @cmd = (
		'cc',
		'-c',
		'-fPIC',
		'-Werror',
		'-DCORAZA_SANITY_CHECKS=1',
		@includes,
		'-o',
		$object,
		"$root/$source",
	);

	my $ok = system(@cmd) == 0;
	ok($ok, "$source compiles with CORAZA_SANITY_CHECKS=1");
}

sub command_exists {
	my ($cmd) = @_;
	for my $dir (split /:/, $ENV{PATH}) {
		return 1 if -x "$dir/$cmd";
	}
	return 0;
}
