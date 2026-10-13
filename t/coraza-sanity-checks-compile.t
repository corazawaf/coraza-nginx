#!/usr/bin/perl

# Compile regression for the CORAZA_SANITY_CHECKS compatibility no-op.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;
use File::Temp qw/tempdir/;

###############################################################################

my $root = "$FindBin::Bin/..";
my $nginx = $ENV{TEST_NGINX_SOURCE};
my $ci = defined $ENV{CI} && $ENV{CI} eq 'true';

# A local run may opt out by leaving the source unset.  CI, or any explicit
# source selection, promises compilation and must fail on missing prerequisites.
plan skip_all => 'set TEST_NGINX_SOURCE to a configured nginx source tree'
	unless defined $nginx || $ci;
BAIL_OUT('TEST_NGINX_SOURCE must name a configured nginx source tree')
	unless defined $nginx && length $nginx;
BAIL_OUT('cc not found') unless command_exists('cc');
for my $header (qw(ngx_auto_config.h ngx_auto_headers.h)) {
	BAIL_OUT("TEST_NGINX_SOURCE is missing objs/$header")
		unless -f "$nginx/objs/$header";
}

my ($coraza_include) = grep { -f "$_/coraza/coraza.h" }
	(defined $ENV{TEST_LIBCORAZA_INCLUDE} ? ($ENV{TEST_LIBCORAZA_INCLUDE})
		: qw(/usr/local/include /usr/include));
BAIL_OUT('coraza headers not available') unless defined $coraza_include;

my $tmp = tempdir(CLEANUP => 1);
my @includes = map { "-I$_" } (
	$coraza_include,
	"$nginx/src/core",
	"$nginx/src/event",
	"$nginx/src/event/modules",
	"$nginx/src/event/quic",
	"$nginx/src/os/unix",
	"$nginx/objs",
	"$nginx/src/http",
	"$nginx/src/http/modules",
	"$nginx/src/http/v2",
	"$nginx/src/http/v3",
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

	# Redirect stderr to stdout and capture so a failing -Werror compile
	# surfaces the actual diagnostics in CI instead of just pass/fail.
	my $shell = join ' ', map { quotemeta } @cmd;
	my $output = `$shell 2>&1`;
	my $ok = $? == 0;
	diag($output) unless $ok;
	ok($ok, "$source compiles with CORAZA_SANITY_CHECKS=1");
}

sub command_exists {
	my ($cmd) = @_;
	for my $dir (split /:/, $ENV{PATH}) {
		return 1 if -x "$dir/$cmd";
	}
	return 0;
}
