#!/usr/bin/perl

# Regression for the r->http_version -> WAF protocol string mapping.
#
# The rewrite handler translates r->http_version into the protocol string
# handed to coraza_process_uri(). A missing case falls through to the
# "1.0" default, so HTTP/3 requests were reported to the WAF as HTTP/1.0
# and rules keyed on REQUEST_PROTOCOL silently did not match.
#
# The mapping lives inside ngx_http_coraza_rewrite_handler(), which needs a
# live request and transaction, so it cannot be called directly. Instead
# extract the switch body from the source and compile it standalone against
# nginx's real NGX_HTTP_VERSION_* constants, then assert what it produces.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;
use File::Temp qw/tempdir/;

###############################################################################

# The tests may run from the repo (t/../) or from an unpacked nginx-tests
# checkout with t/* copied in, so locate the module source and the nginx
# build tree rather than assuming either sits at a fixed path.
my $root = find_root();
my $nginx = find_nginx($root);
my $source = defined $root ? "$root/src/ngx_http_coraza_rewrite.c" : undef;

plan skip_all => 'cc not found' unless command_exists('cc');
plan skip_all => 'rewrite source not available'
	unless defined $source && -f $source;
plan skip_all => 'nginx build tree not available' unless defined $nginx;

# Pull the switch statement out of the real source so this test cannot
# drift away from the code it guards.
my $switch = extract_switch($source);
plan skip_all => 'could not locate http_version switch' unless defined $switch;

plan tests => 6;

like($switch, qr/NGX_HTTP_VERSION_30/,
	'source has an explicit HTTP/3 case');

my $tmp = tempdir(CLEANUP => 1);

my $driver = <<"EOF";
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>

/* nginx < 1.25.0 has no HTTP/3 and does not define this. Define it so the
 * mapping can still be exercised: the value is what the module's own guard
 * compares against, and the switch case is compiled out there anyway. */
#ifndef NGX_HTTP_VERSION_30
#define NGX_HTTP_VERSION_30 3000
#endif

static const char *map_version(ngx_uint_t v)
{
    char *http_version = NULL;
    ngx_uint_t r_http_version = v;

$switch

    return http_version;
}

int main(void)
{
    printf("9=%s\\n",  map_version(NGX_HTTP_VERSION_9));
    printf("10=%s\\n", map_version(NGX_HTTP_VERSION_10));
    printf("11=%s\\n", map_version(NGX_HTTP_VERSION_11));
    printf("20=%s\\n", map_version(NGX_HTTP_VERSION_20));
    printf("30=%s\\n", map_version(NGX_HTTP_VERSION_30));
    printf("xx=%s\\n", map_version(4000));
    printf("ver=%d\\n", (int) nginx_version);
    return 0;
}
EOF

my $csrc = "$tmp/map.c";
open my $fh, '>', $csrc or die "open: $!";
print $fh $driver;
close $fh;

my @includes = map { "-I$_" } (
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

my @cmd = ('cc', @includes, '-o', "$tmp/map", $csrc);
my $shell = join ' ', map { quotemeta } @cmd;
my $out = `$shell 2>&1`;

unless ($? == 0) {
	diag($out);
	BAIL_OUT('protocol-map driver failed to compile');
}

my %got = map { /^(\w+)=(.*)$/ ? ($1 => $2) : () } split /\n/, `$tmp/map`;

is($got{9},  '0.9', 'HTTP/0.9 maps to 0.9');
is($got{11}, '1.1', 'HTTP/1.1 maps to 1.1');
is($got{20}, '2.0', 'HTTP/2 maps to 2.0');
is($got{xx}, '1.0', 'unknown version falls back to 1.0');

# The module guards its HTTP/3 case on nginx >= 1.25.0, so on an older
# nginx the case is compiled out and HTTP/3 legitimately maps to the
# default. Only assert the fixed behaviour where the case is live.
SKIP: {
	skip "nginx $got{ver} predates HTTP/3", 1 if $got{ver} < 1025000;

	is($got{30}, '3.0', 'HTTP/3 maps to 3.0, not the 1.0 default');
}

###############################################################################

# Read the switch on r->http_version out of the rewrite handler and rewrite
# the scrutinee so it compiles against a plain local variable.
sub extract_switch {
	my ($file) = @_;

	open my $in, '<', $file or return undef;
	my $text = do { local $/; <$in> };
	close $in;

	return undef unless $text =~ /
		(switch \s* \( \s* r->http_version \s* \) \s* \{ .*? \n \s* \})
	/sx;

	my $block = $1;
	$block =~ s/r->http_version/r_http_version/;
	return $block;
}

# Walk up looking for the module source tree. Covers both running from the
# repo's own t/ and from an unpacked nginx-tests dir inside the workspace.
sub find_root {
	my $dir = $FindBin::Bin;

	for (0 .. 4) {
		return $dir if -f "$dir/src/ngx_http_coraza_rewrite.c";
		$dir = "$dir/..";
	}

	return undef;
}

# Find any configured nginx build tree near the workspace. The version is
# not pinned here: CI has built 1.24.0 and may move later, and this test
# only needs the NGX_HTTP_VERSION_* constants plus ngx_auto_config.h.
sub find_nginx {
	my ($root) = @_;
	return undef unless defined $root;

	for my $base ($root, "$root/..") {
		for my $cand (sort glob("$base/nginx-*")) {
			return $cand if -f "$cand/objs/ngx_auto_config.h";
		}
	}

	return undef;
}

sub command_exists {
	my ($cmd) = @_;
	for my $dir (split /:/, $ENV{PATH}) {
		return 1 if -x "$dir/$cmd";
	}
	return 0;
}
