#!/usr/bin/perl

# Static regression checks for request context publication after construction.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_module.c");

my $body = create_ctx_body($src);

if (!defined $body) {
	fail('ngx_http_coraza_create_ctx body could be extracted');
	done_testing();
	exit;
}

pass('ngx_http_coraza_create_ctx body could be extracted');

# comments are dropped so that prose cannot satisfy or confuse the order checks
$body =~ s{/\*.*?\*/}{ }gs;
$body =~ s{//[^\n]*}{ }g;

my $set = qr/ngx_http_set_ctx\s*\(\s*r\s*,\s*ctx\s*,\s*ngx_http_coraza_module\s*\)\s*;/;

my @sets;
push @sets, $-[0] while $body =~ /$set/g;
is(scalar @sets, 1,
	'request context is published exactly once in ngx_http_coraza_create_ctx');

SKIP: {
	skip 'no single publication point to order', 4 if @sets != 1;

	my $at = $sets[0];

	my @fails;
	push @fails, $-[0] while $body =~ /\breturn\s+NULL\s*;/g;
	cmp_ok(scalar @fails, '>', 0, 'create_ctx has failure returns to order against');

	my @late = grep { $_ > $at } @fails;
	is(scalar @late, 0,
		'request context is published after every failure return');

	my $cln = index($body, 'ngx_pool_cleanup_add');
	ok($cln >= 0 && $cln < $at,
		'request context is published after the cleanup registration');

	like(substr($body, $at),
		qr/\A$set\s*return\s+ctx\s*;\s*\}\s*\z/,
		'request context publication is immediately followed by return ctx');
}

done_testing();

###############################################################################

sub create_ctx_body {
	my ($text) = @_;

	$text =~ /^ngx_http_coraza_create_ctx\(ngx_http_request_t \*r\)[ \t]*\n(\{\n.*?\n\})[ \t]*$/ms
		or return undef;
	return $1;
}

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
