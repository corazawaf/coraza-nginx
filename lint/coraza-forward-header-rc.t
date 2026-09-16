#!/usr/bin/perl

# Static regression check for delayed response header forwarding.
#
# forward_header() bottoms out in the write filter, which returns NGX_AGAIN
# (not just NGX_OK/NGX_ERROR) whenever the headers can't be fully flushed.
# Bailing on that NGX_AGAIN before handing pending_chain to the body filter
# orphans the buffered body (truncated response).  Only a hard NGX_ERROR may
# short-circuit; NGX_AGAIN must fall through to ngx_http_next_body_filter(),
# whose return value carries it back up.  See coraza-response-body-delayed.t
# for the behavioural (limit_rate) regression test.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_body_filter.c");

like($src,
	qr/rc\s*=\s*ngx_http_coraza_forward_header\(r\);\s*if\s*\(rc\s*==\s*NGX_ERROR\)\s*\{\s*return NGX_ERROR;\s*\}/s,
	'delayed header forwarding short-circuits only on NGX_ERROR');

unlike($src,
	qr/rc\s*=\s*ngx_http_coraza_forward_header\(r\);\s*if\s*\(rc\s*!=\s*NGX_OK\)/s,
	'delayed header forwarding does not strand the body on NGX_AGAIN');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
