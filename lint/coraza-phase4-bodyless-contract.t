#!/usr/bin/perl

# Static regression check for bodyless responses in the header filter
# (issues #165 and #166).
#
# A HEAD request, a 204, a 304 and a response the handler already marked
# header_only (ngx_http_dav_module's PUT) never get a body-filter call, so
# phase 4 can only run from the header filter's finalise-before-headers
# branch.  That branch must therefore admit them regardless of
# coraza_delay_response_headers, while the delay branch must keep them out.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_header_filter.c");

# the bodyless predicate covers all four forms
like($src,
	qr/bodyless\s*=\s*r->header_only\s*\|\|\s*r->method\s*==\s*NGX_HTTP_HEAD\s*\|\|\s*r->headers_out\.status\s*==\s*NGX_HTTP_NO_CONTENT\s*\|\|\s*r->headers_out\.status\s*==\s*NGX_HTTP_NOT_MODIFIED;/s,
	'bodyless covers header_only, HEAD, 204 and 304');

# the finalise branch admits bodyless responses in both delay modes: the
# delay flag only gates the "body not inspected" alternative
like($src,
	qr/if\s*\(!r->error_page\s*&&\s*r\s*==\s*r->main\s*&&\s*r->headers_out\.status\s*!=\s*NGX_HTTP_SWITCHING_PROTOCOLS\s*&&\s*\(bodyless\s*\|\|\s*\(mcf->delay_response_headers\s*&&\s*!ctx->response_body_processable\)\)\)/s,
	'finalise branch runs for bodyless responses regardless of the delay flag');

# phase 4 is finalised in that branch and the body filter is told so
like($src,
	qr/\(bodyless\s*\|\|.*?coraza_process_response_body\(ctx->coraza_transaction\);\s*ctx->response_phase4_done\s*=\s*1;/s,
	'finalise branch runs phase 4 and marks it done');

# the delay branch still excludes every bodyless form
like($src,
	qr/if\s*\(mcf->delay_response_headers\s*&&\s*r->method\s*!=\s*NGX_HTTP_HEAD\s*&&\s*!r->header_only\s*&&\s*!r->error_page.*?NGX_HTTP_NO_CONTENT.*?NGX_HTTP_NOT_MODIFIED.*?ngx_http_coraza_is_sse_response\(r\)\)/s,
	'delay branch keeps HEAD, header_only, 204 and 304 out');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
