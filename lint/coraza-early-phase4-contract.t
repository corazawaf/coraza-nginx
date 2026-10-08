#!/usr/bin/perl

# Static regression check for the early phase-4 branch of the header filter
# (response body not inspected, coraza_delay_response_headers on).
#
# That branch finalises phase 4 before any header goes out.  If the engine
# fails (phase-4 processing error, or the intervention poll returns < 0) the
# request must be finalised with a 500 and must NOT fall through to
# ngx_http_next_header_filter(), which would forward headers of a response
# the engine could not vet.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_header_filter.c");

my $start_anchor = '!ctx->response_body_processable';
my $end_anchor = 'if (mcf->delay_response_headers';

my $start = index($src, $start_anchor);
my $end = $start < 0 ? -1 : index($src, $end_anchor, $start);
my $block = $end > $start && $start >= 0
	? substr($src, $start, $end - $start) : '';

ok($block ne '', 'early phase-4 block located')
	or diag('anchor not found in src/ngx_http_coraza_header_filter.c');

my $fin500 = qr/return\s+ngx_http_filter_finalize_request\(\s*r,\s*&ngx_http_coraza_module,\s*NGX_HTTP_INTERNAL_SERVER_ERROR\);/;

like($block,
	qr/ngx_http_coraza_process_body_failed\(pret\)\)\s*\{[^{}]*?$fin500\s*\}/s,
	'phase-4 processing error finalises with 500');

like($block,
	qr/if\s*\(ret\s*<\s*0\)\s*\{[^{}]*?$fin500\s*\}/s,
	'intervention poll error finalises with 500');

# the only header forwarding allowed before the final one is in the
# error_page and redirect branches, never ahead of the error checks
my $first_fwd = index($block, 'ngx_http_next_header_filter(r)');
my $fail_at = index($block, 'ngx_http_coraza_process_body_failed(pret)');
ok($first_fwd > $fail_at && $fail_at >= 0,
	'processing error is checked before any header is forwarded');

# once the error_page and redirect branches are cut out, nothing ahead of the
# intervention poll error may forward headers
my $poll_fail_at = index($block, 'if (ret < 0)');
ok($poll_fail_at >= 0, 'intervention poll error check located');
my $pre_poll = substr($block, 0, $poll_fail_at < 0 ? 0 : $poll_fail_at);
my $allowed = 0;
$allowed += $pre_poll =~ s{
	if\s*\(r->error_page\)\s*\{
		\s*return\s+ngx_http_next_header_filter\(r\);\s*
	\}
}{}sx;
$allowed += $pre_poll =~ s{
	if\s*\(ngx_http_coraza_is_redirect_status\(ret\)\s*&&\s*r->headers_out\.location\)\s*\{
		[^{}]*?return\s+ngx_http_next_header_filter\(r\);\s*
	\}
}{}sx;
is($allowed, 2, 'error_page and redirect forwarding branches located');
unlike($pre_poll, qr/ngx_http_next_header_filter\(r\)/,
	'no unapproved header forwarding precedes the intervention poll error');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/;
	return <$fh>;
}
