#!/usr/bin/perl

# Static regression check for final-location transaction binding.
#
# The connector must not create its transaction in a REWRITE-phase handler:
# nginx runs module handlers registered there before ngx_http_rewrite_module
# itself, so the transaction would bind to the location a `rewrite ... last`
# is about to leave. Binding happens in PREACCESS once routing has settled,
# in the response header filter for an early response that skips PREACCESS,
# and in LOG, audit-only, for a headerless exit such as `return 444`. The header
# filter binds the main request only, so a subrequest issued by an enabled
# location never starts a transaction of its own there. The
# behavioural test is t/coraza-rewrite-location-policy.t; this file pins the
# registration and the audit-only guard that the socket test cannot reach.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $module = slurp("$root/src/ngx_http_coraza_module.c");
my $header = slurp("$root/src/ngx_http_coraza_common.h");
my $rewrite = slurp("$root/src/ngx_http_coraza_rewrite.c");
my $preaccess = slurp("$root/src/ngx_http_coraza_pre_access.c");
my $filter = slurp("$root/src/ngx_http_coraza_header_filter.c");
my $log = slurp("$root/src/ngx_http_coraza_log.c");

my ($init) = $module =~ /(ngx_http_coraza_init\(ngx_conf_t \*cf\)\s*\{.*?^\})/ms;
ok(defined $init, 'module initializer found');

unlike($init, qr/NGX_HTTP_REWRITE_PHASE/,
	'no handler is registered in the REWRITE phase');

like($init,
	qr/phases\[NGX_HTTP_PREACCESS_PHASE\]\.handlers\).*?=\s*ngx_http_coraza_pre_access_handler;/s,
	'the PREACCESS handler is registered');

like($init,
	qr/phases\[NGX_HTTP_LOG_PHASE\]\.handlers\).*?=\s*ngx_http_coraza_log_handler;/s,
	'the LOG handler is registered');

unlike($header, qr/ngx_http_coraza_rewrite_handler/,
	'the old rewrite handler is no longer declared');

like($header,
	qr/ngx_int_t ngx_http_coraza_request_headers\(ngx_http_request_t \*r,\s*ngx_flag_t audit_only\);/,
	'request-header processing takes an audit_only flag');

like($preaccess,
	qr/ngx_http_coraza_request_headers\(r, 0\);\s*if \(header_rc != NGX_DECLINED\)\s*\{\s*return header_rc;/s,
	'PREACCESS binds the transaction before request-body processing');

like($filter,
	qr/if \(ctx == NULL\) \{\s*if \(mcf->enable != 1\)\s*\{\s*return ngx_http_next_header_filter\(r\);\s*\}.*?ngx_http_coraza_request_headers\(r, 0\);/s,
	'the header filter binds an enabled location that skipped PREACCESS');

like($filter,
	qr/if \(mcf->enable != 1\)\s*\{\s*return ngx_http_next_header_filter\(r\);\s*\}.*?if \(r != r->main\)\s*\{\s*return ngx_http_next_header_filter\(r\);\s*\}\s*(?:\/\*.*?\*\/\s*)?rc = ngx_http_coraza_request_headers\(r, 0\);/s,
	'the header filter binds only the main request; a subrequest passes through');

like($filter,
	qr/if \(ctx == NULL \|\| ctx->coraza_transaction == 0\) \{\s*return NGX_ERROR;/s,
	'the header filter ends the request when binding left no usable context');

like($filter,
	qr/if \(r->err_status\) \{\s*return ngx_http_filter_finalize_request\(r,\s*&ngx_http_coraza_module, rc\);\s*\}.*?return rc;/s,
	'an early denial keeps filter finalization only for a special response');

like($log,
	qr/if \(ctx == NULL\) \{.*?ngx_http_coraza_request_headers\(r, 1\);.*?audit_only = 1;/s,
	'LOG binds a headerless exit in audit-only mode');

like($log,
	qr/if \(audit_only\) \{.*?coraza_update_status_code\(ctx->coraza_transaction,\s*\(int\) r->headers_out\.status\);/s,
	'the audit-only path records the completed status in Coraza');

like($rewrite,
	qr/pret = coraza_process_request_headers\(ctx->coraza_transaction\);\s*if \(audit_only\) \{[^}]*return NGX_DECLINED;\s*\}\s*dd\(.*?\);\s*ret = ngx_http_coraza_poll_after_process\(/s,
	'the audit-only path never applies an intervention');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
