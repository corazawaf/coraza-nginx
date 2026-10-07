#!/usr/bin/perl

# Compile the production early-finalization block with controlled engine results.
# Socket tests cover the real engine; this harness reaches its error contracts.
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw/tempdir/;

open my $src, '<', "$FindBin::Bin/../src/ngx_http_coraza_header_filter.c"
    or die "header filter: $!";
my $source = do { local $/; <$src> };
my @blocks = $source =~ /(    if \(mcf->delay_response_headers\n(?:(?!    if).)*?!ctx->response_body_processable\)\n    \{.*?\n    \})/sg;
is(scalar @blocks, 1, 'exactly one production early phase-4 branch');
BAIL_OUT('production branch missing or ambiguous') unless @blocks == 1;
my $dir = tempdir(CLEANUP => 1);
open my $c, '>', "$dir/early.c" or die "harness: $!";
print $c <<'C';
#include <stdio.h>
#include <string.h>
#define NGX_HTTP_HEAD 2
#define NGX_HTTP_SWITCHING_PROTOCOLS 101
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_LOG_ERR 3
#define ngx_log_error(...) ((void) 0)
static int ngx_http_coraza_module;
typedef struct request request;
struct request {
    int method, header_only, error_page;
    request *main;
    struct { int status, location; } headers_out;
};
typedef struct { int delay_response_headers; } config;
typedef struct {
    int response_body_processable, coraza_transaction;
    int response_phase4_done, intervention_triggered;
} context;
static int process_result, poll_result, reentry;
static int process_calls, poll_calls, next_calls, final_calls, redirect_calls;
static int coraza_process_response_body(int tx) {
    (void) tx; process_calls++; return process_result;
}
static int ngx_http_coraza_process_body_failed(int result) { return result < 0; }
static int ngx_http_coraza_poll_after_process(context *ctx, request *r, int x, int result) {
    (void) ctx; (void) x; (void) result;
    poll_calls++; if (reentry) r->error_page = 1; return poll_result;
}
static int ngx_http_next_header_filter(request *r) {
    (void) r; next_calls++; return 901;
}
static int ngx_http_filter_finalize_request(request *r, int *module, int status) {
    (void) r; (void) module; final_calls++; return status;
}
static int ngx_http_coraza_is_redirect_status(int status) {
    return status == 302;
}
static void ngx_http_coraza_prepare_redirect(request *r, int status) {
    (void) r; (void) status; redirect_calls++;
}
static int run(request *r, config *mcf, context *ctx) {
    int ret, pret;
C
print $c $blocks[0];
print $c <<'C';
    return 902;
}
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "case %d line %d: %s\n", i, __LINE__, #expr); return 1; \
} } while (0)
int main(void) {
    for (int i = 0; i < 15; i++) {
        request r = {0}, other = {0};
        context ctx = {0};
        config mcf = {1};
        r.main = &r; r.headers_out.status = 200;
        process_result = poll_result = reentry = 0;
        process_calls = poll_calls = next_calls = final_calls = redirect_calls = 0;
        switch (i) {
        case 1: mcf.delay_response_headers = 0; break;
        case 2: r.method = NGX_HTTP_HEAD; break;
        case 3: r.header_only = 1; break;
        case 4: r.error_page = 1; break;
        case 5: r.main = &other; break;
        case 6: r.headers_out.status = 101; break;
        case 7: ctx.response_body_processable = 1; break;
        case 8: process_result = -1; break;
        case 9: process_result = 1; poll_result = 403; break;
        case 10: poll_result = -1; break;
        case 11: poll_result = 302; r.headers_out.location = 1; break;
        case 12: poll_result = 302; break;
        case 13: poll_result = 403; reentry = 1; break;
        case 14: process_result = 1; break;
        }
        int result = run(&r, &mcf, &ctx);
        if (i >= 1 && i <= 7) {
            CHECK(result == 902 && process_calls == 0 && poll_calls == 0);
            CHECK(!ctx.response_phase4_done && !ctx.intervention_triggered);
            continue;
        }
        CHECK(process_calls == 1 && ctx.response_phase4_done == 1);
        CHECK(poll_calls == (i != 8));
        if (i == 8 || i == 10) {
            CHECK(result == 500 && final_calls == 1 && next_calls == 0);
            CHECK(ctx.intervention_triggered == 1);
        } else if (i == 9 || i == 12) {
            CHECK(result == poll_result && final_calls == 1 && next_calls == 0);
            CHECK(ctx.intervention_triggered == 1);
        } else {
            CHECK(result == 901 && next_calls == 1 && final_calls == 0);
            CHECK(ctx.intervention_triggered == (i == 11));
        }
        CHECK(redirect_calls == (i == 11));
    }
    puts("15 early phase-4 outcomes passed");
    return 0;
}
C
close $c or die "harness close: $!";
my $cc = $ENV{CC} || 'cc';
is(system($cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
    "$dir/early.c", '-o', "$dir/early"), 0, 'production branch compiles');
is(system("$dir/early"), 0,
    'eligibility, engine errors, interventions, redirects and error-page reentry');
done_testing();
