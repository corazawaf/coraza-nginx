/*
 * Coraza connector for nginx
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#ifndef _ngx_http_coraza_COMMON_H_INCLUDED_
#define _ngx_http_coraza_COMMON_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <coraza/coraza.h>


/**
 * TAG_NUM:
 *
 * Alpha  - 001
 * Beta   - 002
 * Dev    - 010
 * Rc1    - 051
 * Rc2    - 052
 * ...    - ...
 * Release- 100
 *
 */

#define CORAZA_NGINX_MAJOR "0"
#define CORAZA_NGINX_MINOR "1"
#define CORAZA_NGINX_PATCHLEVEL "0"
#define CORAZA_NGINX_TAG ""
#define CORAZA_NGINX_TAG_NUM "100"

#define CORAZA_NGINX_VERSION CORAZA_NGINX_MAJOR "." \
    CORAZA_NGINX_MINOR "." CORAZA_NGINX_PATCHLEVEL \
    CORAZA_NGINX_TAG

#define CORAZA_NGINX_VERSION_NUM CORAZA_NGINX_MAJOR \
    CORAZA_NGINX_MINOR CORAZA_NGINX_PATCHLEVEL \
    CORAZA_NGINX_TAG_NUM

#define CORAZA_NGINX_WHOAMI "coraza-nginx v" \
    CORAZA_NGINX_VERSION


/* Deferred rule storage — rules are collected as strings during config
 * parsing (master process) and replayed after fork in init_process. */

typedef enum {
    NGX_CORAZA_RULE_INLINE,
    NGX_CORAZA_RULE_FILE
} ngx_http_coraza_rule_type_e;

typedef struct {
    ngx_http_coraza_rule_type_e  type;
    ngx_str_t                    value;
} ngx_http_coraza_rule_entry_t;


typedef struct {
    ngx_str_t name;
    ngx_str_t value;
} ngx_http_coraza_header_t;


typedef struct {
    ngx_http_request_t *r;
    coraza_transaction_t coraza_transaction;
    coraza_intervention_t *delayed_intervention;
    ngx_str_t transaction_id;

    ngx_chain_t *pending_chain;
    ngx_chain_t **pending_chain_last;
    size_t       pending_bytes;   /* bytes buffered while headers are delayed */

    /* When non-NULL, ngx_http_coraza_add_response_header() collects pairs
     * here instead of making one cgo call each, so the header filter can
     * submit the whole set via coraza_add_response_headers() in a single
     * crossing (libcoraza 1.6+).  NULL => direct per-header cgo path. */
    ngx_array_t *resp_hdr_collect;

    unsigned waiting_more_body:1;
    unsigned body_requested:1;
    unsigned processed:1;
    unsigned logged:1;
    unsigned intervention_triggered:1;
    unsigned headers_delayed:1;
    unsigned response_body_processable:1; /* body inspection needed for this tx */
} ngx_http_coraza_ctx_t;


typedef struct {
    void                      *pool;
    coraza_waf_t               waf;
    ngx_array_t               *rules;       /* of ngx_http_coraza_rule_entry_t */
    ngx_array_t               *loc_confs;   /* of ngx_http_coraza_conf_t * */
    ngx_uint_t                 rules_inline;
    ngx_uint_t                 rules_file;
    ngx_uint_t                 rules_remote;
} ngx_http_coraza_main_conf_t;


typedef struct {
    void                      *pool;
    coraza_waf_t               waf;
    ngx_array_t               *rules;       /* of ngx_http_coraza_rule_entry_t */

    ngx_flag_t                 enable;
    ngx_flag_t                 has_rules;
    ngx_flag_t                 delay_response_headers;

    ngx_http_complex_value_t  *transaction_id;
} ngx_http_coraza_conf_t;


typedef ngx_int_t (*ngx_http_coraza_resolv_header_pt)(ngx_http_request_t *r, ngx_str_t name, off_t offset);

typedef struct {
    ngx_str_t name;
    ngx_uint_t offset;
    ngx_http_coraza_resolv_header_pt resolver;
} ngx_http_coraza_header_out_t;


/*
 * Upper bound on how many response-body bytes the connector will buffer in the
 * request pool while it delays response headers for phase-4 inspection.  Once
 * the accumulated body passes this cap the delayed headers and everything
 * buffered so far are flushed and the remainder streams through, so a large or
 * open-ended (streaming) response cannot grow worker memory without limit.
 * Coraza's own SecResponseBodyLimit governs how much it actually inspects; this
 * only bounds the connector's delayed-header buffering.  Override at build time
 * with -DNGX_HTTP_CORAZA_MAX_DELAYED_BODY=<bytes>.
 */
#ifndef NGX_HTTP_CORAZA_MAX_DELAYED_BODY
#define NGX_HTTP_CORAZA_MAX_DELAYED_BODY (1024 * 1024)
#endif


/*
 * coraza_process_request_body() / coraza_process_response_body() can fail to
 * evaluate the phase at all (the Go engine returned an error, e.g. it could not
 * parse the buffered body).  On such a failure NO interruption is recorded on
 * the transaction, so the coraza_intervention() poll that follows returns
 * nothing and the body phase is silently skipped while nginx still forwards the
 * body -- a fail-open inspection bypass.  We must fail closed on that error.
 *
 * libcoraza >= 1.7 is required (enforced in the addon `config` build probe and
 * again at runtime in ngx_http_coraza_dl_open), so the tri-state coraza_result_t
 * contract always applies: CORAZA_OK(0), CORAZA_INTERRUPTION(1), CORAZA_ERROR(-1).
 * 1 means "interrupted" (the coraza_intervention() poll handles it); only a
 * negative return is an engine error -> error iff ret < 0.
 */
static ngx_inline ngx_int_t
ngx_http_coraza_process_body_failed(int ret)
{
    /* libcoraza >= 1.7 is required (see config / ngx_http_coraza_dl_open), so
     * the tri-state coraza_result_t contract always applies: CORAZA_ERROR (-1)
     * is the only failure; CORAZA_INTERRUPTION (1) is a normal interruption. */
    return ret < 0;
}


extern ngx_module_t ngx_http_coraza_module;

/* ngx_http_coraza_module.c */
ngx_int_t ngx_http_coraza_process_intervention (ngx_http_coraza_ctx_t *ctx, ngx_http_request_t *r, ngx_int_t early_log);
ngx_http_coraza_ctx_t *ngx_http_coraza_create_ctx(ngx_http_request_t *r);

/*
 * CORAZA_INTERRUPTION is the coraza_result_t value libcoraza 1.6+ returns from
 * coraza_process_{request_headers,request_body,response_headers,response_body}
 * when a rule interrupted the transaction (added upstream b3fedde3, the same
 * commit that added the bulk-header symbols). Older libcoraza headers (<1.6) do
 * NOT define the coraza_result_t enum, so provide a local fallback of the stable
 * value (1) to keep the connector compilable against a 1.4 header. The value is
 * only consulted on a bulk-capable (>=1.6) library — see
 * ngx_http_coraza_poll_after_process() below — so the fallback is never trusted
 * as a real signal on an old lib.
 */
#ifndef CORAZA_INTERRUPTION
#define CORAZA_INTERRUPTION 1
#endif

/*
 * ngx_http_coraza_poll_after_process — CGO-thrifty intervention poll for the
 * four rule-phase entry points. Post phase, coraza_intervention() is almost
 * always NULL; on libcoraza 1.6+ the process fn already told us whether a rule
 * interrupted via its return value (pret), so we only cross into Go to fetch the
 * intervention when pret == CORAZA_INTERRUPTION. On <1.6 the return value is not
 * a reliable signal (request/response_headers always returned 0, the body fns
 * returned 1 only on error), so we MUST fall back to an unconditional poll —
 * gating on the return there would fail open and skip a real block. The 1.6+
 * guarantee is proxied by ngx_http_coraza_bulk_headers_available() (same commit
 * introduced both). Semantics are otherwise identical to a bare
 * ngx_http_coraza_process_intervention() call: returns NGX_OK / >0 status /
 * NGX_ERROR exactly as that helper does, so callers keep their existing
 * error_page and ret handling.
 */
/* Forward declaration (full prototype in the ngx_http_coraza_dl.c block below);
 * needed here because the inline poll helper calls it under -Werror. */
int ngx_http_coraza_bulk_headers_available(void);

static ngx_inline ngx_int_t
ngx_http_coraza_poll_after_process(ngx_http_coraza_ctx_t *ctx,
    ngx_http_request_t *r, ngx_int_t early_log, int pret)
{
    if (ngx_http_coraza_bulk_headers_available()
        && pret != CORAZA_INTERRUPTION)
    {
        /* 1.6+ said OK: no rule interrupted this phase, nothing to fetch. */
        return NGX_OK;
    }

    return ngx_http_coraza_process_intervention(ctx, r, early_log);
}

/* ngx_http_coraza_dl.c */
ngx_int_t ngx_http_coraza_dl_open(ngx_log_t *log);
void ngx_http_coraza_dl_close(ngx_log_t *log);
int ngx_http_coraza_is_request_body_accessible(coraza_transaction_t t);
int ngx_http_coraza_is_response_body_processable(coraza_transaction_t t);
/* Bulk header entry points (libcoraza 1.6+); guard every call with
 * ngx_http_coraza_bulk_headers_available() (forward-declared above). */
/* NOTE: `packed` is non-const to match libcoraza's SWIG-generated 1.6 header
 * (which declares `char *packed`); a `const char *` here trips -Werror
 * conflicting-types when the connector is built against the real 1.6 header. */
int coraza_add_request_headers(coraza_transaction_t t, char *packed,
    int packed_len, int count);
int coraza_add_response_headers(coraza_transaction_t t, char *packed,
    int packed_len, int count);

/* ngx_http_coraza_body_filter.c */
ngx_int_t ngx_http_coraza_body_filter_init(void);
ngx_int_t ngx_http_coraza_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

/* ngx_http_coraza_header_filter.c */
ngx_int_t ngx_http_coraza_header_filter_init(void);
ngx_int_t ngx_http_coraza_header_filter(ngx_http_request_t *r);
ngx_int_t ngx_http_coraza_forward_header(ngx_http_request_t *r);
void ngx_http_coraza_prepare_redirect(ngx_http_request_t *r, ngx_int_t status);

/* ngx_http_coraza_log.c */
ngx_int_t ngx_http_coraza_log_handler(ngx_http_request_t *r);

/* ngx_http_coraza_pre_access.c */
ngx_int_t ngx_http_coraza_pre_access_handler(ngx_http_request_t *r);

/* ngx_http_coraza_rewrite.c */
ngx_int_t ngx_http_coraza_rewrite_handler(ngx_http_request_t *r);

/* ngx_http_coraza_utils.c */
ngx_int_t ngx_str_to_char(ngx_str_t a, char **str, ngx_pool_t *p);
ngx_int_t ngx_http_coraza_pack_headers(ngx_http_request_t *r,
    ngx_http_coraza_header_t *pairs, ngx_uint_t count,
    u_char **out, size_t *out_len);

#endif /* _ngx_http_coraza_COMMON_H_INCLUDED_ */
