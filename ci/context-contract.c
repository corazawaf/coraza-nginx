/* Isolated constructor ownership contract; handles are inert integer tokens. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u_char;
typedef unsigned long coraza_waf_t;
typedef unsigned long coraza_transaction_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct {
    coraza_transaction_t coraza_transaction;
    ngx_str_t transaction_id;
    int logged;
} ngx_http_coraza_ctx_t;
typedef struct {
    void (*handler)(void *);
    void *data;
} ngx_pool_cleanup_t;
typedef struct { ngx_pool_cleanup_t *cleanup; } ngx_pool_t;
typedef struct { coraza_waf_t waf; int *transaction_id; } ngx_http_coraza_conf_t;
typedef struct { coraza_waf_t waf; } ngx_http_coraza_main_conf_t;
typedef struct {
    ngx_pool_t *pool;
    ngx_http_coraza_ctx_t *ctx;
    ngx_http_coraza_conf_t *loc;
    ngx_http_coraza_main_conf_t *main;
} ngx_http_request_t;

#define NGX_OK 0
#define ngx_inline static
#define dd(...) ((void) 0)
#define ngx_http_get_module_main_conf(r, module) ((r)->main)
#define ngx_http_get_module_loc_conf(r, module) ((r)->loc)
#define ngx_http_set_ctx(r, value, module) ((r)->ctx = (value))
#define ngx_str_null(s) do { (s)->len = 0; (s)->data = NULL; } while (0)

static const coraza_transaction_t transaction = 73;
static ngx_http_coraza_ctx_t storage;
static ngx_pool_cleanup_t cleanup;
static u_char id_data[] = "contract-id";
static u_char id_copy[sizeof(id_data)];
static const char *case_name;
static int fail_at, live, frees, logs, cleanup_runs;
static int allocations, evaluations, creations, registrations, copies;
static int id_configured, empty_id;
static coraza_waf_t expected_waf;

enum { NONE, CONTEXT, COMPLEX, TRANSACTION, CLEANUP, ID_COPY };

static void
check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s: %s\n", case_name, message);
        exit(EXIT_FAILURE);
    }
}

static void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    allocations++;
    check(size == sizeof(storage), "context allocation size");
    return fail_at == CONTEXT ? NULL : &storage;
}

static int
ngx_http_complex_value(ngx_http_request_t *r, int *expression, ngx_str_t *s)
{
    (void) r;
    check(expression != NULL, "transaction ID expression");
    evaluations++;
    s->data = id_data;
    s->len = empty_id ? 0 : sizeof(id_data) - 1;
    return fail_at == COMPLEX ? -1 : NGX_OK;
}

static coraza_transaction_t
coraza_new_transaction(coraza_waf_t waf)
{
    check(waf == expected_waf, "selected WAF");
    creations++;
    live = fail_at != TRANSACTION;
    return live ? transaction : 0;
}

static coraza_transaction_t
coraza_new_transaction_with_id(coraza_waf_t waf, char *id)
{
    check(id == (char *) id_data, "evaluated ID reaches constructor");
    return coraza_new_transaction(waf);
}

static int
coraza_free_transaction(coraza_transaction_t handle)
{
    check(handle == transaction && live, "dispose exactly one valid transaction");
    frees++;
    live = 0;
    return NGX_OK;
}

static int
coraza_process_logging(coraza_transaction_t handle)
{
    check(handle == transaction && live, "log a valid transaction before disposal");
    logs++;
    return NGX_OK;
}

static ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    registrations++;
    check(size == 0, "cleanup uses existing context");
    check(pool->cleanup == NULL, "only one cleanup registration");
    if (fail_at == CLEANUP) {
        return NULL;
    }
    pool->cleanup = &cleanup;
    return &cleanup;
}

static u_char *
ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *s)
{
    copies++;
    check(pool->cleanup == &cleanup && cleanup.handler != NULL,
          "cleanup owns transaction before ID allocation");
    check(cleanup.data == &storage, "cleanup owns the constructed context");
    check(s->len <= sizeof(id_copy), "ID copy fits fixture");
    if (fail_at == ID_COPY) {
        return NULL;
    }
    memcpy(id_copy, s->data, s->len);
    return id_copy;
}

#include "context-functions.inc"

static void
run_cleanup(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t *cln = pool->cleanup;
    pool->cleanup = NULL;
    if (cln != NULL) {
        check(cln->handler == ngx_http_coraza_cleanup, "registered cleanup handler");
        check(cln->data == &storage, "registered cleanup context");
        cleanup_runs++;
        cln->handler(cln->data);
    }
}

static void
check_publication(const ngx_http_request_t *request, const ngx_http_coraza_ctx_t *result,
                  int success)
{
    check((result != NULL) == success, "constructor result");
    if (!success) {
        check(request->ctx == NULL, "failed construction must not publish context");
        return;
    }
    check(result == &storage && request->ctx == result, "publish completed context");
    check(result->coraza_transaction == transaction && live, "published handle is live");
    check(result->transaction_id.len == (id_configured && !empty_id ? 11 : 0),
          "published ID length");
    check(result->transaction_id.data == (id_configured ? id_copy : NULL),
          "published ID storage");
    if (id_configured) {
        check(memcmp(result->transaction_id.data, id_data, result->transaction_id.len) == 0,
              "published ID bytes");
    }
}

int
main(int argc, char **argv)
{
    static const struct {
        const char *name;
        int failure, with_id, no_waf, fallback, empty, logged;
        int evaluate, create, register_cleanup, copy, success;
    } cases[] = {
        {"context-allocation", CONTEXT,     0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {"missing-waf",        NONE,        0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
        {"complex-value",      COMPLEX,     1, 0, 0, 0, 0, 1, 0, 0, 0, 0},
        {"transaction",        TRANSACTION, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0},
        {"transaction-id",     TRANSACTION, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0},
        {"cleanup",            CLEANUP,     0, 0, 0, 0, 0, 0, 1, 1, 0, 0},
        {"cleanup-with-id",    CLEANUP,     1, 0, 0, 0, 0, 1, 1, 1, 0, 0},
        {"id-copy",            ID_COPY,     1, 0, 0, 0, 0, 1, 1, 1, 1, 0},
        {"success",            NONE,        0, 0, 0, 0, 0, 0, 1, 1, 0, 1},
        {"success-with-id",    NONE,        1, 0, 0, 0, 0, 1, 1, 1, 1, 1},
        {"empty-id",           NONE,        1, 0, 0, 1, 0, 1, 1, 1, 1, 1},
        {"main-waf",           NONE,        0, 0, 1, 0, 0, 0, 1, 1, 0, 1},
        {"already-logged",     NONE,        0, 0, 0, 0, 1, 0, 1, 1, 0, 1},
    };
    size_t i;
    ngx_pool_t pool = {0};
    int expression = 1;
    ngx_http_coraza_conf_t loc = {11, NULL};
    ngx_http_coraza_main_conf_t main_conf = {22};
    ngx_http_request_t request = {&pool, NULL, &loc, &main_conf};
    ngx_http_coraza_ctx_t *result;

    case_name = argc == 2 ? argv[1] : "missing case";
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (strcmp(case_name, cases[i].name) == 0) {
            break;
        }
    }
    if (i == sizeof(cases) / sizeof(cases[0])) {
        fprintf(stderr, "%s: unknown contract case\n", case_name);
        return EXIT_FAILURE;
    }
    fail_at = cases[i].failure;
    id_configured = cases[i].with_id;
    empty_id = cases[i].empty;
    loc.transaction_id = id_configured ? &expression : NULL;
    loc.waf = cases[i].no_waf || cases[i].fallback ? 0 : 11;
    main_conf.waf = cases[i].no_waf ? 0 : 22;
    expected_waf = cases[i].fallback ? 22 : 11;

    result = ngx_http_coraza_create_ctx(&request);
    check(allocations == 1, "context allocation attempted once");
    check(evaluations == cases[i].evaluate, "ID evaluation count");
    check(creations == cases[i].create, "transaction creation count");
    check(registrations == cases[i].register_cleanup, "cleanup allocation count");
    check(copies == cases[i].copy, "ID allocation count");
    check_publication(&request, result, cases[i].success);
    check(logs == 0, "no logging during construction");
    check(frees == (fail_at == CLEANUP), "only unregistered failure disposes immediately");
    check((pool.cleanup != NULL) == (cases[i].success || fail_at == ID_COPY),
          "cleanup retained for success and late ID failure");
    if (pool.cleanup != NULL) {
        check(storage.coraza_transaction == transaction && live, "cleanup owns a live handle");
        storage.logged = cases[i].logged;
    }
    run_cleanup(&pool);
    run_cleanup(&pool);
    check(cleanup_runs == (cases[i].success || fail_at == ID_COPY), "cleanup runs exactly once");
    check(frees == (cases[i].register_cleanup != 0), "created transaction disposed exactly once");
    check(logs == (cleanup_runs && !cases[i].logged), "cleanup logs once unless already logged");
    check(live == 0, "no transaction remains owned");
    return EXIT_SUCCESS;
}
