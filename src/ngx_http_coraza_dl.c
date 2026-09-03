/*
 * Coraza connector for nginx — dlopen wrapper
 *
 * Instead of linking against libcoraza.so at build time, we load it
 * at runtime via dlopen() during init_process (after fork).  This
 * ensures the Go runtime inside libcoraza initializes fresh in each
 * worker process, avoiding the post-fork deadlock.
 *
 * Every coraza_* function used by the module is provided here as a
 * thin wrapper that forwards to the real symbol resolved via dlsym().
 */

#include "dynlib.h"
#include <ngx_core.h>
#include <coraza/coraza.h>

/* ------------------------------------------------------------------ */
/* Function-pointer types matching the exact signatures from coraza.h  */
/* ------------------------------------------------------------------ */

typedef coraza_waf_config_t  (*fn_coraza_new_waf_config)(void);
typedef int                  (*fn_coraza_rules_add)(coraza_waf_config_t, char *);
typedef int                  (*fn_coraza_rules_add_file)(coraza_waf_config_t, char *);
typedef int                  (*fn_coraza_free_waf_config)(coraza_waf_config_t);
typedef coraza_waf_t         (*fn_coraza_new_waf)(coraza_waf_config_t, char **);
typedef int                  (*fn_coraza_free_waf)(coraza_waf_t);

/* Frees a char* returned by the Go runtime (e.g. the char **err reason from
 * coraza_new_waf()). MUST be used instead of libc free(): libcoraza's own doc
 * comment for coraza_free_string requires it "to avoid allocator mismatches on
 * Windows", and freeing a cgo-allocated string with libc free() is undefined
 * behavior. Exported since libcoraza 1.7.0 (coraza.go:586), this module's hard
 * version floor, so it is bound required like every other core symbol. */
typedef void                 (*fn_coraza_free_string)(char *);
typedef int                  (*fn_coraza_rules_count)(coraza_waf_t);
typedef coraza_transaction_t (*fn_coraza_new_transaction)(coraza_waf_t);
typedef coraza_transaction_t (*fn_coraza_new_transaction_with_id)(coraza_waf_t, char *);
typedef int                  (*fn_coraza_free_transaction)(coraza_transaction_t);
typedef coraza_intervention_t *(*fn_coraza_intervention)(coraza_transaction_t);
typedef int                  (*fn_coraza_free_intervention)(coraza_intervention_t *);
typedef int                  (*fn_coraza_process_connection)(coraza_transaction_t, char *, int, char *, int);
typedef int                  (*fn_coraza_process_uri)(coraza_transaction_t, char *, char *, char *);
typedef int                  (*fn_coraza_add_request_header)(coraza_transaction_t, char *, int, char *, int);
typedef int                  (*fn_coraza_process_request_headers)(coraza_transaction_t);
typedef int                  (*fn_coraza_append_request_body)(coraza_transaction_t, unsigned char *, int);
typedef int                  (*fn_coraza_process_request_body)(coraza_transaction_t);
typedef int                  (*fn_coraza_is_request_body_accessible)(coraza_transaction_t);
typedef int                  (*fn_coraza_add_response_header)(coraza_transaction_t, char *, int, char *, int);
typedef int                  (*fn_coraza_append_response_body)(coraza_transaction_t, unsigned char *, int);
typedef int                  (*fn_coraza_process_response_body)(coraza_transaction_t);
typedef int                  (*fn_coraza_process_response_headers)(coraza_transaction_t, int, char *);
typedef int                  (*fn_coraza_process_logging)(coraza_transaction_t);
typedef int                  (*fn_coraza_update_status_code)(coraza_transaction_t, int);

/* Present in libcoraza 1.4+.  Returns 1 if the response body
 * should be inspected (SecResponseBodyAccess On and Content-Type matches
 * SecResponseBodyMimeType).  Must be called after
 * coraza_process_response_headers(). */
typedef int                  (*fn_coraza_is_response_body_processable)(coraza_transaction_t);

/* Bulk header submission, present in libcoraza 1.6+.  Adds every request /
 * response header in a single cgo crossing from a packed buffer
 * ([u16 name_len][name][u32 value_len][value] repeated `count` times),
 * replacing one coraza_add_*_header cgo call per header.  Required symbols:
 * libcoraza >= 1.7 is a hard requirement, so these always resolve; the
 * per-header path they sit beside now serves only as the pack-failure
 * (INT_MAX overflow) safety net, not as an old-library fallback. */
typedef int                  (*fn_coraza_add_request_headers)(coraza_transaction_t, char *, int, int);
typedef int                  (*fn_coraza_add_response_headers)(coraza_transaction_t, char *, int, int);

/* libcoraza >= 1.7: reports the loaded library version (major*10000 +
 * minor*100 + patch), gated in ngx_http_coraza_dl_open(). */
typedef int                  (*fn_coraza_version_num)(void);

/* ------------------------------------------------------------------ */
/* Static function pointers — set once by ngx_http_coraza_dl_open()   */
/* ------------------------------------------------------------------ */

static fn_coraza_new_waf_config          dl_new_waf_config;
static fn_coraza_rules_add               dl_rules_add;
static fn_coraza_rules_add_file          dl_rules_add_file;
static fn_coraza_free_waf_config         dl_free_waf_config;
static fn_coraza_new_waf                 dl_new_waf;
static fn_coraza_free_waf                dl_free_waf;
static fn_coraza_free_string             dl_free_string;
static fn_coraza_rules_count             dl_rules_count;
static fn_coraza_new_transaction         dl_new_transaction;
static fn_coraza_new_transaction_with_id dl_new_transaction_with_id;
static fn_coraza_free_transaction        dl_free_transaction;
static fn_coraza_intervention            dl_intervention;
static fn_coraza_free_intervention       dl_free_intervention;
static fn_coraza_process_connection      dl_process_connection;
static fn_coraza_process_uri             dl_process_uri;
static fn_coraza_add_request_header      dl_add_request_header;
static fn_coraza_process_request_headers dl_process_request_headers;
static fn_coraza_append_request_body     dl_append_request_body;
static fn_coraza_process_request_body    dl_process_request_body;
static fn_coraza_is_request_body_accessible dl_is_request_body_accessible;
static fn_coraza_add_response_header     dl_add_response_header;
static fn_coraza_append_response_body    dl_append_response_body;
static fn_coraza_process_response_body   dl_process_response_body;
static fn_coraza_process_response_headers dl_process_response_headers;
static fn_coraza_process_logging         dl_process_logging;
static fn_coraza_update_status_code      dl_update_status_code;

static fn_coraza_is_response_body_processable dl_is_response_body_processable;

/* Bulk-header entry points (libcoraza 1.6+) — required (>= 1.7 is enforced). */
static fn_coraza_add_request_headers     dl_add_request_headers;
static fn_coraza_add_response_headers    dl_add_response_headers;

static fn_coraza_version_num             dl_version_num;

static dynlib_t dl_handle;

/* ------------------------------------------------------------------ */
/* Resolve one symbol — returns NGX_ERROR on failure                   */
/* ------------------------------------------------------------------ */

#define DL_SYM(ptr, name)                                               \
    do {                                                                \
        *(void **)(&ptr) = dynlib_sym(dl_handle, #name);               \
        if ((ptr) == NULL) {                                            \
            ngx_log_error(NGX_LOG_EMERG, log, 0,                       \
                          "coraza: dynlib_sym(\"%s\") failed: %s",     \
                          #name, dynlib_error());                       \
            dynlib_close(dl_handle);                                   \
            dl_handle = NULL;                                          \
            return NGX_ERROR;                                          \
        }                                                              \
    } while (0)


/* Resolve a best-effort symbol — leaves the pointer NULL (no failure) when
 * the running libcoraza does not export it, so the caller can fall back. */
#define DL_SYM_OPT(ptr, name)                                           \
    do {                                                                \
        *(void **)(&ptr) = dynlib_sym(dl_handle, #name);               \
        if (ptr == NULL) {                                             \
            (void) dynlib_error();  /* consume: absence is not fatal */ \
        }                                                              \
    } while (0)


/* ------------------------------------------------------------------ */
/* Public: load libcoraza.so and resolve every symbol                  */
/* ------------------------------------------------------------------ */

ngx_int_t
ngx_http_coraza_dl_open(ngx_log_t *log)
{
    if (dl_handle != NULL) {
        return NGX_OK;                     /* already loaded */
    }

    dl_handle = dynlib_open(CORAZA_DYNLIB_BASENAME DYNLIB_EXT);
    if (dl_handle == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "coraza: dynlib_open(\"%s\") failed: %s",
                      CORAZA_DYNLIB_BASENAME DYNLIB_EXT,
                      dynlib_error());
        return NGX_ERROR;
    }

    DL_SYM(dl_new_waf_config,           coraza_new_waf_config);
    DL_SYM(dl_rules_add,                coraza_rules_add);
    DL_SYM(dl_rules_add_file,           coraza_rules_add_file);
    DL_SYM(dl_free_waf_config,          coraza_free_waf_config);
    DL_SYM(dl_new_waf,                  coraza_new_waf);
    DL_SYM(dl_free_waf,                 coraza_free_waf);

    DL_SYM(dl_free_string,              coraza_free_string);
    DL_SYM(dl_rules_count,              coraza_rules_count);
    DL_SYM(dl_new_transaction,           coraza_new_transaction);
    DL_SYM(dl_new_transaction_with_id,   coraza_new_transaction_with_id);
    DL_SYM(dl_free_transaction,          coraza_free_transaction);
    DL_SYM(dl_intervention,              coraza_intervention);
    DL_SYM(dl_free_intervention,         coraza_free_intervention);
    DL_SYM(dl_process_connection,        coraza_process_connection);
    DL_SYM(dl_process_uri,              coraza_process_uri);
    DL_SYM(dl_add_request_header,       coraza_add_request_header);
    DL_SYM(dl_process_request_headers,  coraza_process_request_headers);
    DL_SYM(dl_append_request_body,      coraza_append_request_body);
    DL_SYM(dl_process_request_body,     coraza_process_request_body);
    DL_SYM(dl_is_request_body_accessible,
           coraza_is_request_body_accessible);
    DL_SYM(dl_add_response_header,      coraza_add_response_header);
    DL_SYM(dl_append_response_body,     coraza_append_response_body);
    DL_SYM(dl_process_response_body,    coraza_process_response_body);
    DL_SYM(dl_process_response_headers, coraza_process_response_headers);
    DL_SYM(dl_process_logging,          coraza_process_logging);
    DL_SYM(dl_update_status_code,       coraza_update_status_code);

    DL_SYM(dl_is_response_body_processable,
           coraza_is_response_body_processable);

    /* Bulk-header entry points (libcoraza 1.6+) — required. */
    DL_SYM(dl_add_request_headers,  coraza_add_request_headers);
    DL_SYM(dl_add_response_headers, coraza_add_response_headers);

    /* Version gate. coraza_version_num() first appears in 1.7.0 and reports the
     * version of the library actually dlopen'd -- the authoritative check for a
     * module that resolves everything at runtime.  A library that does not
     * export it, or reports < 1.7.0, is unsupported: fail so the worker refuses
     * to start (fail closed) rather than run against an old ABI. */
    DL_SYM(dl_version_num, coraza_version_num);
    {
        int version = dl_version_num();
        if (version < 10700) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "coraza: libcoraza >= 1.7.0 required, but the loaded "
                          "library reports %d.%d.%d",
                          version / 10000, version / 100 % 100, version % 100);
            dynlib_close(dl_handle);
            dl_handle = NULL;
            return NGX_ERROR;
        }
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "coraza: %s loaded via dynlib_open (libcoraza %d.%d.%d)",
                      CORAZA_DYNLIB_BASENAME DYNLIB_EXT,
                      version / 10000, version / 100 % 100, version % 100);
    }

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Public: keep libcoraza.so loaded until the process exits            */
/* ------------------------------------------------------------------ */

void
ngx_http_coraza_dl_close(ngx_log_t *log)
{
    if (dl_handle != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                       "coraza: %s left loaded for process lifetime",
                       CORAZA_DYNLIB_BASENAME DYNLIB_EXT);
    }
}

/* ------------------------------------------------------------------ */
/* Wrapper functions — same signatures as the extern declarations in   */
/* coraza/coraza.h.  Since we no longer link with -lcoraza, these      */
/* definitions satisfy those extern declarations at link time.         */
/* ------------------------------------------------------------------ */

coraza_waf_config_t coraza_new_waf_config(void)
{
    return dl_new_waf_config();
}

int coraza_rules_add(coraza_waf_config_t c, char *directives)
{
    return dl_rules_add(c, directives);
}

int coraza_rules_add_file(coraza_waf_config_t c, char *file)
{
    return dl_rules_add_file(c, file);
}

int coraza_free_waf_config(coraza_waf_config_t config)
{
    return dl_free_waf_config(config);
}

coraza_waf_t coraza_new_waf(coraza_waf_config_t config, char **err)
{
    return dl_new_waf(config, err);
}

int coraza_free_waf(coraza_waf_t w)
{
    return dl_free_waf(w);
}

/* The NULL check is for the argument, not the symbol: callers pass a char *out
 * param that libcoraza only sets on failure, so a successful call hands us a
 * pointer that was never written to. */
void coraza_free_string(char *s)
{
    if (s != NULL) {
        dl_free_string(s);
    }
}

int coraza_rules_count(coraza_waf_t w)
{
    return dl_rules_count(w);
}

coraza_transaction_t coraza_new_transaction(coraza_waf_t w)
{
    return dl_new_transaction(w);
}

coraza_transaction_t coraza_new_transaction_with_id(coraza_waf_t w, char *id)
{
    return dl_new_transaction_with_id(w, id);
}

int coraza_free_transaction(coraza_transaction_t t)
{
    return dl_free_transaction(t);
}

coraza_intervention_t *coraza_intervention(coraza_transaction_t t)
{
    return dl_intervention(t);
}

int coraza_free_intervention(coraza_intervention_t *it)
{
    return dl_free_intervention(it);
}

int coraza_process_connection(coraza_transaction_t t, char *addr,
                              int client_port, char *server,
                              int server_port)
{
    return dl_process_connection(t, addr, client_port, server, server_port);
}

int coraza_process_uri(coraza_transaction_t t, char *uri,
                       char *method, char *proto)
{
    return dl_process_uri(t, uri, method, proto);
}

int coraza_add_request_header(coraza_transaction_t t, char *name,
                              int name_len, char *value, int value_len)
{
    return dl_add_request_header(t, name, name_len, value, value_len);
}

int coraza_process_request_headers(coraza_transaction_t t)
{
    return dl_process_request_headers(t);
}

int coraza_append_request_body(coraza_transaction_t t,
                               unsigned char *data, int length)
{
    return dl_append_request_body(t, data, length);
}

int coraza_process_request_body(coraza_transaction_t t)
{
    return dl_process_request_body(t);
}

/*
 * ngx_http_coraza_is_request_body_accessible — wrapper around the
 * coraza_is_request_body_accessible symbol.
 *
 * This predicate is valid after coraza_process_request_headers() and reports
 * whether request-body bytes should be submitted for this transaction.  A
 * false result skips only buffering and submission; coraza_process_request_body
 * must still run because it evaluates phase-2 rules on non-body variables.
 *
 * libcoraza 1.7.0 introduced the symbol and is the connector's minimum
 * supported version, so ngx_http_coraza_dl_open() resolves it as mandatory.
 */
int
ngx_http_coraza_is_request_body_accessible(coraza_transaction_t t)
{
    return dl_is_request_body_accessible(t);
}

int coraza_add_response_header(coraza_transaction_t t, char *name,
                               int name_len, char *value, int value_len)
{
    return dl_add_response_header(t, name, name_len, value, value_len);
}

int coraza_append_response_body(coraza_transaction_t t,
                                unsigned char *data, int length)
{
    return dl_append_response_body(t, data, length);
}

int coraza_process_response_body(coraza_transaction_t t)
{
    return dl_process_response_body(t);
}

int coraza_process_response_headers(coraza_transaction_t t, int status,
                                    char *proto)
{
    return dl_process_response_headers(t, status, proto);
}

int coraza_process_logging(coraza_transaction_t t)
{
    return dl_process_logging(t);
}

int coraza_update_status_code(coraza_transaction_t t, int code)
{
    return dl_update_status_code(t, code);
}

/*
 * ngx_http_coraza_is_response_body_processable — wrapper around the
 * coraza_is_response_body_processable symbol.
 *
 * Returns 1 if the response body should be inspected for this transaction
 * (i.e. SecResponseBodyAccess is On and the Content-Type matches
 * SecResponseBodyMimeType).  Must be called after
 * coraza_process_response_headers().
 *
 * Requires libcoraza >= 1.4.0.  The symbol is resolved with the mandatory
 * DL_SYM in ngx_http_coraza_dl_open(), so dl_is_response_body_processable is
 * guaranteed non-NULL here: if the running library did not export it, dl_open
 * failed and the worker never started.  No NULL guard is needed (and none must
 * be relied upon) -- if this symbol is ever downgraded to DL_SYM_OPT, this
 * wrapper and its callers must add an availability check first.
 */
int
ngx_http_coraza_is_response_body_processable(coraza_transaction_t t)
{
    return dl_is_response_body_processable(t);
}

/*
 * Bulk header wrappers (libcoraza 1.6+).  These forward to the resolved
 * symbols; callers must first check ngx_http_coraza_bulk_headers_available()
 * because the pointers may be NULL on an older library.
 */
int coraza_add_request_headers(coraza_transaction_t t, char *packed,
                               int packed_len, int count)
{
    if (dl_add_request_headers == NULL) {
        return -1;
    }
    return dl_add_request_headers(t, packed, packed_len, count);
}

int coraza_add_response_headers(coraza_transaction_t t, char *packed,
                                int packed_len, int count)
{
    if (dl_add_response_headers == NULL) {
        return -1;
    }
    return dl_add_response_headers(t, packed, packed_len, count);
}

/*
 * ngx_http_coraza_bulk_headers_available — 1 when the loaded libcoraza
 * exports both bulk-header entry points, 0 otherwise.  Callers use the
 * per-header path when this returns 0.
 */
int
ngx_http_coraza_bulk_headers_available(void)
{
    return dl_add_request_headers != NULL && dl_add_response_headers != NULL;
}
