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
typedef int                  (*fn_coraza_rules_count)(coraza_waf_t);
typedef int                  (*fn_coraza_rules_merge)(coraza_waf_t, coraza_waf_t, char **);
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
typedef int                  (*fn_coraza_request_body_from_file)(coraza_transaction_t, char *);
typedef int                  (*fn_coraza_process_request_body)(coraza_transaction_t);
typedef int                  (*fn_coraza_add_response_header)(coraza_transaction_t, char *, int, char *, int);
typedef int                  (*fn_coraza_append_response_body)(coraza_transaction_t, unsigned char *, int);
typedef int                  (*fn_coraza_process_response_body)(coraza_transaction_t);
typedef int                  (*fn_coraza_process_response_headers)(coraza_transaction_t, int, char *);
typedef int                  (*fn_coraza_process_logging)(coraza_transaction_t);
typedef int                  (*fn_coraza_update_status_code)(coraza_transaction_t, int);
typedef int                  (*fn_coraza_add_get_args)(coraza_transaction_t, char *, char *);

/* ------------------------------------------------------------------ */
/* Static function pointers — set once by ngx_http_coraza_dl_open()   */
/* ------------------------------------------------------------------ */

static fn_coraza_new_waf_config          dl_new_waf_config;
static fn_coraza_rules_add               dl_rules_add;
static fn_coraza_rules_add_file          dl_rules_add_file;
static fn_coraza_free_waf_config         dl_free_waf_config;
static fn_coraza_new_waf                 dl_new_waf;
static fn_coraza_free_waf                dl_free_waf;
static fn_coraza_rules_count             dl_rules_count;
static fn_coraza_rules_merge             dl_rules_merge;
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
static fn_coraza_request_body_from_file  dl_request_body_from_file;
static fn_coraza_process_request_body    dl_process_request_body;
static fn_coraza_add_response_header     dl_add_response_header;
static fn_coraza_append_response_body    dl_append_response_body;
static fn_coraza_process_response_body   dl_process_response_body;
static fn_coraza_process_response_headers dl_process_response_headers;
static fn_coraza_process_logging         dl_process_logging;
static fn_coraza_update_status_code      dl_update_status_code;
static fn_coraza_add_get_args            dl_add_get_args;

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
    DL_SYM(dl_rules_count,              coraza_rules_count);
    DL_SYM(dl_rules_merge,              coraza_rules_merge);
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
    DL_SYM(dl_request_body_from_file,   coraza_request_body_from_file);
    DL_SYM(dl_process_request_body,     coraza_process_request_body);
    DL_SYM(dl_add_response_header,      coraza_add_response_header);
    DL_SYM(dl_append_response_body,     coraza_append_response_body);
    DL_SYM(dl_process_response_body,    coraza_process_response_body);
    DL_SYM(dl_process_response_headers, coraza_process_response_headers);
    DL_SYM(dl_process_logging,          coraza_process_logging);
    DL_SYM(dl_update_status_code,       coraza_update_status_code);
    DL_SYM(dl_add_get_args,             coraza_add_get_args);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "coraza: %s loaded via dynlib_open",
                  CORAZA_DYNLIB_BASENAME DYNLIB_EXT);

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Public: unload libcoraza.so                                         */
/* ------------------------------------------------------------------ */

void
ngx_http_coraza_dl_close(ngx_log_t *log)
{
    if (dl_handle != NULL) {
        dynlib_close(dl_handle);
        dl_handle = NULL;
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "coraza: %s unloaded",
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

int coraza_rules_count(coraza_waf_t w)
{
    return dl_rules_count(w);
}

int coraza_rules_merge(coraza_waf_t w1, coraza_waf_t w2, char **err)
{
    return dl_rules_merge(w1, w2, err);
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

int coraza_request_body_from_file(coraza_transaction_t t, char *file)
{
    return dl_request_body_from_file(t, file);
}

int coraza_process_request_body(coraza_transaction_t t)
{
    return dl_process_request_body(t);
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

int coraza_add_get_args(coraza_transaction_t t, char *name,
                        char *value)
{
    return dl_add_get_args(t, name, value);
}
