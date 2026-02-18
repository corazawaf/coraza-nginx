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

/* 
 * Type definition for coraza_waf_config_t from the new libcoraza API.
 * This type represents an opaque handle to a WAF configuration object.
 */
typedef uint64_t coraza_waf_config_t;


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

typedef struct {
    ngx_str_t name;
    ngx_str_t value;
} ngx_http_coraza_header_t;


typedef struct {
    ngx_http_request_t *r;
    coraza_transaction_t coraza_transaction;
    coraza_intervention_t *delayed_intervention;

    unsigned waiting_more_body:1;
    unsigned body_requested:1;
    unsigned processed:1;
    unsigned logged:1;
    unsigned intervention_triggered:1;
} ngx_http_coraza_ctx_t;


typedef struct {
    void                      *pool;
    coraza_waf_config_t        config;
    coraza_waf_t               waf;
    ngx_uint_t                 rules_inline;
    ngx_uint_t                 rules_file;
    ngx_uint_t                 rules_remote;
} ngx_http_coraza_main_conf_t;


typedef struct {
    void                      *pool;
    /* RulesSet or Rules */
    coraza_waf_config_t        config;
    coraza_waf_t               waf;

    ngx_flag_t                 enable;

    ngx_http_complex_value_t  *transaction_id;
} ngx_http_coraza_conf_t;


typedef ngx_int_t (*ngx_http_coraza_resolv_header_pt)(ngx_http_request_t *r, ngx_str_t name, off_t offset);

typedef struct {
    ngx_str_t name;
    ngx_uint_t offset;
    ngx_http_coraza_resolv_header_pt resolver;
} ngx_http_coraza_header_out_t;


extern ngx_module_t ngx_http_coraza_module;

/* ngx_http_coraza_module.c */
ngx_int_t ngx_http_coraza_process_intervention (coraza_transaction_t transaction, ngx_http_request_t *r, ngx_int_t early_log);
ngx_http_coraza_ctx_t *ngx_http_coraza_create_ctx(ngx_http_request_t *r);

/* ngx_http_coraza_body_filter.c */
ngx_int_t ngx_http_coraza_body_filter_init(void);
ngx_int_t ngx_http_coraza_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

/* ngx_http_coraza_header_filter.c */
ngx_int_t ngx_http_coraza_header_filter_init(void);
ngx_int_t ngx_http_coraza_header_filter(ngx_http_request_t *r);

/* ngx_http_coraza_log.c */
void ngx_http_coraza_log(void *log, const void* data);
ngx_int_t ngx_http_coraza_log_handler(ngx_http_request_t *r);

/* ngx_http_coraza_pre_access.c */
ngx_int_t ngx_http_coraza_pre_access_handler(ngx_http_request_t *r);

/* ngx_http_coraza_rewrite.c */
ngx_int_t ngx_http_coraza_rewrite_handler(ngx_http_request_t *r);

/* ngx_http_coraza_utils.c */
ngx_int_t ngx_str_to_char(ngx_str_t a, char **str, ngx_pool_t *p);

#endif /* _ngx_http_coraza_COMMON_H_INCLUDED_ */
