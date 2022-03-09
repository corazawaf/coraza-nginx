/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */


#include "ngx_http_coraza_common.h"


void
ngx_http_coraza_log(void *log, const void* data)
{
    const char *msg;
    if (log == NULL) {
        return;
    }
    msg = (const char *) data;

    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *)log, 0, "%s", msg);
}


ngx_int_t
ngx_http_coraza_log_handler(ngx_http_request_t *r)
{
    ngx_http_coraza_ctx_t   *ctx;
    ngx_http_coraza_conf_t  *mcf;

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_coraza_module);
    if (mcf == NULL || mcf->enable != 1)
    {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->logged) {
        return NGX_OK;
    }

    coraza_process_logging(ctx->coraza_transaction);

    return NGX_OK;
}
