/*
 * Coraza connector for nginx, http://www.coraza.io/
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */


#include "ngx_http_coraza_common.h"


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
        /* LOG-phase handlers must return NGX_OK */
        return NGX_OK;
    }

    if (ctx->logged) {
        return NGX_OK;
    }

    coraza_process_logging(ctx->coraza_transaction);

    /*
     * Claim the transaction so the ngx_http_coraza_cleanup() fallback does not
     * log it a second time.
     */
    ctx->logged = 1;

    return NGX_OK;
}
