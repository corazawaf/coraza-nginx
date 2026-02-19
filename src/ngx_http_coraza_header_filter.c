/*
 * Coraza connector for nginx
 * Copyright (c) 2022 Coraza author and contributors (https://www.coraza.io/)
 * Based on ModSecurity connector for nginx, http://www.modsecurity.org/
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */


#include "ngx_http_coraza_common.h"

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_coraza_resolv_header_server(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_date(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_last_modified(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_connection(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_coraza_resolv_header_vary(ngx_http_request_t *r, ngx_str_t name, off_t offset);

ngx_http_coraza_header_out_t ngx_http_coraza_headers_out[] = {

    { ngx_string("Server"),
            offsetof(ngx_http_headers_out_t, server),
            ngx_http_coraza_resolv_header_server },

    { ngx_string("Date"),
            offsetof(ngx_http_headers_out_t, date),
            ngx_http_coraza_resolv_header_date },

    { ngx_string("Content-Length"),
            offsetof(ngx_http_headers_out_t, content_length_n),
            ngx_http_coraza_resolv_header_content_length },

    { ngx_string("Content-Type"),
            offsetof(ngx_http_headers_out_t, content_type),
            ngx_http_coraza_resolv_header_content_type },

    { ngx_string("Last-Modified"),
            offsetof(ngx_http_headers_out_t, last_modified),
            ngx_http_coraza_resolv_header_last_modified },

    { ngx_string("Connection"),
            0,
            ngx_http_coraza_resolv_header_connection },

    { ngx_string("Transfer-Encoding"),
            0,
            ngx_http_coraza_resolv_header_transfer_encoding },

    { ngx_string("Vary"),
            0,
            ngx_http_coraza_resolv_header_vary },

    { ngx_null_string, 0, 0 }
};


static ngx_int_t
ngx_http_coraza_resolv_header_server(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    static char ngx_http_server_full_string[] = NGINX_VER;
    static char ngx_http_server_string[] = "nginx";

    ngx_http_core_loc_conf_t *clcf = NULL;
    ngx_http_coraza_ctx_t *ctx = NULL;
    ngx_str_t value;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens) {
            value.data = (u_char *)ngx_http_server_full_string;
            value.len = sizeof(ngx_http_server_full_string);
        } else {
            value.data = (u_char *)ngx_http_server_string;
            value.len = sizeof(ngx_http_server_string);
        }
    } else {
        ngx_table_elt_t *h = r->headers_out.server;
        value.data = h->value.data;
        value.len =  h->value.len;
    }


    return coraza_add_response_header(ctx->coraza_transaction,
        (char *) name.data,
        name.len,
        (char *) value.data,
        value.len);
}


static ngx_int_t
ngx_http_coraza_resolv_header_date(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;
    ngx_str_t date;

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.date == NULL) {
        date.data = ngx_cached_http_time.data;
        date.len = ngx_cached_http_time.len;
    } else {
        ngx_table_elt_t *h = r->headers_out.date;
        date.data = h->value.data;
        date.len = h->value.len;
    }

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
    ngx_http_coraza_store_ctx_header(r, &name, &date);
#endif

    return coraza_add_response_header(ctx->coraza_transaction,
        (char *) name.data,
        name.len,
        (char *) date.data,
        date.len);
}


static ngx_int_t
ngx_http_coraza_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;
    ngx_str_t value;
    char buf[NGX_INT64_LEN+2];

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.content_length_n > 0)
    {
        ngx_sprintf((u_char *)buf, "%O%Z", r->headers_out.content_length_n);
        value.data = (unsigned char *)buf;
        value.len = strlen(buf);

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
        ngx_http_coraza_store_ctx_header(r, &name, &value);
#endif
        return coraza_add_response_header(ctx->coraza_transaction,
            (char *) name.data,
            name.len,
            (char *) value.data,
            value.len);
    }

    return 1;
}


static ngx_int_t
ngx_http_coraza_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.content_type.len > 0)
    {

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
        ngx_http_coraza_store_ctx_header(r, &name, &r->headers_out.content_type);
#endif

        return coraza_add_response_header(ctx->coraza_transaction,
            (char *) name.data,
            name.len,
            (char *) r->headers_out.content_type.data,
            r->headers_out.content_type.len);
    }

    return 1;
}


static ngx_int_t
ngx_http_coraza_resolv_header_last_modified(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;
    u_char buf[1024], *p;
    ngx_str_t value;

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.last_modified_time == -1) {
        return 1;
    }

    p = ngx_http_time(buf, r->headers_out.last_modified_time);

    value.data = buf;
    value.len = (int)(p-buf);

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
    ngx_http_coraza_store_ctx_header(r, &name, &value);
#endif

    return coraza_add_response_header(ctx->coraza_transaction,
        (char *) name.data,
        name.len,
        (char *) value.data,
        value.len);
}


static ngx_int_t
ngx_http_coraza_resolv_header_connection(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;
    ngx_http_core_loc_conf_t *clcf = NULL;
    char *connection = NULL;
    ngx_str_t value;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        connection = "upgrade";
    } else if (r->keepalive) {
        connection = "keep-alive";
        if (clcf->keepalive_header)
        {
            u_char buf[1024];
            ngx_sprintf(buf, "timeout=%T%Z", clcf->keepalive_header);
            ngx_str_t name2 = ngx_string("Keep-Alive");

            value.data = buf;
            value.len = strlen((char *)buf);

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
            ngx_http_coraza_store_ctx_header(r, &name2, &value);
#endif

            coraza_add_response_header(ctx->coraza_transaction,
                (char *) name2.data,
                name2.len,
                (char *) value.data,
                value.len);
        }
    } else {
        connection = "close";
    }

    value.data = (u_char *) connection;
    value.len = strlen(connection);

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
    ngx_http_coraza_store_ctx_header(r, &name, &value);
#endif

    return coraza_add_response_header(ctx->coraza_transaction,
        (char *) name.data,
        name.len,
        (char *) value.data,
        value.len);
}

static ngx_int_t
ngx_http_coraza_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;

    if (r->chunked) {
        ngx_str_t value = ngx_string("chunked");

        ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
        ngx_http_coraza_store_ctx_header(r, &name, &value);
#endif

        return coraza_add_response_header(ctx->coraza_transaction,
            (char *) name.data,
            name.len,
            (char *) value.data,
            value.len);
    }

    return 1;
}

static ngx_int_t
ngx_http_coraza_resolv_header_vary(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
#if (NGX_HTTP_GZIP)
    ngx_http_coraza_ctx_t *ctx = NULL;
    ngx_http_core_loc_conf_t *clcf = NULL;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (r->gzip_vary && clcf->gzip_vary) {
        ngx_str_t value = ngx_string("Accept-Encoding");

        ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
        ngx_http_coraza_store_ctx_header(r, &name, &value);
#endif

        return coraza_add_response_header(ctx->coraza_transaction,
            (char *) name.data,
            name.len,
            (char *) value.data,
            value.len);
    }
#endif

    return 1;
}

ngx_int_t
ngx_http_coraza_header_filter_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_coraza_header_filter;

    return NGX_OK;
}


ngx_int_t
ngx_http_coraza_header_filter(ngx_http_request_t *r)
{
    ngx_http_coraza_ctx_t *ctx;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
    int ret = 0;
    ngx_uint_t status;
    char *http_response_ver;


/* XXX: if NOT_MODIFIED, do we need to process it at all?  see xslt_header_filter() */

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);


    if (ctx == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    if (ctx->intervention_triggered) {
        return ngx_http_next_header_filter(r);
    }

/* XXX: can it happen ?  already processed i mean */
/* XXX: check behaviour on 'Coraza off' */

    if (ctx && ctx->processed)
    {
        /*
         * FIXME: verify if this request is already processed.
         */
        return ngx_http_next_header_filter(r);
    }

    /*
     * Lets ask nginx to keep the response body in memory
     *
     * FIXME: I don't see a reason to keep it `1' when SecResponseBody is disabled.
     */
    r->filter_need_in_memory = 1;

    ctx->processed = 1;
    /*
     *
     * Assuming Coraza module is running immediately before the
     * ngx_http_header_filter, we will be able to populate Coraza with
     * headers from the headers_out structure.
     *
     * As ngx_http_header_filter place a direct call to the
     * ngx_http_write_filter_module, we cannot hook between those two. In order
     * to enumerate all headers, we first look at the headers_out structure,
     * and later we look into the ngx_list_part_t. The ngx_list_part_t must be
     * checked. Other module(s) in the chain may added some content to it.
     *
     */
    for (i = 0; ngx_http_coraza_headers_out[i].name.len; i++)
    {

                ngx_http_coraza_headers_out[i].resolver(r,
                    ngx_http_coraza_headers_out[i].name,
                    ngx_http_coraza_headers_out[i].offset);
    }

    for (i = 0 ;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
        ngx_http_coraza_store_ctx_header(r, &data[i].key, &data[i].value);
#endif

        /*
         * Doing this ugly cast here, explanation on the request_header
         */
        coraza_add_response_header(ctx->coraza_transaction,
            (char *) data[i].key.data,
            data[i].key.len,
            (char *) data[i].value.data,
            data[i].value.len);
    }

    /* prepare extra paramters for msc_process_response_headers() */
    if (r->err_status) {
        status = r->err_status;
    } else {
        status = r->headers_out.status;
    }

    /*
     * NGINX always sends HTTP response with HTTP/1.1, except cases when
     * HTTP V2 module is enabled, and request has been posted with HTTP/2.0.
     */
    http_response_ver = "HTTP 1.1";
#if (NGX_HTTP_V2)
    if (r->stream) {
        http_response_ver = "HTTP 2.0";
    }
#endif

    coraza_process_response_headers(ctx->coraza_transaction, status, http_response_ver);
    ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 0);
    if (r->error_page) {
        return ngx_http_next_header_filter(r);
    }
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        return ngx_http_filter_finalize_request(r, &ngx_http_coraza_module, ret);
    }

    /*
     * Proxies will not like this... but it is necessary to unset
     * the content length in order to manipulate the content of
     * response body in Coraza.
     *
     * This header may arrive at the client before Coraza had
     * a change to make any modification. That is why it is necessary
     * to set this to -1 here.
     *
     * We need to have some kind of flag the decide if Coraza
     * will make a modification or not. If not, keep the content and
     * make the proxy servers happy.
     *
     */

    /*
     * The line below is commented to make the spdy test to work
     */
     //r->headers_out.content_length_n = -1;

    /*
     * Delay forwarding response headers until the body filter has finished
     * processing phase 4 (response body inspection).  This ensures that if
     * a phase-4 rule denies the request we can still return a clean error
     * page because the original 200 headers have not yet been sent to the
     * client.
     *
     * We skip the delay for HEAD requests (no body to inspect), error pages
     * (already an error response), and subrequests (handled independently).
     */
    if (!r->header_only && !r->error_page && r == r->main) {
        ctx->headers_delayed = 1;
        ctx->pending_chain = NULL;
        ctx->pending_chain_last = &ctx->pending_chain;
        return NGX_OK;
    }

    return ngx_http_next_header_filter(r);
}


ngx_int_t
ngx_http_coraza_forward_header(ngx_http_request_t *r)
{
    return ngx_http_next_header_filter(r);
}
