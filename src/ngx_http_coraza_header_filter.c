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

static ngx_int_t ngx_http_coraza_add_response_header(ngx_http_request_t *r,
    ngx_http_coraza_ctx_t *ctx, ngx_str_t *name, ngx_str_t *value);
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
ngx_http_coraza_add_response_header(ngx_http_request_t *r,
    ngx_http_coraza_ctx_t *ctx, ngx_str_t *name, ngx_str_t *value)
{
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "coraza: missing context while adding response header \"%V\"", name);
        return NGX_ERROR;
    }

    if (coraza_add_response_header(ctx->coraza_transaction,
        (char *) name->data,
        name->len,
        (char *) value->data,
        value->len) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "coraza: failed to add response header \"%V\"", name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


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
            value.len = sizeof(ngx_http_server_full_string) - 1;
        } else {
            value.data = (u_char *)ngx_http_server_string;
            value.len = sizeof(ngx_http_server_string) - 1;
        }
    } else {
        ngx_table_elt_t *h = r->headers_out.server;
        value.data = h->value.data;
        value.len =  h->value.len;
    }


    return ngx_http_coraza_add_response_header(r, ctx, &name, &value);
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

    return ngx_http_coraza_add_response_header(r, ctx, &name, &date);
}


static ngx_int_t
ngx_http_coraza_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;
    ngx_str_t value;
    char buf[NGX_INT64_LEN+2];

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.content_length_n >= 0)
    {
        ngx_sprintf((u_char *)buf, "%O%Z", r->headers_out.content_length_n);
        value.data = (unsigned char *)buf;
        value.len = strlen(buf);

        return ngx_http_coraza_add_response_header(r, ctx, &name, &value);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_coraza_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (r->headers_out.content_type.len > 0)
    {

        return ngx_http_coraza_add_response_header(r, ctx, &name,
            &r->headers_out.content_type);
    }

    return NGX_OK;
}


/*
 * A streaming response has no meaningful end-of-body: the origin emits events
 * indefinitely and never sends a last_buf, so the header-delay flush (which
 * fires on last_buf) holds the response headers until the delayed-body cap
 * (NGX_HTTP_CORAZA_MAX_DELAYED_BODY) is reached.  A real SSE endpoint emits a
 * few bytes per event, so that cap is reached only after minutes or hours --
 * in practice the client receives nothing (issue #81).
 *
 * Detect Server-Sent Events (Content-Type: text/event-stream) so the caller
 * can skip the delay, exactly as it does for 101 Switching Protocols.
 *
 * SECURITY TRADE-OFF: Content-Type is chosen by the upstream, so an origin
 * that emits text/event-stream opts this response out of the phase-4 header
 * delay.  Phase 4 still RUNS on such a response (the body filter always calls
 * coraza_process_response_body()), and phase 1-3 are untouched -- what is lost
 * is only the ability to turn a phase-4 match into a clean error page, because
 * the headers are already on the wire.  A late match degrades to a connection
 * reset instead.  That is the same trade-off 101 Switching Protocols already
 * accepts, and it is inherent: streaming and full-response WAF buffering are
 * mutually exclusive by construction.  Operators who do not proxy untrusted
 * origins and want the delay unconditionally can leave their upstreams from
 * emitting text/event-stream, or disable streaming endpoints at the proxy.
 */
static ngx_int_t
ngx_http_coraza_is_sse_response(ngx_http_request_t *r)
{
    ngx_str_t *ct = &r->headers_out.content_type;
    static const u_char sse[] = "text/event-stream";
    size_t sse_len = sizeof(sse) - 1;
    size_t i;

    if (ct->len < sse_len) {
        return 0;
    }

    /* Match the media type; tolerate a trailing "; charset=..." etc. */
    if (ngx_strncasecmp(ct->data, (u_char *) sse, sse_len) != 0) {
        return 0;
    }

    /*
     * The media type must be followed by end-of-value or a semicolon-
     * delimited parameter list, with optional OWS (SP / HTAB, RFC 9110
     * 5.6.3) before the semicolon.  Anything else ("text/event-streamx",
     * "text/event-stream application/json") is NOT SSE and must keep the
     * phase-4 header delay.
     */
    for (i = sse_len; i < ct->len; i++) {
        if (ct->data[i] == ' ' || ct->data[i] == '\t') {
            continue;
        }
        return ct->data[i] == ';';
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
        return NGX_OK;
    }

    p = ngx_http_time(buf, r->headers_out.last_modified_time);

    value.data = buf;
    value.len = (int)(p-buf);

    return ngx_http_coraza_add_response_header(r, ctx, &name, &value);
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

    if (r->http_version >= NGX_HTTP_VERSION_20) {
        /*
         * HTTP/2 (RFC 9113 §8.2.2) and HTTP/3 (RFC 9114 §4.2) both forbid the
         * connection-specific header fields Connection and Keep-Alive, and
         * nginx never emits them on an h2 stream or an h3 request.  Synthesizing
         * a phantom Connection/Keep-Alive here would make the WAF inspect a
         * header the client never receives -- e.g. a rule on
         * RESPONSE_HEADERS:Connection would false-positive on every HTTP/2 and
         * HTTP/3 response.  A version check (rather than r->stream, which is
         * h2-only and NULL for h3) covers both protocols.
         */
        return NGX_OK;
    }

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

            if (ngx_http_coraza_add_response_header(r, ctx, &name2, &value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    } else {
        connection = "close";
    }

    value.data = (u_char *) connection;
    value.len = strlen(connection);

    return ngx_http_coraza_add_response_header(r, ctx, &name, &value);
}

static ngx_int_t
ngx_http_coraza_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_coraza_ctx_t *ctx = NULL;

    if (r->chunked) {
        ngx_str_t value = ngx_string("chunked");

        ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

        return ngx_http_coraza_add_response_header(r, ctx, &name, &value);
    }

    return NGX_OK;
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

        return ngx_http_coraza_add_response_header(r, ctx, &name, &value);
    }
#endif

    return NGX_OK;
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
    ngx_int_t rc;
    ngx_uint_t status;
    char *http_response_ver;
    ngx_http_coraza_conf_t *mcf;


    /* 304 Not Modified responses are still processed for header inspection
     * and audit logging; body inspection is naturally skipped (no body). */

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);


    if (ctx == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_coraza_module);

    if (ctx->intervention_triggered) {
        return ngx_http_next_header_filter(r);
    }

    /* Skip if already processed (can happen with subrequests or error pages) */
    if (ctx && ctx->processed)
    {
        return ngx_http_next_header_filter(r);
    }

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

        rc = ngx_http_coraza_headers_out[i].resolver(r,
            ngx_http_coraza_headers_out[i].name,
            ngx_http_coraza_headers_out[i].offset);
        if (rc != NGX_OK) {
            return rc;
        }
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

        /* skip deleted headers (hash == 0): their key/value pointers may be
         * stale, like nginx does in its own header filter */
        if (data[i].hash == 0) {
            continue;
        }

        /*
         * Doing this ugly cast here, explanation on the request_header
         */
        rc = ngx_http_coraza_add_response_header(r, ctx, &data[i].key,
            &data[i].value);
        if (rc != NGX_OK) {
            return rc;
        }
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

    /*
     * Determine whether response-body inspection is needed for this
     * transaction.  coraza_process_response_headers() must have been called
     * first so the library can evaluate SecResponseBodyAccess and the
     * Content-Type against SecResponseBodyMimeType.
     *
     * With libcoraza 1.4+ the library answers this directly:
     *   - SecResponseBodyAccess Off  → 0 (no inspection needed)
     *   - Content-Type not in SecResponseBodyMimeType → 0
     *   - Otherwise → 1
     * With older libcoraza the helper always returns 1 (conservative).
     */
    ctx->response_body_processable =
        ngx_http_coraza_is_response_body_processable(ctx->coraza_transaction);

    ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 0);
    if (r->error_page) {
        return ngx_http_next_header_filter(r);
    }
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        if (r->headers_out.location) {
            /* Redirect: send status + Location through normal filter chain.
             * ngx_http_filter_finalize_request would generate a new error
             * page with fresh headers, discarding our Location header.
             * Clear status_line so the core filter builds it from status
             * (proxy sets status_line from upstream, e.g. "404 Not Found"). */
            r->headers_out.status = ret;
            r->headers_out.status_line.len = 0;
            r->err_status = 0;
            r->header_only = 1;

            /* Clear entity/representation headers carried over from the
             * original response so the synthesized 3xx redirect is not
             * protocol-inconsistent (RFC 9110 §15.4 / §8.3-8.8): a body-less
             * redirect must not advertise Content-Length, Content-Type,
             * Content-Encoding, Last-Modified, ETag or Accept-Ranges that
             * describe the representation we are discarding. */
            r->headers_out.content_length_n = -1;
            if (r->headers_out.content_length) {
                r->headers_out.content_length->hash = 0;
                r->headers_out.content_length = NULL;
            }
            ngx_str_null(&r->headers_out.content_type);
            r->headers_out.content_type_len = 0;
            r->headers_out.last_modified_time = -1;
            if (r->headers_out.last_modified) {
                r->headers_out.last_modified->hash = 0;
                r->headers_out.last_modified = NULL;
            }
            if (r->headers_out.content_encoding) {
                r->headers_out.content_encoding->hash = 0;
                r->headers_out.content_encoding = NULL;
            }
            if (r->headers_out.etag) {
                r->headers_out.etag->hash = 0;
                r->headers_out.etag = NULL;
            }
            ngx_http_clear_accept_ranges(r);

            return ngx_http_next_header_filter(r);
        }
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
     * We skip the delay when coraza_delay_response_headers is off (operators
     * who know their loaded ruleset has no phase-4 response rules can restore
     * normal header streaming and accept that late phase-4 interventions can
     * no longer produce a clean error page after headers are sent), for HEAD
     * requests (no body to inspect; nginx's final header filter sets
     * r->header_only for HEAD, but check r->method explicitly so a delayed HEAD
     * can never stall), error pages (already an error response), and
     * subrequests (handled independently).
     * We also skip the delay when body inspection is not needed
     * (SecResponseBodyAccess Off or Content-Type mismatch): in that case
     * there is no phase-4 buffering and the response must not be held back.
     *
     * We also skip 101 Switching Protocols: an upgraded connection (e.g.
     * WebSocket) becomes a raw bidirectional tunnel with no HTTP response
     * body, so the body filter never sees a last_buf to trigger the flush.
     * Delaying the 101 would hold the handshake forever and the upgrade
     * would never complete.
     *
     * We likewise skip Server-Sent Events (Content-Type: text/event-stream):
     * an SSE stream emits events indefinitely and never sends a last_buf, so
     * the headers would be held until the delayed-body cap forces a flush --
     * minutes or hours on a real event stream, i.e. the client gets nothing
     * (issue #81).  See ngx_http_coraza_is_sse_response() above for the
     * security trade-off this accepts.
     */
    if (mcf->delay_response_headers
        && r->method != NGX_HTTP_HEAD && !r->header_only && !r->error_page
        && r == r->main
        && r->headers_out.status != NGX_HTTP_SWITCHING_PROTOCOLS
        && !ngx_http_coraza_is_sse_response(r))
    {
        /*
         * Delay sending headers until phase 4 completes so that
         * phase 4 rules can still return a clean error page.
         * Only force body into memory when body inspection is needed.
         */
        if (ctx->response_body_processable) {
            r->filter_need_in_memory = 1;
        }
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
