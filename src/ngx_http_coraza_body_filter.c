/*
 * Coraza connector for nginx
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#include "ngx_http_coraza_common.h"

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

/* XXX: check behaviour on few body filters installed */
ngx_int_t
ngx_http_coraza_body_filter_init(void)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_coraza_body_filter;

    return NGX_OK;
}


/*
 * Extract body data from a buffer, handling both in-memory and file buffers.
 * Our body filter runs before the copy filter, so file-backed responses
 * (e.g. static files) arrive as file buffers with pos/last unset.  We need
 * to read the file data ourselves so Coraza can inspect it.
 */
static ngx_int_t
ngx_http_coraza_read_body_data(ngx_http_request_t *r, ngx_buf_t *buf,
    u_char **out_data, size_t *out_len)
{
    if (ngx_buf_in_memory(buf)) {
        *out_data = buf->pos;
        *out_len = buf->last - buf->pos;
        return NGX_OK;
    }

    if (buf->in_file && buf->file) {
        size_t len = buf->file_last - buf->file_pos;
        if (len == 0) {
            *out_data = NULL;
            *out_len = 0;
            return NGX_OK;
        }

        u_char *data = ngx_pnalloc(r->pool, len);
        if (data == NULL) {
            return NGX_ERROR;
        }

        size_t  remaining = len;
        off_t   offset = buf->file_pos;
        size_t  total_read = 0;

        while (remaining > 0) {
            ssize_t n = ngx_read_file(buf->file, data + total_read,
                                      remaining, offset);
            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "coraza: failed to read response body from file");
                return NGX_ERROR;
            }

            if (n == 0) {
                break;
            }

            total_read += (size_t) n;
            remaining -= (size_t) n;
            offset += n;
        }

        *out_data = data;
        *out_len = total_read;
        return NGX_OK;
    }

    /* Empty buffer (e.g. flush-only) */
    *out_data = NULL;
    *out_len = 0;
    return NGX_OK;
}


ngx_int_t
ngx_http_coraza_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *chain = in;
    ngx_http_coraza_ctx_t *ctx = NULL;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->intervention_triggered) {
        return ngx_http_next_body_filter(r, in);
    }

    int is_request_processed = 0;
    for (chain = in; chain != NULL; chain = chain->next)
    {
        u_char *data;
        size_t len;
        int ret;

        if (ngx_http_coraza_read_body_data(r, chain->buf, &data, &len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (len > 0) {
            coraza_append_response_body(ctx->coraza_transaction, data, len);
        }

        ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 0);
        if (ret > 0) {
            if (ctx->headers_delayed) {
                ctx->intervention_triggered = 1;
                ctx->headers_delayed = 0;
                return ret;
            }
            return ngx_http_filter_finalize_request(r,
                &ngx_http_coraza_module, ret);
        }

/* XXX: chain->buf->last_buf || chain->buf->last_in_chain */
        is_request_processed = chain->buf->last_buf;

        if (is_request_processed) {

            coraza_process_response_body(ctx->coraza_transaction);

            ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 0);
            if (ret > 0) {
                if (ctx->headers_delayed) {
                    ctx->intervention_triggered = 1;
                    ctx->headers_delayed = 0;
                    return ret;
                }
                return ret;
            }
            else if (ret < 0) {
                if (ctx->headers_delayed) {
                    ctx->intervention_triggered = 1;
                    ctx->headers_delayed = 0;
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                return ngx_http_filter_finalize_request(r,
                    &ngx_http_coraza_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    if (ctx->headers_delayed) {
        if (is_request_processed) {
            /*
             * Phase 4 completed with no intervention.  Now forward the
             * delayed response headers followed by the accumulated body.
             */
            ngx_int_t rc;
            ngx_chain_t *out;

            ctx->headers_delayed = 0;

            rc = ngx_http_coraza_forward_header(r);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            /* Combine pending chain (previous calls) with current input */
            if (ctx->pending_chain) {
                *ctx->pending_chain_last = in;
                out = ctx->pending_chain;
                ctx->pending_chain = NULL;
            } else {
                out = in;
            }

            return ngx_http_next_body_filter(r, out);
        }

        /* Not the last buffer yet — accumulate chain links */
        for (chain = in; chain != NULL; chain = chain->next) {
            ngx_chain_t *cl;

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = chain->buf;
            cl->next = NULL;
            *ctx->pending_chain_last = cl;
            ctx->pending_chain_last = &cl->next;
        }

        return NGX_OK;
    }

    if (!is_request_processed)
    {
        //dd("buffer was not fully loaded! ctx: %p", ctx);
    }

/* XXX: xflt_filter() -- return NGX_OK here */
    return ngx_http_next_body_filter(r, in);
}
