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

/*
 * Length of the body data ngx_http_coraza_read_body_data would return,
 * without performing the read/allocation -- lets callers reject an
 * oversized chunk before paying for it.
 */
static size_t
ngx_http_coraza_body_chunk_len(ngx_buf_t *buf)
{
    if (ngx_buf_in_memory(buf)) {
        return buf->last - buf->pos;
    }

    if (buf->in_file && buf->file) {
        return buf->file_last - buf->file_pos;
    }

    return 0;
}


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
        size_t len = ngx_http_coraza_body_chunk_len(buf);
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
        /* Use last_buf (not last_in_chain) to detect end of the full response */
        is_request_processed = chain->buf->last_buf;

        /*
         * Only forward body data to the Coraza engine when body inspection
         * is actually enabled for this transaction.  When SecResponseBodyAccess
         * is Off (or the Content-Type does not match SecResponseBodyMimeType)
         * ctx->response_body_processable is 0 and we skip the Go FFI call
         * entirely, preventing the large-response hang.
         */
        if (ctx->response_body_processable) {
            u_char *data;
            size_t  len;
            int     ret;

            /*
             * coraza_append_response_body takes an int length; guard the
             * size_t -> int narrowing so a >INT_MAX buffer cannot wrap to a
             * bogus length and skip inspection. Fail closed. Checked against
             * the buffer's own bounds before the read/allocation below, so
             * an oversized on-disk chunk is rejected without paying for the
             * file read first.
             */
            if (ngx_http_coraza_body_chunk_len(chain->buf) > INT_MAX) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "coraza: response body chunk too large to inspect");
                ctx->intervention_triggered = 1;
                return NGX_ERROR;
            }

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
            } else if (ret < 0) {
                ctx->intervention_triggered = 1;
                if (ctx->headers_delayed) {
                    ctx->headers_delayed = 0;
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                return ngx_http_filter_finalize_request(r,
                    &ngx_http_coraza_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        /*
         * Always call coraza_process_response_body() on the last buffer,
         * even when body inspection is disabled. This triggers phase 4
         * rule evaluation which can match on non-body variables (ARGS,
         * TX, etc.).
         */
        if (is_request_processed) {
            int ret;

            coraza_process_response_body(ctx->coraza_transaction);

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

        /*
         * When response headers are being delayed (waiting for phase 4),
         * move every buffer into pending_chain so the flush logic below
         * is uniform: pending_chain IS the complete chain to forward, and
         * `in` is never appended.
         *
         *   - Intermediate buffers (last_buf=0) are deep-copied into the
         *     request pool and the original is marked consumed (pos=last).
         *     This lets nginx recycle proxy/upstream buffers while we wait
         *     for the last buffer, avoiding the large-response hang.
         *
         *   - The final buffer (last_buf=1) is appended as a passthrough
         *     chain link (no copy needed -- the flush below forwards it
         *     synchronously, so the original storage is still valid).
         */
        if (ctx->headers_delayed) {
            ngx_chain_t *cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            if (is_request_processed) {
                cl->buf = chain->buf;
            } else {
                ngx_buf_t *b;
                u_char    *data;
                size_t     len;

                if (ngx_http_coraza_read_body_data(r, chain->buf, &data, &len)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                b = ngx_calloc_buf(r->pool);
                if (b == NULL) {
                    return NGX_ERROR;
                }

                if (len > 0) {
                    /*
                     * Always make a pool copy: in-memory buffers may point
                     * into nginx's single reusable upstream buffer (u->buffer)
                     * which nginx will overwrite once we mark it consumed.
                     */
                    u_char *copy = ngx_pnalloc(r->pool, len);
                    if (copy == NULL) {
                        return NGX_ERROR;
                    }
                    ngx_memcpy(copy, data, len);
                    b->pos    = copy;
                    b->last   = copy + len;
                    b->memory = 1;
                }

                ctx->pending_bytes += len;

                b->last_buf      = 0;
                b->last_in_chain = chain->buf->last_in_chain;
                b->flush         = chain->buf->flush;

                /* Mark original buffer consumed so nginx may reuse it. */
                if (ngx_buf_in_memory(chain->buf)) {
                    chain->buf->pos = chain->buf->last;
                } else if (chain->buf->in_file) {
                    chain->buf->file_pos = chain->buf->file_last;
                }

                cl->buf = b;
            }

            cl->next = NULL;
            *ctx->pending_chain_last = cl;
            ctx->pending_chain_last  = &cl->next;
        }
    }

    if (ctx->headers_delayed) {
        if (is_request_processed) {
            /*
             * Phase 4 completed with no intervention.  Forward the delayed
             * response headers, then the accumulated chain.  pending_chain
             * is guaranteed non-NULL here: every iteration of the loop above
             * appended to it (either a copy or a passthrough link).
             */
            ngx_int_t    rc;
            ngx_chain_t *out;

            ctx->headers_delayed = 0;

            rc = ngx_http_coraza_forward_header(r);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            /*
             * forward_header() bottoms out in the write filter, which returns
             * NGX_AGAIN (not just NGX_OK) whenever the headers can't be fully
             * flushed -- e.g. a full socket buffer, or limit_rate throttling
             * via c->write->delayed even on an empty socket.  We must NOT bail
             * on that NGX_AGAIN: the buffered body has not entered r->out yet
             * (the write filter only buffered the headers it was handed).  On
             * the write retry nginx calls ngx_http_output_filter(r, NULL), so
             * this body filter would run with in == NULL and headers_delayed
             * already 0, fall straight through, and pending_chain would be
             * orphaned -- headers sent, body truncated.  Hand pending_chain to
             * the body filter unconditionally; its return value carries the
             * NGX_AGAIN up so the retry flushes headers and body together.
             */
            out = ctx->pending_chain;
            ctx->pending_chain = NULL;
            return ngx_http_next_body_filter(r, out);
        }

        /*
         * Not the last buffer yet.  If we have buffered more than the cap,
         * stop delaying: flush the delayed headers plus everything accumulated
         * so far and let the remainder stream through.  This bounds worker
         * memory on large or open-ended (streaming, e.g. SSE / long-poll)
         * responses, whose delayed-header buffering would otherwise grow
         * without limit in r->pool waiting for a last_buf that may never come.
         *
         * Trade-off: once the headers are on the wire a phase-4 rule can no
         * longer produce a clean error page for this (oversized) response — an
         * intervention past this point degrades to a connection reset.  We
         * accept that to prevent an OOM/DoS on unbounded responses.
         */
        if (ctx->pending_bytes > NGX_HTTP_CORAZA_MAX_DELAYED_BODY) {
            ngx_int_t    rc;
            ngx_chain_t *out;

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "coraza: delayed response body exceeded %uz bytes; flushing "
                "headers early, phase-4 body blocking is no longer clean for "
                "this response",
                (size_t) NGX_HTTP_CORAZA_MAX_DELAYED_BODY);

            ctx->headers_delayed = 0;

            /*
             * Short-circuit only on NGX_ERROR.  forward_header() can return
             * NGX_AGAIN (write filter buffered the headers but couldn't flush
             * them yet); bailing here would leave pending_chain unsent and
             * truncate the body.  Fall through and hand it to the body filter,
             * whose return value carries the NGX_AGAIN up so the retry flushes
             * headers and body together (same contract as the end-of-body
             * flush above).
             */
            rc = ngx_http_coraza_forward_header(r);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            out = ctx->pending_chain;
            ctx->pending_chain = NULL;
            ctx->pending_chain_last = &ctx->pending_chain;
            return ngx_http_next_body_filter(r, out);
        }

        /* Under the cap -- keep accumulating until last_buf. */
        return NGX_OK;
    }

    if (!is_request_processed)
    {
        //dd("buffer was not fully loaded! ctx: %p", ctx);
    }

    return ngx_http_next_body_filter(r, in);
}
