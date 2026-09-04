/*
 * Coraza connector for nginx
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#ifndef CORAZA_DDEBUG
#define CORAZA_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_coraza_common.h"

#define NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE (64 * 1024)

void
ngx_http_coraza_request_read(ngx_http_request_t *r)
{
    ngx_http_coraza_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


/*
 * Reusable per-worker chunk buffer for ngx_http_coraza_append_request_body_file().
 * nginx workers are single-threaded and this function never yields to the
 * event loop between its use and its last read, so no two requests can be
 * inside this function at once and the buffer needs no locking.
 */
static u_char ngx_http_coraza_request_body_file_chunk[
    NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE];


/*
 * Finish the request-body phase after any body submission.  This must also run
 * when request-body access is off: Coraza still evaluates phase-2 rules on
 * headers, URI arguments and other non-body variables in that case.
 */
static ngx_int_t
ngx_http_coraza_process_request_body_phase(ngx_http_coraza_ctx_t *ctx,
    ngx_http_request_t *r)
{
    int pret;
    int ret;

    pret = coraza_process_request_body(ctx->coraza_transaction);
    if (ngx_http_coraza_process_body_failed(pret))
    {
        /*
         * The engine could not evaluate phase 2; no interruption is set,
         * so the poll below would let the body through uninspected.  Fail
         * closed rather than inspect nothing while nginx forwards the body.
         */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "coraza: request body phase processing failed");
        ctx->intervention_triggered = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ret = ngx_http_coraza_poll_after_process(ctx, r, 0, pret);
    if (r->error_page) {
        return NGX_DECLINED;
    }
    if (ret < 0) {
        /* NGX_ERROR from the intervention handler: fail closed. */
        ctx->intervention_triggered = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        return ret;
    }

    return NGX_DECLINED;
}


/*
 * Submit a file-buffered request body in reusable 64 KiB chunks.  Opening a
 * separate descriptor keeps ngx_read_file() from changing nginx's file offset
 * state on platforms without pread(); nginx may still need its descriptor to
 * forward the same body upstream after inspection.
 */
static ngx_int_t
ngx_http_coraza_append_request_body_file(ngx_http_coraza_ctx_t *ctx,
    ngx_http_request_t *r, ngx_temp_file_t *temp_file)
{
    ngx_file_t  file;
    u_char     *data;
    off_t       body_size;
    off_t       offset;
    size_t      size;
    ssize_t     n;
    ngx_int_t   rc;
    ngx_int_t   ret;

    body_size = temp_file->file.offset;
    if (body_size == 0) {
        return NGX_OK;
    }

    if (body_size < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "coraza: invalid file-buffered request body size");
        ctx->intervention_triggered = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = temp_file->file.name;
    file.log = r->connection->log;
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
            ngx_open_file_n " \"%V\" failed", &file.name);
        ctx->intervention_triggered = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    data = ngx_http_coraza_request_body_file_chunk;

    offset = 0;
    rc = NGX_OK;

    while (offset < body_size) {
        if (body_size - offset
            > (off_t) NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE)
        {
            size = NGX_HTTP_CORAZA_REQUEST_BODY_FILE_CHUNK_SIZE;
        } else {
            size = (size_t) (body_size - offset);
        }

        n = ngx_read_file(&file, data, size, offset);
        if (n == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "coraza: file-buffered request body ended at %O of %O bytes",
                offset, body_size);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        if (coraza_append_request_body(ctx->coraza_transaction, data,
                                       (int) n) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "coraza: failed to append file-buffered request body chunk "
                "for inspection");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        offset += n;

        if (offset < body_size) {
            ret = ngx_http_coraza_process_intervention(ctx, r, 0);
            if (ret < 0) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                rc = ret;
                goto done;
            }
        }
    }

done:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
            ngx_close_file_n " \"%V\" failed", &file.name);
    }

    if (rc != NGX_OK) {
        ctx->intervention_triggered = 1;
    }

    return rc;
}


ngx_int_t
ngx_http_coraza_pre_access_handler(ngx_http_request_t *r)
{
    ngx_http_coraza_ctx_t   *ctx;
    ngx_http_coraza_conf_t  *mcf;

    dd("catching a new _preaccess_ phase handler");

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_coraza_module);
    if (mcf == NULL || mcf->enable != 1)
    {
        dd("CORAZA not enabled... returning");
        return NGX_DECLINED;
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("ctx is null; Nothing we can do, returning an error.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->intervention_triggered) {
        return NGX_DECLINED;
    }

    if (ctx->waiting_more_body == 1)
    {
        dd("waiting for more data before proceed. / count: %d",
            r->main->count);

        return NGX_DONE;
    }

    /*
     * Request-header processing has already run in the rewrite handler, so
     * libcoraza can now answer whether request-body bytes are accessible for
     * this transaction.  When access is off, leave body_requested clear and
     * let the eventual content handler read/forward the body; Coraza discards
     * those bytes, so reading them here would only add buffering, copies and
     * cgo crossings.
     *
     * body_requested also records that this predicate was true.  On the
     * NGX_AGAIN resume path it prevents a second predicate call and a second
     * ngx_http_read_client_request_body() call.
     */
    if (ctx->body_requested == 0)
    {
        ngx_int_t rc = NGX_OK;

        if (!ngx_http_coraza_is_request_body_accessible(
                ctx->coraza_transaction))
        {
            return ngx_http_coraza_process_request_body_phase(ctx, r);
        }

        ctx->body_requested = 1;

        dd("asking for the request body, if any. Count: %d",
            r->main->count);
        r->request_body_in_persistent_file = 1;
        if (!r->request_body_in_file_only) {
            // If the above condition fails, then the flag below will have been
            // set correctly elsewhere. We need to set the flag here for other
            // conditions (client_body_in_file_only not used but
            // client_body_buffer_size is)
            r->request_body_in_clean_file = 1;
        }

        rc = ngx_http_read_client_request_body(r,
            ngx_http_coraza_request_read);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
    (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }
        if (rc == NGX_AGAIN)
        {
            dd("nginx is asking us to wait for more data.");

            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    if (ctx->waiting_more_body == 0)
    {
        int ret = 0;
        int already_inspected = 0;
        ngx_int_t rc;

        dd("request body phase is ready to be processed");

        ngx_chain_t *chain = r->request_body->bufs;

        /* TODO: send chunks to Coraza as they arrive instead of waiting
         * for the full body, to reduce latency on large requests. */

        r->write_event_handler = ngx_http_core_run_phases;

        if (r->request_body->temp_file != NULL) {
            /*
             * Request body was saved to a file, probably we don't have a
             * copy of it in memory.
             */
            dd("request body inspection: file");

            rc = ngx_http_coraza_append_request_body_file(ctx, r,
                    r->request_body->temp_file);
            if (rc != NGX_OK) {
                return rc;
            }

            already_inspected = 1;
        } else {
            dd("inspection request body in memory.");
        }

        while (chain && !already_inspected)
        {
            u_char *data = chain->buf->pos;
            size_t  blen = (size_t) (chain->buf->last - data);

            /*
             * coraza_append_request_body takes an int length; guard the
             * narrowing so a >INT_MAX chunk cannot wrap negative and have
             * the engine inspect the wrong span. Fail closed.
             */
            if (blen > INT_MAX) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "coraza: request body chunk too large to inspect");
                ctx->intervention_triggered = 1;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /*
             * A non-zero return means the chunk was not appended, so the
             * engine would inspect a shorter body than nginx forwards
             * upstream (a request-smuggling-style bypass). Fail closed.
             * (libcoraza signals failure with a positive sentinel, so test
             * != 0, not < 0.)
             */
            if (blen > 0
                && coraza_append_request_body(ctx->coraza_transaction, data,
                                              blen) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "coraza: failed to append request body chunk for inspection");
                ctx->intervention_triggered = 1;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (chain->buf->last_buf) {
                break;
            }
            chain = chain->next;

            /* Check for intervention after each chunk for prompt detection */
            ret = ngx_http_coraza_process_intervention(ctx, r, 0);
            if (ret < 0) {
                /* NGX_ERROR from the intervention handler: fail closed. */
                ctx->intervention_triggered = 1;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                return ret;
            }
        }

        /**
         * At this point, all the request body was sent to CORAZA
         * and we want to make sure that all the request body inspection
         * happened; consequently we have to check if CORAZA have
         * returned any kind of intervention.
         */

        /* Check for body limit intervention before processing rules. */
        ret = ngx_http_coraza_process_intervention(ctx, r, 0);
        if (r->error_page) {
            return NGX_DECLINED;
        }
        if (ret < 0) {
            /* NGX_ERROR from the intervention handler: fail closed. */
            ctx->intervention_triggered = 1;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

        return ngx_http_coraza_process_request_body_phase(ctx, r);
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
    return NGX_DECLINED;
}
