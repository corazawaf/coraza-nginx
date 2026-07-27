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


ngx_int_t
ngx_http_coraza_pre_access_handler(ngx_http_request_t *r)
{
#if 1
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

    if (ctx->body_requested == 0)
    {
        ngx_int_t rc = NGX_OK;

        ctx->body_requested = 1;

        dd("asking for the request body, if any. Count: %d",
            r->main->count);
        /* Ensure the full request body lands in a single buffer for inspection */
        r->request_body_in_single_buf = 1;
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
        int pret = 0;
        int already_inspected = 0;
        char *file_name = NULL;

        dd("request body is ready to be processed");

        r->write_event_handler = ngx_http_core_run_phases;

        ngx_chain_t *chain = r->request_body->bufs;

        /* TODO: send chunks to Coraza as they arrive instead of waiting
         * for the full body, to reduce latency on large requests. */

        if (r->request_body->temp_file != NULL) {
            ngx_str_t file_path = r->request_body->temp_file->file.name;
            if (ngx_str_to_char(file_path, &file_name, r->pool) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            /*
             * Request body was saved to a file, probably we don't have a
             * copy of it in memory.
             */
            dd("request body inspection: file -- %s", file_name);

            /*
             * A non-zero return means libcoraza could not read/submit the
             * body file, so the engine would evaluate phase 2 against no (or
             * a partial) body while nginx forwards the full body upstream.
             * Fail closed rather than inspect less than we forward.
             * (libcoraza signals failure with a positive sentinel, so test
             * != 0, not < 0.)
             */
            if (coraza_request_body_from_file(ctx->coraza_transaction, file_name) != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "coraza: failed to submit file-buffered request body for inspection");
                ctx->intervention_triggered = 1;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
            if (coraza_append_request_body(ctx->coraza_transaction, data, blen) != 0) {
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

        /* Check for body limit intervention before processing rules */
        ret = ngx_http_coraza_process_intervention(ctx, r, 0);
        if (r->error_page) {
            return NGX_DECLINED;
        }
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

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
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
#endif
    return NGX_DECLINED;
}

