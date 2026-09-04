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

ngx_int_t
ngx_http_coraza_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_coraza_ctx_t   *ctx;
    ngx_http_coraza_conf_t  *mcf;
    ngx_str_t ngx_server_addr;
    char *client_addr = NULL;
    char *server_addr = NULL;
    char *uri = NULL;
    char *method = NULL;
    char *http_version = NULL;

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_coraza_module);
    if (mcf == NULL || mcf->enable != 1) {
        dd("coraza not enabled... returning");
        return NGX_DECLINED;
    }

    dd("catching a new _rewrite_ phase handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        int ret = 0;
        int pret = 0;

        ngx_connection_t *connection = r->connection;

        ngx_str_t addr_text = connection->addr_text;
        
        ctx = ngx_http_coraza_create_ctx(r);

        dd("ctx was NULL, creating new context: %p", ctx);

        if (ctx == NULL) {
            dd("ctx still null; Nothing we can do, returning an error.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * The rewrite phase is the earliest phase where nginx allows
         * content handlers to be registered (FIND_CONFIG_PHASE is not
         * an array and cannot be hooked).
         */
        int client_port = 0;
        int server_port = 0;

        /* For unix domain sockets, pass a conventional address/port instead
         * of the socket file path so rules and audit logs see sane values. */
        if (connection->sockaddr->sa_family == AF_UNIX) {
            client_addr = "unix";
        } else {
            client_port = ngx_inet_get_port(connection->sockaddr);
            if (ngx_str_to_char(addr_text, &client_addr, r->pool) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (connection->local_sockaddr->sa_family == AF_UNIX) {
            server_addr = "unix";
        } else {
            u_char addr[NGX_SOCKADDR_STRLEN];
            ngx_server_addr.len = NGX_SOCKADDR_STRLEN;
            ngx_server_addr.data = addr;
            if (ngx_connection_local_sockaddr(r->connection, &ngx_server_addr, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            server_port = ngx_inet_get_port(connection->local_sockaddr);
            if (ngx_str_to_char(ngx_server_addr, &server_addr, r->pool) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        ret = coraza_process_connection(ctx->coraza_transaction,
                                        client_addr,
                                        client_port,
                                        server_addr,
                                        server_port);
        if (ret != 1){
            dd("Was not able to extract connection information.");
        }
        /*
         * No intervention poll here: coraza_process_connection only populates
         * connection variables (REMOTE_ADDR/PORT, SERVER_ADDR/PORT) and runs no
         * rule phase, so tx.Interruption() is provably nil at this point on
         * every libcoraza version (coraza core sets tx.interruption only inside
         * phase evaluation, first reached at ProcessRequestHeaders). A phase-1
         * REMOTE_ADDR deny still fires at the post-request-headers poll below.
         */
        dd("connection variables filled in; first rule phase is request headers");

        /* Coraza sets REQUEST_PROTOCOL to this string verbatim
         * (Transaction.ProcessURI -> requestProtocol.Set), and every
         * Coraza-native caller hands it the slash-delimited form: the Go
         * middleware passes net/http's req.Proto ("HTTP/1.1"), as do
         * libcoraza's own tests. Emitting a bare "1.1" here means the
         * documented rule form -- SecRule REQUEST_PROTOCOL "@streq HTTP/1.1"
         * -- can never match. The ModSecurity-nginx connector strips the
         * "HTTP/" prefix instead, which is a ModSecurity v2 convention; do
         * not copy it. Keep this in sync with the response-side string built
         * in ngx_http_coraza_header_filter.c, which is already prefixed. */
        switch (r->http_version) {
            case NGX_HTTP_VERSION_9 :
                http_version = "HTTP/0.9";
                break;
            case NGX_HTTP_VERSION_10 :
                http_version = "HTTP/1.0";
                break;
            case NGX_HTTP_VERSION_11 :
                http_version = "HTTP/1.1";
                break;
#if defined(nginx_version) && nginx_version >= 1009005
            case NGX_HTTP_VERSION_20 :
                http_version = "HTTP/2.0";
                break;
#endif
#if defined(nginx_version) && nginx_version >= 1025000
            case NGX_HTTP_VERSION_30 :
                http_version = "HTTP/3.0";
                break;
#endif
            default :
                http_version = "HTTP/1.0";
                break;
        }

        if (ngx_str_to_char(r->unparsed_uri, &uri, r->pool) != NGX_OK) {
            dd("uri is of length zero");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (ngx_str_to_char(r->method_name, &method, r->pool) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        coraza_process_uri(ctx->coraza_transaction, uri, method, http_version);

        /*
         * No intervention poll here either: coraza_process_uri only populates
         * URI-derived variables (REQUEST_URI, REQUEST_METHOD, ARGS, …) and runs
         * no rule phase, so tx.Interruption() is still provably nil. A phase-1
         * REQUEST_URI deny fires at ProcessRequestHeaders → the poll below.
         */
        dd("uri/method/version variables filled in");

        /**
         * Since incoming request headers are already in place, lets send it to Coraza
         *
         */
        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *data = part->elts;
        ngx_uint_t i = 0;
        ngx_int_t  bulk_done = 0;

        /*
         * Fast path: pack every request header into one buffer and hand
         * Coraza the whole set in a single cgo crossing, instead of one
         * crossing per header.  Falls through to the per-header loop below
         * if the pack fails (e.g. an over-range header length -- treated as
         * fail-closed there too).
         */
        {
            ngx_http_coraza_header_t *pairs;
            ngx_uint_t nheaders = 0;
            ngx_list_part_t *cp = part;
            ngx_table_elt_t *cd = cp->elts;

            for (i = 0; ; i++) {
                if (i >= cp->nelts) {
                    if (cp->next == NULL) {
                        break;
                    }
                    cp = cp->next;
                    cd = cp->elts;
                    i = 0;
                }
                if (cd[i].hash != 0) {
                    nheaders++;
                }
            }

            if (nheaders == 0) {
                bulk_done = 1;   /* nothing to add, skip the fallback loop */
            } else {
                pairs = ngx_palloc(r->pool,
                    nheaders * sizeof(ngx_http_coraza_header_t));
                if (pairs != NULL) {
                    ngx_uint_t k = 0;
                    u_char    *packed;
                    size_t     packed_len;

                    cp = part;
                    cd = cp->elts;
                    for (i = 0; ; i++) {
                        if (i >= cp->nelts) {
                            if (cp->next == NULL) {
                                break;
                            }
                            cp = cp->next;
                            cd = cp->elts;
                            i = 0;
                        }
                        if (cd[i].hash == 0) {
                            continue;
                        }
                        pairs[k].name = cd[i].key;
                        pairs[k].value = cd[i].value;
                        k++;
                    }

                    if (ngx_http_coraza_pack_headers(r, pairs, k,
                            &packed, &packed_len) == NGX_OK)
                    {
                        /*
                         * A negative return means Coraza rejected the whole
                         * batch (bad framing, count mismatch, allocation
                         * failure).  Do NOT commit to the bulk path in that
                         * case -- leaving bulk_done == 0 lets the per-header
                         * loop below replay every header, so a batch failure
                         * degrades to the same coverage as the fallback path
                         * rather than to zero headers inspected.
                         */
                        if (coraza_add_request_headers(ctx->coraza_transaction,
                                (char *) packed, (int) packed_len, (int) k) >= 0)
                        {
                            bulk_done = 1;
                        } else {
                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "coraza: bulk request-header submission failed, "
                                "falling back to per-header path");
                        }
                    }
                }
            }
        }

        for (i = 0 ; !bulk_done ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            /* skip deleted headers (hash == 0): their key/value pointers
             * may be stale */
            if (data[i].hash == 0) {
                continue;
            }

            /**
             * By using u_char (utf8_t) I believe nginx is hoping to deal
             * with utf8 strings.
             * Casting those into to unsigned char * in order to pass
             * it to Coraza, it will handle with those later.
             *
             */

            dd("Adding request header: %.*s with value %.*s", (int)data[i].key.len, data[i].key.data, (int) data[i].value.len, data[i].value.data);

            /*
             * coraza_add_request_header takes int lengths; guard the
             * size_t -> int narrowing so an oversized header cannot wrap to
             * a bogus length and slip past inspection. Fail closed.
             */
            if (data[i].key.len > INT_MAX || data[i].value.len > INT_MAX) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "coraza: request header too long to inspect");
                ctx->intervention_triggered = 1;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            coraza_add_request_header(ctx->coraza_transaction,
                                      (char *)data[i].key.data,
                                      (int)data[i].key.len,
                                      (char *)data[i].value.data,
                                      (int)data[i].value.len);
        }

        /**
         * Since Coraza already knew about all headers, i guess it is safe
         * to process this information.
         */

        pret = coraza_process_request_headers(ctx->coraza_transaction);
        dd("Processing intervention with the request headers information filled in");
        ret = ngx_http_coraza_poll_after_process(ctx, r, 1, pret);
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
    }


    return NGX_DECLINED;
}
