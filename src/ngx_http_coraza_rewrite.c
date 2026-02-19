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

        ngx_connection_t *connection = r->connection;

        ngx_str_t addr_text = connection->addr_text;
        
        ctx = ngx_http_coraza_create_ctx(r);

        dd("ctx was NULL, creating new context: %p", ctx);

        if (ctx == NULL) {
            dd("ctx still null; Nothing we can do, returning an error.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /**
         * FIXME: Check if it is possible to hook on nginx on a earlier phase.
         *
         * At this point we are doing an late connection process. Maybe
         * we have to hook into NGX_HTTP_FIND_CONFIG_PHASE, it seems to be the
         * erliest phase that nginx allow us to attach those kind of hooks.
         *
         */
        int client_port = ngx_inet_get_port(connection->sockaddr);
        int server_port = ngx_inet_get_port(connection->local_sockaddr);
        
        u_char addr[NGX_SOCKADDR_STRLEN];
        ngx_server_addr.len = NGX_SOCKADDR_STRLEN;
        ngx_server_addr.data = addr;
        if (ngx_connection_local_sockaddr(r->connection, &ngx_server_addr, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_str_to_char(addr_text, &client_addr, r->pool) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_str_to_char(ngx_server_addr, &server_addr, r->pool) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } 

        /* FIXME: addr_text here is an nginx str that might be a path if
         * this is a unix socket. Because of this, using the socket 
         * structure might be better
         */
        ret = coraza_process_connection(ctx->coraza_transaction,
                                        client_addr,
                                        client_port,
                                        server_addr,
                                        server_port);
        if (ret != 1){
            dd("Was not able to extract connection information.");
        }
        /**
         *
         * FIXME: Check how we can finalize a request without crash nginx.
         *
         * I don't think nginx is expecting to finalize a request at that
         * point as it seems that it clean the ngx_http_request_t information
         * and try to use it later.
         *
         */
        dd("Processing intervention with the connection information filled in");
        ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

        switch (r->http_version) {
            case NGX_HTTP_VERSION_9 :
                http_version = "0.9";
                break;
            case NGX_HTTP_VERSION_10 :
                http_version = "1.0";
                break;
            case NGX_HTTP_VERSION_11 :
                http_version = "1.1";
                break;
#if defined(nginx_version) && nginx_version >= 1009005
            case NGX_HTTP_VERSION_20 :
                http_version = "2.0";
                break;
#endif
            default :
                http_version = "1.0";
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

        dd("Processing intervention with the transaction information filled in (uri, method and version)");
        ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

        /**
         * Since incoming request headers are already in place, lets send it to Coraza
         *
         */
        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *data = part->elts;
        ngx_uint_t i = 0;
        for (i = 0 ; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            /**
             * By using u_char (utf8_t) I believe nginx is hoping to deal
             * with utf8 strings.
             * Casting those into to unsigned char * in order to pass
             * it to Coraza, it will handle with those later.
             *
             */

            dd("Adding request header: %.*s with value %.*s", (int)data[i].key.len, data[i].key.data, (int) data[i].value.len, data[i].value.data);
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

        coraza_process_request_headers(ctx->coraza_transaction);
        dd("Processing intervention with the request headers information filled in");
        ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 1);
        if (r->error_page) {
            return NGX_DECLINED;
            }
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }


    return NGX_DECLINED;
}
