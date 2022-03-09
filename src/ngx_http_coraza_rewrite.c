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
        /**
         * FIXME: We may want to use struct sockaddr instead of addr_text.
         *
         */
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

        const char *client_addr = ngx_str_to_char(addr_text, r->pool);
        if (client_addr == (char*)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_t s;
        u_char addr[NGX_SOCKADDR_STRLEN];
        s.len = NGX_SOCKADDR_STRLEN;
        s.data = addr;
        if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        const char *server_addr = ngx_str_to_char(s, r->pool);
        if (server_addr == (char*)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ret = coraza_process_connection(ctx->coraza_transaction,
                                        (char *)client_addr, client_port,
                                        (char *)server_addr, server_port);
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

        const char *http_version;
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

        const char *n_uri = ngx_str_to_char(r->unparsed_uri, r->pool);
        const char *n_method = ngx_str_to_char(r->method_name, r->pool);
        if (n_uri == (char*)-1 || n_method == (char*)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (n_uri == NULL) {
            dd("uri is of length zero");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        coraza_process_uri(ctx->coraza_transaction, (char *)n_uri, (char *)n_method, (char *)http_version);

        dd("Processing intervention with the transaction information filled in (uri, method and version)");
        ret = ngx_http_coraza_process_intervention(ctx->coraza_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

        /**
         * Since incoming request headers are already in place, lets send it to ModSecurity
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
             * it to ModSecurity, it will handle with those later.
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
         * Since ModSecurity already knew about all headers, i guess it is safe
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
