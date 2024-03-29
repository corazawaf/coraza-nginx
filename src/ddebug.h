/*
 * Coraza connector for nginx
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

// From: https://raw.githubusercontent.com/openresty/lua-nginx-module/master/src/ddebug.h

/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _DDEBUG_H_INCLUDED_
#define _DDEBUG_H_INCLUDED_

#include <ngx_core.h>

/*
 * #undef CORAZA_DDEBUG
 * #define CORAZA_DDEBUG 1
 */

/*
 * Setting CORAZA_SANITY_CHECKS will help you in the debug process. By
 * defining CORAZA_SANITY_CHECKS a set of functions will be executed in
 * order to make sure the well behavior of CORAZA, letting you know (via
 * debug_logs) if something unexpected happens.
 *
 * If performance is not a concern, it is safe to keep it set.
 *
 */
#ifndef CORAZA_SANITY_CHECKS
#define CORAZA_SANITY_CHECKS 0
#endif

#if defined(CORAZA_DDEBUG) && (CORAZA_DDEBUG)

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "coraza *** %s: ", __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static void dd(const char *fmt, ...) {
}

#    endif

#else

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static void dd(const char *fmt, ...) {
}

#   endif

#endif

#if defined(CORAZA_DDEBUG) && (CORAZA_DDEBUG)

#define dd_check_read_event_handler(r)   \
    dd("r->read_event_handler = %s", \
        r->read_event_handler == ngx_http_block_reading ? \
            "ngx_http_block_reading" : \
        r->read_event_handler == ngx_http_test_reading ? \
            "ngx_http_test_reading" : \
        r->read_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN")

#define dd_check_write_event_handler(r)   \
    dd("r->write_event_handler = %s", \
        r->write_event_handler == ngx_http_handler ? \
            "ngx_http_handler" : \
        r->write_event_handler == ngx_http_core_run_phases ? \
            "ngx_http_core_run_phases" : \
        r->write_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN")

#else

#define dd_check_read_event_handler(r)
#define dd_check_write_event_handler(r)

#endif


#endif /* _DDEBUG_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
