/*
 * Minimal nginx shim for fuzzing ngx_str_to_char().
 *
 * The real ngx_http_coraza_common.h pulls in <ngx_config.h>/<ngx_core.h>/
 * <ngx_http.h> plus the dlopen'd libcoraza surface — the whole nginx tree.
 * ngx_str_to_char() only touches a tiny, well-defined slice of that surface
 * (ngx_str_t, a pool allocator, ngx_memcpy), so we reproduce just that slice
 * here with the EXACT upstream semantics. The fuzz target then includes the
 * real, shipped function body verbatim (sliced by extract_parser.sh into
 * generated_parser.inc), so we are fuzzing production code — not a
 * re-implementation.
 *
 * The pool here is a trivial bump allocator over malloc so ASan/UBSan see the
 * real allocation + memcpy the connector performs. If nginx ever changes the
 * semantics of ngx_pnalloc / ngx_memcpy this shim must be updated to match;
 * the comments below cite the upstream source these are copied from.
 */

#ifndef NGX_CORAZA_FUZZ_SHIM_H
#define NGX_CORAZA_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Guard against the real nginx/coraza headers being pulled in alongside. */
#define NGX_HTTP_CORAZA_COMMON_H_SHIMMED 1

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

#define NGX_OK     0
#define NGX_ERROR -1

/* src/core/ngx_string.h */
typedef struct {
    size_t  len;
    u_char *data;
} ngx_str_t;

/*
 * Trivial pool stand-in. The real ngx_pool_t is opaque to ngx_str_to_char():
 * it only ever passes the pointer to ngx_pnalloc(). We record every live
 * allocation so the harness can free them between iterations (no leak
 * accumulation across the fuzz loop) while still routing the actual bytes
 * through malloc, where ASan tracks bounds.
 */
#define NGX_FUZZ_POOL_MAX 8
typedef struct {
    void   *allocs[NGX_FUZZ_POOL_MAX];
    size_t  n;
} ngx_pool_t;

/* src/core/ngx_palloc.c: ngx_pnalloc() — unaligned pool allocation. */
static inline void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (pool->n >= NGX_FUZZ_POOL_MAX) {
        return NULL;
    }
    void *p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->n++] = p;
    return p;
}

/* Release everything ngx_pnalloc handed out this iteration. */
static inline void
ngx_fuzz_pool_reset(ngx_pool_t *pool)
{
    for (size_t i = 0; i < pool->n; i++) {
        free(pool->allocs[i]);
    }
    pool->n = 0;
}

/* src/core/ngx_string.h: ngx_memcpy() — thin wrapper over memcpy(). */
#define ngx_memcpy(dst, src, n)  (void) memcpy(dst, src, n)

/* src/core/ddebug.h: dd() is compiled out unless CORAZA_DDEBUG. */
#ifndef dd
#define dd(...) (void) 0
#endif

#endif /* NGX_CORAZA_FUZZ_SHIM_H */
