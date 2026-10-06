/*
 * libFuzzer target for the coraza-nginx connector's ngx_str->C-string
 * conversion, ngx_str_to_char().
 *
 * Converts nginx strings used for URI, method, address, and other C-string
 * arguments. Header and body submission use length-taking APIs and do not
 * generally pass through this helper.
 *
 * The real function body is sliced verbatim from
 * ../src/ngx_http_coraza_utils.c by extract_parser.sh — we fuzz production
 * code, not a copy. ngx_shim.h supplies the tiny nginx slice it needs
 * (ngx_str_t, a malloc-backed pool, ngx_memcpy) so ASan/UBSan observe the
 * real allocation + copy.
 *
 * Invariants asserted every iteration:
 *   - len==0 input allocates an empty NUL-terminated C-string on NGX_OK.
 *   - non-empty input yields a C-string whose first `len` bytes equal the
 *     input and whose byte at [len] is '\0'.
 *   - no read/write outside the len+1 allocation (enforced by ASan).
 */

#include <assert.h>
#include <string.h>

#include "ngx_shim.h"

/* Verbatim ngx_str_to_char() body, extracted from the shipped source. */
#include "generated_parser.inc"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t  pool = {0};
    ngx_str_t   in;
    char       *out = (char *) 0x1;   /* poison: must be overwritten */
    ngx_int_t   rc;

    in.len  = size;
    in.data = (u_char *) data;        /* deliberately NOT NUL-terminated */

    rc = ngx_str_to_char(in, &out, &pool);

    if (rc == NGX_OK) {
        /*
         * On success the contract is the same for every length, including 0:
         * ngx_str_to_char() allocates a.len + 1 bytes and NUL-terminates at
         * a.len, so an empty input yields a valid pointer to "" -- never NULL.
         * Every caller passes the result straight to the Coraza engine, where
         * an empty C string is correct and NULL would be the actual bug, so
         * asserting NULL-on-empty here would encode an invariant the function
         * has never had (and does not want).
         */
        assert(out != NULL);

        if (size > 0) {
            /* First `size` bytes copied faithfully... */
            assert(memcmp(out, data, size) == 0);
        }

        /* ...and NUL-terminated exactly one past the copy. */
        assert(out[size] == '\0');
    }
    /* NGX_ERROR is only the alloc-failure path (pool exhausted); nothing to
     * check but that we did not scribble a bogus pointer callers would use. */

    ngx_fuzz_pool_reset(&pool);
    return 0;
}
