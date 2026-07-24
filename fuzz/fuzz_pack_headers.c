/*
 * libFuzzer target for ngx_http_coraza_pack_headers().
 *
 * pack_headers() serialises an array of (name,value) header pairs into the
 * single length-prefixed buffer the connector hands to libcoraza's bulk
 * header-submission entry points (coraza_add_{request,response}_headers).
 * The wire format is, per header:
 *
 *     u16 name_len | name bytes | u32 value_len | value bytes
 *
 * Unlike ngx_str_to_char() this function carries real length arithmetic: a
 * running total guarded against the `int` packed-length ceiling, per-field
 * u16/u32/INT_MAX bounds, and two memcpy()s whose destination offsets are
 * driven by attacker-influenced header lengths. A slip in the total, the
 * shift/mask encoding, or a pointer advance is a heap overflow reachable from
 * request/response header data, so this is a higher-value pure-C fuzz surface
 * than the str->C-string leaf.
 *
 * The real function body is sliced verbatim from
 * ../src/ngx_http_coraza_utils.c by extract_pack_headers.sh — we fuzz
 * production code, not a copy. ngx_shim.h supplies the nginx slice it needs
 * (ngx_str_t, a malloc-backed pool, a request stub carrying only the pool,
 * ngx_http_coraza_header_t, ngx_memcpy) so ASan/UBSan observe the real
 * allocation + copies.
 *
 * The fuzzer input is consumed as a self-describing pair list:
 *   [count]                                  1 byte
 *   then `count` pairs, each:
 *     [nlen_hi][nlen_lo]                      name length (u16, from input)
 *     [vlen_hi][vlen_lo]                      value length (u16, from input)
 *     name bytes ... value bytes ...          pointed into the input buffer
 * A pair whose declared bytes run past the input is clamped, so no read is
 * made outside `data` — the packing itself is what we are exercising.
 *
 * Invariants asserted every iteration:
 *   - on NGX_OK, out_len equals the sum of 6 + nlen + vlen over all pairs;
 *   - the packed buffer round-trips: decoding it reproduces every pair's
 *     lengths and bytes exactly (no truncation, no misalignment);
 *   - no read/write outside the out_len allocation (enforced by ASan).
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "ngx_shim.h"

/* Verbatim ngx_http_coraza_pack_headers() body, sliced from the shipped source. */
#include "generated_pack_headers.inc"

#define MAX_PAIRS 32

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t                pool = {0};
    ngx_http_request_t        r = { .pool = &pool };
    ngx_http_coraza_header_t  pairs[MAX_PAIRS];
    ngx_uint_t                count = 0;
    size_t                    pos = 0;
    u_char                   *out = (u_char *) 0x1;   /* poison */
    size_t                    out_len = 0xdead;
    ngx_int_t                 rc;
    ngx_uint_t                i;
    size_t                    expected_total = 0;

    if (size == 0) {
        return 0;
    }

    ngx_uint_t want = data[pos++];
    if (want > MAX_PAIRS) {
        want = MAX_PAIRS;
    }

    while (count < want && pos + 4 <= size) {
        size_t nlen = ((size_t) data[pos] << 8) | data[pos + 1];
        size_t vlen = ((size_t) data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        /* Clamp the declared field lengths to what remains, so name/value
         * pointers never reference bytes outside the fuzzer input. */
        if (nlen > size - pos) {
            nlen = size - pos;
        }
        pairs[count].name.len  = nlen;
        pairs[count].name.data = (u_char *) (data + pos);
        pos += nlen;

        if (vlen > size - pos) {
            vlen = size - pos;
        }
        pairs[count].value.len  = vlen;
        pairs[count].value.data = (u_char *) (data + pos);
        pos += vlen;

        expected_total += 6 + nlen + vlen;
        count++;
    }

    /* NGX_FUZZ_POOL_MAX is 8; pack_headers does exactly one allocation, so a
     * single call never exhausts the shim pool. */
    rc = ngx_http_coraza_pack_headers(&r, pairs, count, &out, &out_len);

    if (rc != NGX_OK) {
        ngx_fuzz_pool_reset(&pool);
        return 0;
    }

    if (count == 0 || expected_total == 0) {
        assert(out == NULL);
        assert(out_len == 0);
        ngx_fuzz_pool_reset(&pool);
        return 0;
    }

    assert(out != NULL);
    assert(out_len == expected_total);

    /* Round-trip: decode the packed buffer and confirm it reproduces every
     * pair's lengths and bytes exactly. Any decode read past out_len would be
     * caught by ASan. */
    {
        size_t p = 0;
        for (i = 0; i < count; i++) {
            assert(p + 2 <= out_len);
            size_t nlen = ((size_t) out[p] << 8) | out[p + 1];
            p += 2;
            assert(nlen == pairs[i].name.len);
            assert(p + nlen <= out_len);
            if (nlen) {
                assert(memcmp(out + p, pairs[i].name.data, nlen) == 0);
            }
            p += nlen;

            assert(p + 4 <= out_len);
            size_t vlen = ((size_t) out[p] << 24) | ((size_t) out[p + 1] << 16)
                        | ((size_t) out[p + 2] << 8) | out[p + 3];
            p += 4;
            assert(vlen == pairs[i].value.len);
            assert(p + vlen <= out_len);
            if (vlen) {
                assert(memcmp(out + p, pairs[i].value.data, vlen) == 0);
            }
            p += vlen;
        }
        assert(p == out_len);
    }

    ngx_fuzz_pool_reset(&pool);
    return 0;
}
