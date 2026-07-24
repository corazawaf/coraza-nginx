/*
 * Coraza connector for nginx
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#include "ddebug.h"
#include "ngx_http_coraza_common.h"

/*
 * ngx_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones before passing to CORAZA
 */
ngx_int_t
ngx_str_to_char(ngx_str_t a, char **str, ngx_pool_t *p)
{
    *str = ngx_pnalloc(p, a.len + 1);
    if (*str == NULL)
    {
        dd("failed to allocate memory to convert ngx_string to C string");
        return NGX_ERROR;
    }
    if (a.len > 0) {
        ngx_memcpy(*str, a.data, a.len);
    }
    (*str)[a.len] = '\0';

    return NGX_OK;
}


/*
 * Serialize an array of name/value header pairs into the packed wire format
 * consumed by coraza_add_request_headers / coraza_add_response_headers:
 *
 *     [u16 name_len BE][name bytes][u32 value_len BE][value bytes]  x count
 *
 * The buffer is allocated from r->pool.  On success *out / *out_len describe
 * the packed bytes and *out_count the number of pairs; the caller passes them
 * straight to the bulk cgo entry point.
 *
 * Fails closed (NGX_ERROR) on any pair whose name exceeds the u16 range or
 * whose value exceeds INT_MAX, or if the whole packed buffer would exceed
 * INT_MAX (the cgo boundary takes an int length) -- the caller then treats
 * inspection as unsafe, exactly as the per-header narrowing guards do.
 */
ngx_int_t
ngx_http_coraza_pack_headers(ngx_http_request_t *r,
    ngx_http_coraza_header_t *pairs, ngx_uint_t count,
    u_char **out, size_t *out_len)
{
    ngx_uint_t  i;
    size_t      total = 0;
    u_char     *buf, *p;

    for (i = 0; i < count; i++) {
        size_t nlen = pairs[i].name.len;
        size_t vlen = pairs[i].value.len;

        /* name length is carried in a u16, value length in a u32; the cgo
         * boundary also takes the packed length as an int. Reject anything
         * that would not round-trip. */
        if (nlen > 0xffff || vlen > INT_MAX) {
            return NGX_ERROR;
        }

        /* 2 (name_len) + name + 4 (value_len) + value, guarding overflow of
         * the running total against the int packed_len ceiling. */
        if (total > (size_t) INT_MAX - 6
            || nlen > (size_t) INT_MAX - 6 - total
            || vlen > (size_t) INT_MAX - 6 - total - nlen)
        {
            return NGX_ERROR;
        }
        total += 6 + nlen + vlen;
    }

    if (total == 0) {
        *out = NULL;
        *out_len = 0;
        return NGX_OK;
    }

    buf = ngx_pnalloc(r->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    for (i = 0; i < count; i++) {
        size_t nlen = pairs[i].name.len;
        size_t vlen = pairs[i].value.len;

        *p++ = (u_char) ((nlen >> 8) & 0xff);
        *p++ = (u_char) (nlen & 0xff);
        if (nlen) {
            ngx_memcpy(p, pairs[i].name.data, nlen);
            p += nlen;
        }

        *p++ = (u_char) ((vlen >> 24) & 0xff);
        *p++ = (u_char) ((vlen >> 16) & 0xff);
        *p++ = (u_char) ((vlen >> 8) & 0xff);
        *p++ = (u_char) (vlen & 0xff);
        if (vlen) {
            ngx_memcpy(p, pairs[i].value.data, vlen);
            p += vlen;
        }
    }

    *out = buf;
    *out_len = total;
    return NGX_OK;
}
