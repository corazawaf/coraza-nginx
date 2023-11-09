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
ngx_str_to_char(ngx_str_t a, char *str, ngx_pool_t *p)
{
    if (str) {
        free(str);
        str = NULL;
    }

    if (a.len == 0)
    {
        return NGX_OK;
    }

    str = ngx_pnalloc(p, a.len + 1);
    if (str == NULL)
    {
        dd("failed to allocate memory to convert space ngx_string to C string");
        /* We already returned NULL for an empty string, so return -1 here to indicate allocation error */
        return NGX_ERROR;
    }
    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return NGX_OK;
}
