/* Standalone contracts for the verbatim production header packer.
 * Metadata-only cases always deny allocation: no large copy can execute,
 * even if a length guard regresses. Output arguments are unchanged on error.
 */
#include <assert.h>
#include <stdio.h>
#include "ngx_shim.h"

static size_t allocations, copies, requested;
static int deny_allocation;

static void *
contract_alloc(ngx_pool_t *pool, size_t size)
{
    allocations++;
    requested = size;
    if (deny_allocation) {
        return NULL;
    }
    assert(size <= 131082);
    return ngx_pnalloc(pool, size);
}

static void
contract_copy(void *dst, const void *src, size_t size)
{
    assert(!deny_allocation);
    copies++;
    memcpy(dst, src, size);
}

#define ngx_pnalloc contract_alloc
#undef ngx_memcpy
#define ngx_memcpy contract_copy
#include "generated_pack_headers.inc"

static void
metadata_contract(size_t n1, size_t v1, size_t n2, size_t v2,
    ngx_uint_t count, size_t expected_allocations, size_t expected_size)
{
    ngx_pool_t pool = {0};
    ngx_http_request_t r = { .pool = &pool };
    u_char sentinel = 0;
    u_char *out = &sentinel;
    size_t out_len = 17;
    ngx_http_coraza_header_t pairs[2] = {
        {{n1, NULL}, {v1, NULL}}, {{n2, NULL}, {v2, NULL}}
    };

    allocations = copies = requested = 0;
    deny_allocation = 1;
    assert(ngx_http_coraza_pack_headers(&r, pairs, count, &out, &out_len)
           == NGX_ERROR);
    assert(allocations == expected_allocations);
    assert(requested == expected_size);
    assert(copies == 0);
    assert(pool.n == 0);
    assert(out == &sentinel && out_len == 17);
}

static void
success_contracts(void)
{
    ngx_pool_t pool = {0};
    ngx_http_request_t r = { .pool = &pool };
    u_char *out = NULL;
    size_t out_len = 17;
    u_char name[] = {'X', 0, 'Y'};
    u_char value[] = {0xff, 'v'};
    ngx_http_coraza_header_t pairs[2] = {
        {{sizeof(name), name}, {sizeof(value), value}},
        {{0, NULL}, {0, NULL}}
    };
    const u_char expected[] = {
        0, 3, 'X', 0, 'Y', 0, 0, 0, 2, 0xff, 'v',
        0, 0, 0, 0, 0, 0
    };
    u_char long_name[65535];

    allocations = copies = requested = 0;
    deny_allocation = 1;
    assert(ngx_http_coraza_pack_headers(&r, NULL, 0, &out, &out_len) == NGX_OK);
    assert(out == NULL && out_len == 0);
    assert(allocations == 0 && copies == 0);

    deny_allocation = 0;
    assert(ngx_http_coraza_pack_headers(&r, pairs, 2, &out, &out_len) == NGX_OK);
    assert(out_len == sizeof(expected));
    assert(memcmp(out, expected, sizeof(expected)) == 0);
    assert(allocations == 1 && copies == 2 && requested == sizeof(expected));
    ngx_fuzz_pool_reset(&pool);

    memset(long_name, 'n', sizeof(long_name));
    pairs[0].name = (ngx_str_t) {sizeof(long_name), long_name};
    pairs[0].value = (ngx_str_t) {sizeof(long_name), long_name};
    assert(ngx_http_coraza_pack_headers(&r, pairs, 1, &out, &out_len) == NGX_OK);
    assert(out_len == 131076);
    assert(out[0] == 0xff && out[1] == 0xff);
    assert(memcmp(out + 2, long_name, sizeof(long_name)) == 0);
    assert(memcmp(out + 65537, "\0\0\xff\xff", 4) == 0);
    assert(memcmp(out + 65541, long_name, sizeof(long_name)) == 0);
    ngx_fuzz_pool_reset(&pool);
}

int
main(void)
{
    /* Per-field rejection, including the largest representable metadata. */
    metadata_contract(65536, 0, 0, 0, 1, 0, 0);
    metadata_contract(0, (size_t) INT_MAX + 1, 0, 0, 1, 0, 0);
    metadata_contract(SIZE_MAX, 0, 0, 0, 1, 0, 0);
    metadata_contract(0, SIZE_MAX, 0, 0, 1, 0, 0);
    /* Exact aggregate ceiling reaches the rejecting allocator; +1 does not. */
    metadata_contract(0, (size_t) INT_MAX - 6, 0, 0, 1, 1, INT_MAX);
    metadata_contract(0, (size_t) INT_MAX - 5, 0, 0, 1, 0, 0);
    metadata_contract(0, INT_MAX, 0, 0, 1, 0, 0);
    /* Each running-total guard, with individually representable fields. */
    metadata_contract(0, (size_t) INT_MAX - 6, 0, 0, 2, 0, 0);
    metadata_contract(0, (size_t) INT_MAX - 12, 1, 0, 2, 0, 0);
    metadata_contract(0, (size_t) INT_MAX - 12, 0, 1, 2, 0, 0);
    metadata_contract(0, (size_t) INT_MAX - 12, 0, 0, 2, 1, INT_MAX);
    /* Ordinary and maximum-name allocations can also fail without copying. */
    metadata_contract(1, 1, 0, 0, 1, 1, 8);
    metadata_contract(65535, 0, 0, 0, 1, 1, 65541);
    success_contracts();
    puts("PASS: 13 metadata/allocation cases and zero/ordinary/max-name success");
    return 0;
}
