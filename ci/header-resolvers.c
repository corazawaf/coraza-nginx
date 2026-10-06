#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

/* The real nginx request and configuration types are used; only allocation
 * and the final header collector are replaced to inject deterministic errors. */
typedef struct { int unused; } ngx_http_coraza_ctx_t;
static ngx_http_coraza_ctx_t context;
static ngx_http_core_loc_conf_t config;
static u_char storage[512];
static u_char collected[512];
static size_t collected_len;
static int calls, allocation_fails, collector_fails;
#undef ngx_http_get_module_loc_conf
#define ngx_http_get_module_loc_conf(r, module) (&config)
#undef ngx_http_get_module_ctx
#define ngx_http_get_module_ctx(r, module) (&context)
#undef NGINX_VER
#define NGINX_VER "nginx/unit-version"
#undef NGINX_VER_BUILD
#define NGINX_VER_BUILD "nginx/unit-version (unit-build)"

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    assert(size <= sizeof(storage));
    return allocation_fails ? NULL : storage;
}

static ngx_int_t
ngx_http_coraza_add_response_header(ngx_http_request_t *r,
    ngx_http_coraza_ctx_t *ctx, ngx_str_t *name, ngx_str_t *value)
{
    calls++;
    assert(value->len <= sizeof(collected));
    collected_len = value->len;
    memcpy(collected, value->data, value->len);
    return collector_fails ? NGX_ERROR : NGX_OK;
}

#include "header-resolvers.inc"

static void
expect(const char *value)
{
    assert(calls == 1);
    assert(collected_len == strlen(value));
    assert(memcmp(collected, value, collected_len) == 0);
    calls = 0;
}

static void
check_chunk_case(ngx_uint_t version, ngx_uint_t status, ngx_uint_t method,
    unsigned flags)
{
    ngx_http_request_t r;
    ngx_str_t transfer = ngx_string("Transfer-Encoding");
    int enabled = flags & 1;
    int known = flags & 2;
    int trailers = flags & 4;
    int main_request = flags & 8;
    int expected = version == NGX_HTTP_VERSION_11 && enabled && main_request
        && (trailers || !known) && method != NGX_HTTP_HEAD
        && (method != NGX_HTTP_CONNECT || status >= 300)
        && status >= 200 && status != 204 && status != 304;

    memset(&r, 0, sizeof(r));
    r.http_version = version;
    r.headers_out.status = status;
    r.headers_out.content_length_n = known ? 20 : -1;
    r.method = method;
    r.main = main_request ? &r : NULL;
    r.expect_trailers = !!trailers;
    config.chunked_transfer_encoding = enabled;
    assert(ngx_http_coraza_will_chunk(&r) == expected);
    assert(ngx_http_coraza_resolv_header_transfer_encoding(&r, transfer, 0) == NGX_OK);
    if (expected) {
        expect("chunked");
        collector_fails = 1;
        assert(ngx_http_coraza_resolv_header_transfer_encoding(&r, transfer, 0) == NGX_ERROR);
        expect("chunked");
        collector_fails = 0;
    } else {
        assert(calls == 0);
    }
}

static void
check_vary(ngx_uint_t version)
{
    ngx_http_request_t r;
    ngx_str_t vary = ngx_string("Vary");
    int enabled, selected;

    memset(&r, 0, sizeof(r));
    r.http_version = version;
    for (enabled = 0; enabled <= 1; enabled++) {
        for (selected = 0; selected <= 1; selected++) {
            r.gzip_vary = selected;
            config.gzip_vary = enabled;
            assert(ngx_http_coraza_resolv_header_vary(&r, vary, 0) == NGX_OK);
            if (enabled && selected) {
                expect(version == NGX_HTTP_VERSION_30 ? "accept-encoding" : "Accept-Encoding");
                collector_fails = 1;
                assert(ngx_http_coraza_resolv_header_vary(&r, vary, 0) == NGX_ERROR);
                expect(version == NGX_HTTP_VERSION_30 ? "accept-encoding" : "Accept-Encoding");
                collector_fails = 0;
            } else {
                assert(calls == 0);
            }
        }
    }
}

static void
test_transform_resolvers(void)
{
    ngx_uint_t versions[] = { NGX_HTTP_VERSION_10, NGX_HTTP_VERSION_11,
                              NGX_HTTP_VERSION_20, NGX_HTTP_VERSION_30 };
    ngx_uint_t statuses[] = { 101, 199, 200, 201, 204, 304, 403, 404 };
    ngx_uint_t methods[] = { NGX_HTTP_GET, NGX_HTTP_HEAD, NGX_HTTP_CONNECT };
    size_t v, st, m;
    unsigned flags;

    for (v = 0; v < sizeof(versions) / sizeof(versions[0]); v++) {
        for (st = 0; st < sizeof(statuses) / sizeof(statuses[0]); st++) {
            for (m = 0; m < sizeof(methods) / sizeof(methods[0]); m++) {
                for (flags = 0; flags < 16; flags++) {
                    check_chunk_case(versions[v], statuses[st], methods[m], flags);
                }
            }
        }
        check_vary(versions[v]);
    }
}

int
main(void)
{
    ngx_http_request_t r;
    ngx_table_elt_t upstream;
    ngx_str_t server = ngx_string("Server");
    ngx_str_t type = ngx_string("Content-Type");
    ngx_str_t original;

    memset(&r, 0, sizeof(r));
    memset(&upstream, 0, sizeof(upstream));
    config.server_tokens = NGX_HTTP_SERVER_TOKENS_OFF;
    assert(ngx_http_coraza_resolv_header_server(&r, server, 0) == NGX_OK);
    expect("nginx");
    config.server_tokens = NGX_HTTP_SERVER_TOKENS_ON;
    assert(ngx_http_coraza_resolv_header_server(&r, server, 0) == NGX_OK);
    expect(NGINX_VER);
    config.server_tokens = NGX_HTTP_SERVER_TOKENS_BUILD;
    assert(ngx_http_coraza_resolv_header_server(&r, server, 0) == NGX_OK);
    expect(NGINX_VER_BUILD);
    ngx_str_set(&upstream.value, "origin-unit");
    r.headers_out.server = &upstream;
    assert(ngx_http_coraza_resolv_header_server(&r, server, 0) == NGX_OK);
    expect("origin-unit");
    ngx_str_set(&upstream.value, "");
    assert(ngx_http_coraza_resolv_header_server(&r, server, 0) == NGX_OK);
    expect("");
    collector_fails = 1;
    assert(ngx_http_coraza_resolv_header_server(&r, server, 0) == NGX_ERROR);
    expect("");
    collector_fails = 0;

    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_OK);
    assert(calls == 0);
    ngx_str_set(&r.headers_out.content_type, "text/plain");
    r.headers_out.content_type_len = r.headers_out.content_type.len;
    original = r.headers_out.content_type;
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_OK);
    expect("text/plain");
    ngx_str_set(&r.headers_out.charset, "utf-8");
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_OK);
    expect("text/plain; charset=utf-8");
    assert(r.headers_out.content_type.data == original.data);
    assert(r.headers_out.content_type.len == original.len);
    allocation_fails = 1;
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_ERROR);
    assert(calls == 0);
    allocation_fails = 0;
    collector_fails = 1;
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_ERROR);
    expect("text/plain; charset=utf-8");
    collector_fails = 0;
    ngx_str_set(&r.headers_out.content_type, "text/plain; charset=latin1");
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_OK);
    expect("text/plain; charset=latin1");

    /* Invalid internal length metadata must fail before allocation or copying. */
    r.headers_out.content_type = original;
    r.headers_out.charset.len = NGX_MAX_SIZE_T_VALUE;
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_ERROR);
    assert(calls == 0);
    r.headers_out.charset.len = 5;
    r.headers_out.content_type.len = NGX_MAX_SIZE_T_VALUE;
    r.headers_out.content_type_len = NGX_MAX_SIZE_T_VALUE;
    assert(ngx_http_coraza_resolv_header_content_type(&r, type, 0) == NGX_ERROR);
    assert(calls == 0);
    test_transform_resolvers();
    puts("response-header boundary matrix passed");
    return 0;
}
