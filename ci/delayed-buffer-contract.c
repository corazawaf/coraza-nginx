/* Compile the production delayed-buffer block with real nginx buffer types.
 * Allocation and reads are controlled so failures and source ownership can be
 * checked without running an HTTP server. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *allocations[16];
static unsigned allocated, allocation_calls, fail_at;
static int read_failure;

typedef struct {
    unsigned headers_delayed;
    size_t pending_bytes;
    ngx_chain_t *pending_chain;
    ngx_chain_t **pending_chain_last;
} ngx_http_coraza_ctx_t;

static void *
allocate(size_t size)
{
    void *p;
    if (++allocation_calls == fail_at) {
        return NULL;
    }
    p = calloc(1, size);
    if (p == NULL || allocated == 16) {
        abort();
    }
    allocations[allocated++] = p;
    return p;
}

void *ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return allocate(size);
}

void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return allocate(size);
}

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool)
{
    (void) pool;
    return allocate(sizeof(ngx_chain_t));
}

/* Same memory/empty-buffer contract as the production reader. File clones
 * bypass the reader; unexpected file reads fail explicitly. */
static ngx_int_t
ngx_http_coraza_read_body_data(ngx_http_request_t *r, ngx_buf_t *b,
    u_char **data, size_t *len)
{
    (void) r;
    if (read_failure || b->in_file) {
        return NGX_ERROR;
    }
    *data = ngx_buf_in_memory(b) ? b->pos : NULL;
    *len = ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos) : 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_coraza_body_filter_internal_error(ngx_http_request_t *r,
    ngx_http_coraza_ctx_t *ctx, ngx_chain_t *in)
{
    (void) r;
    (void) ctx;
    (void) in;
    return NGX_ERROR;
}

static ngx_int_t
clone_buffer(ngx_http_request_t *r, ngx_http_coraza_ctx_t *ctx,
    ngx_chain_t *chain, int is_last)
{
    ngx_chain_t *in = chain;
#include "delayed-buffer.inc"
    return NGX_OK;
}

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        (void) fprintf(stderr, "%s: %s\n", name, message); \
        return 1; \
    } \
} while (0)

static int
run_case(const char *name, unsigned flags, int kind, unsigned failure)
{
    ngx_http_request_t r = {0};
    ngx_http_coraza_ctx_t ctx = {0};
    ngx_buf_t source = {0}, *copy;
    ngx_file_t file = {0};
    ngx_chain_t chain = {&source, NULL};
    u_char payload[] = "alpha:0123:omega";
    ngx_int_t rc;

    ctx.headers_delayed = kind != 4;
    ctx.pending_chain_last = &ctx.pending_chain;
    source.sync = !!(flags & 1);
    source.flush = !!(flags & 2);
    source.last_in_chain = !!(flags & 4);
    source.last_buf = kind == 2 || kind == 5;
    if (kind == 1 || kind == 2 || kind == 4) {
        source.memory = 1;
        source.pos = payload;
        source.last = payload + sizeof(payload) - 1;
    } else if (kind == 3) {
        source.in_file = 1;
        source.file = &file;
        source.file_pos = 3;
        source.file_last = 19;
    }
    allocation_calls = 0;
    fail_at = failure;
    read_failure = failure == 4;
    rc = clone_buffer(&r, &ctx, &chain, source.last_buf);
    if (failure) {
        CHECK(rc == NGX_ERROR, "allocation/read failure is propagated");
        CHECK(ctx.pending_chain == NULL, "failure does not append a buffer");
        CHECK(source.pos == payload, "failure leaves source unconsumed");
    } else if (kind == 4) {
        CHECK(rc == NGX_OK && ctx.pending_chain == NULL,
              "non-delayed path does not clone");
        CHECK(source.pos == payload, "non-delayed source stays unconsumed");
    } else {
        CHECK(rc == NGX_OK && ctx.pending_chain != NULL, "buffer appended");
        copy = ctx.pending_chain->buf;
        CHECK(copy->sync == !!(flags & 1), "sync flag preserved");
        CHECK(copy->flush == !!(flags & 2), "flush flag preserved");
        CHECK(copy->last_in_chain == !!(flags & 4), "chain end preserved");
        CHECK(copy->last_buf == (kind == 2 || kind == 5), "response end preserved");
        CHECK(ctx.pending_chain->next == NULL, "one ordered chain link");
        CHECK(ctx.pending_chain_last == &ctx.pending_chain->next,
              "append cursor follows new link");
        if (kind == 0) {
            CHECK(!copy->memory && !copy->in_file, "marker has no payload");
            CHECK(!!ngx_buf_special(copy) == !!(flags & 3),
                  "writer recognizes sync/flush markers only");
            CHECK(ctx.pending_bytes == 0, "marker adds no payload bytes");
        } else if (kind == 1) {
            CHECK(copy != &source && copy->pos != payload, "data owns a copy");
            CHECK(copy->memory && !copy->in_file, "data remains in memory");
            CHECK(source.pos == source.last, "source data consumed");
            CHECK(copy->last - copy->pos == sizeof(payload) - 1,
                  "complete copied size");
            payload[0] = 'X';
            CHECK(memcmp(copy->pos, "alpha:0123:omega", sizeof(payload) - 1) == 0,
                  "copy survives source reuse");
            CHECK(ctx.pending_bytes == sizeof(payload) - 1, "data accounted");
        } else if (kind == 2 || kind == 5) {
            CHECK(copy == &source, "final buffer is passed through");
            CHECK(source.pos == (kind == 2 ? payload : NULL),
                  "final source remains unchanged");
            CHECK(kind == 2 || ngx_buf_special(copy), "empty final is special");
            CHECK(ctx.pending_bytes == 0, "final buffer is not copied");
        } else {
            CHECK(copy != &source && copy->file == &file && copy->in_file,
                  "file clone shares the original file");
            CHECK(copy->file_pos == 3 && copy->file_last == 19,
                  "file range retained");
            CHECK(source.file_pos == 19, "original file range consumed");
            CHECK(ctx.pending_bytes == 16, "file range accounted");
        }
    }
    while (allocated) {
        free(allocations[--allocated]);
    }
    return 0;
}

int main(void)
{
    unsigned flags, kind, failure;
    char name[64];
    for (kind = 0; kind < 6; kind++) {
        for (flags = 0; flags < 8; flags++) {
            (void) snprintf(name, sizeof(name), "kind=%u flags=%u", kind, flags);
            if (run_case(name, flags, (int) kind, 0)) {
                return 1;
            }
        }
    }
    for (failure = 1; failure <= 4; failure++) {
        (void) snprintf(name, sizeof(name), "failure=%u", failure);
        if (run_case(name, 7, 1, failure)) {
            return 1;
        }
    }
    puts("52 delayed buffer cases passed");
    return 0;
}
