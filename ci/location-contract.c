/* Production intervention logic, real nginx list and header definitions. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Coraza is inert: these fields are the intervention function's inputs. */
typedef struct {
    int status;
    char *action;
    char *data;
} coraza_intervention_t;
typedef struct {
    int coraza_transaction;
    ngx_str_t transaction_id;
    int logged;
} ngx_http_coraza_ctx_t;

#undef ngx_inline
#define ngx_inline static
#undef ngx_log_error
#define ngx_log_error(...) ((void) 0)
#define dd(...) ((void) 0)

static const char *case_name;
static void *allocations[64];
static size_t allocation_count, fail_allocation;
static int fail_push, fail_value, frees, logs, updates, absent;
static coraza_intervention_t intervention = {302, NULL, "https://policy.example/new"};

static void
check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s: %s\n", case_name, message);
        exit(EXIT_FAILURE);
    }
}

void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    void *p;
    (void) pool;
    if (fail_allocation && allocation_count + 1 == fail_allocation) return NULL;
    check(allocation_count < 64, "bounded fixture allocations");
    p = malloc(size ? size : 1);
    if (p == NULL) {
        fprintf(stderr, "fixture allocation failed\n");
        exit(EXIT_FAILURE);
    }
    /* ngx_list_push returns uninitialized storage, including next. */
    memset(p, 0xa5, size);
    allocations[allocation_count++] = p;
    return p;
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return fail_value ? NULL : ngx_palloc(pool, size);
}

static void *
push_header(ngx_list_t *list)
{
    return fail_push ? NULL : ngx_list_push(list);
}

static coraza_intervention_t *
coraza_intervention(int transaction)
{
    check(transaction == 1, "valid transaction");
    return absent ? NULL : &intervention;
}

static void
coraza_free_intervention(coraza_intervention_t *value)
{
    check(value == &intervention, "free matching intervention");
    frees++;
}

static void
coraza_update_status_code(int transaction, int status)
{
    check(transaction == 1 && status == intervention.status, "audit status");
    updates++;
}

static void
ngx_http_coraza_log_handler(ngx_http_request_t *r)
{
    check(r != NULL, "log request");
    logs++;
}

#define ngx_list_push push_header
#include "intervention.inc"
#undef ngx_list_push

static ngx_table_elt_t *
add_header(ngx_list_t *list, const char *name, const char *value, int active)
{
    ngx_table_elt_t *h = ngx_list_push(list);
    check(h != NULL, "seed header");
    memset(h, 0, sizeof(*h));
    h->hash = active;
    h->key.data = (u_char *) name;
    h->key.len = strlen(name);
    h->value.data = (u_char *) value;
    h->value.len = strlen(value);
    return h;
}

int
main(int argc, char **argv)
{
    ngx_http_request_t r;
    ngx_http_coraza_ctx_t ctx = {1, {0, NULL}, 0};
    ngx_table_elt_t *old = NULL, *other, *h;
    ngx_list_part_t *part;
    ngx_uint_t i, count = 0;
    ngx_int_t status;
    int replace = 1, expected = 302, old_active = 1, empty = 0;
    const char *target = "https://policy.example/new";
    check(argc == 2, "one named case required");
    case_name = argv[1];
    memset(&r, 0, sizeof(r));
    if (strcmp(case_name, "replace-empty") == 0) empty = 1;
    else if (strcmp(case_name, "replace-inactive") == 0) old_active = 0;
    else if (strncmp(case_name, "status-", 7) == 0) {
        intervention.status = atoi(case_name + 7);
        expected = intervention.status;
    } else if (strcmp(case_name, "empty-target") == 0) target = "";
    else if (strcmp(case_name, "control-byte") == 0) {
        intervention.data = "https://policy.example/new\nignored";
    } else if (strcmp(case_name, "del-byte") == 0) {
        intervention.data = "https://policy.example/new\177ignored";
    } else if (strcmp(case_name, "push-failure") == 0) {
        fail_push = 1; replace = 0; expected = 500;
    } else if (strcmp(case_name, "list-part-failure") == 0
               || strcmp(case_name, "list-storage-failure") == 0) {
        replace = 0; expected = 500;
    } else if (strcmp(case_name, "no-early-log") == 0) {
        /* Exercise response-phase intervention without early logging. */
    } else if (strcmp(case_name, "value-failure") == 0) {
        fail_value = 1; replace = 0; expected = 500;
    } else if (strcmp(case_name, "deny") == 0) {
        intervention.status = 403; replace = 0; expected = 403;
    } else if (strcmp(case_name, "no-data") == 0) {
        intervention.data = NULL; replace = 0;
    } else if (strcmp(case_name, "ok") == 0) {
        intervention.status = 200; replace = 0; expected = NGX_OK;
    } else if (strcmp(case_name, "no-intervention") == 0) {
        absent = 1; replace = 0; expected = NGX_OK;
    } else if (strcmp(case_name, "no-context") == 0) {
        replace = 0; expected = 500;
    } else if (strcmp(case_name, "already-sent") == 0) {
        r.header_sent = 1; replace = 0; expected = NGX_ERROR;
    } else check(strcmp(case_name, "replace-many") == 0, "known test case");
    if (strcmp(case_name, "empty-target") == 0) intervention.data = "";

    /* Capacity two forces old matches and the new header across list parts. */
    check(ngx_list_init(&r.headers_out.headers, NULL, 2, sizeof(*h)) == NGX_OK,
          "initialize real nginx list");
    other = add_header(&r.headers_out.headers, "X-Control", "unchanged", 1);
    if (!empty) {
        old = add_header(&r.headers_out.headers, "Location", "https://origin.example/old", old_active);
        r.headers_out.location = old;
        add_header(&r.headers_out.headers, "lOcAtIoN", "https://origin.example/second", old_active);
        add_header(&r.headers_out.headers, "Location-Extra", "unchanged", 1);
    }
    add_header(&r.headers_out.headers, "X-Origin", "unchanged", 1);
    add_header(&r.headers_out.headers, "X-Other", "unchanged", 1);
    if (strcmp(case_name, "list-part-failure") == 0) fail_allocation = allocation_count + 1;
    if (strcmp(case_name, "list-storage-failure") == 0) fail_allocation = allocation_count + 2;
    status = ngx_http_coraza_process_intervention(
        strcmp(case_name, "no-context") == 0 ? NULL : &ctx, &r, strcmp(case_name, "no-early-log") != 0);
    check(status == expected, "expected intervention status");
    check(frees == (!absent && strcmp(case_name, "no-context") != 0), "free exactly once");
    check(logs == (strcmp(case_name, "no-early-log") == 0 ? 0 : updates)
          && ctx.logged == (logs != 0), "early logging preserved");
    check(other->hash == 1, "unrelated header remains active");
    for (part = &r.headers_out.headers.part; part != NULL; part = part->next) {
        h = part->elts;
        for (i = 0; i < part->nelts; i++) {
            if (h[i].hash && h[i].key.len == 8
                && ngx_strncasecmp(h[i].key.data, (u_char *) "Location", 8) == 0) {
                count++;
                if (replace) {
                    check(h[i].value.len == strlen(target)
                          && memcmp(h[i].value.data, target, strlen(target)) == 0,
                          "active Location is the policy destination");
                }
            }
            if (h[i].key.len == 14) check(h[i].hash == 1, "prefix near miss remains active");
        }
    }
    if (replace) {
        check(count == 1, "exactly one active Location");
        check(r.headers_out.location != old && r.headers_out.location->hash == 1,
              "publish replacement pointer");
        check(r.headers_out.location->next == NULL, "replacement next initialized");
    } else {
        check(count == 2 && r.headers_out.location == old && old->hash == 1,
              "no partial replacement on error or non-redirect");
    }
    while (allocation_count) free(allocations[--allocation_count]);
    return EXIT_SUCCESS;
}
