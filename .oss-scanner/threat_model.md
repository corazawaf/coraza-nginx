# Threat model

This file is read by Anthropic's OSS Scanner before it analyses coraza-nginx. It
complements [`README.md`](../README.md): how the module works, its five directives, the
response-header delay, what phase 3 sees, how disruptive actions are enforced and
audited, and the documented limitations — read it first. The engine this module drives,
OWASP Coraza, is enrolled separately with its own threat model; read that one for
anything about rule evaluation, body parsing, transformations and operators.

## What this project does and where untrusted input enters

coraza-nginx is a dynamic nginx module, written in C, that runs the OWASP Coraza WAF
engine against every HTTP transaction nginx handles. The engine is a Go library; the
module reaches it through libcoraza, a cgo shared object it `dlopen()`s at startup
(`src/ngx_http_coraza_dl.c`), and feeds it one nginx request at a time: connection and
URI (phase 1), request headers (phase 1), request body (phase 2), response headers
(phase 3), response body (phase 4), then logging. When the engine reports an
intervention, the module enforces it: `deny` serves the rule's status through nginx's
error handling, `redirect` serves a `Location`, `drop` closes the connection without a
byte on the wire.

**Every byte of the request and of the response is attacker-controlled**, as seen by
nginx: method, URI, query string, headers, the body in any encoding and framing
(Content-Length, chunked, pipelined, HTTP/2 and HTTP/3 streams), and, for a proxied
location, the upstream's headers and body too. The attacker also controls timing: slow
bodies, early disconnects, pipelined requests behind a blocked one, concurrent streams
on one connection.

**Rules and configuration are trusted.** `coraza on|off`, `coraza_rules`,
`coraza_rules_file`, the `coraza_transaction_id` template and
`coraza_delay_response_headers`, like the rest of `nginx.conf` (body sizes, temp paths,
proxy settings), are the operator's choice. A
finding that needs control of the nginx configuration or the ruleset is not a
vulnerability. A finding where a *valid* configuration silently does less than it
promises (a rule the engine never sees fire, a limit accepted but not enforced, a
response the engine never inspected) is in scope: that is the module's whole job.

**In scope**: everything under `src/` — the C/Go boundary (symbol gate and ABI
assumptions in `dl.c`, the packed header buffers handed to `coraza_add_*_headers`, string
lifetimes across cgo calls), request-body buffering and replay to the backend, the
response-header delay and the finalisation of phase 4 before headers go out, the body
filter's delayed and file-backed brigades, intervention enforcement at every phase site,
transaction binding across rewrites and internal redirects, the audit and error logging.

**Out of scope here** (report upstream instead): nginx and Angie themselves, libcoraza
and the Go engine (corazawaf/libcoraza, corazawaf/coraza — the latter is enrolled), the
OWASP CRS's detection logic (coreruleset/coreruleset), OpenSSL/QUIC.

## Components that matter most / least

Most, in this order:

1. `src/ngx_http_coraza_header_filter.c` — the response path: resolvers that mirror what
   nginx will put on the wire (chunking, charset, `Server`, 204 normalisation) before
   phase 3; the finalise-before-headers branch (bodyless responses, uninspected bodies)
   and the delay branch that holds headers until phase 4; redirect preparation; the
   `drop` path from a filter (`ngx_http_coraza_drop_connection()`); the phase-1 bind site
   for responses generated in the rewrite phase. The filter order (a companion
   header-only module registered before the range filter) is set up in `config` and
   `module.c`.
2. `src/ngx_http_coraza_body_filter.c` — delayed response buffering (memory and file
   backed, size cap, `sync`/`flush`/`last_buf` propagation), phase-4 finalisation on the
   last buffer, the fail-closed paths when the engine errors mid-stream.
3. `src/ngx_http_coraza_pre_access.c` — phase 1 binding to the final location, request
   body buffering (memory, temp file, chunked), what is replayed to the backend and when,
   `SecRequestBodyAccess`-driven skipping.
4. `src/ngx_http_coraza_module.c` — `ngx_http_coraza_process_intervention()` (every
   disruptive action: deny/redirect/drop, status remapping, `Location` replacement),
   context creation and cleanup (transaction lifetime, double-free and reuse), WAF
   construction and the rule-content deduplication cache, directive parsing.
5. `src/ngx_http_coraza_dl.c` — `dlopen()` of libcoraza, the version floor, the ABI
   assumptions on every symbol, and the bulk header packing format
   ([u16 len][name][u32 len][value]) the engine decodes.
6. `src/ngx_http_coraza_rewrite.c`, `ngx_http_coraza_log.c`, `ngx_http_coraza_utils.c`
   — phase-1 helpers, the LOG-phase audit fallback for headerless exits, string
   conversions.

Less: `lint/` and `t/` (the suites themselves), `tools/` (soak harness), `fuzz/` (the
harnesses — the functions they extract are in scope, the harness code is not), `debian/`,
`docs`, `README.md`, the CI workflows.

## How to exercise it

- `cd /src/nginx-tests && prove --timer coraza*.t` runs the integration suite (about 90
  files, ~1,200 checks, around a minute) against the nginx built in this image, with
  `TEST_NGINX_BINARY`, `TEST_NGINX_GLOBALS` and `TEST_NGINX_SOURCE` already set. Each file
  is a self-contained Test::Nginx script: it writes an `nginx.conf` with inline
  `coraza_rules`, starts nginx, speaks HTTP over raw sockets and asserts on the wire
  bytes, the audit log and `error.log`. `t/coraza_crash_check.pm` is the crash oracle
  most files end with. HTTP/3 files need CryptX (installed) and skip otherwise.
  `coraza-response-body.t` serves files with `directio`; on overlayfs, O_DIRECT reads fail
  with EIO and its file-backed cases fail. Run the suite with `/tmp` on a tmpfs (CI does);
  that failure is the filesystem, not a finding.
- `prove /src/lint/*.t` runs the static source contracts (regexes that pin a structure
  of the C source: fail-closed paths, call-site ordering, the filter registration).
- `/src/nginx-asan-<ver>/objs/nginx` is the ASan/UBSan build; run any `t/` file against
  it by pointing `TEST_NGINX_BINARY` and `TEST_NGINX_GLOBALS` at `objs/nginx` and
  `objs/ngx_http_coraza_module.so`. The image sets CI's
  `ASAN_OPTIONS=verify_asan_link_order=0:detect_odr_violation=0`: the Go runtime in
  libcoraza is uninstrumented, and nginx defines `ngx_module_names` in both the binary and
  every dynamic module, which ASan reports as an ODR violation.
- `bash tools/soak.sh <nginx-binary> 60 4` drives a live nginx with concurrent benign and
  attack traffic across every connector path (body spooling, bulk headers, delayed
  responses, phase-4 denies) and fails on any sanitizer report, crash, `[alert]`, or a
  verdict regression. It is the deep check CI runs monthly under ASan, memcheck and
  helgrind.
- `bash fuzz/run.sh 60` fuzzes `ngx_str_to_char`; `FUZZ_BIN=./fuzz_pack_headers
  CORPUS_DIR=./corpus_pack_headers bash fuzz/run.sh 60` fuzzes the header packer.
- `.oss-scanner/serve.sh` (or `serve.sh asan`) starts nginx with the module and the full
  OWASP CRS on 127.0.0.1:80, the configuration CI's go-ftw run uses; `go-ftw` is
  installed to replay `tests/ftw/*.yaml` and the CRS regression suite (see the script's
  header for the commands). This is the end-to-end target for probing bypasses.
- The declarative way to state "this configuration + this request should give this
  response" is a new case in the `t/` file that owns the behaviour; a reproducer in that
  form is what a report needs.

## How you rate severity

We score with CVSS 3.1 and re-score at triage. The rules:

- **Policy bypass** — the backend receives bytes the engine never inspected, or inspected
  in a different form (a body replayed with content the engine did not see, a header the
  engine was not given, a transaction bound to the wrong location's rules, a response
  served although a rule fired, an intervention the module failed to enforce): **High**
  when it fires from attacker-supplied traffic alone on a default configuration, Medium
  when it needs a specific directive combination or a race. The audit log recording the
  wrong status for a block (the reason a bare `drop` went unnoticed) is part of the same
  class.
- **Worker crash, use-after-free, invalid read or write reachable from traffic** — High
  (a worker takes every connection it handles with it; nginx respawns it, so this is also
  a DoS). Confirm under the ASan build; UBSan reports in nginx core itself are out of
  scope (see below).
- **Response framing corruption** — a body sent after a 304/204/HEAD, a Range desync, a
  truncated or duplicated stream, headers emitted twice, a redirect carrying the origin's
  body: High (cache poisoning and desync are the usual consequences).
- **Denial of service** — memory or CPU that grows beyond what the configured limits
  bound (nginx's `client_max_body_size` and buffer sizes, the module's delayed-body cap,
  the engine's `SecRequestBodyLimit`/`SecResponseBodyLimit`) from one request is High; cost that stays
  bounded by those limits but is larger than it should be is Medium. Say how many bytes
  in produce how much memory or time.
- **Transaction or memory leak per request** — Medium (it is a slow DoS), High if a
  single request leaks an unbounded amount.
- **Audit log loss, forgery or injection** — Low, unless it hides a block (then it is
  scored as the bypass it hides).
- **Parity with ModSecurity-nginx** — the module is meant to be a drop-in replacement for
  ModSecurity-nginx (libmodsecurity v3). Where the two differ in what the engine sees or
  in how an intervention is enforced, the difference is a finding only if the module does
  *less*; cite the ModSecurity-nginx source (`src/ngx_http_modsecurity_*.c`) when claiming
  parity either way. Deliberate differences are documented in `README.md`.

Not vulnerabilities, do not report:

- Anything that needs control of the nginx configuration, the ruleset, the filesystem
  nginx reads, or the backend.
- Behaviour documented as a limitation in `README.md` (for example, a phase-4 intervention
  cannot replace headers already sent when `coraza_delay_response_headers` is off; a
  subrequest answered in the rewrite phase is not inspected; a response body is inspected
  before gzip, so `RESPONSE_BODY` is plaintext while `RESPONSE_HEADERS` shows the final
  `Content-Encoding`).
- UBSan diagnostics inside nginx core (notably the deliberate misaligned `uint32_t` load
  in `ngx_str3_cmp()`, `src/http/ngx_http_parse.c`) and memcheck reports inside the Go
  runtime of libcoraza (SIMD over-reads in `indexbyte`/`memmove`): both are known, both
  are suppressed in CI (`valgrind.suppress`, `tools/ubsan-owned-pattern.sh`), neither is
  ours.
- Issues in the engine's rule evaluation, body processors, transformations or operators:
  report them to corazawaf/coraza.
- Lack of TLS, authentication or rate limiting: those belong to nginx.

## What a good report and patch look like

- A reproducer we can run: a Test::Nginx case (configuration, request bytes, expected
  wire response and expected audit/error-log lines) in the `t/` file that owns the
  behaviour — or a new file if none does — plus the output on the unpatched module. A
  `curl`/raw-socket transcript against `serve.sh` is a fine starting point, but the
  `t/` case is what we merge.
- The CVSS vector with the preconditions spelled out, scored with the rules above, and
  the ModSecurity-nginx behaviour for the same case when parity is part of the argument.
- A patch that keeps the project's shape: the fix at the one site all callers route
  through (interventions go through `ngx_http_coraza_process_intervention()`, fail-closed
  exits through the existing finalisers, header packing through `dl.c`), a regression case
  in `t/`, a `lint/` contract when the fix pins a structural property (an ordering, a
  guard), nothing under a new `ci/` tree, no new test harness that extracts and recompiles
  production code. It must pass `prove lint/*.t`, the full `prove coraza*.t`, and stay
  clean under the ASan build and `tools/soak.sh`.
- We fix on private advisory forks and publish through GitHub Security Advisories, with
  the reporter credited.
