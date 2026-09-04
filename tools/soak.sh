#!/usr/bin/env bash
#
# Sustained mixed-load soak for the coraza-nginx connector. Drives a real
# nginx (ideally an ASan/UBSan build, optionally under valgrind memcheck or
# helgrind) with concurrent benign AND attack-shaped requests for a fixed
# duration, then asserts the worker survived cleanly: no sanitizer report,
# no valgrind/helgrind error, no crash, no leak, no error-log [alert]/[emerg].
#
# The traffic mix deliberately exercises the WAF decision path in both
# directions — benign requests that must pass (200) and attack requests the
# in-config SecRules must block (403) — across nine request shapes that drive
# every attacker-reachable pure-C connector path under the checker:
#   * URI-arg, request-body, and request-HEADER attacks (phase 1/2 deny)
#   * benign GET, POST, and large response body (pass)
#   * large CHUNKED request body -> file-backed body_filter buffer chain
#   * 40 large request headers -> ngx_str_to_char loop across ngx_list parts
#   * RESPONSE_BODY inspection, both pass and phase-4 deny (body_filter clone)
# so allocation/free of the Coraza transaction, header forwarding
# (ngx_str_to_char), and request/response body inspection all run every
# iteration. Deep coverage of THIS connector lives here (memcheck/helgrind),
# not in the fuzzer — the fuzzable pure-C leaf is just ngx_str_to_char; the
# rest of the connector needs a live nginx request, which is what this drives.
#
# Requires libcoraza installed (dlopen'd at runtime; see README). The nginx
# binary passed in must have been built --add-dynamic-module against this
# tree and be able to load libcoraza (LD_LIBRARY_PATH=/usr/local/lib if that
# is where `make install` put it).
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 120 8
#   USE_HELGRIND=1 tools/soak.sh <nginx-binary> 120 8
#
# Exit non-zero on ANY of: sanitizer error, valgrind/helgrind error, nginx
# crash/non-clean exit, error-log alert/emerg, or a WAF verdict regression
# (benign blocked / attack allowed).

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-8}"
MODULE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

WORK="$(mktemp -d)"
# Kill the (possibly valgrind-wrapped) server too: under `set -e` an early
# failure would otherwise orphan it, holding the port for later runs.
trap 'kill -9 "${NGINX_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

echo "hello coraza" > "$WORK/html/index.html"
head -c 200000 /dev/urandom | base64 > "$WORK/html/medium"
# Benign response body scanned by the phase-4 RESPONSE_BODY rule (must pass).
head -c 120000 /dev/urandom | base64 > "$WORK/html/respbody"
# Response body carrying the leak marker (must be blocked 403 at phase 4).
{ head -c 40000 /dev/urandom | base64; echo "leakmarker"; } > "$WORK/html/leak"

# Locate the built module (.so). --add-dynamic-module builds it into objs/;
# if the caller installed it, allow an override via $CORAZA_MODULE_SO.
MODULE_SO="${CORAZA_MODULE_SO:-}"
if [ -z "$MODULE_SO" ]; then
    MODULE_SO="$(dirname "$NGINX")/ngx_http_coraza_module.so"
fi
LOAD_MODULE_DIRECTIVE=""
if [ -f "$MODULE_SO" ]; then
    LOAD_MODULE_DIRECTIVE="load_module $MODULE_SO;"
fi

# In-config SecRules: block a URI-arg attack marker and a request-body
# marker so both the header/URI path and the body-inspection path are
# exercised. Benign traffic hits neither.
cat > "$WORK/conf/nginx.conf" <<EOF
$LOAD_MODULE_DIRECTIVE
daemon off;
master_process on;
worker_processes 4;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 127.0.0.1:18223;
        root $WORK/html;
        default_type text/plain;

        # Small body buffer so the large chunked upload spills to a temp file,
        # exercising the connector's file-backed request-body inspection path.
        client_body_buffer_size 16k;
        # Headroom for the many-large-headers traffic shape (40 headers).
        large_client_header_buffers 8 16k;
        coraza on;
        coraza_rules 'SecRuleEngine On
                      SecRequestBodyAccess On
                      SecResponseBodyAccess On
                      SecResponseBodyMimeType text/plain text/html
                      SecRule ARGS "@rx attackmarker" "id:100,phase:2,deny,status:403"
                      SecRule REQUEST_BODY "@rx evilbody" "id:101,phase:2,deny,status:403"
                      SecRule REQUEST_HEADERS:X-Attack "@rx headermarker" "id:102,phase:1,deny,status:403"
                      SecRule RESPONSE_BODY "@rx leakmarker" "id:103,phase:4,deny,status:403"
                      ';

        # The static handler rejects POST with 405; the soak POSTs benign
        # bodies (must pass) and attack bodies (Coraza denies 403 in phase 2,
        # before the handler). Route POSTs that survive the WAF to a 200 so a
        # clean benign body is a 200, not a spurious 405.
        error_page 405 = @ok;
        location @ok { return 200 "ok\n"; }

        location / { }
        location /medium { alias $WORK/html/medium; }
        # Response-body inspect target: served content is scanned by the
        # phase-4 RESPONSE_BODY rule above, exercising the body_filter copy/
        # clone + buffered-inspection path (pure-C connector code).
        location /respbody { alias $WORK/html/respbody; }
        # A response carrying the leak marker MUST be blocked at phase 4,
        # driving the response-body deny path end to end.
        location /leak { alias $WORK/html/leak; }
        # Redirect path: exercises header_filter resolv_* + the entity-header
        # clearing the connector does when Coraza rewrites Location.
        location /redir { return 302 /medium; }
    }
}
EOF

# detect_odr_violation=0: nginx defines ngx_module_names/ngx_modules in BOTH
# the main binary and the dynamic module .so (build artifact of
# --add-dynamic-module) — ASan flags the duplicate global as an ODR violation
# and aborts at load. It is benign nginx dynamic-module duplication, not a bug.
ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:detect_odr_violation=0:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
# UBSan recovers (halt_on_error=0) so nginx-core's benign init nullability
# trips don't kill startup; real UB is still logged to ubsan* and asserted
# below. print the stack for triage.
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=0:log_path=$WORK/logs/ubsan"
# libcoraza is usually installed under /usr/local/lib.
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/usr/local/lib}:/usr/local/lib"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    RUN=(valgrind --error-exitcode=99 --leak-check=full
         --errors-for-leak-kinds=definite
         --suppressions="$MODULE_DIR/valgrind.suppress"
         --log-file="$WORK/logs/valgrind.%p" "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    RUN=(valgrind --tool=helgrind --error-exitcode=99
         --suppressions="$MODULE_DIR/valgrind.suppress"
         --log-file="$WORK/logs/helgrind.%p" "${RUN[@]}")
fi

# Capture nginx (and valgrind) stderr — config-parse / dlopen(libcoraza)
# failures print HERE, before error.log is ever opened.
"${RUN[@]}" >"$WORK/logs/stdout.txt" 2>"$WORK/logs/stderr.txt" &
NGINX_PID=$!

# Wait for listen. valgrind + the cgo Go runtime start slowly, so allow up
# to ~120s; bail early if the process already died (config error, missing
# libcoraza, etc.) rather than burning the full timeout.
up=0
for _ in $(seq 1 1200); do
    if ! kill -0 "$NGINX_PID" 2>/dev/null; then
        break   # process gone — startup failed, report below
    fi
    curl -fsS -o /dev/null "http://127.0.0.1:18223/" 2>/dev/null && { up=1; break; }
    sleep 0.1
done
if [ "$up" -ne 1 ]; then
    echo "FAIL: nginx never came up"
    echo "--- stderr ---"; cat "$WORK/logs/stderr.txt" 2>/dev/null || true
    echo "--- error.log ---"; cat "$WORK/logs/error.log" 2>/dev/null || echo "(none written)"
    # valgrind/helgrind print startup aborts to their own --log-file, not
    # stderr — dump them too or a sub-second crash shows nothing.
    if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
        echo "--- valgrind/helgrind log ---"
        cat "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null || true
    fi
    kill "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'; [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)')"
END=$(( $(date +%s) + DURATION ))
fail=0

# A large body forces nginx to buffer the request into a temp file, driving
# the connector's body_filter temp-file/multi-buffer chain path (not just the
# in-memory single-buffer case a tiny -d body hits).
BIG_BODY="$WORK/html/bigreq"
head -c 300000 /dev/urandom | base64 > "$BIG_BODY"

worker() {
    while [ "$(date +%s)" -lt "$END" ]; do
        case $((RANDOM % 9)) in
        0)  # benign GET -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign GET got $code"; return 1; } ;;
        1)  # benign larger response body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "http://127.0.0.1:18223/medium" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign /medium got $code"; return 1; } ;;
        2)  # URI-arg attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "http://127.0.0.1:18223/?q=attackmarker" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "URI attack got $code (want 403)"; return 1; } ;;
        3)  # request-body attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -d 'x=evilbody' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "body attack got $code (want 403)"; return 1; } ;;
        4)  # benign POST body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -d 'x=harmless' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign POST got $code"; return 1; } ;;
        5)  # large chunked request body -> temp-file buffer chain, must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -H 'Transfer-Encoding: chunked' \
                   --data-binary "@$BIG_BODY" \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "large chunked body got $code"; return 1; } ;;
        6)  # many + large request headers -> ngx_str_to_char per-header loop
            #                                  across multiple ngx_list parts
            hdrs=(); for i in $(seq 1 40); do hdrs+=(-H "X-H$i: v$i-$(head -c 64 /dev/zero | tr '\0' a)"); done
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "${hdrs[@]}" \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "many-headers got $code"; return 1; } ;;
        7)  # request-header attack -> phase-1 header rule, must block 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -H 'X-Attack: headermarker' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "header attack got $code (want 403)"; return 1; } ;;
        8)  # response-body: benign scanned body passes, leak marker blocks 403
            if [ $((RANDOM % 2)) -eq 0 ]; then
                code=$(curl -s -o /dev/null -w '%{http_code}' \
                       "http://127.0.0.1:18223/respbody" 2>/dev/null || echo 000)
                [ "$code" = "200" ] || { echo "benign respbody got $code"; return 1; }
            else
                code=$(curl -s -o /dev/null -w '%{http_code}' \
                       "http://127.0.0.1:18223/leak" 2>/dev/null || echo 000)
                [ "$code" = "403" ] || { echo "resp leak got $code (want 403)"; return 1; }
            fi ;;
        esac
    done
}

pids=()
for _ in $(seq 1 "$CONC"); do worker & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done

# Clean shutdown so all pool cleanups (incl. the Coraza transaction) run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null; rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASan report:"; cat "$WORK"/logs/asan*; problems=1
fi
# UBSan noise from nginx core / third-party init (benign nullability trips
# gcc can't scope out) is print-only. A diagnostic whose source location is
# in OUR src/ is real UB in the connector's pure-C paths and fails the soak.
# Do not match connector frames deeper in a third-party diagnostic's stack:
# those identify a caller, not the source location that triggered UBSan. The
# fuzz job also gates those paths, but the soak drives the live-nginx call sites
# the fuzzer can't reach.
if ls "$WORK"/logs/ubsan* >/dev/null 2>&1; then
    echo "note: UBSan diagnostics:"
    cat "$WORK"/logs/ubsan*
    module_dir_re=$(printf '%s\n' "$MODULE_DIR" \
        | sed 's/[][(){}.^$*+?|\\]/\\&/g')
    UBSAN_OWNED_SUFFIX='src/ngx_http_coraza_[^[:space:]]*:[0-9]+(:[0-9]+)?: runtime error:'
    UBSAN_OWNED_PATTERN="^(${module_dir_re}/)?${UBSAN_OWNED_SUFFIX}"
    ubsan_grep_rc=0
    grep -qE "$UBSAN_OWNED_PATTERN" "$WORK"/logs/ubsan* || ubsan_grep_rc=$?
    if [ "$ubsan_grep_rc" -eq 0 ]; then
        echo "FAIL: UBSan diagnostic from our src/ (see above)"; problems=1
    elif [ "$ubsan_grep_rc" -ne 1 ]; then
        echo "FAIL: could not inspect UBSan diagnostics"; problems=1
    fi
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$fail" -ne 0 ]; then
    echo "FAIL: a worker reported a WAF verdict regression"; problems=1
fi
# QUIT is a clean exit; valgrind uses 99, ASAN 42 on error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, no sanitizer/leak/crash, WAF verdicts held"
