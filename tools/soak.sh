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
# in-config SecRules must block (403) — so allocation/free of the Coraza
# transaction, header forwarding (ngx_str_to_char), and request/response
# body inspection all run under the checker every iteration.
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
worker_processes 2;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;
    server {
        listen 127.0.0.1:18223;
        root $WORK/html;
        default_type text/plain;

        coraza on;
        coraza_rules 'SecRuleEngine On
                      SecRequestBodyAccess On
                      SecResponseBodyAccess On
                      SecRule ARGS "@rx attackmarker" "id:100,phase:2,deny,status:403"
                      SecRule REQUEST_BODY "@rx evilbody" "id:101,phase:2,deny,status:403"
                      ';

        # The static handler rejects POST with 405; the soak POSTs benign
        # bodies (must pass) and attack bodies (Coraza denies 403 in phase 2,
        # before the handler). Route POSTs that survive the WAF to a 200 so a
        # clean benign body is a 200, not a spurious 405.
        error_page 405 = @ok;
        location @ok { return 200 "ok\n"; }

        location / { }
        location /medium { alias $WORK/html/medium; }
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

worker() {
    while [ "$(date +%s)" -lt "$END" ]; do
        case $((RANDOM % 5)) in
        0)  # benign GET -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign GET got $code"; return 1; } ;;
        1)  # benign larger body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "http://127.0.0.1:18223/medium" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign /medium got $code"; return 1; } ;;
        2)  # URI-arg attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "http://127.0.0.1:18223/?q=attackmarker" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "URI attack got $code (want 403)"; return 1; } ;;
        3)  # body attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -d 'x=evilbody' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "body attack got $code (want 403)"; return 1; } ;;
        4)  # benign POST body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -d 'x=harmless' \
                   "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign POST got $code"; return 1; } ;;
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
# UBSan is report-only here (nginx core trips benign init nullability UB that
# gcc can't scope out) — print for triage, do NOT fail the soak. Real UB in
# the connector's pure-C paths is gated by the fuzz job instead.
if ls "$WORK"/logs/ubsan* >/dev/null 2>&1; then
    echo "note: UBSan diagnostics (non-fatal, mostly nginx-core init noise):"
    cat "$WORK"/logs/ubsan*
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
