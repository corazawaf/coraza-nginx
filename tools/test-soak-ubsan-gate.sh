#!/usr/bin/env bash
#
# Negative control for the UBSan-ownership gate in soak.sh: proves the
# detector goes red on a diagnostic originating in our src/ and stays green on
# third-party/system-library noise, WITHOUT running a real soak or shipping
# any UB in the connector's C code. Feeds synthetic ubsan log fixtures
# through the exact same detection regex soak.sh uses.
#
# Usage: tools/test-soak-ubsan-gate.sh

set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
SOAK="$SELF/soak.sh"
MODULE_DIR="$(cd "$SELF/.." && pwd)"

# Extract the live detection regex straight out of soak.sh so this test
# fails loudly if that line is edited/removed, instead of silently testing
# a stale copy of the pattern.
PATTERN_SUFFIX="$(sed -n "s/^[[:space:]]*UBSAN_OWNED_SUFFIX='\\([^']*\\)'$/\\1/p" "$SOAK")"
if [ -z "$PATTERN_SUFFIX" ]; then
	echo "FAIL: could not locate the UBSan ownership pattern in soak.sh (drifted?)"
	exit 1
fi
module_dir_re=$(printf '%s\n' "$MODULE_DIR" \
	| sed 's/[][(){}.^$*+?|\\]/\\&/g')
PATTERN="^(${module_dir_re}/)?${PATTERN_SUFFIX}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

check() {
	local name="$1" fixture="$2" want="$3" # want: red|green
	printf '%s' "$fixture" >"$WORK/ubsan.log"
	local grep_rc=0
	grep -qE "$PATTERN" "$WORK/ubsan.log" || grep_rc=$?
	if [ "$grep_rc" -eq 0 ]; then
		got=red
	elif [ "$grep_rc" -eq 1 ]; then
		got=green
	else
		echo "FAIL: $name: could not inspect fixture"
		exit 1
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL: $name: detector went $got, want $want"
		echo "--- fixture ---"
		cat "$WORK/ubsan.log"
		exit 1
	fi
	echo "ok: $name -> $got"
}

# Real report naming our connector source (absolute workspace path, as the
# ASan/UBSan build in asan.yml actually emits).
check "own-src absolute path" \
	"$MODULE_DIR/src/ngx_http_coraza_body_filter.c:214:9: runtime error: signed integer overflow
    #0 0x55a1b2 in ngx_http_coraza_body_filter src/ngx_http_coraza_body_filter.c:214" \
	red

# Real report naming our connector source, relative path form.
check "own-src relative path" \
	"src/ngx_http_coraza_utils.c:88:5: runtime error: null pointer passed as argument 2, which is declared to never be null" \
	red

# Third-party/system noise: nginx core init nullability trip (the documented
# benign case) — must NOT flip the gate red, even when the connector appears
# later in its stack as the caller.
check "nginx-core noise" \
	"/usr/src/nginx-1.31.4/src/core/ngx_cycle.c:1123:5: runtime error: null pointer passed as argument 2, which is declared to never be null
	#0 0x55a1b2 in ngx_init_cycle src/core/ngx_cycle.c:1123
	#1 0x55a1c3 in ngx_http_coraza_body_filter src/ngx_http_coraza_body_filter.c:214" \
	green

# An unrelated source tree can use the same connector-looking filename. Only
# this checkout's absolute path (or the compiler's relative src/ form) is ours.
check "external connector-like path" \
	"/usr/src/ngx_http_coraza_vendor.c:10:2: runtime error: signed integer overflow" \
	green

# Third-party/system noise: a libc/PCRE2 frame with no coraza src/ mention.
check "system-library noise" \
	"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0: runtime error: applying zero offset to null pointer" \
	green

echo "PASS: UBSan ownership gate detector (soak.sh) — red on diagnostics from our src/, green on third-party noise"
