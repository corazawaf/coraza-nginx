#!/usr/bin/env bash
# Test the actual cleanup and shutdown blocks with harmless child exits.
# No server, requests, sanitizer campaign, or load is started.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${SOAK_SOURCE:-$ROOT/tools/soak.sh}"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT:?}"' EXIT
awk '/^WORK=/ { copy=1 } /^mkdir -p/ { copy=0 } copy' "$SOURCE" >"$TEST_ROOT/setup.sh"
awk '/^# Clean shutdown/ { copy=1 } copy' "$SOURCE" >"$TEST_ROOT/shutdown.sh"
test -s "$TEST_ROOT/setup.sh"
test -s "$TEST_ROOT/shutdown.sh"
cat >"$TEST_ROOT/runner.sh" <<'SH'
source "$TEST_ROOT/setup.sh"
printf '%s\n' "$WORK" >"$TEST_ROOT/work-path"
mkdir -p "$WORK/logs"
printf 'inert error-log evidence\n' >"$WORK/logs/error.log"
printf 'inert stderr evidence\n' >"$WORK/logs/stderr.txt"
if [ "$MODE" = early ]; then exit 23; fi
if [ "$MODE" = no-error-log ]; then rm "$WORK/logs/error.log"; fi
# Suppress signals only; wait still observes a real child's exit status.
kill() { return 0; }
(exit "$MASTER_STATUS") &
NGINX_PID=$!
source "$TEST_ROOT/shutdown.sh"
SH
export TEST_ROOT MODULE_DIR="$ROOT" DURATION=0 CONC=1 fail=0
run_case() {
	local name="$1" result=0 work
	export MASTER_STATUS="$2" MODE="$3"
	bash -euo pipefail "$TEST_ROOT/runner.sh" >"$TEST_ROOT/output" 2>&1 || result=$?
	work="$(cat "$TEST_ROOT/work-path")"
	if [ "$MASTER_STATUS" -eq 0 ] && [ "$MODE" != early ]; then
		if [ "$result" -ne 0 ] || [ -e "$work" ] || ! grep -Fq 'soak clean:' "$TEST_ROOT/output"; then
			echo "FAIL: $name: benign success must report clean and remove work directory"
			cat "$TEST_ROOT/output"
			exit 1
		fi
		if grep -Fq 'failure evidence retained' "$TEST_ROOT/output"; then
			echo "FAIL: $name: benign success reported failure evidence"
			exit 1
		fi
	else
		local expected=1 marker="FAIL: nginx exited $MASTER_STATUS"
		if [ "$MODE" = early ]; then
			expected=23
			marker='failure evidence retained'
		fi
		if [ "$result" -ne "$expected" ] || ! grep -Fq "$marker" "$TEST_ROOT/output"; then
			echo "FAIL: $name: expected status $expected and diagnostic: $marker; got $result"
			cat "$TEST_ROOT/output"
			exit 1
		fi
		if ! grep -Fq "soak: failure evidence retained at $work" "$TEST_ROOT/output" ||
			[ ! -f "$work/logs/stderr.txt" ] ||
			[ "$(cat "$work/logs/stderr.txt")" != 'inert stderr evidence' ]; then
			echo "FAIL: $name: failure must retain and report original evidence"
			exit 1
		fi
		if [ "$MODE" != no-error-log ] && [ "$(cat "$work/logs/error.log")" != 'inert error-log evidence' ]; then
			echo "FAIL: $name: error log was not preserved"
			exit 1
		fi
		if grep -Fq 'soak clean:' "$TEST_ROOT/output"; then
			echo "FAIL: $name: failure claimed a clean soak"
			exit 1
		fi
	fi
	rm -rf "${work:?}"
	echo "ok: $name"
}
# Keep generated work directories inside the test root, even on assertion failure.
mkdir "$TEST_ROOT/work"
export TMPDIR="$TEST_ROOT/work"
run_case benign-zero-exit 0 normal
for status in 1 42 99 130 255; do
	run_case "master-exit-$status" "$status" normal
done
run_case missing-error-log 42 no-error-log
run_case early-error-status 0 early
echo 'PASS: soak exit and evidence fixtures'
