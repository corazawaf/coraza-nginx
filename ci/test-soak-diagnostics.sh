#!/usr/bin/env bash
# Exercise the actual soak report blocks with inert logs; no server or load.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${SOAK_SOURCE:-$ROOT/tools/soak.sh}"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

# Extract whole control-flow blocks, retaining set -e in the child shell.
awk '/^if \[ "\$up" -ne 1 \]; then$/ { copy=1 }
     /^echo "soak:/ { copy=0 }
     copy' "$SOURCE" >"$TEST_ROOT/startup.sh"
awk '/^problems=0$/ { copy=1 } copy' "$SOURCE" >"$TEST_ROOT/report.sh"
awk '/^pids=\(\)$/ { copy=1 }
     /^# Clean shutdown/ { copy=0 }
     copy' "$SOURCE" >"$TEST_ROOT/workers.sh"
for block in startup report workers; do
	test -s "$TEST_ROOT/$block.sh"
done

export MODULE_DIR="$ROOT" DURATION=0 CONC=2
# The startup block only signals this nonexistent positive PID; no real server.
export NGINX_PID=2147483647 up=0 rc=0 fail=0
export USE_VALGRIND=0 USE_HELGRIND=0
new_case() {
	export WORK="$TEST_ROOT/$1"
	mkdir -p "$WORK/logs"
	: >"$WORK/logs/error.log"
	: >"$WORK/logs/stderr.txt"
	export USE_VALGRIND=0 USE_HELGRIND=0 fail=0 rc=0
}
report() {
	printf '==123== ERROR SUMMARY: %s errors from 0 contexts\n' "$2" >"$WORK/logs/$1.${3:-123}"
	printf '==123== definitely lost: 0 bytes in 0 blocks\n' >>"$WORK/logs/$1.${3:-123}"
}
check() {
	local name="$1" block="$2" expected="$3" marker="$4" result=0
	bash -euo pipefail "$TEST_ROOT/$block.sh" >"$TEST_ROOT/output" 2>&1 || result=$?
	if [ "$result" -ne "$expected" ] || ! grep -Fq -- "$marker" "$TEST_ROOT/output"; then
		echo "FAIL: $name: status $result (want $expected), expected output: $marker"
		cat "$TEST_ROOT/output"
		exit 1
	fi
	if [ "$expected" -ne 0 ] && grep -Fq 'soak clean:' "$TEST_ROOT/output"; then
		echo "FAIL: $name: failure claimed a clean soak"
		exit 1
	fi
	echo "ok: $name"
}

for family in valgrind helgrind both neither; do
	new_case "startup-$family"
	case "$family" in
	valgrind | helgrind) report "$family" 1 ;;
	both)
		report valgrind 1
		report helgrind 2
		;;
	esac
	check "startup-$family" startup 1 'FAIL: nginx never came up'
	for tool in valgrind helgrind; do
		if [ "$family" = "$tool" ] || [ "$family" = both ]; then
			while IFS= read -r line; do
				grep -Fq -- "$line" "$TEST_ROOT/output" || {
					echo "FAIL: startup-$family: hidden $tool diagnostic"
					exit 1
				}
			done <"$WORK/logs/$tool.123"
		fi
	done
	if grep -Eq 'No such file|cannot access' "$TEST_ROOT/output"; then
		echo "FAIL: startup-$family: unmatched glob leaked"
		exit 1
	fi
	new_case "clean-$family"
	case "$family" in
	valgrind)
		export USE_VALGRIND=1
		report valgrind 0
		;;
	helgrind)
		export USE_HELGRIND=1
		report helgrind 0
		;;
	both)
		export USE_VALGRIND=1 USE_HELGRIND=1
		report valgrind 0
		report helgrind 0
		;;
	esac
	check "clean-$family" report 0 'soak clean:'
done

for tool in valgrind helgrind; do
	new_case "missing-$tool"
	if [ "$tool" = valgrind ]; then export USE_VALGRIND=1; else export USE_HELGRIND=1; fi
	check "missing-$tool" report 1 "FAIL: missing $tool report"
	# The other family's clean file must not satisfy this requirement.
	if [ "$tool" = valgrind ]; then report helgrind 0; else report valgrind 0; fi
	check "wrong-family-$tool" report 1 "FAIL: missing $tool report"
	for kind in errors leak unreadable; do
		new_case "$tool-$kind"
		case "$kind" in
		errors) report "$tool" 1 ;;
		leak) printf 'definitely lost: 1,024 bytes\n' >"$WORK/logs/$tool.123" ;;
		unreadable) mkdir "$WORK/logs/$tool.123" ;;
		esac
		if [ "$kind" = unreadable ]; then
			check "$tool-$kind" report 1 'FAIL: could not inspect'
		else
			check "$tool-$kind" report 1 'FAIL: valgrind/helgrind errors:'
		fi
	done
	new_case "$tool-second-report-error"
	if [ "$tool" = valgrind ]; then export USE_VALGRIND=1; else export USE_HELGRIND=1; fi
	report "$tool" 0
	report "$tool" 1 456
	check "$tool-second-report-error" report 1 'FAIL: valgrind/helgrind errors:'
	new_case "$tool-empty-report"
	if [ "$tool" = valgrind ]; then export USE_VALGRIND=1; else export USE_HELGRIND=1; fi
	: >"$WORK/logs/$tool.123"
	check "$tool-empty-report" report 1 'FAIL: empty selected-tool report:'
done
new_case both-flags-precedence
export USE_VALGRIND=1 USE_HELGRIND=1
report valgrind 0
check both-flags-precedence report 0 'soak clean:'
report helgrind 1
check both-families-one-error report 1 'FAIL: valgrind/helgrind errors:'
new_case both-flags-unselected-empty
export USE_VALGRIND=1 USE_HELGRIND=1
report valgrind 0
: >"$WORK/logs/helgrind.123"
check both-flags-unselected-empty report 0 'soak clean:'

new_case sanitizer
printf 'inert ASan diagnostic\n' >"$WORK/logs/asan.123"
check asan report 1 'FAIL: ASan report:'
new_case ubsan-owned
printf 'src/ngx_http_coraza_utils.c:88:5: runtime error: inert fixture\n' >"$WORK/logs/ubsan.123"
check ubsan-owned report 1 'FAIL: UBSan diagnostic from our src/'
new_case ubsan-external
printf '/external/library.c:88:5: runtime error: inert fixture\n' >"$WORK/logs/ubsan.123"
check ubsan-external report 0 'note: UBSan diagnostics:'
for severity in alert emerg; do
	new_case "$severity"
	printf '[%s] inert fixture\n' "$severity" >"$WORK/logs/error.log"
	check "$severity" report 1 'FAIL: alert/emerg in error.log'
done

# Exercise actual worker wait aggregation, including failed background
# workers. This is separate from the nginx master wait (F15).
new_case workers
cat >"$TEST_ROOT/worker-report.sh" <<'SH'
worker() { return "${WORKER_STATUS:?}"; }
source "${WORKER_BLOCK:?}"
source "${REPORT_BLOCK:?}"
SH
export WORKER_BLOCK="$TEST_ROOT/workers.sh" REPORT_BLOCK="$TEST_ROOT/report.sh"
export WORKER_STATUS=0
check workers-clean worker-report 0 'soak clean:'
export WORKER_STATUS=7
check workers-fail worker-report 1 'FAIL: a worker reported a WAF verdict regression'
echo 'PASS: soak diagnostics fixtures'
