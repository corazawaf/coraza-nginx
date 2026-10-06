#!/usr/bin/env bash
# Exercise the ordinary connection path in a CORAZA_DDEBUG=1 module build.
set -euo pipefail

: "${NGINX_TESTS_DIR:?set to a disposable nginx-tests checkout}"
: "${TEST_NGINX_BINARY:?set to the nginx test binary}"
: "${TEST_NGINX_GLOBALS:?load the debug-built connector module}"

repo_dir=$(cd "$(dirname "$0")/.." && pwd)
test_dir=$(cd "$NGINX_TESTS_DIR" && pwd)
log_file=$(mktemp)
trap 'rm -f "$log_file"' EXIT

cp "$repo_dir/t/coraza-phase1-addr-uri-deny.t" \
    "$repo_dir/t/coraza_crash_check.pm" "$test_dir/"

(
    cd "$test_dir"
    TEST_NGINX_CATLOG=1 prove -v coraza-phase1-addr-uri-deny.t
) >"$log_file" 2>&1 || {
    cat "$log_file"
    exit 1
}

# A missing marker means the test never exercised this debug call site.
grep -q 'connection variables filled in; first rule phase is request headers' "$log_file"
if grep -q 'Was not able to extract connection information' "$log_file"; then
    echo 'ordinary connection incorrectly logged as a failure' >&2
    exit 1
fi
echo 'ordinary connection debug check passed'
