#!/usr/bin/env bash
#
# Shared libFuzzer run wrapper so ci-fast and ci-deep drive the fuzz target
# with IDENTICAL breadth flags — only the duration (and parallelism) differ.
# Broad-as-possible coverage for a tiny pure-C function means: value-profile
# (byte-level comparison feedback), large max_len (stress the len+alloc+copy
# past small inputs), a generous RSS ceiling, the dictionary, and the seed
# corpus. ci-deep additionally fans out across all cores (-jobs/-workers) so
# a long wall-clock buys N× more executions.
#
# Usage:
#   fuzz/run.sh <seconds> [jobs]
#     seconds : -max_total_time
#     jobs    : parallel libFuzzer jobs/workers (default 1). When >1, each job
#               shares the same corpus dir and merges coverage.
#
# Env:
#   FUZZ_BIN   : target binary (default ./fuzz_str_to_char, relative to here)
#   CORPUS_DIR : seed/working corpus (default ./corpus)
#   DICT       : dictionary (default ./fuzz.dict)
#   MAX_LEN    : -max_len (default 16384)
#   RSS_MB     : -rss_limit_mb (default 4096)

set -uo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECS="${1:?usage: run.sh <seconds> [jobs]}"
JOBS="${2:-1}"

FUZZ_BIN="${FUZZ_BIN:-$FUZZ_DIR/fuzz_str_to_char}"
CORPUS_DIR="${CORPUS_DIR:-$FUZZ_DIR/corpus}"
DICT="${DICT:-$FUZZ_DIR/fuzz.dict}"
MAX_LEN="${MAX_LEN:-16384}"
RSS_MB="${RSS_MB:-4096}"

cd "$FUZZ_DIR" || exit 1

# Common breadth flags — the point of the "broadest possible" ask.
COMMON=(
    -max_total_time="$SECS"
    -dict="$DICT"
    -max_len="$MAX_LEN"
    -rss_limit_mb="$RSS_MB"
    -use_value_profile=1
    -print_final_stats=1
    -artifact_prefix=crash-
)

echo "fuzz: ${SECS}s, jobs=${JOBS}, max_len=${MAX_LEN}, value_profile=1, dict=$(basename "$DICT")"

rc=0
if [ "$JOBS" -gt 1 ]; then
    # -jobs runs N sequential-per-worker campaigns; -workers parallelises them.
    # libFuzzer forks children and writes fuzz-N.log; a crash makes a child
    # exit non-zero and the parent returns non-zero.
    "$FUZZ_BIN" "${COMMON[@]}" \
        -jobs="$JOBS" -workers="$JOBS" \
        "$CORPUS_DIR/"
    rc=$?
    # Surface any child crash logs.
    if [ "$rc" -ne 0 ]; then
        echo "--- fuzz child logs (tails) ---"
        for l in fuzz-*.log; do [ -f "$l" ] && { echo "== $l =="; tail -20 "$l"; }; done
    fi
else
    "$FUZZ_BIN" "${COMMON[@]}" "$CORPUS_DIR/"
    rc=$?
fi

[ "$rc" -eq 0 ] || { echo "❌ fuzzer crash (exit $rc)"; exit 1; }
echo "✓ no crashes in ${SECS}s (jobs=${JOBS})"
