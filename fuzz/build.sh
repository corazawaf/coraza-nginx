#!/usr/bin/env bash
#
# Build the connector's libFuzzer targets:
#   - fuzz_str_to_char    (ngx_str_to_char)
#   - fuzz_pack_headers   (ngx_http_coraza_pack_headers)
#
# Usage: fuzz/build.sh [output-dir-or-first-binary]
#
# When run with no argument both targets are built next to this script. When
# OSS-Fuzz / ClusterFuzzLite invoke it they pass $OUT as a directory; if the
# first argument is a directory both binaries land inside it. A first argument
# that is not an existing directory keeps the old single-path behaviour for
# fuzz_str_to_char (backwards compatible).
#
# Requires clang with libFuzzer (clang >= 6). CFLAGS/CC overridable for
# OSS-Fuzz / ClusterFuzzLite, which pass their own sanitizer flags.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-clang}"

# OSS-Fuzz sets $LIB_FUZZING_ENGINE and its own $CFLAGS; honour them.
ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
CFLAGS="${CFLAGS:--g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined}"

if [ $# -ge 1 ] && [ ! -d "$1" ]; then
    # Legacy single-target invocation: build only fuzz_str_to_char to that path.
    bash "$FUZZ_DIR/extract_parser.sh"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS $ENGINE -I"$FUZZ_DIR" \
        "$FUZZ_DIR/fuzz_str_to_char.c" -o "$1"
    echo "✓ built fuzz target: $1"
    exit 0
fi

OUTDIR="${1:-$FUZZ_DIR}"

bash "$FUZZ_DIR/extract_parser.sh"
bash "$FUZZ_DIR/extract_pack_headers.sh"

# shellcheck disable=SC2086
"$CC" $CFLAGS $ENGINE -I"$FUZZ_DIR" \
    "$FUZZ_DIR/fuzz_str_to_char.c" -o "$OUTDIR/fuzz_str_to_char"
echo "✓ built fuzz target: $OUTDIR/fuzz_str_to_char"

# shellcheck disable=SC2086
"$CC" $CFLAGS $ENGINE -I"$FUZZ_DIR" \
    "$FUZZ_DIR/fuzz_pack_headers.c" -o "$OUTDIR/fuzz_pack_headers"
echo "✓ built fuzz target: $OUTDIR/fuzz_pack_headers"
