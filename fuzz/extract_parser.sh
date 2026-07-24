#!/usr/bin/env bash
#
# Slice the verbatim body of ngx_str_to_char() out of the shipped
# ../src/ngx_http_coraza_utils.c into generated_parser.inc.
#
# This keeps the fuzz target locked to production code: there is no
# hand-maintained copy of the function. If the signature or body changes
# upstream, the next fuzz build picks it up automatically. If the function
# can no longer be found, we fail loudly rather than fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../src/ngx_http_coraza_utils.c"
OUT="$FUZZ_DIR/generated_parser.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# The definition is nginx style: return type `ngx_int_t` on its own line,
# then `ngx_str_to_char(...)` on the next, body closing with a bare `}` in
# column 1. Capture from the return-type line through that closing brace.
awk '
    /^ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_str_to_char\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

if ! grep -q 'ngx_str_to_char' "$OUT" || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract ngx_str_to_char() from $SRC" >&2
    echo "  (source layout changed? update extract_parser.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted ngx_str_to_char() — $LINES lines -> $OUT"
