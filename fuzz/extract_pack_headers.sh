#!/usr/bin/env bash
#
# Slice the verbatim body of ngx_http_coraza_pack_headers() out of the shipped
# ../src/ngx_http_coraza_utils.c into generated_pack_headers.inc.
#
# Same rationale as extract_parser.sh: the fuzz target is locked to production
# code, there is no hand-maintained copy of the function, and we fail loudly if
# the function can no longer be located.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../src/ngx_http_coraza_utils.c"
OUT="$FUZZ_DIR/generated_pack_headers.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# nginx style: return type `ngx_int_t` on its own line, then
# `ngx_http_coraza_pack_headers(...` on the next, body closing with a bare `}`
# in column 1. Capture from the return-type line through that closing brace.
awk '
    /^ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_coraza_pack_headers\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

if ! grep -q 'ngx_http_coraza_pack_headers' "$OUT" || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract ngx_http_coraza_pack_headers() from $SRC" >&2
    echo "  (source layout changed? update extract_pack_headers.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted ngx_http_coraza_pack_headers() — $LINES lines -> $OUT"
