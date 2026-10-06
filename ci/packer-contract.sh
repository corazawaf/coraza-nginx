#!/usr/bin/env bash
# Safe boundary, allocation, round-trip and success-oracle contracts.
# A retained evidence directory is optional; temporary artifacts are removed.
set -euo pipefail
ulimit -c 0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-clang}"
if [[ -n "${PACKER_EVIDENCE_DIR:-}" ]]; then
	mkdir -p "$PACKER_EVIDENCE_DIR"
	WORK="$(cd "$PACKER_EVIDENCE_DIR" && pwd)"
else
	WORK="$(mktemp -d)"
	trap 'rm -rf "$WORK"' EXIT
fi
FLAGS=(-std=c11 -g -O1 -Wall -Wextra -Werror "-fsanitize=address,undefined"
	-fno-sanitize-recover=undefined)
bash "$ROOT/fuzz/extract_pack_headers.sh"
cp "$ROOT/fuzz/generated_pack_headers.inc" "$ROOT/fuzz/fuzz_pack_headers.c" "$WORK/"
cp "$ROOT/ci/packer-contract.c" "$WORK/"
cp "$WORK/generated_pack_headers.inc" "$WORK/production.inc"

build() {
	local name="$1"
	shift
	printf '%q ' "$CC" "${FLAGS[@]}" -I"$ROOT/fuzz" -I"$WORK" "$@" -o "$WORK/$name"
	printf '\n'
	"$CC" "${FLAGS[@]}" -I"$ROOT/fuzz" -I"$WORK" "$@" -o "$WORK/$name"
	stat -c '%n size=%s mtime=%y' "$WORK/$name"
	sha256sum "$WORK/$name"
}
expect_red() {
	local name="$1" assertion="$2" status=0
	"$WORK/$name" >"$WORK/$name.log" 2>&1 || status=$?
	if [[ "$status" -eq 0 ]] || ! grep -Fq "$assertion" "$WORK/$name.log"; then
		cat "$WORK/$name.log"
		echo "FAIL: $name did not reach the expected assertion" >&2
		exit 1
	fi
	grep -F "$assertion" "$WORK/$name.log"
	echo "PASS: $name detected (exit $status)"
}

build contract "$WORK/packer-contract.c"
"$WORK/contract"
build adapter "$WORK/fuzz_pack_headers.c" "$ROOT/ci/packer-fuzz-inputs.c"
"$WORK/adapter"

# Disable the entire validation loop in a private copy. total stays zero,
# so this control cannot reach allocation or copy, even for huge metadata.
sed '0,/for (i = 0; i < count; i++)/s//for (i = count; i < count; i++)/' \
	"$WORK/production.inc" >"$WORK/generated_pack_headers.inc"
build no-validation "$WORK/packer-contract.c"
expect_red no-validation '== NGX_ERROR'

# Harmless replacement: valid inputs must not silently accept NGX_ERROR.
cat >"$WORK/generated_pack_headers.inc" <<'DOUBLE'
ngx_int_t
ngx_http_coraza_pack_headers(ngx_http_request_t *r,
    ngx_http_coraza_header_t *pairs, ngx_uint_t count,
    u_char **out, size_t *out_len)
{
    (void) r; (void) pairs; (void) count; (void) out; (void) out_len;
    return NGX_ERROR;
}
DOUBLE
build always-error "$WORK/fuzz_pack_headers.c" "$ROOT/ci/packer-fuzz-inputs.c"
expect_red always-error 'rc == NGX_OK'

cp "$WORK/production.inc" "$WORK/generated_pack_headers.inc"
build restored-contract "$WORK/packer-contract.c"
"$WORK/restored-contract"
build restored-adapter "$WORK/fuzz_pack_headers.c" "$ROOT/ci/packer-fuzz-inputs.c"
"$WORK/restored-adapter"
echo 'PASS: packer contracts and both negative controls'
