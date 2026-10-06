# Fuzzing coraza-nginx

Two libFuzzer targets covering the connector's pure-C surfaces — the parts
that can be exercised without a live `ngx_http_request_t`/libcoraza runtime.
Every other connector function needs the full nginx event loop and the Go
engine, so the real parsing there is fuzzed upstream in Coraza itself.

1. **`ngx_str_to_char()`** — converts nginx strings used for URI, method,
   address and other C-string arguments. Empty input allocates a one-byte
   NUL-terminated string on success. Header and body submission use
   length-taking APIs and do not generally pass through this helper.
2. **`ngx_http_coraza_pack_headers()`** — serialises an array of
   (name,value) pairs into the single length-prefixed buffer handed to
   libcoraza's bulk header-submission entry points
   (`coraza_add_{request,response}_headers`). It carries real length
   arithmetic: a running total guarded against the `int` packed-length
   ceiling, per-field u16/u32/INT_MAX bounds, and two `memcpy()`s whose
   destination offsets are driven by attacker-influenced header lengths —
   a higher-value surface than the str→C-string leaf.

## Design

- `fuzz_str_to_char.c` / `fuzz_pack_headers.c` — the libFuzzer entry points +
  per-iteration invariants (for pack_headers, a full decode/round-trip check).
- `extract_parser.sh` / `extract_pack_headers.sh` — slice the **verbatim**
  body of each function out of `../src/ngx_http_coraza_utils.c` into
  `generated_parser.inc` / `generated_pack_headers.inc`. We fuzz production
  code, not a copy; if a function changes upstream the next build picks it up,
  and if it can no longer be found the build fails loudly.
- `ngx_shim.h` — the tiny nginx slice both functions need (`ngx_str_t`, a
  malloc-backed pool so ASan sees the real allocation, `ngx_memcpy`, a request
  stub carrying only `->pool`, and `ngx_http_coraza_header_t`).
- `build.sh` — builds under `-fsanitize=fuzzer,address,undefined`. With no
  argument it builds **both** targets next to the script; a non-directory
  first argument keeps the legacy single-`fuzz_str_to_char` behaviour. Honours
  OSS-Fuzz `$CC`/`$CFLAGS`/`$LIB_FUZZING_ENGINE`.
- `corpus/` — `ngx_str_to_char` seeds (empty, header/URI shaped, embedded NUL,
  4 KiB). `corpus_pack_headers/` — pack_headers seeds (zero/one/two pairs,
  oversized declared lengths, clamped to available input bytes).
- `fuzz.dict` — header/body tokens + NUL/CR/LF boundary bytes.

## Boundary contracts

`bash ci/packer-contract.sh` runs standalone ASan/UBSan contracts and is also
required by the two-target `fuzz/build.sh` route used in `fuzzing.yml`.
It checks zero/ordinary/max-name success, field and aggregate metadata limits,
and allocation failure. Metadata-only cases use a rejecting allocator, so
no oversized allocation or copy executes. Exact `INT_MAX` totals reach that
allocator; over-limit totals must fail before it. Harmless controls disable
validation or return only `NGX_ERROR` and must fail the matching assertions.

The fuzz adapter accepts at most 32 pairs with u16 field lengths, clamped to
the input. Every decoded pair list must succeed and round-trip; this input
space cannot exercise the production packer's larger rejection boundaries.
The standalone tests cover those boundaries separately. Set
`PACKER_EVIDENCE_DIR` to retain binaries and negative-control logs.

## Run

```sh
bash fuzz/build.sh
cd fuzz
./fuzz_str_to_char  -dict=fuzz.dict corpus/
./fuzz_pack_headers corpus_pack_headers/
```

`fuzz/run.sh` wraps a target with the shared breadth flags; point it at the
second target with env vars. Invoke from the repository root — `run.sh` changes
into `fuzz/` before running, so `FUZZ_BIN`/`CORPUS_DIR` are relative to `fuzz/`:

```sh
FUZZ_BIN=./fuzz_pack_headers CORPUS_DIR=./corpus_pack_headers \
  bash fuzz/run.sh 60 1
```

CI runs both targets per PR (`ci-fast.yml`, 60 s each) and monthly in
`ci-deep.yml` (defaults to 600 s/target; manual dispatch can request longer).

## See also

- Valgrind memcheck + helgrind soak of the running module: `../tools/soak.sh`.
