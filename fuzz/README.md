# Fuzzing coraza-nginx

libFuzzer target for the connector's `ngx_str_to_char()` — the single choke
point that converts non-NUL-terminated nginx `ngx_str_t` buffers into the
NUL-terminated C strings libcoraza requires. Every attacker-controlled header
name/value, body chunk and URI forwarded to Coraza passes through it, so a
length/terminator slip is a heap overflow reachable from the request. Short
body, highest-value pure-C surface in the connector.

## Design

- `fuzz_str_to_char.c` — the libFuzzer entry point + per-iteration invariants.
- `extract_parser.sh` — slices the **verbatim** body of `ngx_str_to_char()`
  out of `../src/ngx_http_coraza_utils.c` into `generated_parser.inc`. We fuzz
  production code, not a copy; if the function changes upstream the next build
  picks it up, and if it can no longer be found the build fails loudly.
- `ngx_shim.h` — the tiny nginx slice the function needs (`ngx_str_t`, a
  malloc-backed pool so ASan sees the real allocation, `ngx_memcpy`).
- `build.sh` — builds under `-fsanitize=fuzzer,address,undefined`. Honours
  OSS-Fuzz `$CC`/`$CFLAGS`/`$LIB_FUZZING_ENGINE`.
- `corpus/` — seed inputs (empty, header/URI shaped, embedded NUL, 4 KiB).
- `fuzz.dict` — header/body tokens + NUL/CR/LF boundary bytes.

## Run

```sh
bash fuzz/build.sh
cd fuzz
./fuzz_str_to_char -dict=fuzz.dict corpus/
```

CI runs this 120 s per PR (`ci-fast.yml`) and 4 h/month (`ci-deep.yml`).

## See also

- Valgrind memcheck + helgrind soak of the running module: `../tools/soak.sh`.
