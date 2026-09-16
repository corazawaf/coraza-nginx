# Lint

These are source-text checks, not behavior tests: each one greps a file under
`src/` (or `debian/control`, or the module `config` script) for an expected
string or pattern. They pass on a module that segfaults at runtime and can
break on a harmless refactor that keeps the same behavior but changes the
text they match — so they do not belong in `t/`, which `prove` runs as the
functional suite against a built nginx.

They still catch real drift (a helper silently losing an error-propagation
path, a dynamic-module link flag disappearing, a control-file field going
stale), so CI runs them as a separate lint step rather than dropping them.
See `.github/workflows/build-test.yml`.

Each file uses only `Test::More` and `FindBin` (both core Perl) and resolves
its target file via `$FindBin::Bin/..`, so they run directly from this
directory with plain `prove` — no nginx build, no `Test::Nginx`, no copy into
an nginx-tests checkout.
