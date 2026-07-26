#!/usr/bin/env bash
# build-libcoraza.sh — fetch (sha256-verified), build, and install libcoraza.
#
# Single source of truth for the libcoraza build recipe shared by every CI job
# that links the connector (build-test, asan, codeql, security-scanners, and the
# ci-deep memcheck/helgrind/scanners/codeql/asan jobs). Extracting it keeps the
# sha256 verification in ONE place — a bare `wget` in any single job would be a
# hole in the supply-chain guarantee versions.env + fetch-verify.sh establish.
#
# Reuses the shared `libcoraza-build/` built-tree cache: on a cache hit (the
# caller restored the tree and the .built sentinel exists) the cgo compile is
# skipped and only `make install` runs.
#
# Required env (exported by load-versions.sh into $GITHUB_ENV):
#   LIBCORAZA_VERSION   immutable release tag (e.g. v1.4.0)
#   LIBCORAZA_SHA256    sha256 of the tag archive
#   GITHUB_WORKSPACE    checkout root (set by Actions)
#
# Optional env:
#   LIBCORAZA_CACHE_HIT  "true" if the caller's actions/cache step hit (skip build)
#   MAKE                 make wrapper, e.g. "eatmydata make" (default: "make")
set -euo pipefail

: "${LIBCORAZA_VERSION:?missing LIBCORAZA_VERSION}"
: "${LIBCORAZA_SHA256:?missing LIBCORAZA_SHA256}"
: "${GITHUB_WORKSPACE:?missing GITHUB_WORKSPACE}"

DEST="$GITHUB_WORKSPACE/libcoraza-build"
MAKE="${MAKE:-make}"
CACHE_HIT="${LIBCORAZA_CACHE_HIT:-false}"

if [ "$CACHE_HIT" = "true" ] && [ -f "$DEST/.built" ]; then
  echo "libcoraza built-tree cache hit — installing only, no recompile."
else
  # Cache miss: fetch (sha256-verified), build, stage into $DEST so the caller's
  # cache action can persist the compiled tree for later runs.
  bash "$GITHUB_WORKSPACE/.github/scripts/fetch-verify.sh" \
    "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.zip" \
    "$LIBCORAZA_SHA256" libcoraza.zip
  rm -rf "$DEST"
  unzip -oq libcoraza.zip
  # libcoraza-<ver>/ — normalise to the fixed cache path.
  mv libcoraza-*/ "$DEST"
  # shellcheck disable=SC2086  # MAKE may be "eatmydata make" — intentional split
  ( cd "$DEST" && ./build.sh && ./configure && $MAKE -j"$(nproc)" )
  touch "$DEST/.built"
fi

# make install is cheap (copy .so + header); run on both paths so the lib lands
# under /usr/local regardless of cache state.
# shellcheck disable=SC2086  # MAKE may be "eatmydata make" — intentional split
sudo $MAKE -C "$DEST" install
sudo ldconfig
