#!/usr/bin/env bash
# compute-versions.sh — resolve the latest upstream versions + their sha256 and
# rewrite .github/versions.env in place. Used by bump.yml (monthly). Leaves
# GO_FTW_VERSION untouched (bumped by renovate). Prints a short summary of what
# changed to stdout.
#
# Resolves:
#   nginx mainline (odd minor) + stable (even minor)  — nginx.org download page
#   Angie latest release tag                          — GitHub API
#   OWASP CRS latest LTS release                       — GitHub API (name ~ "(LTS)")
#   libcoraza latest release tag                        — GitHub API
#
# Requires: curl, jq, sha256sum. GITHUB_TOKEN honoured for API rate limits.
set -euo pipefail

VERSIONS_FILE=".github/versions.env"
FV=".github/scripts/fetch-verify.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

api() {
  local url="$1"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$url"
  else
    curl -fsSL "$url"
  fi
}

# sha256 of a URL (download to scratch, hash). Fails the job on download error.
sha_of_url() {
  local url="$1" out="$tmp/dl.$RANDOM"
  # fetch-verify.sh prints "downloading: URL" before the final "SHA  OUTFILE"
  # line, so grab the first field of the LAST line only.
  bash "$FV" "$url" - "$out" | awk 'END { print $1 }'
}

echo "resolving nginx versions from nginx.org..."
dl_html="$(curl -fsSL https://nginx.org/en/download.html)"
# Mainline = first version under the "Mainline version" heading; Stable = first
# under "Stable version". The page lists them in that order, newest first.
NGX_MAINLINE="$(printf '%s' "$dl_html" | grep -oE 'nginx-1\.[0-9]+\.[0-9]+' \
  | awk -F. '$2%2==1' | sort -uV | tail -1 | sed 's/nginx-//')"
NGX_STABLE="$(printf '%s' "$dl_html" | grep -oE 'nginx-1\.[0-9]+\.[0-9]+' \
  | awk -F. '$2%2==0' | sort -uV | tail -1 | sed 's/nginx-//')"
[ -n "$NGX_MAINLINE" ] && [ -n "$NGX_STABLE" ] || { echo "::error::failed to resolve nginx versions" >&2; exit 1; }

echo "resolving Angie latest tag..."
ANGIE="$(api 'https://api.github.com/repos/webserver-llc/angie/releases/latest' | jq -r '.tag_name')"
[ -n "$ANGIE" ] && [ "$ANGIE" != "null" ] || { echo "::error::failed to resolve Angie" >&2; exit 1; }

echo "resolving OWASP CRS latest LTS..."
# Newest release whose name contains "(LTS)".
CRS_TAG="$(api 'https://api.github.com/repos/coreruleset/coreruleset/releases?per_page=30' \
  | jq -r 'map(select(.draft | not) | select(.prerelease | not)
             | select(.name | test("\\(LTS\\)"))) | .[0].tag_name')"
[ -n "$CRS_TAG" ] && [ "$CRS_TAG" != "null" ] || { echo "::error::failed to resolve CRS LTS" >&2; exit 1; }
CRS="${CRS_TAG#v}"

echo "resolving libcoraza latest tag..."
LIBCORAZA="$(api 'https://api.github.com/repos/corazawaf/libcoraza/releases/latest' | jq -r '.tag_name')"
[ -n "$LIBCORAZA" ] && [ "$LIBCORAZA" != "null" ] || { echo "::error::failed to resolve libcoraza" >&2; exit 1; }

echo "hashing archives..."
NGX_MAINLINE_SHA="$(sha_of_url "https://nginx.org/download/nginx-${NGX_MAINLINE}.tar.gz")"
NGX_STABLE_SHA="$(sha_of_url "https://nginx.org/download/nginx-${NGX_STABLE}.tar.gz")"
ANGIE_SHA="$(sha_of_url "https://github.com/webserver-llc/angie/archive/refs/tags/${ANGIE}.tar.gz")"
CRS_SHA="$(sha_of_url "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS}.tar.gz")"
LIBCORAZA_SHA="$(sha_of_url "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA}.zip")"

# Rewrite the pins IN PLACE, one key at a time. This script owns only the keys
# listed in `set_pin` calls below; every other line of versions.env — comments,
# blank lines, and hand-maintained pins like NGINX_TESTS_* (no upstream
# releases, pinned to an immutable commit) and FALLBACK_LIBCORAZA_* (held at
# 1.4.x on purpose so ci-deep keeps exercising the pre-1.6 fallback path) —
# is carried through untouched.
#
# Do NOT go back to regenerating the whole file from a heredoc: that silently
# deletes any pin the heredoc does not know about, which is how the
# NGINX_TESTS_* and FALLBACK_LIBCORAZA_* pins were lost once already.

# set_pin KEY VALUE — replace the value of an existing KEY=... line, preserving
# its position and the comment above it. Missing key = the file and this script
# have drifted apart, which is a bug in one of them; fail loudly rather than
# appending an orphan line at the bottom.
set_pin() {
  local key="$1" val="$2"
  grep -qE "^${key}=" "$VERSIONS_FILE" || {
    echo "::error::${key} not found in ${VERSIONS_FILE} — add it there first" >&2
    exit 1
  }
  # Value is passed through the environment, not `awk -v` (which expands \n and
  # friends) and not sed (where & and \1 are replacement metacharacters), so the
  # pin lands byte-for-byte as resolved. Matters: these are sha256 values.
  key="$key" val="$val" awk \
    'index($0, ENVIRON["key"] "=") == 1 { print ENVIRON["key"] "=" ENVIRON["val"]; next } { print }' \
    "$VERSIONS_FILE" > "$tmp/versions.env"
  mv "$tmp/versions.env" "$VERSIONS_FILE"
}

set_pin NGINX_MAINLINE        "$NGX_MAINLINE"
set_pin NGINX_MAINLINE_SHA256 "$NGX_MAINLINE_SHA"
set_pin NGINX_STABLE          "$NGX_STABLE"
set_pin NGINX_STABLE_SHA256   "$NGX_STABLE_SHA"
set_pin NGINX_VERSION         "$NGX_MAINLINE"
set_pin NGINX_VERSION_SHA256  "$NGX_MAINLINE_SHA"
set_pin ANGIE_VERSION         "$ANGIE"
set_pin ANGIE_SHA256          "$ANGIE_SHA"
set_pin LIBCORAZA_VERSION     "$LIBCORAZA"
set_pin LIBCORAZA_SHA256      "$LIBCORAZA_SHA"
set_pin CRS_VERSION           "$CRS"
set_pin CRS_SHA256            "$CRS_SHA"
# GO_FTW_VERSION is renovate's; NGINX_TESTS_* and FALLBACK_LIBCORAZA_* are
# hand-pinned. None are set here — they survive by not being touched.

echo "----- new versions.env -----"
echo "nginx mainline: ${NGX_MAINLINE}"
echo "nginx stable:   ${NGX_STABLE}"
echo "angie:          ${ANGIE}"
echo "libcoraza:      ${LIBCORAZA}"
echo "crs (LTS):      ${CRS}"
