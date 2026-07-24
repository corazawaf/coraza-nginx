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
  bash "$FV" "$url" - "$out" | awk '{print $1}'
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
  | jq -r 'map(select(.name | test("\\(LTS\\)"))) | .[0].tag_name')"
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

# Keep GO_FTW_VERSION from the current file (renovate owns it).
GO_FTW="$(grep -E '^GO_FTW_VERSION=' "$VERSIONS_FILE" | cut -d= -f2)"

cat > "$VERSIONS_FILE" <<EOF
# Central version + sha256 pins for all CI workflows.
#
# SINGLE SOURCE OF TRUTH. Every workflow sources this file into \$GITHUB_ENV as
# its first step (via .github/scripts/load-versions.sh); the monthly bump.yml
# job rewrites it and opens a PR. Tarballs/zips are pinned by version string
# (release archives are immutable) AND verified against the sha256 recorded
# here, so a compromised/changed upstream archive fails the build.
#
# Regenerate with .github/scripts/compute-versions.sh (bump.yml runs it monthly).
# Keep KEY=value, no spaces, no quotes — this file is both \`source\`d and \`cat\`d.

# nginx mainline (odd minor) — built + prove + go-ftw in build.yml
NGINX_MAINLINE=${NGX_MAINLINE}
NGINX_MAINLINE_SHA256=${NGX_MAINLINE_SHA}

# nginx stable (even minor) — built + prove + go-ftw in build.yml
NGINX_STABLE=${NGX_STABLE}
NGINX_STABLE_SHA256=${NGX_STABLE_SHA}

# nginx version used by the deep/soak/scanner jobs (mainline)
NGINX_VERSION=${NGX_MAINLINE}
NGINX_VERSION_SHA256=${NGX_MAINLINE_SHA}

# Angie (webserver-llc) — build-only cell in build.yml; full soak in ci-deep
ANGIE_VERSION=${ANGIE}
ANGIE_SHA256=${ANGIE_SHA}

# libcoraza (cgo shared lib the module links against)
LIBCORAZA_VERSION=${LIBCORAZA}
LIBCORAZA_SHA256=${LIBCORAZA_SHA}

# OWASP CRS — LTS line (used by build.yml go-ftw regression run)
CRS_VERSION=${CRS}
CRS_SHA256=${CRS_SHA}

# go-ftw (test runner, installed via \`go install\`, pinned by tag only)
GO_FTW_VERSION=${GO_FTW}
EOF

echo "----- new versions.env -----"
echo "nginx mainline: ${NGX_MAINLINE}"
echo "nginx stable:   ${NGX_STABLE}"
echo "angie:          ${ANGIE}"
echo "libcoraza:      ${LIBCORAZA}"
echo "crs (LTS):      ${CRS}"
