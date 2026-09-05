#!/usr/bin/env bash

# Print the UBSan source-location predicate owned by this connector checkout.
# Callers pass the module root so both absolute compiler paths and relative
# src/ paths are accepted. Relative compiler paths carry no checkout identity,
# so the soak deliberately treats the connector's exact src/ basename as ours:
# its input is only the current nginx process's sanitizer log, and rejecting
# that form would let a legitimate connector diagnostic pass the gate.
ubsan_owned_pattern() {
	local module_dir="$1"
	local module_dir_re
	local owned_suffix

	module_dir_re=$(printf '%s\n' "$module_dir" \
		| sed 's/[][(){}.^$*+?|\\]/\\&/g')
	owned_suffix='src/ngx_http_coraza_[^[:space:]]*:[0-9]+(:[0-9]+)?: runtime error:'
	printf '^(%s/)?%s\n' "$module_dir_re" "$owned_suffix"
}
