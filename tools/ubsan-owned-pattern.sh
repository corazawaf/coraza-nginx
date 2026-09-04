#!/usr/bin/env bash

# Print the UBSan source-location predicate owned by this connector checkout.
# Callers pass the module root so both absolute compiler paths and relative
# src/ paths are accepted, while similarly named third-party trees stay out.
ubsan_owned_pattern() {
	local module_dir="$1"
	local module_dir_re
	local owned_suffix

	module_dir_re=$(printf '%s\n' "$module_dir" \
		| sed 's/[][(){}.^$*+?|\\]/\\&/g')
	owned_suffix='src/ngx_http_coraza_[^[:space:]]*:[0-9]+(:[0-9]+)?: runtime error:'
	printf '^(%s/)?%s\n' "$module_dir_re" "$owned_suffix"
}
