#!/bin/bash

set -euo pipefail

# Extract EFW version from CI workflow file
efw_version=$(awk -F': ' '/CI_EFW_VERSION:/ {gsub(/['\''"]/, "", $2); print $2}' .github/workflows/ci.yml)

if [ -z "$efw_version" ]; then
	echo "Error: Could not extract CI_EFW_VERSION from .github/workflows/ci.yml" >&2
	exit 1
fi

echo "Using EFW version: $efw_version"

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT

# Download and process ebpf_structs.h
curl -fsSL "https://github.com/microsoft/ebpf-for-windows/raw/refs/tags/v${efw_version}/include/ebpf_structs.h" -o "$tmp/ebpf_structs.h"
"./internal/cmd/genwinfunctions.awk" "$tmp/ebpf_structs.h" | gofmt > "./asm/func_win.go"
echo "Updated efW structs"
