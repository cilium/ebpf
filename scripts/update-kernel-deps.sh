#!/bin/bash

set -euo pipefail

# Extract kernel version from CI workflow file
kernel_version=$(awk -F': ' '/CI_MAX_KERNEL_VERSION:/ {gsub(/['\''"]/, "", $2); print $2}' .github/workflows/ci.yml)

if [ -z "$kernel_version" ]; then
	echo "Error: Could not extract CI_MAX_KERNEL_VERSION from .github/workflows/ci.yml" >&2
	exit 1
fi

echo "Using kernel version: $kernel_version"

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT

# Download and process libbpf.c
# Truncate .0 patch versions (e.g., 6.16.0 -> 6.16, but leave 7.0 as 7.0)
kernel_version_for_url="$kernel_version"
if [[ $kernel_version =~ ^([0-9]+\.[0-9]+)\.0$ ]]; then
	kernel_version_for_url="${BASH_REMATCH[1]}"
fi
curl -fL "https://raw.githubusercontent.com/gregkh/linux/refs/tags/v$kernel_version_for_url/tools/lib/bpf/libbpf.c" -o "$tmp/libbpf.c"
"./internal/cmd/gensections.awk" "$tmp/libbpf.c" | gofmt > "./elf_sections.go"

# Download and process vmlinux and btf_testmod
go tool crane export "ghcr.io/cilium/ci-kernels:$kernel_version" | tar -x -C "$tmp"

extract-vmlinux "$tmp/boot/vmlinuz" > "$tmp/vmlinux"

objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF="btf/testdata/btf_testmod.btf" {} /dev/null \;
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF.base="btf/testdata/btf_testmod.btf.base" {} /dev/null \;
