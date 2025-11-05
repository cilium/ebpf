#!/bin/bash

set -euo pipefail

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT

# Download and process libbpf.c
# Truncate .0 patch versions (e.g., 6.16.0 -> 6.16, but leave 7.0 as 7.0)
kernel_version_for_url="$KERNEL_VERSION"
if [[ $KERNEL_VERSION =~ ^([0-9]+\.[0-9]+)\.0$ ]]; then
	kernel_version_for_url="${BASH_REMATCH[1]}"
fi
curl -fL "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/tools/lib/bpf/libbpf.c?h=v$kernel_version_for_url" -o "$tmp/libbpf.c"
"./internal/cmd/gensections.awk" "$tmp/libbpf.c" | gofmt > "./elf_sections.go"

# Download and process vmlinux and btf_testmod
go tool crane export "ghcr.io/cilium/ci-kernels:$KERNEL_VERSION" | tar -x -C "$tmp"

extract-vmlinux "$tmp/boot/vmlinuz" > "$tmp/vmlinux"

objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF="btf/testdata/btf_testmod.btf" {} /dev/null \;
