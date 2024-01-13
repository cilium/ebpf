#!/bin/bash

set -euo pipefail

source "$(dirname "$(realpath "$0")")/lib.sh"

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT

if [ -d $KERNEL_VERSION ]; then
  # Copy libbpf/vmlinux/bpf_testmod from local directory
  cp $KERNEL_VERSION/libbpf.c $tmp
  cp $KERNEL_VERSION/vmlinux $tmp
  mkdir -p $tmp/lib/modules
  cp $KERNEL_VERSION/bpf_testmod.ko $tmp/lib/modules
else
  # Download libbpf.c
  curl -fL "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/tools/lib/bpf/libbpf.c?h=v$KERNEL_VERSION" -o "$tmp/libbpf.c"

  # Download vmlinux and btf_testmod
  extract_oci_image "ghcr.io/cilium/ci-kernels:$KERNEL_VERSION" "$tmp"

  "/lib/modules/$(uname -r)/build/scripts/extract-vmlinux" "$tmp/boot/vmlinuz" > "$tmp/vmlinux"
fi

# Process libbpf.c
"./internal/cmd/gensections.awk" "$tmp/libbpf.c" | gofmt > "./elf_sections.go"

# Process vmlinux and btf_testmod
objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF="btf/testdata/btf_testmod.btf" {} /dev/null \;
