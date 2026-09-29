#!/bin/bash

set -euo pipefail

# The kernel test matrix is provided by the ci-kernels/matrix action, whose pin
# in ci.yml is managed by Dependabot. Generate kernel deps from the mainline
# version in the pinned matrix so testdata and CI can't drift apart.
matrix_ref=$(awk -F'@' '/uses: cilium\/ci-kernels\/matrix@/ {gsub(/[[:space:]]/, "", $2); print $2}' .github/workflows/ci.yml)

if [ -z "$matrix_ref" ]; then
	echo "Error: could not find a cilium/ci-kernels/matrix pin in .github/workflows/ci.yml" >&2
	exit 1
fi

kernel_version=$(curl -fsSL "https://raw.githubusercontent.com/cilium/ci-kernels/refs/tags/$matrix_ref/matrix/versions.json" |
	jq -r '.[] | select(.channel == "mainline") | .version')

if [ -z "$kernel_version" ]; then
	echo "Error: no mainline version in versions.json at ci-kernels@$matrix_ref" >&2
	exit 1
fi

echo "Using kernel version $kernel_version (ci-kernels@$matrix_ref)"

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT


# Download and process libbpf.c. Mainline versions ("7.3", "7.3-rc4") always
# have a matching tag in Linus' tree.
echo "Getting libbpf version $kernel_version.."
curl -fsSL "https://raw.githubusercontent.com/torvalds/linux/refs/tags/v$kernel_version/tools/lib/bpf/libbpf.c" -o "$tmp/libbpf.c"
"./internal/cmd/gensections.awk" "$tmp/libbpf.c" | gofmt > "./elf_sections.go"

# Download and process vmlinux and btf_testmod
go tool crane export "ghcr.io/cilium/ci-kernels:$kernel_version" | tar -x -C "$tmp"


if ! command -v extract-vmlinux > /dev/null; then
	echo "Error: need scripts/extract-vmlinux from the kernel tree"
	exit 1
fi

extract-vmlinux "$tmp/boot/vmlinuz" > "$tmp/vmlinux"
objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
echo "Extracted vmlinux"

find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF="btf/testdata/btf_testmod.btf" {} /dev/null \;
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF.base="btf/testdata/btf_testmod.btf.base" {} /dev/null \;
echo "Extracted bpf_testmod"
