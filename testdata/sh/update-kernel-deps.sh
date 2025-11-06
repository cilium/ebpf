#!/bin/bash

set -euo pipefail

readonly docker="${CONTAINER_ENGINE:-docker}"

extract_oci_image() {
	local image_name=$1
	local target_directory=$2

	echo -n "Fetching $image_name... "

	# We abuse the --output flag of docker buildx to obtain a copy of the image.
	# This is simpler than creating a temporary container and using docker cp.
	# It also automatically fetches the image for us if necessary.
	if ! echo "FROM $image_name" | "$docker" buildx build --quiet --pull --output="$target_directory" - &> /dev/null; then
		echo "failed"
		return 1
	fi

	echo "ok"
	return 0
}

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
extract_oci_image "ghcr.io/cilium/ci-kernels:$KERNEL_VERSION" "$tmp"

"/lib/modules/$(uname -r)/build/scripts/extract-vmlinux" "$tmp/boot/vmlinuz" > "$tmp/vmlinux"

objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF="btf/testdata/btf_testmod.btf" {} /dev/null \;
