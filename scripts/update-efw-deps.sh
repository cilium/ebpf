#!/bin/bash

set -euo pipefail

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT

# Download and process ebpf_structs.h
curl -fL "https://github.com/microsoft/ebpf-for-windows/raw/refs/tags/${EFW_VERSION}/include/ebpf_structs.h" -o "$tmp/ebpf_structs.h"
"./internal/cmd/genwinfunctions.awk" "$tmp/ebpf_structs.h" | gofmt > "./asm/func_win.go"
