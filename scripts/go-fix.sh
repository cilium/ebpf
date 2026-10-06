#!/bin/bash

set -euo pipefail

# Include a big-endian architecture to make sure all code is considered.
arches=(linux/amd64 linux/mips64 darwin/amd64 windows/amd64)

for arch in "${arches[@]}"; do
    IFS='/' read -r goos goarch <<< "$arch"
    echo "GOOS=$goos GOARCH=$goarch go fix ./..."
    GOOS=$goos GOARCH=$goarch go fix ./...
done
