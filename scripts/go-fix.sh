#!/bin/bash

set -euo pipefail

# reflecttypefor currently does a few things that don't make sense. Disable it
# for now, see https://github.com/golang/go/issues/78452.
args=("-reflecttypefor=false")

# Include a big-endian architecture to make sure all code is considered.
arches=(linux/amd64 linux/mips64 darwin/amd64 windows/amd64)

for arch in "${arches[@]}"; do
    IFS='/' read -r goos goarch <<< "$arch"
    echo "GOOS=$goos GOARCH=$goarch go fix ${args[*]} ./..."
    GOOS=$goos GOARCH=$goarch go fix "${args[@]}" ./...
done
