#!/bin/bash
# Build a kernel using the Dockerfile. Use for development purposes.
# This is not invoked on CI, see the corresponding workflow.

set -eu
set -o pipefail

if [ $# -lt 3 ]; then
	echo "Usage: $0 <version> <platform> <target>" >&2
	echo "Valid platforms are amd64, arm64"
	exit 1
fi

kernel_version="$1"
platform="linux/$2"
target="${3}"
shift 3

exec docker buildx build --build-arg KERNEL_VERSION="${kernel_version}" --platform "${platform}" --target="${target}" "$@" .
