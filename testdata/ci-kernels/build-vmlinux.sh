#!/bin/bash
# vmlinux.sh TARGET

set -eu
set -o pipefail

source env.sh

readonly n="${NPROC:-$(nproc)}"

# Don't specify targets explicitly. This saves us from dealing with
# arch-specific names for compressed vmlinux.
taskset -c "0-$((n - 1))" make -j"$n"

if [ -d "tools/testing/selftests/bpf/bpf_testmod" ]; then
	make M=tools/testing/selftests/bpf/bpf_testmod modules
fi
