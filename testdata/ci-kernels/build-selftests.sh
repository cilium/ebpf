#!/bin/bash
# build-selftests.sh

set -eu
set -o pipefail

series="$(echo "${KERNEL_VERSION}" | cut -d . -f 1-2)"
readonly series

if [[ "${series}" = "4.9" ]]; then
	echo "No selftests on <= 4.9"
	exit 0
fi

if [ "${series}" = "4.14" ]; then
	inc="$(find /usr/include -iregex '.+/asm/bitsperlong\.h$' | head -n 1)"
	export CLANG="clang '-I${inc%asm/bitsperlong.h}'"
fi

make headers
make -C tools/testing/selftests/bpf
