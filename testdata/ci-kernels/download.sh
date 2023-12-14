#!/bin/bash

set -eu
set -o pipefail

if [[ $KERNEL_VERSION == *"-rc"* ]]; then
    KERNEL_URL="https://git.kernel.org/torvalds/t/linux-${KERNEL_VERSION}.tar.gz"
else
    KERNEL_MAJ_VERSION=$(echo "$KERNEL_VERSION" | cut -d '.' -f 1)
    KERNEL_URL="https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJ_VERSION}.x/linux-${KERNEL_VERSION}.tar.xz"
fi

cd /tmp/kernel
curl --fail -L --time-cond "linux-${KERNEL_VERSION}.tar.${KERNEL_URL##*.}" -o "linux-${KERNEL_VERSION}.tar.${KERNEL_URL##*.}" "$KERNEL_URL"
tar -xf "linux-${KERNEL_VERSION}.tar.${KERNEL_URL##*.}" -C /usr/src
