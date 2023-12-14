#!/bin/bash
# vmlinux.sh

set -eu
set -o pipefail

source env.sh

empty_lsmod="$(mktemp)"
readonly empty_lsmod

make KCONFIG_CONFIG=custom.config defconfig
tee -a < "config" custom.config
make allnoconfig KCONFIG_ALLCONFIG=custom.config
virtme-configkernel --update
make localmodconfig LSMOD="${empty_lsmod}"
make olddefconfig
