#!/bin/bash
# Test the current package under a different kernel.
# Requires virtme and qemu to be installed.

set -eu
set -o pipefail

if [[ "${1:-}" = "--in-vm" ]]; then
  shift

  readonly scratch="${1}"
  shift

  mount -t bpf bpf /sys/fs/bpf

  if [[ -d "${scratch}/bpf" ]]; then
    export KERNEL_SELFTESTS="${scratch}/bpf"
  fi

  echo "Running test binary in VM..."
  "${scratch}"/ebpf.test -test.coverprofile="$scratch/coverage.txt" -test.v -test.count 1
  touch "$scratch/success"
  exit 0
fi

# Use sudo if /dev/kvm isn't accessible by the current user.
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi
readonly sudo

readonly kernel_version="${1:-}"
if [[ -z "${kernel_version}" ]]; then
  echo "Expecting kernel version as first argument"
  exit 1
fi

readonly kernel="linux-${kernel_version}.bz"
readonly selftests="linux-${kernel_version}-selftests-bpf.bz"
readonly scratch="$(mktemp -d)"
readonly tmp_dir="${TMPDIR:-/tmp}"
readonly branch="${BRANCH:-master}"

fetch() {
    echo Fetching "${1}"
    wget -nv -N -P "${tmp_dir}" "https://github.com/cilium/ci-kernels/raw/${branch}/${1}"
}

fetch "${kernel}"

if fetch "${selftests}"; then
  mkdir "${scratch}/bpf"
  tar --strip-components=4 -xjf "${tmp_dir}/${selftests}" -C "${scratch}/bpf"
else
  echo "No selftests found, disabling"
fi

# Pre-build test binary on host, output into scratch directory shared with VM.
CGO_ENABLED=0 go test -cover -c -o "${scratch}/ebpf.test"

echo Testing on "${kernel_version}"
$sudo virtme-run --kimg "${tmp_dir}/${kernel}" --memory 512M --pwd \
  --rw \
  --rwdir=/run/scratch="${scratch}" \
  --script-sh "PATH=\"$PATH\" $(realpath "$0") --in-vm /run/scratch" \
  --qemu-opts -smp 2 # need at least two CPUs for some tests

if [[ ! -e "${scratch}/success" ]]; then
  echo "Test failed on ${kernel_version}"
  exit 1
else
  echo "Test successful on ${kernel_version}"
  if [[ -v COVERALLS_TOKEN ]]; then
    goveralls -coverprofile="${scratch}/coverage.txt" -service=semaphore -repotoken "$COVERALLS_TOKEN"
  fi
fi

$sudo rm -r "${scratch}"
