#!/bin/bash -x
# Taken from https://github.com/kinvolk/stage1-builder/blob/master/examples/semaphore.sh
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set -eu
set -o pipefail

# The kernel versions we want to run the tests on
readonly kernel_versions=("4.16.9")

# The rkt version which is set as a dependency for
# the custom stage1-kvm images
readonly rkt_version="1.30.0"

readonly pkg_name="github.com/newtools/ebpf"

# Download rkt if not available yet as Semaphore CI
# doesn't have rkt at the time of writing
if [[ ! -f "./rkt/rkt" ]] \
  || [[ ! "$(./rkt/rkt version | awk '/rkt Version/{print $3}')" == "${rkt_version}" ]]; then

  curl -LsS "https://github.com/coreos/rkt/releases/download/v${rkt_version}/rkt-v${rkt_version}.tar.gz" \
    -o rkt.tgz

  mkdir -p rkt
  tar -xf rkt.tgz -C rkt --strip-components=1
fi

curl -s https://codecov.io/bash > codecov.sh
chmod +x codecov.sh
# Pre-fetch stage1 dependency due to rkt#2241
# https://github.com/coreos/rkt/issues/2241
sudo ./rkt/rkt image fetch --insecure-options=image "coreos.com/rkt/stage1-kvm:${rkt_version}" >/dev/null

for kernel_version in "${kernel_versions[@]}"; do
  # The stage1-kvm image to use for the tests
  stage1_name="https://github.com/newtools/ci-kernels/blob/master/stage1-kvm-${rkt_version}-linux-${kernel_version}.aci?raw=true"

  # Make sure there's no stale rkt-uuid file
  rm -f ./rkt-uuid

  # You most likely want to provide source code to the
  # container in order to run the tests. You can do this
  # with volumes:
  # https://coreos.com/rkt/docs/latest/subcommands/run.html#mounting-volumes

  # Depending on the level of privileges you need,
  # `--insecure-options=all-run` might be necessary:
  # https://coreos.com/rkt/docs/latest/commands.html#global-options

  # timeout can be used to make sure tests finish in
  # a reasonable amount of time
  sudo timeout --foreground --kill-after=10 5m \
    ./rkt/rkt \
    run --interactive \
    --uuid-file-save=./rkt-uuid \
    --insecure-options=image,all-run \
    --dns=8.8.8.8 \
    --stage1-name="${stage1_name}" \
    --volume=src,kind=host,source="${SEMAPHORE_PROJECT_DIR}" \
    --volume=go,kind=host,source="/home/runner/workspace" \
    --mount=volume=src,target="${SEMAPHORE_PROJECT_DIR}" \
    --mount=volume=go,target="/go" \
    docker://golang:1.10-alpine \
    --environment=GOPATH=/go \
    --exec=/bin/sh -- -c \
    "mount -t tmpfs tmpfs /tmp &&
      mount -t bpf bpf /sys/fs/bpf &&
      mount -t debugfs debugfs /sys/kernel/debug/ &&
      cd /go/src/${pkg_name} &&
      go test -coverprofile=coverage.txt -covermode=atomic -v ./..."

  # Determine exit code from pod status due to rkt#2777
  # https://github.com/coreos/rkt/issues/2777
  test_status=$(sudo ./rkt/rkt status "$(<rkt-uuid)" | awk '/app-/{split($0,a,"=")} END{print a[2]}')
  if [[ $test_status -ne 0 ]]; then
    exit "$test_status"
  fi
  echo "Test successful on ${kernel_version}"
done

./codecov.sh
