# This Dockerfile generates a build environment for generating ELFs
# of testdata programs. Run `make build` in this directory to build it.
FROM golang:bullseye

COPY llvm-snapshot.gpg.key .

RUN apt-get update && \
    apt-get -y --no-install-recommends install ca-certificates gnupg && \
    apt-key add llvm-snapshot.gpg.key && \
    rm llvm-snapshot.gpg.key && \
    apt-get remove -y gnupg && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY llvm.list /etc/apt/sources.list.d

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
    make git \
    libbpf-dev \
    clang-format \
    clang-11 llvm-11 \
    clang-14 llvm-14 \
    clang-17 llvm-17 && \
    rm -rf /var/lib/apt/lists/*

# Examples use `#include <asm/types.h>` which Debian carries in asm-generic/ instead.
RUN ln -s /usr/include/asm-generic /usr/include/asm

RUN GOBIN=/usr/local/bin go install golang.org/x/tools/cmd/stringer@latest && rm -rf /go/pkg
