# This Dockerfile generates a build environment for generating ELFs
# of testdata programs. Run `make build` in this directory to build it.
FROM golang:1.26-bookworm

COPY llvm-snapshot.gpg.key /etc/apt/trusted.gpg.d/apt.llvm.org.asc

COPY llvm.list /etc/apt/sources.list.d

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
    make git gawk \
    libbpf-dev \
    bpftool \
    clang-format \
    clang-14 llvm-14 \
    clang-17 llvm-17 \
    clang-22 llvm-22 && \
    rm -rf /var/lib/apt/lists/*

# Examples use `#include <asm/types.h>` which Debian carries in asm-generic/ instead.
RUN ln -s /usr/include/asm-generic /usr/include/asm

RUN curl -fL "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/scripts/extract-vmlinux" -o "/usr/local/bin/extract-vmlinux" && \
    chmod +x /usr/local/bin/extract-vmlinux
