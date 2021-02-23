# This Dockerfile generates a build environment for generating ELFs
# of testdata programs. Run `make build` in this directory to build it.
FROM debian:buster

RUN apt-get update && \
    apt-get -y install ca-certificates gnupg make

COPY llvm.list /etc/apt/sources.list.d

COPY llvm-snapshot.gpg.key .
RUN apt-key add /llvm-snapshot.gpg.key && rm /llvm-snapshot.gpg.key

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
    clang-7 llvm-7 \
    clang-9 llvm-9 \
    clang-11 llvm-11 && \
    rm -rf /var/lib/apt/lists/*
