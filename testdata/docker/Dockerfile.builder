# This Dockerfile generates a build environment for generating ELFs
# of testdata programs. Run `make build` in this directory to build it.
FROM debian:buster

RUN apt-get update && \
    apt-get -y install curl ca-certificates gnupg make

COPY llvm.list /etc/apt/sources.list.d
RUN curl -s https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN apt-get update && \
    apt-get -y install \
    clang-7 llvm-7 \
    clang-9 llvm-9 \
    clang-11 llvm-11
