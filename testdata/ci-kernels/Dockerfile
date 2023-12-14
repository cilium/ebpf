FROM --platform=$BUILDPLATFORM ghcr.io/cilium/ci-kernels-builder:1696243950 AS configure-vmlinux

ARG KERNEL_VERSION

# Download and cache kernel
COPY download.sh .

RUN --mount=type=cache,target=/tmp/kernel ./download.sh

WORKDIR /usr/src/linux-${KERNEL_VERSION}

COPY configure-vmlinux.sh env.sh config .

ARG KBUILD_BUILD_TIMESTAMP="Thu  6 Jul 01:00:00 UTC 2023"
ARG KBUILD_BUILD_HOST="ci-kernels-builder"
ARG TARGETPLATFORM

RUN ./configure-vmlinux.sh

FROM configure-vmlinux AS build-vmlinux

COPY build-vmlinux.sh .

RUN --mount=type=cache,target=/root/.ccache \
    echo 'max_size = 5.0G' > /root/.ccache/ccache.conf; \
    ./build-vmlinux.sh && \
    ccache -s

# Install compiled artifacts
RUN mkdir -p /tmp/output/boot && \
    find ./ -type f -name '*Image' -exec cp -v {} /tmp/output/boot/vmlinuz \; && \
    if [ -d tools/testing/selftests/bpf/bpf_testmod ]; then \
        make M=tools/testing/selftests/bpf/bpf_testmod INSTALL_MOD_PATH=/tmp/output modules_install; \
    fi

# Build selftests
FROM build-vmlinux as build-selftests

ARG BUILDPLATFORM

RUN if [ "$BUILDPLATFORM" != "$TARGETPLATFORM" ]; then \
        echo "Can't cross compile selftests"; exit 1; \
    fi

COPY build-selftests.sh .
RUN ./build-selftests.sh

COPY copy-selftests.sh .
RUN mkdir /tmp/selftests && ./copy-selftests.sh /tmp/selftests

# Prepare the final kernel image
FROM scratch as vmlinux

COPY --from=build-vmlinux /tmp/output /

# Prepare the selftests image
FROM vmlinux as selftests-bpf

COPY --from=build-selftests /tmp/selftests /usr/src/linux
