FROM debian:bookworm

LABEL org.opencontainers.image.source https://github.com/cilium/ci-kernels

# Preserve the APT cache between runs
RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates

COPY llvm-snapshot.gpg /usr/share/keyrings
COPY llvm.list /etc/apt/sources.list.d
COPY llvm.pref /etc/apt/preferences.d

# Bake the appropriate clang version into the container
ARG CLANG_VERSION=16
ENV CLANG=clang-${CLANG_VERSION}
ENV LLVM_STRIP=llvm-strip-${CLANG_VERSION}

# Update and install dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        tar \
        build-essential \
        crossbuild-essential-amd64 \
        crossbuild-essential-arm64 \
        libncurses5-dev \
        bison \
        flex \
        libssl-dev \
        bc \
        xz-utils \
        ccache \
        libelf-dev \
        python3-docutils \
        python3-pip \
        pahole \
        libcap-dev \
        ${CLANG} \
        llvm-${CLANG_VERSION} \
        lld \
        kmod \
        rsync \
        libc6-dev-i386

# Install virtme-configkernel
RUN pip3 install --break-system-packages https://github.com/amluto/virtme/archive/refs/heads/master.zip
