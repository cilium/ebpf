# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-12
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UIDGID := $(shell stat -c '%u:%g' ${REPODIR})

CONTAINER_ENGINE ?= docker
CONTAINER_RUN_ARGS ?= --user "${UIDGID}"

IMAGE := $(shell cat ${REPODIR}/testdata/docker/IMAGE)
VERSION := $(shell cat ${REPODIR}/testdata/docker/VERSION)

# clang <8 doesn't tag relocs properly (STT_NOTYPE)
# clang 9 is the first version emitting BTF
TARGETS := \
	testdata/loader-clang-7 \
	testdata/loader-clang-9 \
	testdata/loader-$(CLANG) \
	testdata/btf_map_init \
	testdata/invalid_map \
	testdata/raw_tracepoint \
	testdata/invalid_map_static \
	testdata/invalid_btf_map_init \
	testdata/strings \
	testdata/freplace \
	testdata/iproute2_map_compat \
	internal/btf/testdata/relocs

.PHONY: all clean container-all container-shell

.DEFAULT_TARGET = container-all

# Build all ELF binaries using a containerized LLVM toolchain.
container-all:
	${CONTAINER_ENGINE} run --rm ${CONTAINER_RUN_ARGS} \
		-v "${REPODIR}":/ebpf -w /ebpf --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/ebpf=." \
		--env HOME="/tmp" \
		"${IMAGE}:${VERSION}" \
		$(MAKE) all

# (debug) Drop the user into a shell inside the container as root.
container-shell:
	${CONTAINER_ENGINE} run --rm -ti \
		-v "${REPODIR}":/ebpf -w /ebpf \
		"${IMAGE}:${VERSION}"

clean:
	-$(RM) testdata/*.elf
	-$(RM) internal/btf/testdata/*.elf

all: $(addsuffix -el.elf,$(TARGETS)) $(addsuffix -eb.elf,$(TARGETS)) generate
	ln -srf testdata/loader-$(CLANG)-el.elf testdata/loader-el.elf
	ln -srf testdata/loader-$(CLANG)-eb.elf testdata/loader-eb.elf

# $BPF_CLANG is used in go:generate invocations. We can't use clang-12
# since it's not available on CI.
generate: export BPF_CLANG := clang-9
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./cmd/bpf2go
	cd examples/ && go generate ./...

testdata/loader-%-el.elf: testdata/loader.c
	$* $(CFLAGS) -target bpfel -c $< -o $@

testdata/loader-%-eb.elf: testdata/loader.c
	$* $(CFLAGS) -target bpfeb -c $< -o $@

%-el.elf: %.c
	$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@

%-eb.elf : %.c
	$(CLANG) $(CFLAGS) -target bpfeb -c $< -o $@

# Usage: make VMLINUX=/path/to/vmlinux vmlinux-btf
.PHONY: vmlinux-btf
vmlinux-btf: internal/btf/testdata/vmlinux-btf.gz
internal/btf/testdata/vmlinux-btf.gz: $(VMLINUX)
	objcopy --dump-section .BTF=/dev/stdout "$<" /dev/null | gzip > "$@"
