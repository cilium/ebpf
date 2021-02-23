# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-11
CFLAGS := -target bpf -O2 -g -Wall -Werror $(CFLAGS)

# clang <8 doesn't tag relocs properly (STT_NOTYPE)
# clang 9 is the first version emitting BTF
TARGETS := \
	loader-clang-7 \
	loader-clang-9 \
	loader-clang-11 \
	invalid_map \
	raw_tracepoint \
	invalid_map_static \
	initialized_btf_map \
	strings

.DEFAULT_GOAL := help

# Look for the word 'docker' in the first make goal, and only declare
# Docker-related goals if it is. This is to prevent the remaining goals from
# executing after the Dockerized make invocation has completed.
ifeq ($(findstring docker,$(firstword $(MAKECMDGOALS))),)

.PHONY: all clean help

all: $(addsuffix -el.elf,$(TARGETS)) $(addsuffix -eb.elf,$(TARGETS)) ## Build all ELFs.

clean: ## Clean up testdata build output.
	-$(RM) *.elf

loader-%-el.elf: loader.c
	$* $(CFLAGS) -mlittle-endian -c $< -o $@

loader-%-eb.elf: loader.c
	$* $(CFLAGS) -mbig-endian -c $< -o $@

%-el.elf: %.c
	$(CLANG) $(CFLAGS) -mlittle-endian -c $< -o $@

%-eb.elf : %.c
	$(CLANG) $(CFLAGS) -mbig-endian -c $< -o $@

help: ## Display this help.
	@grep -E '^[a-zA-Z_-]+:.*## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

else

# If the first make goal contains `docker`, only declare Docker-related targets.

.PHONY: docker docker-shell

# Get the absolute path and uid/gid of the repository on disk.
GITDIR := $(shell git rev-parse --show-toplevel)
UIDGID := $(shell stat -c '%u:%g' ${GITDIR})

# Pop off the 'docker' goal so the remaining goals can be passed to
# the Dockerized make.
PARAMS := $(filter-out docker,$(MAKECMDGOALS))

DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
REPO := $(shell cat ${DIR}/docker/REPO)
VERSION := $(shell cat ${DIR}/docker/VERSION)

docker: ## Wrap the remaining arguments into a Dockerized 'make'.
	docker run --rm --user "${UIDGID}" \
		-v "${GITDIR}":/ebpf -w /ebpf/testdata \
		"${REPO}:${VERSION}" \
		sh -c "make ${PARAMS}"

docker-shell: ## (debug) Drop the user into a shell inside the Docker container as root.
	docker run --rm -ti \
		-v "${GITDIR}":/ebpf -w /ebpf/testdata \
		"${REPO}:${VERSION}"

# Dummy target to avoid inexisting make target errors.
%:
	@true

endif
