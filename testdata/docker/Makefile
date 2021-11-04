# Makefile to build and push the `cilium/ebpf` llvm builder Docker image.
CONTAINER_ENGINE ?= docker

IMAGE := $(shell cat IMAGE)
EPOCH := $(shell date +'%s')

ifndef IMAGE
$(error IMAGE file not present in Makefile directory)
endif

.PHONY: build push

build:
	${CONTAINER_ENGINE} build --no-cache . -t "$(IMAGE):$(EPOCH)"
	echo $(EPOCH) > VERSION

push:
	${CONTAINER_ENGINE} push "$(IMAGE):$(shell cat VERSION)"
