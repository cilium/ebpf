# Makefile to build and push the `cilium/ebpf` llvm builder Docker image.
IMAGE := $(shell cat IMAGE)
EPOCH := $(shell date +'%s')

ifndef IMAGE
$(error IMAGE file not present in Makefile directory)
endif

.PHONY: build push

build:
	docker build --no-cache . -t "$(IMAGE):$(EPOCH)"
	echo $(EPOCH) > VERSION

push:
	docker push "$(IMAGE):$(shell cat VERSION)"
