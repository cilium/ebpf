# Makefile to build and push the `cilium/ebpf` llvm builder Docker image.
IMAGE := $(shell cat IMAGE)
VERSION := $(shell cat VERSION)

ifndef IMAGE
$(error IMAGE file not present in Makefile directory)
endif
ifndef VERSION
$(error VERSION file not present in Makefile directory)
endif

DATE := $(shell date +'%d%m%Y')
TAG := ${VERSION}-${DATE}

.PHONY: build push

build:
	docker build -f Dockerfile . \
		-t ${IMAGE}:${TAG} \
		-t ${IMAGE}:${VERSION}

push:
	docker push	${IMAGE}:${TAG}
	docker push ${IMAGE}:${VERSION}
