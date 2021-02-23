# Makefile to build and push the `cilium/ebpf` llvm builder Docker image.
DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

REPO := $(shell cat ${DIR}/REPO)
VERSION := $(shell cat ${DIR}/VERSION)

ifndef REPO
$(error REPO file not present in Makefile directory)
endif
ifndef VERSION
$(error VERSION file not present in Makefile directory)
endif

DATE := $(shell date +'%d%m%Y')
TAG := ${VERSION}-${DATE}

.PHONY: build push

build:
	docker build -f "${DIR}/Dockerfile" "${DIR}" \
		-t ${REPO}:${TAG} \
		-t ${REPO}:${VERSION}

push:
	docker push	${REPO}:${TAG}
	docker push ${REPO}:${VERSION}
