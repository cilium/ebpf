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

build: ## Build and tag the Docker image in REPO with VERSION.
	docker build -f "${DIR}/Dockerfile.builder" "${DIR}" \
		-t ${REPO}:${TAG} \
		-t ${REPO}:${VERSION}

push: ## Push the Docker image to the repo specified in REPO.
	docker push	${REPO}:${TAG}
	docker push ${REPO}:${VERSION}

help: ## Display this help.
	@grep -E '^[a-zA-Z_-]+:.*## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build push help
.DEFAULT_GOAL := help
