SHELL := /usr/bin/env bash -euo pipefail -c

REPO_NAME    ?= $(shell basename "$(CURDIR)")
PRODUCT_NAME ?= $(REPO_NAME)
BIN_NAME     ?= $(PRODUCT_NAME)
VERSION      ?= $(shell echo $(CURDIR)/version/VERSION | xargs cat)

# Get local ARCH; on Intel Mac, 'uname -m' returns x86_64 which we turn into amd64.
# Not using 'go env GOOS/GOARCH' here so 'make docker' will work without local Go install.
ARCH     = $(shell A=$$(uname -m); [ $$A = x86_64 ] && A=amd64; echo $$A)
OS       = $(shell uname | tr [[:upper:]] [[:lower:]])
PLATFORM = $(OS)/$(ARCH)
DIST     = dist/$(PLATFORM)
BIN      = $(DIST)/$(BIN_NAME)

# Get latest revision (no dirty check for now).
REVISION = $(shell git rev-parse HEAD)


REGISTRY_NAME?=docker.io/hashicorp
IMAGE_TAG?=$(REGISTRY_NAME)/$(PRODUCT_NAME):$(VERSION)
LATEST_TAG?=$(REGISTRY_NAME)/$(PRODUCT_NAME):latest
BUILD_DIR=dist
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
LDFLAGS?="-X '$(PKG).Version=v$(VERSION)'"

dist:
	mkdir -p $(DIST)
	echo '*' > dist/.gitignore

.PHONY: bin
bin: dist
	CGO_ENABLED=0 GOARCH=$(ARCH) GOOS=$(OS) go build -o $(BIN)

.PHONY: build
build:
	@$(CURDIR)/scripts/crt-build.sh build

.PHONY: image
image:
	CGO_ENABLED=0 GOARCH=$(ARCH) GOOS=linux go build -a -ldflags $(LDFLAGS) -o dist/linux/$(ARCH)/$(BIN_NAME) .
	docker build --platform linux/$(ARCH) --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) -t $(LATEST_TAG) .

.PHONY: clean
clean:
	-rm -rf $(BUILD_DIR)

.PHONY: test
test: unit-test

unit-test:
	go test -race ./...

.PHONY: mod
mod:
	@go mod tidy

.PHONY: fmt
fmt:
	gofmt -w $(GOFMT_FILES)
