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

.PHONY: all test build image clean version
all: build

dist:
	mkdir -p $(DIST)
	echo '*' > dist/.gitignore

.PHONY: bin
bin: dist
	GOARCH=$(ARCH) GOOS=$(OS) go build -o $(BIN)

build:
	@$(CURDIR)/scripts/crt-build.sh build

image:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o dist/linux/amd64/$(BIN_NAME)
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) -t $(LATEST_TAG) .

clean:
	-rm -rf $(BUILD_DIR)

test: unit-test

unit-test:
	go test -race ./...

.PHONY: mod
mod:
	@go mod tidy

fmt:
	gofmt -w $(GOFMT_FILES)