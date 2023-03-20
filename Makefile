REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=vault-benchmark
VERSION?=0.0.0-dev
IMAGE_TAG?=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
LATEST_TAG?=$(REGISTRY_NAME)/$(IMAGE_NAME):latest
BUILD_DIR=dist
BIN_NAME=$(IMAGE_NAME)
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
XC_PUBLISH?=
LDFLAGS?="-X '$(PKG).Version=v$(VERSION)'"

.PHONY: all test build image clean version
all: bin

bin:
	CGO_ENABLED=0 go build \
		-a \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.

image:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -a \
        -ldflags $(LDFLAGS) \
        -o $(BUILD_DIR)/$(BIN_NAME) \
        .
	docker build --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) -t $(LATEST_TAG) .

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
