# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.
#
# Every target has a BIN_NAME argument that must be provided via --build-arg=BIN_NAME=<name>
# when building.


# ===================================
#
#   Non-release images.
#
# ===================================


# devbuild compiles the binary
# -----------------------------------
FROM golang:latest AS devbuild
ARG BIN_NAME=vault-benchmark
# Escape the GOPATH
WORKDIR /build
COPY . ./
RUN go build -o $BIN_NAME


# dev runs the binary from devbuild
# -----------------------------------
FROM alpine:latest AS dev
ARG BIN_NAME=vault-benchmark
# Export BIN_NAME for the CMD below, it can't see ARGs directly.
ENV BIN_NAME=$BIN_NAME
COPY --from=devbuild /build/$BIN_NAME /bin/
CMD /bin/$BIN_NAME


# ===================================
#
#   Release images.
#
# ===================================


# default release image
# -----------------------------------
FROM alpine:latest AS release-default

ARG BIN_NAME=vault-benchmark
# Export BIN_NAME for the CMD below, it can't see ARGs directly.
ENV BIN_NAME=$BIN_NAME
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=$BIN_NAME
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL maintainer="Team Vault Customer Engineering <team-vault-customer-engineering@hashicorp.com>"
LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION
LABEL org.opencontainers.image.licenses="MPL-2.0"

# Create a non-root user to run the software.
RUN addgroup $PRODUCT_NAME && \
    adduser -S -G $PRODUCT_NAME $PRODUCT_NAME

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/
COPY LICENSE /usr/share/doc/$PRODUCT_NAME/LICENSE.txt

USER $PRODUCT_NAME
CMD ["/bin/vault-benchmark"]
