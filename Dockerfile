FROM docker.mirror.hashicorp.services/alpine:latest as dev

RUN addgroup vault && \
    adduser -S -G vault vault

ADD dist/benchmark-vault /benchmark-vault

USER vault

ENTRYPOINT ["/benchmark-vault"]

# This target creates a production release image for the project.
FROM docker.mirror.hashicorp.services/alpine:latest as default

# PRODUCT_VERSION is the tag built, e.g. v0.1.0
# PRODUCT_REVISION is the git hash built
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=benchmark-vault
ARG TARGETOS TARGETARCH

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Benchmark Vault" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      revision=$PRODUCT_REVISION

# Create a non-root user to run the software.
RUN addgroup vault && \
    adduser -S -G vault vault

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk update && apk upgrade libretls && \
    apk add --no-cache ca-certificates libcap su-exec iputils

COPY dist/benchmark-vault /bin/

USER vault
CMD ["/bin/benchmark-vault"]
