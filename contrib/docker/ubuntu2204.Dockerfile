# Firedancer GNU/Linux build based on Ubuntu 22.04
#
# Build context is repo root.
#
# This image is not recommended for production use,
# and is purely provided for compatibility testing.

ARG BUILDER_BASE_IMAGE=ubuntu:22.04
ARG RELEASE_BASE_IMAGE=ubuntu:22.04

# Set up build container

FROM ${BUILDER_BASE_IMAGE} AS builder
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      git \
      make \
      pkgconf \
      perl \
      autoconf \
      automake \
      autopoint \
      flex \
      bison \
      clang \
      llvm \
      lcov \
      gettext

# Fetch and build source dependencies

WORKDIR /firedancer
COPY deps.sh ./
RUN FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh check install

# Build source tree

COPY . ./
RUN make -j all --output-sync=target

# Set up release container

FROM ${RELEASE_BASE_IMAGE} AS release

COPY --from=builder /firedancer/build/native/gcc/bin /opt/firedancer/bin
ENV FD_LOG_PATH=""
ENV PATH="/opt/firedancer/bin:$PATH"

LABEL org.opencontainers.image.title="Firedancer beta (Ubuntu 22.04 base)" \
      org.opencontainers.image.url=https://firedancer.io \
      org.opencontainers.image.source=https://github.com/firedancer-io/firedancer \
      org.opencontainers.image.authors="Firedancer Contributors <firedancer-devs@jumptrading.com>"
