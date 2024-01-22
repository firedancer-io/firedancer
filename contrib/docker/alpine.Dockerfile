# Firedancer GNU/Linux build based on Alpine 3
#
# Build context is repo root.
#
# This image is not recommended for production use,
# and is purely provided for compatibility testing.
#
# Currently known to be broken due to missing ucontext API.

# FIXME Drop permissions
# FIXME multi-arch support

ARG BUILDER_BASE_IMAGE=alpine:3.18.4
ARG RELEASE_BASE_IMAGE=alpine:3.18.4

# Set up build container

FROM ${BUILDER_BASE_IMAGE} AS builder

# Install Rustup
RUN curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Fetch and build source dependencies

RUN apk add bash
WORKDIR /firedancer
COPY deps.sh ./
RUN FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh check install

# Build source tree

COPY . ./
RUN make -j all rust --output-sync=target

# Set up release container

FROM ${RELEASE_BASE_IMAGE} AS release

COPY --from=builder /firedancer/build/native/gcc/bin /opt/firedancer/bin
ENV FD_LOG_PATH=""
ENV PATH="/opt/firedancer/bin:$PATH"

LABEL org.opencontainers.image.title="Firedancer beta (Alpine 3 base)" \
      org.opencontainers.image.url=https://firedancer.io \
      org.opencontainers.image.source=https://github.com/firedancer-io/firedancer \
      org.opencontainers.image.authors="Firedancer Contributors <firedancer-devs@jumptrading.com>"
