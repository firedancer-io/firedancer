# Firedancer GNU/Linux build based on Red Hat Universal Base Image 9
#
# Build context is repo root.
#
# Not ready for production use.

# FIXME Drop permissions
# FIXME multi-arch support

ARG BUILDER_BASE_IMAGE=registry.access.redhat.com/ubi9/ubi:9.2-755
ARG RELEASE_BASE_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal:9.2-755

# Set up build container

FROM ${BUILDER_BASE_IMAGE} AS builder

# Install Rustup
RUN curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Fetch and build source dependencies

WORKDIR /firedancer
COPY deps.sh ./
RUN FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh check install

# Build source tree

COPY . ./
RUN make -j all rust --output-sync=target

# Set up release container

FROM ${RELEASE_BASE_IMAGE} AS release

COPY --from=builder /firedancer/build/linux/gcc/x86_64/bin /opt/firedancer/bin
ENV FD_LOG_PATH=""
ENV PATH="/opt/firedancer/bin:$PATH"

LABEL org.opencontainers.image.title="Firedancer beta (ubi9 base)" \
      org.opencontainers.image.url=https://firedancer.io \
      org.opencontainers.image.source=https://github.com/firedancer-io/firedancer \
      org.opencontainers.image.authors="Firedancer Contributors <firedancer-devs@jumptrading.com>"
