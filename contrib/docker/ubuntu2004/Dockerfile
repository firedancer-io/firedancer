# Firedancer GNU/Linux build based on Ubuntu 20.04
#
# Build context is repo root.
#
# Not ready for production use.

# Pin a specific image version rather than "latest" to avoid introducing issues with updates
# Ubuntu 20.04
ARG BUILDER_BASE_IMAGE=ubuntu@sha256:a4fab1802f08df089c4b2e0a1c8f1a06f573bd1775687d07fef4076d3a2e4900 # 20.04 2024-01-23T13:01:04.825078387Z
ARG RELEASE_BASE_IMAGE=ubuntu@sha256:a4fab1802f08df089c4b2e0a1c8f1a06f573bd1775687d07fef4076d3a2e4900 # 20.04 2024-01-23T13:01:04.825078387Z

# Set up build container
FROM ${BUILDER_BASE_IMAGE} AS builder

RUN INSTALL_PKGS="git curl autoconf gettext automake autopoint flex bison build-essential gcc-multilib protobuf-compiler llvm lcov clang ca-certificates" && \
    apt update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${INSTALL_PKGS}

# Install Rust
ARG RUST_VERSION=1.73.0
RUN /usr/bin/curl "https://sh.rustup.rs" -sfo /tmp/rustup.sh && \
    sh /tmp/rustup.sh -y --default-toolchain ${RUST_VERSION}

ENV PATH="/root/.cargo/bin:${PATH}"

# Fetch and build source dependencies
ENV WORKDIR=/firedancer
WORKDIR ${WORKDIR}

# Default can be overridden on commandline or in docker-compose file
ARG MACHINE=linux_gcc_x86_64
ARG GITTAG
RUN git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git ${WORKDIR} && \
	[ -n ${GITTAG} ] && git checkout ${GITTAG} && \
	./deps.sh install && \
	MACHINE=${MACHINE} make -j all rust --output-sync=target && \
	cp -a $(find build -type d -name bin) build/out

# Set up release container
FROM ${RELEASE_BASE_IMAGE} AS release

RUN useradd firedancer && \
    apt update && \
    apt install -y bzip2

COPY --from=builder /firedancer/build/out /opt/firedancer/bin
COPY --from=builder /firedancer/src/app/fdctl/config /opt/firedancer/config
COPY --chmod=555 entrypoint.sh /

ENV FD_LOG_PATH="/opt/firedancer/log"
ENV PATH="/opt/firedancer/bin:$PATH"

ENTRYPOINT [ "/entrypoint.sh" ]
CMD  [ "/bin/bash" ]

LABEL org.opencontainers.image.title="Firedancer (Ubuntu 20.04 base)" \
      org.opencontainers.image.url=https://firedancer.io \
      org.opencontainers.image.source=https://github.com/firedancer-io/firedancer \
      org.opencontainers.image.authors="Firedancer Contributors <firedancer-devs@jumptrading.com>"
