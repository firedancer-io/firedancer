# Firedancer GNU/Linux build based on Red Hat Universal Base Image 8.5
#
# Build context is repo root.
#
# Not ready for production use.

# Pin a specific image version rather than "latest" to avoid introducing issues with updates
# UBI8.5
ARG BUILDER_BASE_IMAGE=docker.io/redhat/ubi8@sha256:56c374376a42da40f3aec753c4eab029b5ea162d70cb5f0cda24758780c31d81 # 8.5-236.1647448331
ARG RELEASE_BASE_IMAGE=docker.io/redhat/ubi8@sha256:56c374376a42da40f3aec753c4eab029b5ea162d70cb5f0cda24758780c31d81 # 8.5-236.1647448331

# Set up build container
FROM ${BUILDER_BASE_IMAGE} AS builder

RUN INSTALL_PKGS="git perl autoconf gettext-devel automake flex bison cmake clang protobuf-compiler llvm-toolset lcov hostname patch bzip2" && \
    dnf install -y --setopt=tsflags=nodocs https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && \
    dnf install -y --setopt=tsflags=nodocs $INSTALL_PKGS

# Install Rust
ARG RUST_VERSION=1.73.0
RUN curl "https://sh.rustup.rs" -sfo /tmp/rustup.sh && \
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
    dnf install -y bzip2

COPY --from=builder /firedancer/build/out /opt/firedancer/bin
COPY --from=builder /firedancer/src/app/fdctl/config /opt/firedancer/config
COPY --chmod=555 entrypoint.sh /

ENV FD_LOG_PATH="/opt/firedancer/log"
ENV PATH="/opt/firedancer/bin:$PATH"

ENTRYPOINT [ "/entrypoint.sh" ]
CMD  [ "/bin/bash" ]

LABEL org.opencontainers.image.title="Firedancer (ubi8.5 base)" \
      org.opencontainers.image.url=https://firedancer.io \
      org.opencontainers.image.source=https://github.com/firedancer-io/firedancer \
      org.opencontainers.image.authors="Firedancer Contributors <firedancer-devs@jumptrading.com>"
