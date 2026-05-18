FROM archlinux:latest

# Install required packages
RUN pacman -Syu --noconfirm && \
    pacman -S --needed --noconfirm \
      base-devel \
      curl \
      zstd \
      cmake \
      clang \
      perl \
      protobuf \
      systemd-libs \
      git \
      wget && \
    pacman -Scc --noconfirm

WORKDIR /data/firedancer

CMD ["/bin/bash"]