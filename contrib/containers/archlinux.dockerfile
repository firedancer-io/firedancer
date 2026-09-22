FROM archlinux:latest
RUN pacman -Syu --noconfirm && \
    pacman -S --needed --noconfirm \
      base-devel \
      git && \
    pacman -Scc --noconfirm
WORKDIR /data/firedancer
CMD ["/bin/bash"]
