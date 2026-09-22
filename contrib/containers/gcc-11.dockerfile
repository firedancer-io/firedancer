FROM rockylinux:9
RUN dnf groupinstall -qy "Development Tools" && \
    dnf install -qy git && \
    dnf clean all
WORKDIR /data/firedancer
CMD ["/bin/bash"]
