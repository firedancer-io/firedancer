FROM rockylinux:9
RUN dnf install -qy gcc-toolset-13 git && \
    dnf clean all
ENV PATH=/opt/rh/gcc-toolset-13/root/usr/bin:${PATH}
WORKDIR /data/firedancer
CMD ["/bin/bash"]
