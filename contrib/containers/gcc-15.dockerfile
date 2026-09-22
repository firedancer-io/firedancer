FROM rockylinux:10
RUN dnf install -qy gcc-toolset-15 git && \
    dnf clean all
ENV PATH=/opt/rh/gcc-toolset-15/root/usr/bin:${PATH}
WORKDIR /data/firedancer
CMD ["/bin/bash"]
