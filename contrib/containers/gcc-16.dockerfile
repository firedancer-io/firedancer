FROM quay.io/centos/centos:stream10
RUN dnf install -qy gcc-toolset-16 git && \
    dnf clean all
ENV PATH=/opt/rh/gcc-toolset-16/root/usr/bin:${PATH}
WORKDIR /data/firedancer
CMD ["/bin/bash"]
