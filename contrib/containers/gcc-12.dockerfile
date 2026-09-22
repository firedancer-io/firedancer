FROM rockylinux:9
RUN dnf install -qy gcc-toolset-12 git which && \
    dnf clean all
ENV PATH=/root/.cargo/bin:/opt/rh/gcc-toolset-12/root/usr/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/rh/gcc-toolset-12/root/usr/lib64:${LD_LIBRARY_PATH}
WORKDIR /data/firedancer
CMD ["/bin/bash"]
