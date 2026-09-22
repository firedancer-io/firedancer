FROM rockylinux:8
RUN yum install -qy gcc-toolset-10 git && \
    yum clean all
ENV PATH=/opt/rh/gcc-toolset-10/root/usr/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/rh/gcc-toolset-10/root/usr/lib64:${LD_LIBRARY_PATH}
WORKDIR /data/firedancer
CMD ["/bin/bash"]
