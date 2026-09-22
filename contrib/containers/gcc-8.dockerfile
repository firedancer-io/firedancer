FROM rockylinux:8
RUN yum groupinstall -qy "Development Tools" && \
    yum install -qy git && \
    yum clean all
WORKDIR /data/firedancer
CMD ["/bin/bash"]
