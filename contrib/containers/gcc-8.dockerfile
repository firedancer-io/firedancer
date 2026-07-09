FROM rockylinux:8

# Install GCC 8 and development tools (Rocky Linux 8 ships with GCC 8.5.0 by default)
RUN yum groupinstall -qy "Development Tools" && \
    yum install -qy wget git && \
    yum clean all

# Download and install pre-built CMake 3.26.5 binary
RUN cd /tmp && \
    wget https://github.com/Kitware/CMake/releases/download/v3.26.5/cmake-3.26.5-linux-x86_64.tar.gz && \
    tar -xzf cmake-3.26.5-linux-x86_64.tar.gz -C /opt && \
    ln -s /opt/cmake-3.26.5-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -s /opt/cmake-3.26.5-linux-x86_64/bin/ctest /usr/local/bin/ctest && \
    ln -s /opt/cmake-3.26.5-linux-x86_64/bin/cpack /usr/local/bin/cpack && \
    rm -f /tmp/cmake-3.26.5-linux-x86_64.tar.gz

WORKDIR /data/firedancer

CMD ["/bin/bash"]
