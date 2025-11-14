FROM rockylinux:8

# Install GCC Toolset 10
RUN yum install -qy gcc-toolset-10 wget git && \
    yum clean all

# Enable GCC Toolset 10 by default
ENV PATH=/opt/rh/gcc-toolset-10/root/usr/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/rh/gcc-toolset-10/root/usr/lib64:${LD_LIBRARY_PATH}

# Download and install pre-built CMake 3.26.5 binary
RUN cd /tmp && \
    wget https://github.com/Kitware/CMake/releases/download/v3.26.5/cmake-3.26.5-linux-x86_64.tar.gz && \
    tar -xzf cmake-3.26.5-linux-x86_64.tar.gz -C /opt && \
    ln -s /opt/cmake-3.26.5-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -s /opt/cmake-3.26.5-linux-x86_64/bin/ctest /usr/local/bin/ctest && \
    ln -s /opt/cmake-3.26.5-linux-x86_64/bin/cpack /usr/local/bin/cpack && \
    rm -f /tmp/cmake-3.26.5-linux-x86_64.tar.gz

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Enable Rust by default
ENV PATH=/root/.cargo/bin:${PATH}
ENV RUSTUP_HOME=/root/.rustup
ENV CARGO_HOME=/root/.cargo

WORKDIR /data/firedancer

CMD ["/bin/bash"]
