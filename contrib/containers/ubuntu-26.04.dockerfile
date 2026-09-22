FROM ubuntu:26.04
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /data/firedancer
CMD ["/bin/bash"]
