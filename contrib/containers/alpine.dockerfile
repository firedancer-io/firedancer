FROM alpine:latest
RUN apk add --no-cache \
    build-base \
    clang \
    git \
    linux-headers
WORKDIR /data/firedancer
ENV CC=clang
CMD ["/bin/bash"]
