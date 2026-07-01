# GCC Containers

These dockerfiles can be used to build containers with GCC 8, GCC 9, GCC 10 and GCC 12.

## Build the container

This assumes you are currently in the top directory of the repository.

```bash
podman build -t gcc:8 -f ./contrib/containers/gcc-8.dockerfile
```

## Run the container

Check if SELinux is enabled:
```bash
# SELinux status check
getenforce

# Enforcing - SELinux is enabled and enforcing policies
# Permissive - SELinux is enabled but only logging violations
# Disabled - SELinux is completely disabled
```

If SELinux is enabled, run the following command once:

```bash
chcon -R -t container_file_t ./
```

When running the container, mount the top directory of the repository at `/data/firedancer`:

```bash
podman run -ti -v ./:/data/firedancer gcc:8 bash
```

## Build the binaries

When building with different compilers, you should cleanup any existing files.

> [!WARNING]
> Since we mount the files from the host, this cleanup, even though running inside
> the container, will cleanup the files on the host as well. If you want to avoid
> that, make a fresh clone of the repository on the host and mount that directory
> while running the container.

```bash
./deps.sh nuke && make -j distclean
```

Install and compile the dependencies:

```bash
FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev fetch check install
```

Compile desired targets:

```bash
make -j
```

## GCC 12 AVX512 build example

On machines with AVX512 support, build the GCC 12 Rocky 8 image:

```bash
podman build -t firedancer-gcc12:rocky8 -f contrib/containers/gcc-12.dockerfile .
```

Run the container and build with the Ice Lake GCC machine config:

```bash
podman run --rm -v "$PWD:/data/firedancer" firedancer-gcc12:rocky8 bash -lc '
set -e
cd /data/firedancer
FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev fetch check install
source "$HOME/.cargo/env"
MACHINE=linux_gcc_icelake CC=gcc CXX=g++ make -j fddev fdctl
'
```

Exiting / Cleanup

```bash
# Leave the container
exit

# List of containers
podman ps -a

# Remove the container if necessary
podman rm <container_id> # Image - localhost/gcc:8
```
