# GCC Containers

These dockerfiles can be used to build containers with GCC 8, GCC 9 and GCC 10.

## Build the container

This assumes you are currently in the top directory of the repository.

```bash
podman build -t gcc:8 -f ./contrib/containers/gcc-8.dockerfile
```

## Run the container

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
make -j all fdctl fddev
```
