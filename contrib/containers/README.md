# Build Containers

These Dockerfiles can be used to test builds with different compile environments:

- GCC 8 through 16 on Rocky Linux
- Arch Linux
- Alpine Linux
- Ubuntu (22.04, 24.04, 26.04)

```shell
podman build -t gcc:8 -f ./contrib/containers/gcc-8.dockerfile
podman run --rm -v ./:/data/firedancer gcc:8 make -j $(nproc)
```

## SELinux

If SELinux is enabled, run the following command once:

```shell
chcon -R -t container_file_t ./
```
