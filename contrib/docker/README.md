# Container configs

Provides dockerfiles and docker-compose configs for various platforms.

## Provides for two methods of use

### Using compose file

#### cd into the directory of choice and execute the following: 

`docker-compose|podman-compose up -d`

This will build the container, if necessary, and kick off a run with fddev. One stop shopping!

#### To stop the run, from the same directory:

`docker-compose|podman-compose down`

### Using dockerfile

You can build the container using the Dockerfile and run however you wish.

#### To build, cd into directory and:

`docker|podman build . -t firedancer:latest -t firedancer:0.1`

#### to run: 

`docker|podman run -it -d --rm --net=host --name=firedancer --privileged --ipc=host --volume /data/firedancer:/home/firedancer/.firedancer:Z firedancer:latest fddev --config /opt/firedancer/config/default.toml dev --monitor`

## Notes

At this time the container **MUST** be run as root, either directly or via `sudo`, to provide the necessary capabilities.

Can build off a specific release, tag, or branch. Default is *main*. Edit compose-file or pass `docker build . --build-arg=GITTAG=<somevalue>`

Machine type defaults to *linux_gcc_x86_64*. This can be overridden in the compose file or with `--build-arg=MACHINE=<somevalue>`. See *config/machine* for available machine types.


