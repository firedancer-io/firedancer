# Container build

Creates a build container with all build dependencies that will be used for subsequent builds. First build takes slightly longer as it creates the build container.

`fdctl` and `solana` binaries will be generated and exported to `~/build`

## Execution

Just run `./buildit.sh` to build with default options

Supports options for choosing a tag|release|branch and machine type. See `./buildit.sh --help` for usage.

