# Container build

Creates a build container with all build dependencies that will be used for subsequent builds. First build takes slightly longer as it creates the build container.

`fdctl`, `fddev`, and `solana` binaries will be generated and exported to `~/build`

## Execution

Just run `./buildit.sh` to build with default options

Supports options for choosing a tag|release|branch, platform, and machine type. See `./buildit.sh --help` for usage.

## Notes
* Only use `rhel8` if on a RedHat Linux host. The subscription-manager (rhsm) within the ubi image piggybacks off the container host's licenses.
* If you would like to build *bug for bug compatible* binaries for rhel, but aren't on a RedHat host, try the `rocky8` platform.
