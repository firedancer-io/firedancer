# Container build

Creates a build container with all build dependencies that will be used for subsequent builds. First build takes slightly longer as it creates the build container.

`fdctl` and `solana` binaries will be generated and exported to `~/build/out`

## Execution

Just run `./buildit.sh`

Can optionally pass a tag, branch, or release to buildit.sh as `./buildit.sh somebranch`
