# [Firedancer](https://jumpcrypto.com/firedancer/) 🔥💃

Firedancer is a new validator client for Solana.

* **Fast** Designed from the ground up to be *fast*. The concurrency
model is borrowed from the low latency trading space, and the code
contains many novel high performance reimplementations of core Solana
primitives.
* **Secure** The architecture of the validator allows it to run almost
completely in user space with a highly restrictive sandbox.
* **Independent** Firedancer is written from scratch. This brings client
diversity to the Solana network and helps it stay resilient to supply
chain attacks in build tooling or dependencies.

## Installation

Firedancer is currently under heavy development and is not ready for
production use. There are no releases available.

## Developing

The [getting started](doc/getting-started.md) guide has detailed system
setup instructions.

```bash
$ git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ ./deps.sh
$ make -j run
```

The `make run` target runs the `fddev dev` command. This development
command will ensure your system is configured correctly before starting
a Solana validator on the local machine. `fddev` will use `sudo` to make
privileged changes to system configuration where needed.

By default `fddev` will create a new chain with a genesis block, along
with any keys needed to start the initial validator. If you wish to join
this cluster with other validators, you can define `[rpc.entrypoints]`
in the configuration file to point at your first validator and run
`fddev dev` again.

## Running

In production, it is recommended to configure the system immediately at
boot time rather than when running Firedancer. This ensures a contiguous
block of memory can be reserved, as it may not be possible when the
machine has been running a long time.

```bash
$ fdctl configure init all
```

`fdctl` reads from an optional `FIREDANCER_CONFIG_TOML` environment
variable to determine all configuration. A complete list of
configuration options and their defaults are provided in
[default.toml](src/app/fdctl/config/default.toml)

Later, when you wish to start the validator, you can run

```bash
$ fdctl run
```

Unlike `fddev`, `fdctl` will not try to gain root to perform
configuration, and will not automatically create required keys or a
genesis block. The `[rpc.entrypoints]` and `[consensus.identity_path]`
configuration options must be defined in order to start the production
validator.

Some of the privileged system configuration steps performed by `fdctl
configure` are,

* **Huge pages** Memory needed for Firedancer must be pre-allocated
before launching it. Firedancer uses `huge` and `gigantic` memory pages,
which are mounted in a local directory. Enabling huge pages and mounting
them to a pseudo filesystem requires root privileges.
* **XDP** Kernel bypass is used for networking, via the eXpress Data
Path. Installing the packet filtering code into the driver requires a
privileged process, and must be done before running Firedancer. You may
also need to configure the network driver to support multiple channels,
which requires root.
* **Sandboxing** Firedancer installs a BPF program to restrict itself
from making certain system calls, and in certain development
environemnts `fdctl` installs network namespaces to simplify network
debugging when using XDP. Performing these initial restrictions can
require additional capabilities.

A good way to see what privileges are needed to configure the
environment is to run `fdctl configure init all` as a non-privileged
user, which will display information about the operations it wishes to
perform.

## License
Firedancer is available under the [Apache 2
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See [LICENSE](LICENSE) for the full license text.
