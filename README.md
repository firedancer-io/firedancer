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
$ git clone https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ ./deps.sh
$ make -j run
```

Firedancer uses several privileged operating system features to improve
performance and security. These can be configured manually in your
environment, but we also provide a tool for automatic configuration.

The default `make run` target will ensure your system is configured
correctly before running Firedancer, using `sudo` to make privileged
changes where necessary.

## Running

In production, it is recommended to configure the system immediately at
boot time rather than when running Firedancer. This ensures we can
allocate the contiguous memory we need, as over time memory may become
fragmented.

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
