# [Firedancer](https://jumpcrypto.com/firedancer/) 🔥💃

Firedancer is a new validator client for Solana.

* **Fast** Designed from the ground up to be *fast*. The concurrency
model is borrowed from the low latency trading space, and the code
contains many novel high performance reimplementations of core Solana
primitives.
* **Secure** The architecture of the validator allows it to run with a
highly restrictive sandbox and almost no system calls.
* **Independent** Firedancer is written from scratch. This brings client
diversity to the Solana network and helps it stay resilient to supply
chain attacks in build tooling or dependencies.

## Frankendancer 👹💃

Firedancer is a new Solana validator with a new codebase, but it is
being developed incrementally. To enable testing and deployment before
the entire Solana protocol has been implemented we rely on the existing
Solana Labs validator code to provide functionality that is missing.
This side-by-side configuration is referred to as "frankendancer".

This means building and running a Firedancer validator currently also
builds a Solana Labs validator, and runs it as a child process. For now
Firedancer has implemented the transaction networking layer, signature
verification, deduplication, and packing code. All other functionality,
including RPC, transaction execution, remains part of Solana Labs.

## Installation

Firedancer is currently under heavy development and is not ready for
production use. There are no releases available.

## Developing

The below describes building Frankendancer from scratch and running it
optimized on a stock Linux image. You will need basic development tools
like `make`, `gcc` along with `rustc`, and `clang`.

Frankendancer currently only supports Linux, and requires a kernel newer
than v5.7 to build.

```bash
$ sudo dnf groupinstall development
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then you can clone and build the application from source,

```bash
$ git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ ./deps.sh
$ make -j run
```

The `make run` target runs the `fddev dev` command. This development
command will ensure your system is configured correctly before creating
a genesis block, some keys, a faucet, and then starting a validator on
the local machine. `fddev` will use `sudo` to make privileged changes to
system configuration where needed. If `sudo` is not available, you may
need to run the command as root.

By default `fddev` will create a new development cluster, if you wish to
join this cluster with other validators, you can define
`[rpc.entrypoints]` in the configuration file to point at your first
validator and run `fddev dev` again.

## Running

In production, it is recommended to configure the system immediately at
boot time rather than when running Firedancer. This ensures a contiguous
block of memory can be reserved, as it may not be possible when the
machine has been running a long time.

```bash
$ make -j fdctl
$ ./build/native/gcc/bin/fdctl configure init all
```

`fdctl` reads from an optional `FIREDANCER_CONFIG_TOML` environment
variable or `--config` argument to determine all configuration. A
complete list of options and their defaults are provided in
[default.toml](src/app/fdctl/config/default.toml). When providing a
configuration file, it only needs to override the options that you
wish to change from the default. For example, to set the user gossip
port,

```toml
user = "firedancer"
[gossip]
  port = 9010
```

Because Frankendancer relies on the Solana Labs validator for some
functionality, most of the options you might need for running Solana
Labs are present in the Frankendancer configuration file and will be
passed through. RPC commands should continue to work using the existing
`solana` binary, which is built in the `solana/target` directory as part
of `make`.

Later, when you wish to start the validator, you can run

```bash
$ ./build/native/gcc/bin/fdctl run
```

Unlike `fddev`, `fdctl` will not try to gain root to perform
configuration, and will not automatically create keys or a genesis. The
`[rpc.entrypoints]` and `[consensus.identity_path]` configuration
options must be defined in order to start the production validator.

Some of the privileged system configuration steps performed by `fdctl
configure` are,

* **Huge pages** Memory needed for Firedancer must be pre-allocated
before launching it. Firedancer uses `huge` and `gigantic` memory pages,
which are mounted in a local directory. Enabling huge pages and mounting
them to a pseudo filesystem requires root privileges.
* **XDP** Kernel bypass is used for networking, via the eXpress Data
Path. Installing the packet filtering code into the kernel requires a
privileged process, and must be done before running Firedancer.
Firedancer will also set the network driver to use multiple channels to
enable receive side scaling, which requires root.
* **Kernel parameters** Because Frankendancer runs side-by-side with
the Solana Labs validator, which requires certain kernel parameters to
be tuned (`net/core/rmem_max`, `vm/max_map_count`, ...) `fdctl` will
automatically configure these.
* **Sandboxing** Firedancer installs a BPF program to restrict itself
from making certain system calls, and in certain development
environemnts `fdctl` installs network namespaces to simplify network
debugging when using XDP. Performing these initial restrictions can
require additional capabilities.

A good way to see what privileges are needed to configure the
environment is to run `fdctl configure init all` as a non-privileged
user, which will display information about the operations it wishes to
perform.

Firedancer must be started as `root` or with `CAP_NET_RAW` and
`CAP_SYS_ADMIN` capabilities so that it can initialize `XDP` in the
validator process and bind to a raw socket. Once those steps have been
done at startup, Firedancer will drop all privileges, enable a highly
restrictive sandbox, and switch to the user provided in the
configuration file.

## License
Firedancer is available under the [Apache 2
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See [LICENSE](LICENSE) for the full license text.
