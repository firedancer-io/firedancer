# Getting Started

## Installing

### Prerequisites

Firedancer must be built from source and requires the following,

 - A linux kernel version 5.7 or higher, or with support for
   `BPF_OBJ_PIN`.
 - GCC version 8.3 or higher.
 - [rustup](https://rustup.rs/)
 - clang, git, and make

::: tip NOTE

Firedancer currently builds the [Solana
Labs](https://docs.solana.com/running-validator/validator-reqs)
validator as a dependency, which requires a full Rust toolchain. Once
Firedancer is able to stand alone, this will no longer be required.

:::

Other dependencies of the Firedancer build can be installed with a
convenience script. First, clone the source code with:

```sh [bash]
$ git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
$ cd firedancer
```

Then you can run the `deps.sh` script to install system packages and
compile library dependencies. System packages will be installed via. the
package manager on your system, while library dependencies will be
compiled and output placed under `./opt`.

```sh [bash]
$ FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh check install
```

## Building
Once dependencies are installed, you can build Firedancer. Because
Firedancer depends on the Solana Labs validator, this will also build
some Solana components.

```sh [bash]
$ make -j fdctl solana
```

::: tip TIP

The Firedancer production validator is built as a single binary `fdctl`
short for Firedancer control. You can start, stop, and monitor the
Firedancer instance from this one program. The `solana` CLI binary can
be built with make as well for convenience so you can run RPC commands like
`solana transfer`.

:::

Firedancer automatically detects the hardware it is being built on and
enables architecture specific instructions if possible. This means
binaries built on one machine may not be able to run on another.

If you wish to target a lower machine architecture you can compile for a
specific target by setting the `MACHINE` envrionment variable to one of
the targets under `config/`.

```sh [bash]
$ MACHINE=linux_gcc_x86_64 make -j fdctl solana
```

The default target is `native`, and compiled binaries will be placed in
`./build/native/gcc/bin`.

## Running

### Configuration

Firedancer has many configuration options which are [discussed
later](/guide/configuring.md). For now, we override only the essential
options needed to start the validator on Testnet.

```toml [bash]
# /home/firedancer/config.toml
user = "firedancer"

[gossip]
    entrypoints = [
      "entrypoint.testnet.solana.com:8001",
      "entrypoint2.testnet.solana.com:8001",
      "entrypoint3.testnet.solana.com:8001",
    ]

[consensus]
    identity_path = "/home/firedancer/validator-keypair.json"
    vote_account_path = "/home/firedancer/vote-keypair.json"

    known_validators = [
        "5D1fNXzvv5NjV1ysLjirC4WY92RNsVH18vjmcszZd8on",
        "dDzy5SR3AXdYWVqbDEkVFdvSPCtS9ihF5kJkHCtXoFs",
        "Ft5fbkqNa76vnsjYNwjDZUXoTWpP7VYm3mtsaQckQADN",
        "eoKpUABi59aT4rR9HGS3LcMecfut9x7zJyodWWP43YQ",
        "9QxCLckBiJc783jnMvXZubK4wH86Eqqvashtrwvcsgkv",
    ]

[layout]
    affinity = "0-9"

    net_tile_count = 2
    verify_tile_count = 2
```

This configuration will cause Firedancer to run as the user `firedancer`
on the local machine. The `identity_path` and `vote_account_path` should
be Solana Labs style keys, which can be generated with the Solana Labs
CLI.

::: tip NOTE

This will put the ledger in `/home/firedancer/.firedancer/fd1/ledger`.
To customize this path, refer to the [configuration guide](/guide/configuring.md#ledger).

:::

### Initialization

The validator uses some Linux features that must be enabled and
configured before it can be started correctly. It is possible for
advanced operators to do this configuration manually, but `fdctl`
provides a command to check and automate this step.

::: warning WARNING

Running any `fdctl configure` command may make permanent changes to your
system. You should be careful before running these commands on a
production host.

:::

The initialization steps are desribed [in detail](/guide/initializing.md)
later. But plowing ahead at the moment:

```sh [bash]
$ sudo ./build/native/gcc/bin/fdctl configure init all --config ~/config.toml
```

You will be told what steps are performed:

<<< @/snippets/configure.ansi

It is strongly suggested to run the `configure` command when the system
boots, and it needs to be run each time before the validator is restarted.

::: tip NOTE

The configuration file is used when performing system configuration. If
the configuration file changes, you will need to rerun the `configure`
command.

:::

### Running

Finally, we can run Firedancer:

```sh [bash]
$ sudo ./build/native/gcc/bin/fdctl run --config ~/config.toml
```

Firedancer logs selected output to `stderr` and a more detailed log to a
local file.

### Permissions

Many `fdctl` commands require elevated privileges, including
initializing and running the validator. This is because of high
performance features it uses like kernel bypass networking.

It is recommended that you run these commands as `sudo` although in some
cases it is possible to run with capabilities instead. You can see what
capabilities are needed and why by running the command unprivileged.

```sh [bash]
$ ./build/native/gcc/bin/fdctl run
```

<<< @/snippets/capabilities.ansi

Although the run command requires privileges to start the validator it
does not keep them for long. Firedancer will immediately drop all
privileges once it has booted.
