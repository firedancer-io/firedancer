# Getting Started

## Hardware Requirements

Because Firedancer currently depends on the Solana Labs validator, the
hardware requirements are at least [what's
recommended](https://docs.solana.com/running-validator/validator-reqs)
for that validator. Firedancer hopes to reduce these over time.

**Minimum**

- 12-Core CPU @ >2.5GHz
- 64GB RAM
- 512GB SSD

**Recommended**

- 32-Core CPU @ >3GHz with AVX512 support
- 128GB RAM with ECC Memory
- 1TB NVMe SSD with separate disk for OS
- 1 Gigabit/s Network Bandwidth

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

You will need around 32GiB of available memory to build Firedancer.  If
you run out of memory compiling, make can return a variety of errors.

::: tip TIP

The Firedancer production validator is built as a single binary `fdctl`
short for Firedancer control. You can start, stop, and monitor the
Firedancer instance from this one program. The `solana` CLI binary can
be built with make as well for convenience so you can run RPC commands
like `solana transfer`.

:::

Firedancer automatically detects the hardware it is being built on and
enables architecture specific instructions if possible. This means
binaries built on one machine may not be able to run on another.

If you wish to target a lower machine architecture you can compile for a
specific target by setting the `MACHINE` environment variable to one of
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
uid  = 1000
gid  = 1000

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
```

This configuration will cause Firedancer to run as the user `firedancer`
on the local machine. This assumes the `uid` and `gid` of the `firedancer`
user on the machine is `1000` and `1000` respectively. The `identity_path`
and `vote_account_path` should be Solana Labs style keys, which can be
generated with the Solana Labs CLI. Currently, `testnet` is the only live
cluster that Firedancer can be run against and trying to start against
`devnet` or `mainnet-beta` entrypoints will result in an error.

::: tip NOTE

This will put the ledger in `/home/firedancer/.firedancer/fd1/ledger`.
To customize this path, refer to the [configuration
guide](/guide/configuring.md#ledger).

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

The initialization steps are described [in detail](/guide/initializing.md)
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
local file.  Every tile in Firedancer runs in a separate process for
security isolation, so you will see a complete process tree get launched.

```sh [bash]
$ pstree 1741904 -a -s
systemd --switched-root --system --deserialize 17
  └─fdctl
      └─fdctl
          └─fdctl run-solana --config-fd 0
          │   └─957*[{fdctl}]
          ├─fdctl run1 net 1 --pipe-fd 8 --config-fd 0
          ├─fdctl run1 net 0 --pipe-fd 7 --config-fd 0
          ├─fdctl run1 netmux 0 --pipe-fd 11 --config-fd 0
          ├─fdctl run1 quic 0 --pipe-fd 12 --config-fd 0
          ├─fdctl run1 quic 1 --pipe-fd 13 --config-fd 0
          ├─fdctl run1 verify 0 --pipe-fd 16 --config-fd 0
          ├─fdctl run1 verify 1 --pipe-fd 17 --config-fd 0
          ├─fdctl run1 dedup 0 --pipe-fd 20 --config-fd 0
          ├─fdctl run1 pack 0 --pipe-fd 21 --config-fd 0
          └─fdctl run1 shred 0 --pipe-fd 22 --config-fd 0
```

If any of the processes dies or is killed, it will bring all of the
others down with it.

### Permissions

There are two users involved in running Firedancer. The user that you
launch `fdctl` with, and the user Firedancer switches to after it has
started. The requirements for these users are very different:

 - The user Firedancer starts as is not specified in configuration, but
   is simply the user that launches the process. For most commands,
   including `fdctl run` and `configure` it needs to be `root` or have
   various capabilities described below to setup kernel bypass
   networking. It is recommended to simply use the `root` user when
   launching.

 - The user Firedancer switches to after it has booted up and performed
   privileged initialization. This is given by the `uid` and `gid` options
   in your configuration TOML file (which should correspond to the `user`).
   Firedancer requires nothing from this user and it should be as minimally
   permissioned as possible. It should never be `root` or another superuser,
   and the user should not be present in the sudoers file or have any other
   privileges.

Only the `fdctl run` and `monitor` commands will switch to the
non-privileged user, and other commands will run as the startup user
until they complete. Most commands can be started with capabilities
rather than as the `root` user, although this isn't recommended. If you
are an advanced operator, you can see which capabilities are required for
a command by running it unprivileged:

```sh [bash]
$ ./build/native/gcc/bin/fdctl run
```

<<< @/snippets/capabilities.ansi

For additional layers of defense against local privilege escalation, it
is not suggested to `setcap(8)` the `fdctl` binary as this can create a
larger attack surface.
