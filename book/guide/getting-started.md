# Getting Started

## Frankendancer
This guide details building and running the Frankendancer validator
which is a hybrid of Firedancer and Agave code running side by side.
Frankendancer replaces the Agave networking stack and block production
components to perform better while leader.  It is not yet possible
to run a full Firedancer validator, which is in heavy development.

## Hardware Requirements

Because Firedancer currently depends on the Agave validator, the
hardware requirements are at least [what's
recommended](https://docs.anza.xyz/operations/requirements)
for that validator. Firedancer hopes to reduce these over time.

**Minimum**

- 24-Core AMD or Intel CPU @ >2.8GHz
- 256GB RAM
- 2TB PCI Gen3 NVME SSD (High TBW)

**Recommended**

- 32-Core CPU @ >3GHz with AVX512 support
- 512GB RAM with ECC memory
- Same capacity with separate disks for Accounts and Ledger
- 1 Gigabit/s Network Bandwidth

Validator operators also refer to https://solanahcl.org/ which
has a lot of useful information about hardware.

## Installing

### Prerequisites

Firedancer must be built from source and currently only supports
building and running on Linux. Firedancer requires a recent Linux
kernel, at least v4.18. This corresponds to Ubuntu 20.04, Fedora 29,
Debian 11, or RHEL 8.

 - GCC version 8.5 or higher. Only GCC version 11, 12, and 13 are
supported and tested by the Firedancer developers.
 - [rustup](https://rustup.rs/)
 - clang, git, and make

::: tip NOTE

Firedancer currently builds the
[Agave](https://docs.solana.com/running-validator/validator-reqs)
validator as a dependency, which requires a full Rust toolchain. Once
Firedancer is able to stand alone, this will no longer be required.

:::

Other dependencies of the Firedancer build can be installed with a
convenience script. First, clone the source code with:

```sh [bash]
$ git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ git checkout __FD_LATEST_VERSION__ # Or the latest Frankendancer release
```

Then you can run the `deps.sh` script to install system packages and
compile library dependencies. System packages will be installed via. the
package manager on your system, while library dependencies will be
compiled and output placed under `./opt`.

```sh [bash]
$ ./deps.sh
```

## Releases
Firedancer does not produce pre-built binaries and you must build from
source, but Firedancer releases are made available as tags. The
following naming convention is used,

 * `main` This should not be used. The main branch is bleeding edge and
includes all Firedancer development and changes that could break
Frankendancer.
 * `v0.xxx.yyyyy` Official Frankendancer releases.

The Frankendancer versioning has three components,

* Major version is always `0`. The first full Firedancer release will be
`1.x`
* Minor version increments by 100 for each new Frankendancer release.
The minor version will then increment by 1 for new minor versions within
this release.
* The patch number encodes the Agave validator version. An Agave version
of `v1.17.14` is represented as `11714`.

```
================= main branch =================
   \                             \
    \ v0.100.11814                \ v0.200.11901
     \                             \
      \ v0.100.11815                \ v0.201.11902
       \
        \ v0.101.11815
```

## Building
Once dependencies are installed, you can build Firedancer. Because
Firedancer depends on the Agave validator, this will also build some
Agave components.

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
enables architecture specific instructions for maximum performance if
possible. This means binaries built on one machine may not be able to
run on another.

If you wish to target a lower machine architecture you can compile for a
specific target by setting the `MACHINE` environment variable to one of
the targets under `config/`.

```sh [bash]
$ MACHINE=linux_gcc_x86_64 make -j fdctl solana
```

The default target is `native`, and compiled binaries will be placed in
`./build/native/gcc/bin`.

## Updating
If you checked out Firedancer using Git, run through these steps to
check out a newer version, update dependencies, and rebuild binaries.

```sh [bash]
git fetch --tags
git checkout __FD_LATEST_VERSION__
git submodule update
make -j fdctl solana
```

## Running

### Configuration

Firedancer has many configuration options which are [discussed
later](/guide/configuring.md). For now, we override only the essential
options needed to start the validator on Testnet.

::: code-group

```toml [config.toml]
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

[rpc]
    port = 8899
    full_api = true
    private = true

[reporting]
    solana_metrics_config = "host=https://metrics.solana.com:8086,db=tds,u=testnet_write,p=c4fa841aa918bf8274e3e2a44d77568d9861b3ea"
```

:::

This configuration will cause Firedancer to run as the user `firedancer`
on the local machine. The `identity_path` and `vote_account_path` should
be Agave style keys, which can be generated using the [`fdctl keys`.
subcommand](../api/cli.md#keys-new-path). The `vote_account_path` can
also be the public key of an existing vote account.

This will put the ledger in `/home/firedancer/.firedancer/fd1/ledger`.
To customize this path, refer to the [configuration
guide](/guide/configuring.md#ledger).

::: tip LEDGER

The Firedancer blockstore in the ledger directory is compatible with the
one for the Agave validator, and it is possible to switch between
validator clients while keeping the `ledger` directory in place.

:::

Additionally, this configuration enables the full RPC API at port 8899.
Although the port will not be published to other validators in gossip,
use a firewall to restrict access to this port for maximum security.

The Firedancer client can report diagnostic metrics similar to an Agave
client. It is recommended to set the `[reporting.solana_metrics_config]`
in the config file to the appropriate value for the cluster. The options
for the different clusters are listed in the `default.toml` file in the
[`reporting`](https://github.com/firedancer-io/firedancer/blob/main/src/app/fdctl/config/default.toml#L144)
section.

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
   privileged initialization. This is given by the `user` option in your
   configuration TOML file. Firedancer requires nothing from this user
   and it should be as minimally permissioned as possible. It should
   never be `root` or another superuser, and the user should not be
   present in the sudoers file or have any other privileges.

Only the `fdctl run` and `monitor` commands will switch to the
non-privileged user, and other commands will run as the startup user
until they complete. Most commands can be started with capabilities
rather than as the `root` user, although this isn't recommended. If you
are an advanced operator, you can see which capabilities are required for
a command by running it unprivileged:

<<< @/snippets/capabilities.ansi

For additional layers of defense against local privilege escalation, it
is not suggested to `setcap(8)` the `fdctl` binary as this can create a
larger attack surface.

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
boots, and it needs to be run each time the system is rebooted.

### Running

Finally, we can run Firedancer:

```sh [bash]
$ sudo ./build/native/gcc/bin/fdctl run --config ~/config.toml
```

Firedancer logs selected output to `stderr` and a more detailed log to a
local file.  Every tile in Firedancer runs in a separate process for
security isolation, so you will see a complete process tree get launched.

```sh [bash]
$ pstree 1741904 -as
systemd --switched-root --system --deserialize 17
  └─sudo ./build/native/gcc/bin/fdctl run --config ~/config.toml
      └─fdctl run --config ~/config.toml
          └─fdctl run --config ~/config.toml
              ├─fdctl run-agave --config-fd 0
              │   └─35*[{fdctl}]
              ├─cswtch:0 run1 cswtch 0 --pipe-fd 20 --config-fd 0
              ├─dedup:0 run1 dedup 0 --pipe-fd 15 --config-fd 0
              ├─gui:0 run1 gui 0 --pipe-fd 22 --config-fd 0
              ├─metric:0 run1 metric 0 --pipe-fd 19 --config-fd 0
              ├─net:0 run1 net 0 --pipe-fd 7 --config-fd 0
              ├─pack:0 run1 pack 0 --pipe-fd 16 --config-fd 0
              ├─plugin:0 run1 plugin 0 --pipe-fd 21 --config-fd 0
              ├─quic:0 run1 quic 0 --pipe-fd 8 --config-fd 0
              ├─shred:0 run1 shred 0 --pipe-fd 17 --config-fd 0
              ├─sign:0 run1 sign 0 --pipe-fd 18 --config-fd 0
              ├─verify:0 run1 verify 0 --pipe-fd 9 --config-fd 0
              ├─verify:1 run1 verify 1 --pipe-fd 10 --config-fd 0
              ├─verify:2 run1 verify 2 --pipe-fd 11 --config-fd 0
              ├─verify:3 run1 verify 3 --pipe-fd 12 --config-fd 0
              ├─verify:4 run1 verify 4 --pipe-fd 13 --config-fd 0
              └─verify:5 run1 verify 5 --pipe-fd 14 --config-fd 0
```

If any of the processes dies or is killed it will bring all of the
others down with it.

### Networking
Firedancer uses `AF_XDP`, a Linux API for high performance networking. For
more background see the [kernel
documentation](https://www.kernel.org/doc/html/next/networking/af_xdp.html).

Although `AF_XDP` works with any ethernet network interface, results may
vary across drivers. Popular well tested drivers include:

- `ixgbe` &mdash; Intel X540
- `i40e` &mdash; Intel X710 series
- `ice` &mdash; Intel E800 series

Firedancer installs an XDP program on the network interface
`[net.interface]` and `lo` while it is running. This program redirects
traffic on ports that Firedancer is listening on via `AF_XDP`.
Traffic targeting any other applications (e.g. an SSH or HTTP server
running on the system) passes through as usual. The XDP program is
unloaded when the Firedancer process exits.

`AF_XDP` requires `CAP_SYS_ADMIN` and `CAP_NET_RAW` privileges. This is
one of the reasons why Firedancer requires root permissions on Linux.

::: warning

Packets received and sent via `AF_XDP` will not appear under standard
network monitoring tools like `tcpdump`.

:::
