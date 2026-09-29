# Getting Started

## Firedancer
This guide details building and running the Firedancer validator.

## Hardware Requirements

**Minimum**

- 24-Core AMD or Intel CPU @ >2.8GHz
- 256GB RAM
- 2TB PCI Gen3 NVME SSD (High TBW)

**Recommended**

- 32-Core CPU @ >3GHz with AVX512 support
- 512GB RAM with ECC memory
- 1 Gigabit/s Network Bandwidth

Validator operators also refer to https://solanahcl.org/ which
has a lot of useful information about hardware.

## Installing

### Prerequisites

Firedancer must be built from source and currently only supports
building and running on Linux. Firedancer requires a recent Linux
kernel, at least v4.18. This corresponds to Ubuntu 20.04, Fedora 29,
Debian 11, or RHEL 8.

 - GCC version 8.5 or higher
 - `make`

First, clone the source code with:

```sh [bash]
$ git clone https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ git checkout __FD_LATEST_VERSION__ # Or the latest Frankendancer release
```

Then you can run the `deps.sh` script to install system packages.
These will be installed via the package manager on your system.

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
 * `vYY.MM.PATCH` Full Firedancer releases.
 * `v0.xxx.yyyyy` Legacy Frankendancer releases.

Firedancer versioning has three components,

 * The major (year) and minor (month) versions identify the release line.
   A new release line starts every month, containing new features and
   performance improvements.
 * Patch versions contain bug fixes.

```
================= main branch =================
   \                         \
    \ v26.08.0                \ v26.09.0
     \                         \
      \ v26.08.1                \ v26.09.1
       \
        \ v26.08.2
```

## Building
Once dependencies are installed, you can build Firedancer.

```sh [bash]
$ make -j firedancer
```

You will need around 32GiB of available memory to build Firedancer.  If
you run out of memory compiling, make can return a variety of errors.

::: tip TIP

The Firedancer production validator is built as a single binary
`firedancer`. You can start, stop, and monitor the Firedancer instance
from this one program.

:::

Firedancer automatically detects the hardware it is being built on and
enables architecture specific instructions for maximum performance if
possible. This means binaries built on one machine may not be able to
run on another.

If you wish to target a lower machine architecture you can compile for a
specific target by setting the `MACHINE` environment variable to one of
the targets under `config/`.

```sh [bash]
$ MACHINE=linux_gcc_x86_64 make -j firedancer
```

The default target is `native`, and compiled binaries will be placed in
`./build/native/gcc/<compiler-version>/bin`, with a hardlink to each at
`./build/<name>`.

## Updating
If you checked out Firedancer using Git, run through these steps to
check out a newer version, update dependencies, and rebuild binaries.

```sh [bash]
git fetch --tags
git checkout __FD_LATEST_VERSION__
make -j firedancer
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
on the local machine. The `identity_key` and `vote_account` should
be Agave style keys, which can be generated using the [`firedancer keys`
subcommand](../api/cli.md#keys-new-path). The `vote_account` can also be
the public key of an existing vote account.

Additionally, this configuration enables the full RPC API at port 8899.
Although the port will not be published to other validators in gossip,
use a firewall to restrict access to this port for maximum security.

The Firedancer client reports metrics via a Prometheus listening at
`http://127.0.0.1:7999/metrics`.

### Permissions

There are two users involved in running Firedancer. The user that you
launch `firedancer` with, and the user Firedancer switches to after it
has started. The requirements for these users are very different:

 - The user Firedancer starts as is not specified in configuration, but
   is simply the user that launches the process. For most commands,
   including `firedancer run` and `configure` it needs to be `root` or
   have various capabilities described below to setup kernel bypass
   networking. It is recommended to simply use the `root` user when
   launching.

 - The user Firedancer switches to after it has booted up and performed
   privileged initialization. This is given by the `user` option in your
   configuration TOML file. Firedancer requires nothing from this user
   and it should be as minimally permissioned as possible. It should
   never be `root` or another superuser, and the user should not be
   present in the sudoers file or have any other privileges.

Only the `firedancer run` and `monitor` commands will switch to the
non-privileged user, and other commands will run as the startup user
until they complete. Most commands can be started with capabilities
rather than as the `root` user, although this isn't recommended. If you
are an advanced operator, you can see which capabilities are required for
a command by running it unprivileged:

<<< @/snippets/capabilities.ansi

For additional layers of defense against local privilege escalation, it
is not suggested to `setcap(8)` the `firedancer` binary as this can
create a larger attack surface.

### Initialization

The validator uses some Linux features that must be enabled and
configured before it can be started correctly. It is possible for
advanced operators to do this configuration manually, but `firedancer`
provides a command to check and automate this step.

::: warning WARNING

Running any `firedancer configure` command may make permanent changes to
your system. You should be careful before running these commands on a
production host.

:::

The initialization steps are described [in detail](/guide/initializing.md)
later. But plowing ahead at the moment:

```sh [bash]
$ sudo ./build/firedancer configure init all --config ~/config.toml
```

You will be told what steps are performed:

<<< @/snippets/configure.ansi

It is strongly suggested to run the `configure` command when the system
boots, and it needs to be run each time the system is rebooted.

### Running

Finally, we can run Firedancer:

```sh [bash]
$ sudo ./build/firedancer run --config ~/config.toml
```

Firedancer logs selected output to `stderr` and a more detailed log to a
local file.  Every tile in Firedancer runs in a separate process for
security isolation, so you will see a complete process tree get launched.

```sh [bash]
$ pstree 111819 -as
systemd --switched-root --system --deserialize=51
  └─sudo ./build/firedancer run --config ~/config.toml
      └─firedancer run --config ~/config.toml
          └─firedancer run --config ~/config.toml
              ├─accdb:0 run1 accdb 0 --pipe-fd 31 --config-fd 0
              ├─admin:0 run1 admin 0 --pipe-fd 9 --config-fd 0
              ├─dedup:0 run1 dedup 0 --pipe-fd 51 --config-fd 0
              ├─diag:0 run1 diag 0 --pipe-fd 7 --config-fd 0
              ├─event:0 run1 event 0 --pipe-fd 60 --config-fd 0
              ├─execle:0 run1 execle 0 --pipe-fd 54 --config-fd 0
              ├─execle:1 run1 execle 1 --pipe-fd 55 --config-fd 0
              ├─execrp:0 run1 execrp 0 --pipe-fd 32 --config-fd 0
              ├─execrp:1 run1 execrp 1 --pipe-fd 33 --config-fd 0
              ├─execrp:2 run1 execrp 2 --pipe-fd 34 --config-fd 0
              ├─execrp:3 run1 execrp 3 --pipe-fd 35 --config-fd 0
              ├─execrp:4 run1 execrp 4 --pipe-fd 36 --config-fd 0
              ├─execrp:5 run1 execrp 5 --pipe-fd 37 --config-fd 0
              ├─execrp:6 run1 execrp 6 --pipe-fd 38 --config-fd 0
              ├─execrp:7 run1 execrp 7 --pipe-fd 39 --config-fd 0
              ├─execrp:8 run1 execrp 8 --pipe-fd 40 --config-fd 0
              ├─execrp:9 run1 execrp 9 --pipe-fd 41 --config-fd 0
              ├─gossip:0 run1 gossip 0 --pipe-fd 26 --config-fd 0
              ├─gossvf:0 run1 gossvf 0 --pipe-fd 24 --config-fd 0
              ├─gossvf:1 run1 gossvf 1 --pipe-fd 25 --config-fd 0
              ├─gui:0 run1 gui 0 --pipe-fd 61 --config-fd 0
              ├─ipecho:0 run1 ipecho 0 --pipe-fd 8 --config-fd 0
              ├─metric:0 run1 metric 0 --pipe-fd 6 --config-fd 0
              ├─net:0 run1 net 0 --pipe-fd 11 --config-fd 0
              ├─net:1 run1 net 1 --pipe-fd 12 --config-fd 0
              ├─netlnk:0 run1 netlnk 0 --pipe-fd 5 --config-fd 0
              ├─pack:0 run1 pack 0 --pipe-fd 53 --config-fd 0
              ├─poh:0 run1 poh 0 --pipe-fd 56 --config-fd 0
              ├─quic:0 run1 quic 0 --pipe-fd 44 --config-fd 0
              ├─repair:0 run1 repair 0 --pipe-fd 28 --config-fd 0
              ├─replay:0 run1 replay 0 --pipe-fd 30 --config-fd 0
              ├─resolv:0 run1 resolv 0 --pipe-fd 52 --config-fd 0
              ├─rpc:0 run1 rpc 0 --pipe-fd 59 --config-fd 0
              ├─rserve:0 run1 rserve 0 --pipe-fd 29 --config-fd 0
              ├─shred:0 run1 shred 0 --pipe-fd 27 --config-fd 0
              ├─sign:0 run1 sign 0 --pipe-fd 57 --config-fd 0
              ├─sign:1 run1 sign 1 --pipe-fd 58 --config-fd 0
              ├─tower:0 run1 tower 0 --pipe-fd 42 --config-fd 0
              ├─txsend:0 run1 txsend 0 --pipe-fd 43 --config-fd 0
              ├─verify:0 run1 verify 0 --pipe-fd 45 --config-fd 0
              ├─verify:1 run1 verify 1 --pipe-fd 46 --config-fd 0
              ├─verify:2 run1 verify 2 --pipe-fd 47 --config-fd 0
              ├─verify:3 run1 verify 3 --pipe-fd 48 --config-fd 0
              ├─verify:4 run1 verify 4 --pipe-fd 49 --config-fd 0
              ├─verify:5 run1 verify 5 --pipe-fd 50 --config-fd 0
              └─waker:0 run1 waker 0 --pipe-fd 10 --config-fd 0
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
