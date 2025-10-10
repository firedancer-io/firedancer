# `fdctl` Command Line Interface
The Firedancer binary `fdctl` contains many subcommands which can be run
from the command line.

## `run`
Runs the validator. This command does not exit until the validator does,
an error in running the validator will be propagated to the exit code of
the process. The command can be run with the capabilities listed below
but it is suggested to run it as `sudo`. The command writes an
abbreviated log output to `stderr` and nothing will be written to
`stdout`.

| Arguments         | Description |
|-------------------|-------------|
| `--config <path>` | Path to a configuration TOML file to run the validator with |

::: details Capabilities

| Capability             | Reason |
|------------------------|--------|
| `CAP_NET_RAW`          | call `socket(2)` to bind to a raw socket for use by XDP |
| `CAP_SYS_ADMIN`        | call `bpf(2)` with the `BPF_OBJ_GET` command to initialize XDP |
| `CAP_SYS_ADMIN`        | call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace. Only required on kernels which restrict unprivileged user namespaces |
| `CAP_SETUID`           | call `setresuid(2)` to switch uid to the sandbox user. Not required if the UID is already the same as the sandbox UID |
| `CAP_SETGID`           | call `setresgid(2)` to switch gid to the sandbox user. Not required if the GID is already the same as the sandbox GID |
| `CAP_SYS_RESOURCE`     | call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`. Not required if the process already has a high enough limit |
| `CAP_SYS_RESOURCE`     | call `setpriority(2)` to increase thread priorities. Not required if the process already has a nice value of -19 |
| `CAP_SYS_RESOURCE`     | call `rlimit(2)  to increase `RLIMIT_NOFILE` to allow more open files for Agave. Not required if the resource limit is already high enough |
| `CAP_NET_BIND_SERVICE` | call `bind(2)` to bind to a privileged port for serving metrics. Only required if the bind port is below 1024 |

:::

<<< @/snippets/commands/run.ansi

## `monitor`
Monitors a validator that is running locally on this machine. This is a
low level performance monitor mostly useful for diagnosing throughput
issues. The monitor takes over the controlling terminal and refreshes it
many times a second with up to date information. You can exit the
monitor by sending Ctrl+C or `SIGINT`.

| Arguments         | Description |
|-------------------|-------------|
| `--config <path>` | Path to a configuration TOML file to run the monitor with. This must be the same configuration file the validator was started with |

::: details Capabilities

| Capability | Reason |
|------------|--------|
| `CAP_SYS_ADMIN` | call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace. Only required on kernels which restrict unprivileged user namespaces |
| `CAP_SETUID` | call `setresuid(2)` to switch uid to the sandbox user. Not required if the UID is already the same as the sandbox UID |
| `CAP_SETGID` | call `setresgid(2)` to switch gid to the sandbox user. Not required if the GID is already the same as the sandbox GID |
| `CAP_SYS_RESOURCE` | call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`. Not required if the process already has a high enough limit |

:::

<<< @/snippets/commands/monitor.ansi

## `configure`
Configures the operating system so that it can run Firedancer. See
[the guide](/guide/initializing) for more information. There are the
following stages to each configure command:

 - `hugetlbfs` Reserves huge and gigantic pages for use by Firedancer
    and mounts huge page filesystems for then under a path in the
    configuration TOML file.
 - `sysctl` Set required kernel parameters.
 - `hyperthreads` Disables hyperthreaded pair for critical CPU cores.
 - `ethtool-channels` Configures the number of channels on the network
    device.
 - `ethtool-offloads` Disables generic receive offload (GRO) and GRE
    segmentation offload on the network device.
 - `ethtool-loopback` Disables UDP segmentation on the loopback device.
 - `irq-affinity` Removes CPU cores used by Firedancer from IRQ handler
    CPU affinities where possible.

| Arguments         | Description |
|-------------------|-------------|
| `--config <path>` | Path to a configuration TOML file to configure the validator with. This must be the same configuration file the validator will be started with |

::: code-group

```toml [config.toml]
[hugetlbfs]
    mount_path = "/mnt/.fd"
[layout]
    net_tile_count = 2
[tiles]
    [net]
        interface = "ens3f0"
```

:::

### `configure init <stage>...`
Prepare the operating system environment to run Firedancer. This will
reserve and mount the huge page filesystems, set the kernel parameters,
and configure the number of combined channels on the network device.

::: details Capabilities

| Capability      | Reason |
|-----------------|--------|
| `root`          | increase `/proc/sys/vm/nr_hugepages` and mount hugetlbfs filesystems. Only applies for the `hugetlbfs` stage |
| `root`          | increase network device channels with `ethtool --set-channels`. Only applies for the `ethtool-channels` stage |
| `root`          | disable network device offloads with `ethtool --offload IFACE FEATURE off`. Only applies for the `ethtool-offloads` stage |
| `root`          | disable network device tx-udp-segmentation with `ethtool --offload lo tx-udp-segmentation off`. Only applies for the `ethtool-loopback` stage |
| `CAP_SYS_ADMIN` | set kernel parameters in `/proc/sys`. Only applies for the `sysctl` stage |
| `root`          | write `/proc/irq/N/smp_affinity` files and check irqbalance ban list. Only applies for the `irq-affinity` stage |

:::

<<< @/snippets/commands/configure-init.ansi

### `configure check <stage>...`
Check if the operating system environment is properly configured.
Exits with a non-zero exit code if it is not, after printing relevant
diagnostics to `stderr`.

<<< @/snippets/commands/configure-check.ansi

### `configure fini <stage>...`
Remove any Firedancer specific operating system configuration still
lingering. This only unmounts the `hugetlbfs` stages and returns the
reserved huge and gigantic pages to the kernel pool. It will not reduce
sysctls that were earlier increased, or change the network channel count
back as we no longer know what the original value was.

::: details Capabilities

| Capability | Reason |
|------------|--------|
| `root`     | remove directories from `/mnt`, unmount hugetlbfs. Only applies for the `hugetlbfs` stage |

:::

<<< @/snippets/commands/configure-fini.ansi

## `version`
Prints the current version of the validator to the standard output and
exits. The command writes diagnostic messages from logs to `stderr`.

```sh [bash]
$ fdctl version
0.101.11814
```

## `shred-version`
Prints the current shred version of the cluster being joined, according
to the entrypoints, to standard output and exits. The command writes
diagnostic messages from logs to `stderr`.

```sh [bash]
$ fdctl shred-version
9065
```

## `metrics`
Prints the current validator metrics to stdout.  Metrics can typically
be accessed via. HTTP when the `metric` tile is enabled,  but the
command can be used even if the metrics server is not enabled, or the
validator has crashed.

```sh [bash]
$ fdctl metrics --config ~/config.toml
# HELP tile_pid The process ID of the tile.
# TYPE tile_pid gauge
tile_pid{kind="netlnk",kind_id="0"} 627750
tile_pid{kind="net",kind_id="0"} 627759
```

## `set-identity`
Changes the identity key of a running validator. The `<keypair>`
argument is required and must be the path to an Agave style
`identity.json` keypair file. If the path is specified as `-` the key
will instead be read from `stdin`.

::: warning WARNING

`set-identity` must be called with the configuration file you started
the validator with, like `fdctl set-identity --config <config.toml>`,
if the `config` argument is not provided, the command may not update
the key on all tiles and your validator may start skipping slots.

:::

It is not generally safe to call `set-identity`, as another validator
might be running with the same identity, and if they both produce a
block or vote concurrently, the validator may violate consensus and be
subject to (future) slashing.

Best practice requires copying the `tower.bin` file from the prior
to the new validator, to ensure that vote lockouts are respected.

The validator will not change identity in the middle of a leader slot,
and will wait until any in-progress leader slot completes before
switching to the new identity. It is safe to call during or near a
leader slot because of this wait.

The command exits successfully (with an exit code of 0) if the identity
key was changed, otherwise it will fail and print diagnostic messages to
`stderr`. Reasons for failure include the validator being unable to open
or load the tower, when `--require-tower` is specified, or being unable
to load or verify the provided identity key.

Currently due to implementation limitations, the key can be partially
changed if the `set-identity` command is cancelled (for example with
Ctrl+C) while running. The next call to `set-identity` might need to
provide the `--force` argument to succeed if this occurs, to reset this
partial state and proceed with setting a new key.

| Arguments         | Description |
|-------------------|-------------|
| `<keypair>`       | Path to a `identity.json` keypair file, or `-` to read the JSON formatted key from `stdin` |
| `--config <path>` | Path to a configuration TOML file of the validator to change identity for. This must be the same configuration file the validator was started with |
| `--require-tower` | If specified, refuse to set the validator identity if saved tower state is not found |
| `--force`         | If a `set-identity` operation is abandoned part way through, you will need to specify `--force` to reset the validator key state when trying again |

<<< @/snippets/commands/set-identity.ansi

## `keys`

### `keys pubkey <PATH>`
Prints the base58 encoding of the public key in the file at `<PATH>` to
the standard output and exits. The file at `<PATH>` should be an Agave
style `identity.json` key file. The command writes diagnostic messages
from logs to `stderr`.

```sh [bash]
$ fdctl keys pubkey ~/.firedancer/fd1/identity.json
Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF
```

### `keys new <PATH>`
Creates a new keypair from the kernel random number generator and writes
it to the file specified at `<PATH>`. The default user for the operation
is the user running the command and should have write access to `<PATH>`.
The user can be changed by specifying it in the TOML configuration file.

| Arguments  | Description |
|------------|-------------|
| `--config` | Path to a configuration TOML file which determines the user creating the file.

::: code-group

```toml [config.toml]
user = "firedancer"
```

:::

<<< @/snippets/commands/keys-new.ansi

## `mem`
Prints information about the memory requirements and the tile
configuration and layout of the validator to `stdout` before
exiting. The command writes diagnostic messages from logs to `stderr`.

Firedancer preallocates and locks all memory it needs from huge and
gigantic page mounts before booting, and the `hugetlbfs` stage of
`fdctl configure` will reserve the memory described here for exclusive
use by Firedancer.

| Arguments | Description |
|----------|-------------|
| `--config` | Path to a configuration TOML file to print memory usage information with |

```sh [bash]
$ fdctl mem --config config.toml
SUMMARY
              Total Tiles: 17
      Total Memory Locked: 27088932864 bytes (25 GiB + 234 MiB + 20 KiB)
  Required Gigantic Pages: 25
      Required Huge Pages: 117
    Required Normal Pages: 27
  Required Gigantic Pages (NUMA node 0): 25
      Required Huge Pages (NUMA node 0): 117

WORKSPACES
   0 (  1 GiB):     net_quic  page_cnt=1  page_sz=gigantic  numa_idx=0   footprint=68173824    loose=1005563904
   1 (  1 GiB):    net_shred  page_cnt=1  page_sz=gigantic  numa_idx=0   footprint=68173824    loose=1005563904
[...]

LINKS
   0 ( 32 MiB):     net_quic  kind_id=0   wksp_id=0   depth=16384  mtu=2048       burst=1
   1 ( 32 MiB):    net_shred  kind_id=0   wksp_id=1   depth=16384  mtu=2048       burst=1
[...]

TILES
   0 (  3 GiB):          net  kind_id=0   wksp_id=18  cpu_idx=1   out_link=-1  in=[-2, -3]  out=[ 0,  1]
   1 (  3 GiB):         quic  kind_id=0   wksp_id=19  cpu_idx=2   out_link=4   in=[ 0, -21]  out=[ 2, 20]
[...]
```
