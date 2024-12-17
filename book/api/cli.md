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

| Arguments | Description |
|----------|-------------|
| `--config` | Path to a configuration TOML file to run the validator with |

::: details Capabilities

| Capability | Reason |
|------------|--------|
| `CAP_NET_RAW` | call `socket(2)` to bind to a raw socket for use by XDP |
| `CAP_SYS_ADMIN` | call `bpf(2)` with the `BPF_OBJ_GET` command to initialize XDP |
| `CAP_SYS_ADMIN` | call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace. Only required on kernels which restrict unprivileged user namespaces |
| `CAP_SETUID` | call `setresuid(2)` to switch uid to the sandbox user. Not required if the UID is already the same as the sandbox UID |
| `CAP_SETGID` | call `setresgid(2)` to switch gid to the sandbox user. Not required if the GID is already the same as the sandbox GID |
| `CAP_SYS_RESOURCE` | call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`. Not required if the process already has a high enough limit |
| `CAP_SYS_RESOURCE` | call `setpriority(2)` to increase thread priorities. Not required if the process already has a nice value of -19 |
| `CAP_SYS_RESOURCE` | call `rlimit(2)  to increase `RLIMIT_NOFILE` to allow more open files for Agave. Not required if the resource limit is already high enough |
| `CAP_NET_BIND_SERVICE` | call `bind(2)` to bind to a privileged port for serving metrics. Only required if the bind port is below 1024 |

:::

<<< @/snippets/commands/run.ansi

## `monitor`
Monitors a validator that is running locally on this machine. This is a
low level performance monitor mostly useful for diagnosing throughput
issues. The monitor takes over the controlling terminal and refreshes it
many times a second with up to date information. You can exit the
monitor by sending Ctrl+C or `SIGINT`.

| Arguments | Description |
|----------|-------------|
| `--config` | Path to a configuration TOML file to run the monitor with. This must be the same configuration file the validator was started with |

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
[the guide](/guide/initializing) for more information. There are three
possible stages to each configure command:

 - `hugetlbfs` Reserves huge and gigantic pages for use by Firedancer
    and mounts huge page filesystems for then under a path in the
    configuration TOML file.
 - `sysctl` Set required kernel parameters.
 - `ethtool-channels` Configures the number of channels on the network
    device.
 - `ethtool-gro` Disables generic receive offload (GRO) on the network
    device.

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

| Capability | Reason |
|------------|--------|
| `root` | increase `/proc/sys/vm/nr_hugepages` and mount hugetlbfs filesystems. Only applies for the `hugetlbfs` stage |
| `root` | increase network device channels with `ethtool --set-channels`. Only applies for the `ethtool-channels` stage |
| `root` | disable network device generic-receive-offload (gro) with `ethtool --set-offload generic-receive-offload off`. Only applies for the `ethtool-gro` stage |
| `CAP_SYS_ADMIN` | set kernel parameters in `/proc/sys`. Only applies for the `sysctl` stage |

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
| `root` | remove directories from `/mnt`, unmount hugetlbfs. Only applies for the `hugetlbfs` stage |

:::

<<< @/snippets/commands/configure-fini.ansi

## `version`
Prints the current version of the validator to the standard output and
exits. The command writes diagnostic messages from logs to `stderr`.

```sh [bash]
$ fdctl version
0.101.11814
```

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

### `keys new <identity|vote>`
Creates a new keypair from the kernel random number generator and writes
it to the identity key path, or vote key path. The key path is retrieved
from the configuration TOML file

| Arguments | Description |
|----------|-------------|
| `--config` | Path to a configuration TOML file which determines where the key is written. Either `[consensus.identity_path]` or `[consensus.vote_account_path]` for `identity` or `vote` arguments respectively

::: code-group

```toml [config.toml]
[consensus]
    identity_path = "/home/{user}/.fd/keys/identity.json"
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
