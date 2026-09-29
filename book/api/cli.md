# `firedancer` Command Line Interface
The Firedancer binary `firedancer` contains many subcommands which can
be run from the command line.

Commands that attach to a running validator fall into two groups.
`set-identity`, `get-identity`, and `add-authorized-voter` are
versioned and work across releases. Diagnostic commands like `monitor`,
`watch`, and `metrics` read the validator's memory directly and must be
run from the same binary the validator is running.

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
 - `bonding` Prepares bonded network devices for XDP networking.
 - `ethtool-channels` Configures the number of channels on the network
    device.
 - `ethtool-offloads` Modify offload feature flags on the network device.
 - `ethtool-loopback` Disables UDP segmentation on the loopback device.
 - `irq-affinity` Removes Firedancer tile CPUs from configurable
   `/proc/irq/*/smp_affinity` masks.
 - `irq-balance` Configures the irqbalance daemon to avoid Firedancer
   tile CPUs. If irqbalance is not running, this stage is a no-op.
 - `snapshots` Prepares the snapshot download directory.

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
$ firedancer version
26.09.4
```

## `shred-version`
Prints the current shred version of the cluster being joined, according
to the entrypoints, to standard output and exits. The command writes
diagnostic messages from logs to `stderr`.

```sh [bash]
$ firedancer shred-version
9065
```

## `metrics`
Prints the current validator metrics to stdout.  Metrics can typically
be accessed via HTTP when the `metric` tile is enabled, but the
command can be used even if the metrics server is not enabled, or the
validator has crashed.

```sh [bash]
$ firedancer metrics --config ~/config.toml
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

It is not generally safe to call `set-identity`, as another validator
might be running with the same identity, and if they both produce a
block or vote concurrently, the validator may violate consensus and be
subject to (future) slashing.

The validator will not change identity in the middle of a leader slot,
and will wait until any in-progress leader slot completes before
switching to the new identity. It is safe to call during or near a
leader slot because of this wait.

The command exits successfully (with an exit code of 0) if the identity
key was changed, otherwise it will fail and print diagnostic messages to
`stderr`. Reasons for failure include the validator being unable to open
or load the tower, when `--require-tower` is specified, or being unable
to load or verify the provided identity key.

If more than one validator is running, pass
`--name <name>` to select one (see [`ps`](#ps) to list instances). If
`--config` is given, the validator is instead located from the
configuration file: only the `name` and `[hugetlbfs.mount_path]` values
are used, and they must match the running validator. Compatibility with
the running validator is checked either way, and a version mismatch
fails cleanly without changing anything.

| Arguments         | Description |
|-------------------|-------------|
| `<keypair>`       | Path to a `identity.json` keypair file, or `-` to read the JSON formatted key from `stdin` |
| `--name <name>`   | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>` | Optional path to a configuration TOML file naming the validator to attach to. Only the `name` and `[hugetlbfs.mount_path]` values are used, and they must match the running validator |

<<< @/snippets/commands/set-identity.ansi

## `get-identity`
Prints the base58 encoded identity public key the running validator is
currently using for gossip, voting, and block production. This may
differ from `[paths.identity_key]` in the configuration file if the
identity was changed at runtime with `set-identity`.

Like `set-identity`, the command discovers the running validator
automatically when no `--config` is given.

The command exits successfully (with an exit code of 0) and prints the
key to `stdout` if the identity was retrieved, otherwise it fails and
prints diagnostic messages to `stderr`.

| Arguments         | Description |
|-------------------|-------------|
| `--name <name>`   | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>` | Optional path to a configuration TOML file naming the validator to attach to. Only the `name` and `[hugetlbfs.mount_path]` values are used, and they must match the running validator |

## `add-authorized-voter`
Adds an authorized voter to the running validator. The `<keypair>`
argument is required and must be the path to an Agave style
`voter.json` keypair file. If the path is specified as `-` the key
will instead be read from `stdin`.

With no arguments the command discovers the running validator on the
host automatically. If more than one validator is running, pass
`--name <name>` to select one (see [`ps`](#ps) to list instances). If
`--config` is given, the validator is instead located from the
configuration file: only the `name` and `[hugetlbfs.mount_path]` values
are used, and they must match the running validator. Compatibility with
the running validator is checked either way, and a version mismatch
fails cleanly without changing anything.

It is not generally safe to call `add-authorized-voter`, as another
validator might be running with the same authorized voter and vote
account. If they both vote concurrently, the validator may violate
consensus and be subject to (future) slashing.

It is safe to call the command while the validator is running and voting
as the client guarantees that votes will not be produced with the new
authorized voter key until the key has been gracefully added to the
running validator.

The command exits successfully (with an exit code of 0) if the
authorized voter was added, otherwise it will fail and print diagnostic
messages to `stderr`. Reasons for failure include the validator being
unable to load or verify the provided authorized voter key, if the
provided key is a duplicate that the validator is already using, or if
there are too many authorized voters for the running validator (more
than 16).

| Arguments         | Description |
|-------------------|-------------|
| `<keypair>`       | Path to a `voter.json` keypair file, or `-` to read the JSON formatted key from `stdin` |
| `--name <name>`   | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>` | Optional path to a configuration TOML file naming the validator to attach to. Only the `name` and `[hugetlbfs.mount_path]` values are used, and they must match the running validator |

<<< @/snippets/commands/add-authorized-voter.ansi

## `remove-all-authorized-voters`
Removes all authorized voters from the running validator, including any
seeded from `[paths.authorized_voter_paths]` at startup as well as any
added at runtime with `add-authorized-voter`. After removal the validator
can only sign votes for vote accounts whose authorized voter is the
identity key.

::: warning WARNING

Unlike Agave, this command will still leave the validator in a possibly
voting state and will continue producing signed vote transactions with
the identity of the running validator.

:::

The command is idempotent: removing when there are no authorized voters
also succeeds. It exits successfully (with an exit code of 0) and prints
`All authorized voters removed`.

The change is live only: it is not written back to the configuration
file, so any voters listed in `[paths.authorized_voter_paths]` return on
the validator's next restart. To drop them across restarts, also remove
them from the configuration file.

| Arguments         | Description |
|-------------------|-------------|
| `--name <name>`   | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>` | Optional path to a configuration TOML file naming the validator to attach to. Only the `name` and `[hugetlbfs.mount_path]` values are used, and they must match the running validator |

<<< @/snippets/commands/remove-all-authorized-voters.ansi

## `keys`

### `keys pubkey <PATH>`
Prints the base58 encoding of the public key in the file at `<PATH>` to
the standard output and exits. The file at `<PATH>` should be an Agave
style `identity.json` key file. The command writes diagnostic messages
from logs to `stderr`.

```sh [bash]
$ firedancer keys pubkey ~/.firedancer/fd1/identity.json
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
`firedancer configure` will reserve the memory described here for
exclusive use by Firedancer.

| Arguments | Description |
|----------|-------------|
| `--config` | Path to a configuration TOML file to print memory usage information with |
| `--sort` | List all memory allocations sorted by size in decreasing order, including a percentage of total and exact byte count |

```sh [bash]
$ firedancer mem --config config.toml
── Summary ─────────────────────────────────────────────────────────────────────
  Total Tiles              57
  Total Memory Locked      158 GiB + 915 MiB + 520 KiB  (170611187712 bytes)
  Required Gigantic Pages  154
  Required Huge Pages      2504
  Required Normal Pages    898

── Workspaces (102) ────────────────────────────────────────────────────────────
   ID        SIZE  NAME           PAGES  PAGE SZ   NUMA     FOOTPRINT         LOOSE
    0    36.0 MiB  metric            18  huge         0      35946496       1798144
    1     2.0 MiB  diag               1  huge         0        548864       1544192
[...]

── Objects (609) ───────────────────────────────────────────────────────────────
    ID        SIZE  WORKSPACE      OBJECT         WKSP        OFFSET  PROPERTIES
     0     1.0 MiB  net_gossip     mcache           25          4096  depth=32768
     1    64.0 MiB  net_gossip     dcache           25       1056768  depth=32768 burst=1 mtu=2048
[...]

── Links (120) ─────────────────────────────────────────────────────────────────
   ID        SIZE  NAME           KIND  WKSP     DEPTH        MTU  BURST
    0    64.0 MiB  gossip_net        0    25     32768       2048      1
    1    64.0 MiB  shred_net         0    26     32768       2048      1
[...]

── Tiles (57) ──────────────────────────────────────────────────────────────────
   ID       MLOCK  NAME           KIND  WKSP   CPU  NUMA  LINKS / OBJECTS
    0    34.0 MiB  netlnk            0    89   any     0  in=[-80, -81]  out=[79]  objs=[149:rw 150:rw 151:rw 152:rw 153:rw 154:rw 158:rw 157:ro 164:rw 163:ro 531:rw]
    1     1.3 GiB  net               0    88     1     0  in=[79, -1,  0, -2, -3, -4, -5]  out=[80, 82, 84, 86, 88, 90, 92]  objs=[155:rw 156:rw 157:rw 159:rw 151:ro 152:ro 153:ro 154:ro 160:rw 167:rw 160:rw 169:rw 160:rw 171:rw 160:rw 173:rw 160:rw 175:rw 160:rw 177:rw 160:rw 309:rw 2:ro 3:ro 311:rw 0:ro 1:ro 313:rw 4:ro 5:ro 315:rw 6:ro 7:ro 317:rw 8:ro 9:ro 337:rw 10:ro 11:ro]
[...]
```

## `ps`
Lists validator instances on this host. Each row shows the instance
name, the process ID of the validator supervisor, whether the validator
is currently `live` or `stale`, its uptime, and the version and commit
of the running build.

A `stale` entry means a validator was stopped or crashed. Stale entries
are harmless and are cleaned up when the validator next starts, or can
be removed with `--clean`.

The command exits successfully (with an exit code of 0) even if no
validators are found.

| Arguments | Description |
|-----------|-------------|
| `--clean` | Remove entries for validators that are no longer running |

<<< @/snippets/commands/ps.ansi
