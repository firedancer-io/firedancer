# `firedancer` Command Line Interface
The Firedancer binary `firedancer` contains many subcommands which can
be run from the command line. `firedancer` also supports subcommands
from the `fdctl` binary.

Commands that attach to a running validator fall into two groups.
`set-identity`, `get-identity`, and `add-authorized-voter` are
versioned and work across releases. Diagnostic commands like `monitor`,
`watch`, and `metrics` read the validator's memory directly and must be
run from the same binary the validator is running.

## `configure`
The Firedancer binary supports the `configure` command documented in the
[`fdctl` command reference](/api/cli.md#configure), and adds
Firedancer-only configure stages for the full client:

 - `irq-affinity` Removes Firedancer tile CPUs from configurable
   `/proc/irq/*/smp_affinity` masks.
 - `irq-balance` Configures the irqbalance daemon to avoid Firedancer
   tile CPUs. If irqbalance is not running, this stage is a no-op.
 - `snapshots` Prepares the snapshot download directory.

## `set-identity`
The Firedancer binary supports the `set-identity` command documented in
[`fdctl` command reference](/api/cli.md#set-identity), but removes
configuration options `require-tower` and `force`, and adds
`--vote-history-file`.

Unlike `fdctl`, the `firedancer` binary does not require the `--config`
argument: with no arguments the command discovers the running validator
on the host automatically. If more than one validator is running, pass
`--name <name>` to select one (see [`ps`](#ps) to list instances). If
`--config` is given, the validator is instead located from the
configuration file: only the `name` and `[hugetlbfs.mount_path]` values
are used, and they must match the running validator. Compatibility with
the running validator is checked either way, and a version mismatch
fails cleanly without changing anything. `--vote-history-file` can be
passed alongside a tower file produced by Agave or Firedancer (e.g.
`tower-1_9-<pubkey>.bin`). The file will be restored and lockouts
will be preserved as described in the file. If the file is invalid, the
command will fail and the identity of the running validator will not
be changed. When Alpenglow is enabled, pass a vote history file
produced by Agave or Firedancer (e.g. `vote_history-<pubkey>.bin`, at
most 32,688 bytes) instead, and the validator will not vote until the
leader window after the highest slot the previous validator voted in.

If `[tiles.tower.write_vote_history_file]` is enabled, votes are saved
to `tower-1_9-<identity>.bin` in the `[paths.vote_history]` directory
(by default the base directory). With Alpenglow,
`[tiles.votor.write_vote_history_file]` instead saves the votes cast
since the root to `vote_history-<identity>.bin` in the same directory,
and a vote history larger than 32,688 bytes empties the file until it
fits again. The file is only read by `--vote-history-file`, never when
Firedancer boots.
After `set-identity`, the file is renamed to the new identity
when that identity first votes, so the old identity's last vote keeps
its name until then. If a file with the new name already exists, for
example the file passed to `--vote-history-file`, it is not replaced
but renamed with an `.old` suffix.

| Arguments                    | Description |
|------------------------------|-------------|
| `<keypair>`                  | Path to a `identity.json` keypair file, or `-` to read the JSON formatted key from `stdin` |
| `--name <name>`              | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>`            | Optional path to a configuration TOML file naming the validator to attach to. Only the `name` and `[hugetlbfs.mount_path]` values are used, and they must match the running validator |
| `--vote-history-file <path>` | Optional path to the tower file, or the vote history file when Alpenglow is enabled, saved by the validator previously running with the new identity |

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

::: warning WARNING

`add-authorized-voter` is only supported with `firedancer` and not
`fdctl`. In other words, the command is only supported while running the
full client validator and not Frankendancer.

:::

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

::: warning WARNING

`remove-all-authorized-voters` is only supported with `firedancer` and
not `fdctl`. In other words, the command is only supported while running
the full client validator and not Frankendancer.

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

## `wait`
Waits for a window where it would be safe to stop the running
validator before exiting, it does not actually stop the validator.
Various conditions can be waited on, according to the supplied
arguments:

 - The validator is caught up to the tip of the chain
 - There is sufficient time until our next leader slot
 - No full or incremental snapshot is currently being written
 - A new up to date incremental snapshot has been written
 - The cluster delinquent stake is below a certain threshold

Once the supplied checks pass, the command exits successfully with
code 0. If the validator being waited on exits prematurely, or the
command is interrupted, it fails with a non-zero code as follows:

| Exit code | Meaning |
|-----------|---------|
| `0` | A safe window was found |
| `2` | The validator exited while waiting |
| `128+sig` | Interrupted by a signal, as a shell reports it (`130` for `SIGINT`, `143` for `SIGTERM`) |
| `1` | Any other failure |

If run from a terminal, the command prints live diagnostic output, you
can prevent this with `--silent`.

When it fails, the command prints diagnostic messages to `stderr`.
Reasons for failure include no running validator being found, more
than one running validator with nothing to select between them, the
running validator being a different commit than this binary, a
`--config` file that is not the one the validator was started with, or
an idle gap that is larger than an epoch and so can never be
satisfied.

With no arguments the command discovers the running validator on the
host automatically. If more than one validator is running, pass
`--name <name>` to select one (see [`ps`](#ps) to list instances). If
`--config` is given, that resolved configuration is used to locate and
attach to the validator, and its topology layout must match the running
validator. Compatibility with the running validator is checked either
way, and a version mismatch fails cleanly without changing anything.

| Arguments                          | Description |
|------------------------------------|-------------|
| `--min-idle-slots <slots>`         | Minimum number of idle slots required before the next leader slot. Default: 1500. Set to 0 to disable the gap check |
| `--min-idle-seconds <seconds>`     | Minimum idle time in seconds before the next leader slot. Converted to slots using the live slot duration. Mutually exclusive with `--min-idle-slots`. Set to 0 to disable the gap check |
| `--max-delinquent-stake <percent>` | Maximum percentage of delinquent stake allowed, in range [0–100]. Default: 5. Set to 100 to disable the check |
| `--skip-health-check`              | Skip the health check (replay caught-up status) |
| `--skip-snapshot-check`            | Skip the snapshot check |
| `--silent`                         | Do not print the live status panel |
| `--name <name>`   | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>` | Optional path to the configuration TOML file the validator was started with. Its resolved topology layout must match the running validator |

<<< @/snippets/commands/wait.ansi
