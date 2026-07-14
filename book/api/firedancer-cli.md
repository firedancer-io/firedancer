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
configuration options `require-tower` and `force`.

Unlike `fdctl`, the `firedancer` binary does not require the `--config`
argument: with no arguments the command discovers the running validator
on the host automatically. If more than one validator is running, pass
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
