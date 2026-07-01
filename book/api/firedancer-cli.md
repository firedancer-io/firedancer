# `firedancer` Command Line Interface
The Firedancer binary `firedancer` contains many subcommands which can
be run from the command line. `firedancer` also supports subcommands
from the `fdctl` binary.

::: warning WARNING

There is no stable release for the `firedancer` binary. Run the client
and use these commands at your own risk.

:::

## `configure`
The Firedancer binary supports the `configure` command documented in the
[`fdctl` command reference](/api/cli.md#configure), and adds
Firedancer-only configure stages for the full client:

 - `irq-affinity` Removes Firedancer tile CPUs from configurable
   `/proc/irq/*/smp_affinity` masks.
 - `irq-balance` Configures the irqbalance daemon to avoid Firedancer
   tile CPUs. If irqbalance is not running, this stage is a no-op.
 - `snapshots` Prepares the snapshot download directory.

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

::: warning WARNING

`add-authorized-voter` must be called with the configuration file you
started the validator with, like
`firedancer add-authorized-voter --config <config.toml>`, if the
`config` argument is not provided, the command may not add the
authorized voter key on all tiles and your validator may produce invalid
votes.

:::

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
| `--config <path>` | Path to a configuration TOML file of the validator to add an authorized voter for. This must be the same configuration file the validator was started with |

<<< @/snippets/commands/add-authorized-voter.ansi

## `remove-all-authorized-voters`
Removes all authorized voters from the running validator, including any
seeded from `[paths.authorized_voter_paths]` at startup as well as any
added at runtime with `add-authorized-voter`. After removal the validator
can only sign votes for vote accounts whose authorized voter is the
identity key. The command takes no arguments.

::: warning WARNING

`remove-all-authorized-voters` is only supported with `firedancer` and
not `fdctl`. In other words, the command is only supported while running
the full client validator and not Frankendancer.

:::

::: warning WARNING

`remove-all-authorized-voters` must be called with the configuration file
you started the validator with, like
`firedancer remove-all-authorized-voters --config <config.toml>`, if the
`config` argument is not provided, the command may not clear the
authorized voter keys on all tiles and your validator may produce invalid
votes.

:::

It is safe to call the command while the validator is running and voting.
The client clears the tower tile before the sign tiles, so a vote is
never produced referencing an authorized voter after its key has been
removed; in between, the validator simply falls back to signing with the
identity key.

The command is idempotent: removing when there are no authorized voters
also succeeds. It exits successfully (with an exit code of 0) and prints
`All authorized voters removed`.

The change is live only: it is not written back to the configuration
file, so any voters listed in `[paths.authorized_voter_paths]` return on
the validator's next restart. To drop them across restarts, also remove
them from the configuration file.

| Arguments         | Description |
|-------------------|-------------|
| `--config <path>` | Path to a configuration TOML file of the validator to remove authorized voters from. This must be the same configuration file the validator was started with |

<<< @/snippets/commands/remove-all-authorized-voters.ansi
