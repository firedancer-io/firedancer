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
will be preserved as described in the file. With Alpenglow, pass the
Agave-compatible vote history file of the new identity, signed by it.
Without a file, the new identity is treated as never having voted. If
the file is empty or invalid, the command will fail and the identity of
the running validator will not be changed.
With Alpenglow, switching to the identity the validator is already
running as is refused.

Between two Firedancer validators running failover, only use
`firedancer failover promote`, which hands over the vote history
directly. Do not use `--vote-history-file` for this, it is only for a
tower file from a validator that does not run failover, such as Agave.

With failover on, `set-identity` also makes the new key the identity
`failover promote` hands off, unless it is the machine's junk identity.
Only a machine running the same key can take it over, so set that
key as `[paths.identity_key]` on the other machine and restart it.
After a restart, the machine boots as standby under its junk identity
and uses `[paths.identity_key]` as the handoff target again.
The new key cannot also be one of the authorized voters. With
`--vote-history-file`, a failover machine does not vote until the
file's root has been replayed, and ignores a file whose root is not on
the fork of its own root, waiting out the lockouts of its votes.

In Tower, if `[tiles.tower.write_vote_history_file]` is enabled, votes
are saved to `tower-1_9-<identity>.bin` in the `[paths.vote_history]`
directory (by default the base directory).

In Alpenglow, the validator instead writes
`vote_history-<identity>.bin` in the `[paths.vote_history]` directory
before each vote and each block it produces. This is an Agave-compatible
vote history file and it protects against equivocation, both double
voting and double producing blocks. A cluster restart, booting at the
`[consensus.wait_for_supermajority_at_slot]` slot, discards the vote
history, as in Agave.

### Manual failover with Alpenglow
Only one validator may run a staked identity at a time. To move an
identity between two running validators:

1. On the validator giving up the identity, run `set-identity` with an
   unstaked keypair. If failing over _from_ Firedancer, it saves the identity's vote history in
   `[paths.vote_history]` as `vote_history-<identity>.bin.bak`. If the
   validator stopped without switching away, the identity's vote
   history is `vote_history-<identity>.bin` instead, and its `.bak` is
   not the identity's latest.
2. Copy that file to the validator assuming the identity. For Agave,
   place it in the ledger directory as `vote_history-<identity>.bin`.
   For Firedancer, place it anywhere other than `[paths.vote_history]`.
3. Then, on the assuming validator, run `set-identity` with the identity
   keypair. If failing over _to_ Firedancer, pass the vote history file
   with `--vote-history-file <path>`.

A Firedancer validator that restarts after switching away from the
identity it booted as refuses to boot until its vote history file is
back in `[paths.vote_history]`. Copy in the latest vote history file
from the validator that last ran the identity.

A sample runbook, moving identity `A` from Firedancer validator
`primary` to Firedancer validator `standby`, where each validator has
its own unstaked keypair `junk.json` and both use the default
`[paths.vote_history]`:

```sh
# on primary
firedancer set-identity junk.json
scp ~/.firedancer/fd1/vote_history-A.bin.bak standby:/tmp/vote_history-A.bin

# on standby
firedancer set-identity A.json --vote-history-file /tmp/vote_history-A.bin
```

To move it back, run the same steps with the validators swapped.

| Arguments                    | Description |
|------------------------------|-------------|
| `<keypair>`                  | Path to a `identity.json` keypair file, or `-` to read the JSON formatted key from `stdin` |
| `--name <name>`              | Name of the validator instance to attach to, if more than one is running on this host |
| `--config <path>`            | Optional path to a configuration TOML file naming the validator to attach to. Only the `name` and `[hugetlbfs.mount_path]` values are used, and they must match the running validator |
| `--vote-history-file <path>` | Path to the tower file, or the vote history file when Alpenglow is enabled, saved by the validator previously running with the new identity. Without it, the new identity is treated as never having voted |

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

## `failover promote`
This command asks a remote active validator to hand off its identity and
vote history to the local running standby. Run this command on the
standby. The remote validator must have `[failover.enabled]` set to
`true` to accept the request. Both validators must use the same vote
account.

The failover commands are only supported by the full Firedancer client.

```sh
firedancer failover promote [<keypair>] [--name <name>] [--yes] [--force] [--address <address>] [--port <port>]
```

The command attaches to the local running validator and discovers it
automatically. If more than one is running, pass `--name <name>` to
select one (see [`ps`](#ps)). It asks for confirmation when run from a
terminal unless `--yes` is given. Outside a terminal it proceeds
without a prompt.

Before asking for confirmation, the command checks the local validator's
role. A standby with a prepared target identity and a fresh gossip
address authenticates to the remote validator in advance. This connection
does not request a handoff. Confirmation submits the handoff request, so
the prompt does not mean the remote validator is ready to hand off.

The local validator finds the active's address through gossip. Use
`--address` to give the remote validator's IPv4 address or host name
instead, for example when connecting over a private network. Use
`--port` if its failover listener uses a different port from the local
validator's `[failover.listen_port]`.

If gossip has no address for the remote validator, the command refuses
the request. Wait for its contact information or provide `--address`.
Providing an address does not bypass peer authentication.

For example, to connect to a known failover listener over a private
network, run the following on the local standby.

```sh
firedancer failover promote --name standby --address 192.0.2.10 --port 8010
```

The remote validator must be reachable at that TCP address and port. If
it is stopped, its failover listener is disabled, or the connection
cannot be authenticated, the local request cannot complete the handoff.

### Both validators have failover enabled

Set `[failover.enabled]` to `true` on both validators. Configure the same
staked identity in `[paths.identity_key]` and the same vote account in
`[paths.vote_account]`. Firedancer generates a fresh junk identity in memory
on each startup. The private key is never written to a file. Both validators
boot under their junk identities without voting and listen for handoff requests.

Once one validator is active, run the following on the standby to request
a handoff. The staked identity keypair is already loaded from the
configuration, so no keypair argument is needed.

```sh
firedancer failover promote --name standby
firedancer failover status --name standby
```

For example, an accepted request prints the handoff ID and the status
needed to confirm completion.

<<< @/snippets/commands/failover-promote.ansi

After the handoff, the old active can request the identity back with
`failover promote`. If both validators are still standbys, first promote
one with `--force` as described below. An optional keypair argument must
match the standby's current failover target.

### Only the active has failover enabled

Keep `[failover.enabled]` set to `true` on the active and set it to `false`
on the requester. Disabling failover does not disable voting. The
requester starts under `[paths.identity_key]` without generating a junk
identity or automatically becoming a nonvoting standby.

For this workflow, start the requester with a junk identity in
`[paths.identity_key]` and the active's vote account in
`[paths.vote_account]`. The junk identity must differ from the active's
identity and must not be a staked node identity. This keeps the requester
nonvoting while it replays, even with authorized voter keys loaded. The
vote account must remain configured for takeover.

If needed, create a junk key with the existing `keys` command and set
`[paths.identity_key]` to its path before starting the requester.

```sh
firedancer keys new /path/to/standby-identity.json
firedancer run --config /path/to/standby.toml
```

Validators with a vote account include a failover tile for outgoing
requests, so allow for it when assigning CPU affinity. Pass the active's
identity keypair on first use. This prepares the target without installing
it. The requester must still be using the identity it started with. The
target cannot also be an authorized voter.

```sh
firedancer failover promote /path/to/active-identity.json --name standby
firedancer failover status --name standby
```

Later requests can omit the keypair. Repeating the same keypair preserves
an ongoing handoff. A different keypair is refused. After takeover, the
requester's failover listener stays disabled, so the other validator
cannot request the identity back from it. On restart, it returns to its
configured identity and forgets the prepared target, so the next request
needs the keypair again.

If both validators have failover disabled, neither can accept a handoff
request.

### Handoff progress and failures

The following applies to both configurations.

The remote validator refuses the handoff if it has no final vote history
to hand over, the local standby has not started replaying, or the standby
is more than 64 slots behind its last Tower vote or Alpenglow finality
anchor. It keeps its identity in these cases. It also refuses a new
request while another transition is running. Once it agrees to hand
off, it gives up the identity before the local validator adopts its
vote history. If adoption fails or stalls, the handoff can fail with
neither machine voting.

Exit code 0 means the local validator accepted the request. It does not
mean the remote validator has agreed to hand off or that the handoff has
completed. The command prints a handoff ID. Check
[`failover status`](#failover-status) on the local validator for
`role: active` and `last handoff: <id>, taken` with that ID. Check that the
remote validator shows `role: standby` and `action: idle`.

The local validator refuses a new request if it is already active or
another transition is running. A local refusal exits with a non-zero
code and prints the reason to `stderr`. An accepted request can still
fail while connecting to the remote validator, authenticating it, or
adopting its vote history. These later failures do not change the
command's exit code. Check status and the logs on both validators to
determine where it stopped.

If the command itself times out waiting for the local validator to
answer, the outcome is unknown. Check status on both machines because
the request may still complete.

If the request pauses at its network deadline, the local validator stops
dialing. Run `failover status` on both validators before retrying. Run
`failover promote` again on the local validator to resume the
request. This also resumes an active validator that is waiting for the
remote validator to confirm completion. You can provide a new `--address`
or `--port` when resuming it.

### Forced promotion

With `--force`, the local standby takes the identity without contacting
the remote validator. This is also needed for first use when both
machines are standbys. Promotion first tries eligible saved peer vote
history. Tower then tries the vote account and starts with empty vote
history if neither can be adopted. Alpenglow falls back to empty vote
history with a slot bound that prevents voting at or below it. Check for
`role: active` and `action: idle` to confirm completion.

Forced promotion can cancel a handoff that is waiting for the remote
validator's response. It cannot interrupt a local vote history adoption
or identity switch. Replay and adoption must still complete before the
identity can be installed.

::: warning WARNING

Only use `--force` after ensuring every other machine with the identity
cannot sign. It skips the checks on the other machine and can discard
earlier vote lockouts by accepting incomplete or empty vote history.
Never force promotion on both machines at once. `--yes` only skips the
confirmation prompt. It does not imply `--force` or suppress its warning.

:::

| Arguments             | Description |
|-----------------------|-------------|
| `<keypair>`           | Optionally provide the target identity keypair file. Required on first use when `[failover.enabled]` is `false`. |
| `--name <name>`       | Select the validator instance to attach to if more than one is running on this host. |
| `--config <path>`     | Optionally use the configuration TOML file the validator was started with. |
| `--yes`               | Skip the confirmation prompt. |
| `--force`             | Take the identity without cooperation from the remote validator, allowing incomplete or empty vote history. This option cannot be combined with `--address` or `--port`. |
| `--address <address>` | Use this IPv4 address or host name for the remote validator instead of the address found through gossip. This option cannot be combined with `--force`. |
| `--port <port>`       | Set the remote validator's failover TCP port. The default is the local validator's `[failover.listen_port]`, which is 8010 unless configured otherwise. This option cannot be combined with `--force`. |

## `failover status`
This command prints the local running validator's failover role, current
action, peer and last handoff. It also reports what this machine knows
about another holder of the identity and the vote history a forced
promotion would adopt. Use it to check progress after
[`failover promote`](#failover-promote).

```sh
firedancer failover status [--name <name>]
```

The command discovers the local running validator automatically. If more
than one is running, pass `--name <name>` to select one (see [`ps`](#ps)).
It exits with code 0 if status was retrieved, including when failover
is disabled. Otherwise it exits with a non-zero code and prints the
reason to `stderr`.

With `[failover.enabled]` set to `false` and a vote account configured,
status reports `client only, listener disabled` and shows outgoing
handoff progress.

The following example shows a completed handoff. The last handoff ID
matches the ID printed by `failover promote` above. The connection closes
after completion, so `peer role` is unknown until another authenticated
session is established. The new standby reconnects when it discovers the
new active through gossip.

<<< @/snippets/commands/failover-status.ansi

`role` describes the local validator. `peer role` describes the remote
validator only while an authenticated session is open. `last handoff`
records the latest request's outcome, so check `role` and `action` as
well when investigating a failed or paused handoff.

`other holder` reports what the local validator knows about another
machine using the identity. Seeing none does not prove every other
machine is unable to sign. `takeover adopts` shows the vote history
source a forced promotion would currently select. `coverage floor` is
the highest slot known to have been signed locally or reported by the
remote validator. Forced promotion can proceed without history covering
that slot, as described above.

| Arguments         | Description |
|-------------------|-------------|
| `--name <name>`   | Select the validator instance to attach to if more than one is running on this host. |
| `--config <path>` | Optionally use the configuration TOML file the validator was started with. |

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
