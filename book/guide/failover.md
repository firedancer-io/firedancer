# Failover

Failover moves a staked identity from one running Firedancer validator
to another, on demand, without stopping either of them. The validator
taking over the identity asks the one running it to hand it over, and
the two coordinate so that at most one of them signs as the identity at
any moment and the one taking over continues the vote history where the
other left off.

Throughout this page the **local** validator is the one you run
`failover promote` on, which takes the identity, and the **remote**
validator is the one currently running it. Any validator can be either
role, so a pair can hand the identity back and forth as often as needed.

::: tip NOTE

Failover is for moving an identity between two Firedancer validators.
To move an identity between Agave and Firedancer, use
[`set-identity`](/api/cli#set-identity) with a vote history file
instead. Using `set-identity` between two failover-enabled Firedancer
validators is highly discouraged, as it skips the coordination and
safe-guards described here.

:::

## How it works

With `[failover.enabled]` set to `true`, validators
listen on `[failover.listen_address]:[failover.listen_port]` (TCP port
`8010` by default) for requests to hand over the identity. The
coordinated handoff works as follows:

1. **Discovery.** The local validator looks the identity up in gossip and
   dials the gossip address of the validator advertising it. Pass
   `--address` (and `--port`) to dial a known address instead, for
   example over a private network.
2. **Authentication.** The two validators open a TLS connection and each
   proves that it holds the private key of the identity by signing a
   challenge with it. A machine without the identity's private key
   cannot ask for a handoff, nor pretend to be running the identity.
3. **Demotion.** The remote validator stops voting and producing blocks
   as the identity, finishing any leader slot already in progress, and
   switches to an unstaked random junk key. It then sends the local
   validator its final vote history to take over from.
4. **Adoption.** The local validator waits until it has replayed up to
   that vote history's finality anchor, then adopts it.
5. **Promotion.** The local validator adopts the new identity and starts
   voting and producing blocks as it.

A coordinated handoff avoids having both validators double-voting with the
same identity. This may not hold true for a [takeover](#takeover).

## Setup

Make sure `[failover.enabled]` is `true` (it is the default) and
that the other machine can reach this one's failover port. A validator
with it disabled can still adopt an identity from another host but
cannot hand over its own identity to another requester.

```toml
[failover]
    enabled = true
    listen_address = "0.0.0.0"
    listen_port = 8010
```

::: tip RECOMMENDED

Setting `[failover.boot_to_standby]` to `true` on every validator that
uses failover is highly encouraged. Such a validator never boots under
the staked identity, so a restart cannot make it vote alongside the
validator running the identity, or make the duplicate instance check
stop that validator. It comes back without the identity and takes it
with `failover promote`.

:::

There are two ways to designate a spare validator that should boot as
a stand-by, instead of actively voting:

::: code-group

```toml [boot_to_standby]
# Keep the staked identity keypair in [paths.identity_key] but set
# `boot_to_standby` so the validator boots up with a new junk key
# that is automatically generated in memory at every start.
# The staked keypair is the identity this validator takes with
# `failover promote`, so no keypair argument is needed.
[paths]
    identity_key = "/home/firedancer/validator-keypair.json"

[failover]
    boot_to_standby = true
```

```toml [Junk keypair file]
# Create a new unstaked keypair with `firedancer keys new`
# and boot under it.  This validator does not vote until
# `failover promote <staked keypair>` runs on it.
[paths]
    identity_key = "/home/firedancer/junk.json"
```

:::

<<< @/snippets/commands/keys-new-junk.ansi

`[failover.boot_to_standby]` is the recommended setup. A validator
with it can be restarted at any time while the other machine runs the
identity, since it never boots under the identity itself. Otherwise,
you are responsible for not restarting a machine under the staked
identity while the other machine runs it, see [Restarts](#restarts).

## Handing the identity over

On the local validator, the one that should take the identity, run
`failover promote` with the keypair of the identity to take. A validator
with `[failover.boot_to_standby]` reads it from `[paths.identity_key]`
instead. When no validator runs the identity yet, as on first setup with
`[failover.boot_to_standby]` on both, there is nobody to hand it over:
run `failover takeover` on exactly one validator, once nothing else can
sign as the identity.

<<< @/snippets/commands/failover-promote.ansi

In a terminal the command asks for confirmation first, pass `--yes` to
skip the prompt. Ctrl-C may not successfully stop a handoff in progress.

After a successful handoff, the remote validator runs its junk key and
the local validator now runs the identity. Check both machines with
[`get-identity`](/api/cli#get-identity):

<<< @/snippets/commands/get-identity.ansi

To hand the identity back, run `failover promote` on the demoted machine.

To dial a known address rather than the one found in gossip, for example
over a private network, pass `--address` and, if the remote listener is
not on port `8010`, `--port`:

<<< @/snippets/commands/failover-promote-address.ansi

## If a handoff fails

The command prints the result and exits with a
code for the state the validators are in:

<<< @/snippets/commands/failover-promote-failed.ansi

| Exit code | State | What to do |
|-----------|-------|------------|
| `1` or other | The command failed for another reason or was terminated by a signal, the outcome is likely unknown | Read the error, then run [`get-identity`](/api/cli#get-identity) on both validators before anything else |
| `2` | Rejected, no validator changed identity | Fix the cause in the table below, or wait for it to clear, then run `failover promote` again |
| `3` | The outcome is unknown | Run [`get-identity`](/api/cli#get-identity) on both validators before anything else |
| `4` | Nobody runs the identity | Read the local log for the cause, then run `failover takeover` on the machine that last ran the identity, see [takeover](#takeover) |

When the outcome is unknown and `get-identity` shows that neither
validator runs the identity, use `failover takeover` on the machine
that last ran it.

| Result | Exit | Meaning | What to do |
|--------|------|---------|------------|
| Any other | 1 | A failure not listed in this table | Read the error, then check both validators |
| `busy` | 2 | Another failover command is running on the local validator | Wait for it to finish |
| `in_progress` | 2 | A handoff or identity switch is running on the local or the remote validator | Wait for it to finish |
| `no_holder_address` | 2 | Gossip did not show a validator running the identity | Wait for gossip, or pass `--address` |
| `not_holder` | 2 | The validator at the given address does not run the identity | Check `--address`, or wait for gossip to show the validator that runs the identity |
| `no_peer` | 2 | No validator running the identity responded at the given address | Check the address, port and firewall, that failover is enabled there |
| `handed_off` | 2 | The local validator handed the identity off and waits for the remote validator's answer | Wait |
| `no_final_history` | 2 | The remote validator has no vote history for its last vote yet | Wait for the remote validator to vote |
| `replay_behind` | 2 | The local validator's replay is too far behind the finality anchor of the vote history | Wait for the local validator to catch up |
| `holds_other` | 2 | The local validator runs a staked identity other than the one in the keypair | Hand that identity off first, or `set-identity` to an unstaked key |
| `holder_live` | 2 | `failover takeover` only. The remote validator may still be alive | Wait and retry, or use `--force` if the remote validator cannot sign |
| `keypair_mismatch` | 2 | The public key in the keypair file does not match its private key | Use a valid keypair file |
| `authorized_voter` | 2 | The identity is an authorized voter on the local validator | Remove it with [`remove-all-authorized-voters`](/api/cli#remove-all-authorized-voters) |
| `timeout` | 3 | The remote validator did not respond in time | Check both validators |
| `peer_restarted` | 3 | The remote validator restarted before it responded | Check both validators |
| `handoff_aborted` | 3 | The remote validator aborted the handoff and may have given up the identity | Check both validators |
| `peer_holds` | 3 | Another validator runs the identity | Check both validators |
| `identity_changed` | 3 | `set-identity` interrupted and changed the local validator's identity | Check both validators |
| `adoption_failed` | 4 | The local validator did not adopt the vote history | Read the logs, then try `failover takeover` on the machine that last ran the identity |
| `switch_failed` | 4 | The local validator's identity switch failed | Read the logs, then try `failover takeover` on the machine that last ran the identity |

With `failover takeover`, a failed handoff logs a warning, and the local
validator then tries to take the identity without coordinating with the remote
validator. If that also fails, the command logs the reason and exits
with a failure code.

## Restarts

A validator boots under its `[paths.identity_key]` unless
`[failover.boot_to_standby]` is set. Before restarting the machine that
gave the identity up, point its `[paths.identity_key]` at a junk key of
its own, or set `[failover.boot_to_standby]` there. If it boots under the
identity while the other machine runs it, the duplicate instance check
stops the other machine. A machine with `[failover.boot_to_standby]` boots
under a fresh junk key every time, so it can restart while the other
machine runs the identity, and it takes the identity back with
`failover promote`.

Leaving an identity renames its vote history file in
`[paths.vote_history]` to `vote_history-<pubkey>.bin.bak`. A validator
that boots under a keypair file checks for that key's vote history
file. If the file is missing while other vote history files are there,
it refuses to boot. A validator with `[failover.boot_to_standby]` skips
this check and needs none of the steps below.

- To restart a machine that took the identity under its junk key, first
  rename `vote_history-<junk>.bin.bak` back to `vote_history-<junk>.bin`.
- To restart the machine that gave the identity up under a junk key,
  first move the `vote_history-*` files out of `[paths.vote_history]`.
  The identity's vote history now lives on the other machine.

## Takeover

`failover takeover` is for when the remote validator may be dead or
unreachable. It first asks the remote validator for a handoff. If that
fails, the local validator takes the identity anyway, but only if the
remote shows no signs of life (neither in gossip nor on the failover
channel).

`failover takeover --force` takes the identity no matter what, bypassing
all checks. Use it when the remote still shows signs of life and
you have confirmed that it cannot sign.

::: warning WARNING

A takeover skips every check on the remote machine. If that machine is
still signing as the identity, both machines vote and produce blocks as
it. Only take over once every other machine is stopped or cannot
complete a promotion. Never take over on both machines simultaneously.

:::

A takeover starts from an empty vote history.

After a takeover, the machine that was down still has the identity in
its configuration. Set `[failover.boot_to_standby]` there or point its
`[paths.identity_key]` at a junk keypair before it starts again, see
[Restarts](#restarts).

<<< @/snippets/commands/failover-takeover.ansi

<<< @/snippets/commands/failover-takeover-force.ansi

## `set-identity` with failover

`set-identity` keeps working on a failover-enabled validator, as a
break-glass that does not need the other machine. It installs the given
keypair and restarts failover on it. The new identity becomes the one
`failover promote` on this machine hands off. The other machines view
it as a reboot.
