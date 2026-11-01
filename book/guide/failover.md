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

Validators with `[failover.enabled]` set run a failover tile, which
listens on `[failover.listen_address]:[failover.listen_port]` (TCP port
`8010` by default). The coordinated handoff works as follows:

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
   voting and producing blocks as it, and tells the remote validator the
   handoff is done.

A coordinated handoff avoids having both validators double-voting with the
same identity. This may not hold true for a [forced promotion](#forced-promotion).

## Setup

Make sure `[failover.enabled]` is `true` on both validators (it is the
default) and that each machine can reach the other's failover port.

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
instead.

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
code for the state the validators are in. The validator logs show the
result as a number, as shown in the table below:

<<< @/snippets/commands/failover-promote-failed.ansi

| Exit code | State | What to do |
|-----------|-------|------------|
| `2` | Rejected, no validator changed identity | Fix the cause in the table below, or wait for it to clear, then run `failover promote` again |
| `3` | The outcome is unknown | Run [`get-identity`](/api/cli#get-identity) on both validators before anything else |
| `4` | Nobody runs the identity | Read the local log for the cause, then run `failover promote --adopt`, see [forced promotion](#forced-promotion) |

When the outcome is unknown and `get-identity` shows that neither
validator runs the identity, use `failover promote --adopt`.

| Result | Code | Exit | Meaning | What to do |
|--------|------|------|---------|------------|
| `busy` | `0x4001` | 2 | Another failover command is running on the local validator | Wait for it to finish |
| `in_progress` | `0x4003` | 2 | A handoff or identity switch is running on the local or the remote validator | Wait for it to finish |
| `no_holder_address` | `0x4007` | 2 | Gossip did not show a validator running the identity | Wait for gossip, or pass `--address` |
| `not_holder` | `0x4002` | 2 | The validator at the address does not run the identity | Check `--address`, or wait for gossip to show the validator that runs the identity |
| `no_peer` | `0x4010` | 2 | No validator running the identity answered at the address before the deadline | Check the address, port and firewall, that failover is enabled there |
| `handed_off` | `0x4012` | 2 | The local validator handed the identity off and waits for the remote validator's answer | Wait. A remote validator that is alive takes the identity or declines it once its adoption is done, which can take up to three 64-second stages (replay to the finality anchor, the adoption, the switch) plus a reconnect, and this validator's log says which (`the peer took the identity`, `the peer declined the identity`); its warning `the peer has not answered` after 64 seconds does not mean the remote is dead, and `get-identity` on the remote shows its junk key while it is adopting. Take the identity back with `--force` only once the remote validator is stopped; `--adopt` refuses with `holder_live` while the answer is pending |
| `no_final_history` | `0x4006` | 2 | The remote validator has no vote history for its last vote yet | Wait for the remote validator to vote |
| `replay_behind` | `0x4008` | 2 | The local validator's replay is too far behind the finality anchor of the vote history to adopt | Wait for the local validator to catch up |
| `holds_other` | `0x400d` | 2 | The local validator runs a staked identity other than the one in the keypair | Hand that identity off first, or `set-identity` to an unstaked key |
| `holder_live` | `0x400f` | 2 | `--adopt` only. The remote validator may still be live: it was in gossip within the last 15 seconds, a validator that says it runs the identity is connected on the failover channel or was within the last 15 seconds, the keypair was given less than 15 seconds ago, or this validator handed the identity to it and waits for its answer | Wait and retry, or use `--force` once the remote validator cannot sign |
| `keypair_mismatch` | `0x3001` | 2 | The public key in the keypair file does not match its private key | Use a valid keypair file |
| `authorized_voter` | `0x3004` | 2 | The identity is an authorized voter on the local validator | Remove it with [`remove-all-authorized-voters`](/api/cli#remove-all-authorized-voters) |
| `timeout` | `0x4009` | 3 | The remote validator did not answer before the deadline | Check both validators |
| `peer_restarted` | `0x400a` | 3 | The remote validator restarted before it answered | Check both validators |
| `handoff_aborted` | `0x4004` | 3 | The remote validator aborted the handoff and may have given up the identity | Check both validators. The remote validator's log says why |
| `peer_holds` | `0x4005` | 3 | Another validator runs the identity | Check both validators |
| `identity_changed` | `0x400e` | 3 | `set-identity` changed the local validator's identity while the command ran | Check both validators |
| `adoption_failed` | `0x400b` | 4 | The local validator did not adopt the vote history | Read the local log, then run `failover promote --adopt` |
| `switch_failed` | `0x400c` | 4 | The local validator's identity switch failed | Read the local log, then run `failover promote --adopt` |

With `--adopt` or `--force`, a failed handoff is a warning, and the
local validator then tries to take the identity without the remote one.
If that also fails, the command prints why and exits with a failure code.

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
`[paths.vote_history]` to `vote_history-<pubkey>.bin.bak`, and a
validator refuses to boot under a key whose vote history file is missing
while other vote history files are there.

- To restart a machine that took the identity under its junk key, first
  rename `vote_history-<junk>.bin.bak` back to `vote_history-<junk>.bin`.
- To restart the machine that gave the identity up under a junk key,
  first move the `vote_history-*` files out of `[paths.vote_history]`.
  The identity's vote history now lives on the other machine.

## Forced promotion

`failover promote --force` first asks the remote validator for a handoff
and, if that fails, makes the local validator take the identity anyway.
`failover promote --adopt` does the same, but only while the remote
shows no sign of life, neither in gossip nor on the failover channel,
and fails otherwise.

::: warning WARNING

A forced promotion skips every check on the remote machine. If that
machine is still signing as the identity, both machines vote and
produce blocks as it. Only force a promotion once `get-identity` on
every other machine shows it does not run the identity, or that machine
is stopped. Never force a promotion on both machines.

:::

A forced promotion adopts the vote history the remote handed over in an
earlier handoff if it still covers every vote this pair knows about.
Otherwise, it starts from an empty history with a bound at the higher of
the current replay slot and the last vote either machine is known to
have cast, and casts no vote and leads no window at or below that bound.
Votes the remote cast beyond what the local validator knows about are
not protected.

After a forced promotion, the machine that was down still has the
identity in its configuration. Set `[failover.boot_to_standby]` there or
point its `[paths.identity_key]` at a junk keypair before it starts
again, see [Restarts](#restarts).

<<< @/snippets/commands/failover-promote-force.ansi

## `set-identity` with failover

`set-identity` keeps working on a failover-enabled validator, as a
break-glass that does not need the other machine. It installs the given
keypair and restarts failover on it. A handoff in progress is discarded.
The new identity becomes the one `failover promote` on this machine
hands off. The other machines view it as a reboot.
