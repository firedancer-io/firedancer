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
`8010` by default) and dials the same port on the remote validator when
you ask for a handoff. The coordinated handoff works as follows:

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

`[failover.boot_to_standby]` is the recommendation for a dedicated
standby. Such a validator can be restarted at any time while the other
machine runs the identity, since it never boots under the identity
itself. Otherwise, you are responsible for not restarting a machine
under the staked identity while the other machine runs it, see
[Restarts](#restarts).

## Handing the identity over

On the local validator, the one that should take the identity, run
`failover promote` with the keypair of the identity to take. A validator
with `[failover.boot_to_standby]` reads it from `[paths.identity_key]`
instead.

<<< @/snippets/commands/failover-promote.ansi

In a terminal the command asks for confirmation first, pass `--yes` to
skip the prompt. Ctrl-C may not successfully stop a hand- off in progress.

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

The command prints the reason and exits with a code for the state the
machines are in. The codes, the reasons and what to do next are listed
under [`failover promote`](/api/cli#failover-promote). Most failures
happen before the remote validator gives anything up, leaving both
machines as they were:

<<< @/snippets/commands/failover-promote-failed.ansi

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

`failover promote --force` makes the local validator take the identity
without contacting the remote validator. It is for when no machine runs
the identity: after both machines restarted, after a handoff that failed
part way, or when the machine running the identity is down and cannot
be reached.

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
