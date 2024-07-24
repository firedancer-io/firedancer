# Firedancer WebSocket API
Firedancer provides an optional [HTTP
websockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
API for consumers to subscribe to validator information. It primarily
exists in the current form to support the Firedancer GUI.

::: warning WARNING
The API is not currently stable, is not versioned, may not exist for
long, may break or start producing incorrect data at any moment, and
should not generally be used for anything without extreme caution.
:::

## Connecting
To connect to the API, create a WebSocket client from the language of
your choice, for example in JavaScript

::: code-group

```js [client.js]
client = new WebSocket("ws://localhost:80/websocket");
```

```toml [config.toml]
[tiles]
    [tiles.http]
        gui_listen_port = 80
```

:::

The port to connect to is specified in the validator configuration TOML
file.

The API is split into various topics which will be streamed to any and
all connected clients.

### Keeping Up
The server does not drop information, slow down, or stop publishing the
stream of information if the client cannot keep up. A client that is
reading too slow and cannot keep up with incoming data stream will have
its connection forcibly closed by the server.

Most data updates are streamed in real time as the changes occur except
certain updates (performance counters like packet counters) which would
change too quickly, which are instead republished on a regular frequency
described below.

Each message is published with frequency described in the documentation
below. The meaning of these frequencies are:

| Frequency&nbsp;&nbsp;&nbsp; | Meaning |
|-----------------------------|---------|
| *Once*                      | The message is published only once, immediately after a connection is established. |
| *Live*                      | The message is published live, immediately after the underlying data in the validator is changed. |
| *1s*                        | The message is republished at regular one second intervals. |
| *Once* + *Live*             | The message is published immediately after a connection is established, and then republished whenever the data is changed. |

Most information related to the state of the validator is sent both
`Once` when the connection is established, and then live whenever it is
updated.

All data is encoded in JSON, with a containing envelope as follows:

```json
{
    "topic": "summary",
    "key": "cluster",
    "value": "mainnet-beta",
}
```

## Forks
The WebSocket API does not communicate information for all forks tracked
by the validator. Instead, only information about the currently active
fork is represented and streamed. For example, the `completed_slot` is
the last completed slot on the current active fork, and `slot.update`
messages are only received for slots changing on the currently active
fork.

## Topics

### summary
A set of high level informational fields about the validator.

#### `summary.version`
| frequency | type     | example         |
|-----------|----------|-----------------|
| Once      | `string` | `"0.106.11814"` |

The current version of the running validator.

#### `summary.cluster`
| frequency | type     | example        |
|-----------|----------|----------------|
| Once      | `string` | `"mainnet-beta"` |

One of `mainnet-beta`, `devnet`, `testnet`, `pythtest`, `pythnet`, or
`unknown`. Indicates the cluster that the validator is likely to be
running on. If a validator is misconfigured and, for example, connects
to multiple networks, the first (highest priority) network in the above
list will be displayed.

#### `summary.identity_key`
| frequency | type     | example        |
|-----------|----------|----------------|
| Once      | `string` | `"Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF"` |

The public identity key assigned to the running validator, encoded in
base58. Firedancer does not support changing the identity key of the
validator while it is running and this value does not change.

#### `summary.root_slot`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `275138349` |

The last slot that was rooted. Rooted slots are fully confirmed and
irreversible, and the rooted slot will never decrease as switching fork
cannot unroot the slot. The number will not always increase by one, as
skipped slots do not update the root slot. For example, if the root slot
goes from `1001` to `1003` it means slot `1002` was skipped.

#### `summary.optimistically_confirmed_slot`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `275138349` |

The highest slot on the current fork that was optimistically confirmed.
Optimistic confirmation means that over two-thirds of stake have voted
to confirm the slot, and it is unlikely (although still possible, if
validators switch vote) to not become rooted.

Although rare, the `optimistically_confirmed_slot` could decrease if the
validator switches to another fork that does not have this slot.

#### `summary.completed_slot`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `275138349` |

The highest completed slot on the current fork choice of the validator.
The completed slot may decrease if the validator is switching forks, or
could stay the same for much more than the slot production time (400
milliseconds) if leaders are offline and not producing blocks.

#### `summary.estimated_slot`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `275138349` |

The estimated slot is the same as the completd slot, except it still
progresses forward even if the current leaders are skipping (not
producing) their slot. For example, if the last completed slot was
`1001` and it has been 800 milliseconds since that slot, the estimated
slot is likely to be `1003`.

#### `summary.estimated_tps`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + 1s   | `number` | `6048` |

The estimated number of transactions per second the network is running
at. This is a moving average from the prior 150 slots, or around one
minute. For a more precise view of transactions per second, the client
can calculate it from the stream of new slot data.

#### `summary.estimated_nonvote_tps`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + 1s   | `number` | `2145` |

The estimated number of non-vote transactions per second the network is
running at. This is a moving average from the prior 150 slots, or around
one minute. For a more precise view of non-vote transactions per second,
the client can calculate it from the stream of new slot data.

#### `summary.upcoming_slot_txn_info`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + 1s   | `SlotTxnInfo` | below |

::: details Example

:::

The number of transactions of that have been acquired or dropped in the
lead up to our next leader slot. If we are currently in a leader slot
but have not completed it, this includes transactions acquired and
dropped during the leader slot. The values are reset to zero when the
leader slot completes and begin counting up again.

### epoch
Information about an epoch. Epochs are never modified once they have
been determined, so the topic only publishes a continuous stream of new
epochs as they are known. When connecting, the current and next epoch
are known. Epochs become known one epoch in advance, and will only be
published once they are confirmed (the prior epoch has fully rooted).

#### `epoch.new`
| frequency   | type   | example     |
|-------------|--------|-------------|
| Once + Live | `EpochSchedule` | below |

::: details Example

```json
{
    "epoch": 636,
    "start_slot": 274752000,
    "end_slot": 275183999,
    "excluded_stake_lamports": 0,
    "staked_pubkeys": [
        "Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF",
        "2CeCyRoYQcctDmbXWrSUfTT4aQkGVCnArAmbdmQ5QGFi",
        "6JPDr4URdEDP5MqPgmDT6jk2nToyMUzNU27qsGxrRgKz",
        "8ri9HeWZv4Dcf4BD46pVPjmefzJLpbtfdAtyxyeG4enL",
        // ... many more ...
    ],
    "staked_lamports": [
        360,
        240,
        180,
        9991,
        // ... many more ...
    ],
    "leader_slots": [
        15,
        1542,
        761,
        // ... many more ...
    ]
}
```

:::

**`EpochSchedule`**
| Field      | Type    | Description
|------------|---------|------------
| epoch      | `number` | An identity counter for each epoch, starting at zero for the first epoch and going up |
| start_slot | `number` | The first slot (inclusive) in the epoch |
| end_slot   | `number` | The last slot (inclusive) in the epoch |
| excluded_stake_lamports | `number` | This number is almost always zero. Firedancer has a limit of 40,200 for the number of staked peer validators it can keep track of. In the unlikely event that this number is exceeded, the lowest staked peers will be forgotten, and their stake will not appear in the below lists. But is is useful to know the total stake in the epoch, so this value represents the leftover/excluded ("poisoned") amount of stake that we do not know which validator it belongs to
| staked_pubkeys | `string[]` | A list of all of validator identity keys for validators which have are staked in this epoch.  There will be at most 40,200 staked keys, after which lower staked keys will not be included |
| staked_lamports | `string[]` | A list with the same length as the `staked_pubkeys` field. `stake_lamports[ i ]` is the number of lamports staked on the pubkey `staked_pubkeys[ i ]` as of this epoch
| leader_slots | `number[]` | An array, one entry per four slots, of which pubkey in the `leader_pubkeys` array is leader for those slots. On `mainnet-beta` this array will always have a length of 108,000, which is the number of slots in an epoch divded by four.  Leader slots are in groups of four because the leader schedule is generated in such a way as to guarantee each leader gets at least four consecutive slots.  For example, to find the pubkey of the leader in slot 1000 of the epoch, it is `staked_pubkeys[ leader_slots[ 1000/4 ] ]` |

On establishing a connection two epochs are sent to the client. The
current epoch that the cluster is in, and the next epoch. From then on,
new epochs are published live as they calculated by the validator. For
epoch T, it is published as as `end_slot` in epoch T-2 is rooted. The
epoch is speculatively known as soon as `end_slot` in epoch T-2 is
compelted, rather than rooted, but no speculative epoch information is
published until the epoch is finalized by rooting the slot.

### gossip
Information about validator peers from the gossip network. Gossip
information is self reported by other nodes, and except for the identity
of the node, the data is not validated nor checked for correctness. A
peer node can report arbitrary or corrupt data for any value in the
gossip object, although they must be in posession of the private key for
the reported identity.

#### `gossip.update`
| frequency   | type   | example     |
|-------------|--------|-------------|
| Once + 5s   | `GossipUpdate` | below |

::: details Example

```json
{
    "update": [
        {
            "identity": "Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF",
            "version": "1.18.15",
            "feature_set": 4215500110,
            "wallclock": 0,
            "shred_version": 0,
            "sockets": {
                "gossip": "93.119.195.160:8001",
                "tpu": "192.64.85.26:8000",
                // ... other sockets ...
            }
        },
    ],
    "remove": [
        { "identity": "8ri9HeWZv4Dcf4BD46pVPjmefzJLpbtfdAtyxyeG4enL" }
    ]
}
```

:::

**`GossipPeerUpdate`**
| Field      | Type   | Description
|------------|--------|------------
| identity | `string` | Identity public key of the validator, encoded in base58. This is authenticated and the gossip node must have been in posession of the private key to publish gossip data as this identity |
| wallclock | `number` | Not entirely sure yet TODO |
| shred_version | `number` | A `u16` representing the shred version the validator is configured to use. The shred version is changed when the cluster restarts, and is used to make sure the validator is talking to nodes that have participated in the same cluster restart |
| version | `string\|null` | Software version being advertised by the validator. Might be `null` if the validator is not gossiping a version, or we have received the contact information but not the version yet. The version string, if not null, will always be formatted like `major`.`minor`.`patch` where `major`, `minor`, and `patch` are `u16`s |
| feature_set | `number\|null` | First four bytes of the `FeatureSet` hash interpreted as a little endian `u32`. Might be `null` if the validator is not gossiping a feature set, or we have received the contact information but not the feature set yet |
| sockets | `[key: string]: string` | A dictionary of sockets that are advertised by the validator. `key` will be one of `gossip`, `repair`, `rpc`, `rpc_pubsub`, `serve_repair`, `serve_repair_quic`, `tpu`, `tpu_forwards`, `tpu_forwards_quic`, `tpu_quic`, `tpu_vote`, `tvu`, or `tvu_forwards`. The value is an address like `<addr>:<port>`: the location to send traffic to for this validator with the given protocol. Address might be either an IPv4 or an IPv6 address |

**`GossipPeerRemove`**
| Field    | Type   | Description
|----------|--------|------------
| identity | `string` | Identity public key of the validator, encoded in base58.

**`GossipUpdate`**
| Field      | Type   | Description
|------------|--------|------------
| add    | `GossipPeerUpdate[]` | List of peer validators that were added since the last update, or all of the peers for the first update after connecting |
| update | `GossipPeerUpdate[]` | List of peer validators that were changed since the last update |
| remove | `GossipPeerRemove[]` | List of peer validators that were removed since the last update |

The `gossip.update` message is republished every five seconds, with a
list of gossip peers added, removed, or updated. The list of peers is
full and includes this node itself, nodes with a different
`shred_version`, nodes publishing corrupt or bad information, and so
on.

### slot
Slots are opportunities to produce a block. Slots are not fully
determined once they are published, and might be changed as the
validator switches back and forth between forks. The state machine
for a slot looks like:

```text
           unpublished
              |   ^
              v   |
            completed
              |   ^
              v   |
      optimistically confirmed

      .... ???? complete this TODO ...

```

#### `slot.publish`
| frequency   | type   | example     |
|-------------|--------|-------------|
| Live        | `SlotPublish` | below |

:::details Example

:::

**`SlotTxnInfo`**
| Field      | Type      | Description |
|-----------------------------|-----------|-------------|
| acquired_txns               | `number` | The total number of transactions that were acquired since the end of our prior leader slot, until the end of this leader slot. Transactions can be acquired for many reasons, which are given individually below.
| acquired_txns_leftover      | `number` | The transactions were received during or prior to an earlier leader slot, but weren't executed yet so they stayed available to execute in this slot.
| acquired_txns_quic          | `number` | A transaction stream was received via. QUIC.  The stream does not have to successfully complete.
| acquired_txns_nonquic       | `number` | A transaction stream was received via. regular UDP.
| acquired_txns_gossip        | `number` | A gossipped vote was received from a gossip peer.
| dropped_txns                | `number` | The total number of transactions that were dropped from the end of our prior leader slot, until the end of this leader slot. Transactions can be dropped for many reasons, which are given individually below.
| dropped_txns_verify_overrun | `number` | Count of transactions that were dropped because the system could not verify incoming transactions quickly enough, and a verify tile was overrun.
| dropped_txns_verify_failed  | `number` | Count of transactions that were dropped because signature verification failed.
| dropped_txns_dedup_failed   | `number` | Count of transactions that were dropped because they were a duplicate of another recently received transaction.
| dropped_txns_pack_overrun   | `number` | Count of transactions that were dropped because the pack buffer was filled prior to becoming leader, and we had to start dropping lower priority transactions.
| dropped_txns_pack_invalid   | `number` | Count of transactions that were dropped because pack determined they would never execute. Reasons can include the transaction expired, requested too many compute units, or was too large to fit in a block.
| dropped_txns_bank_overrun   | `number` | Count of transactions that were dropped because the system could not execute incoming transactions quickly enough, and pack was overrun while it was trying to execute transaxtions.
| dropped_txns_fee_payer      | `number` | Count of transactions that were dropped because the fee payer did not have enough balance.
| dropped_txns_lookup_table   | `number` | Count of transactions that were dropped because there was an error loading an account lookup table.

**`SlotPublish`**
| Field      | Type      | Description |
|------------|-----------|-------------|
| slot       | `number`  | Identity of the slot, counting up from zero for the first slot in the chain |
| mine       | `boolean` | True if this validator was the leader for this slot. This will never change for a slot once it has been published, and will be aligned with the epoch information |
| skipped    | `boolean` | True if the slot was skipped. The skipped state is the state in the currently active fork of the validator. The skipped state can change if the validator switches active fork, in which case an update will be published in a `slot.update` message |
| status     | `string`  | One of `rooted`, `optimistically_confirmed`, `completed`, or `unpublished`. The state is the state in the currently active fork of the validator. The state can change normally (for example, a completed slot becoming optimisitically confirmed or rooted), or also because the validator switched forks |
| transactions | `number` | Total number of transactions (vote and non-vote) in the block. In some cases, this will be non-zero even for skipped slots, because we might still have learned how many transactions were in the skipped slot. Sometimes though, we never receive information for a skipped slot and it will be zero |
| vote_transactions | `number` | Total number of vote transactions in the block. Will always be less than or equal to `transactions`. The number of non-vote transactions is given by `transactions - vote_transactions`
| failed_transactions | `number` | Total number of failed transactions (vote and non-vote) in the block. Failed transactions are those which are included in the block and were charged fees, but failed to execute successfully. This is different from dropped transations which do not pay fees and are not included in the  block. In some cases, this will be non-zero even for skipped slots, because we might still have learned how many transactions were in the skipped slot. Sometimes though, we never receive information for a skipped slot and it will be zero |
| failed_vote_transactions | `number` | Total number of failed vote transactions. Will always be less than or equal to `vote_transactions`
| compute_units | `number` | Total number of compute units used by the slot
| leader_info | `SlotTxnInfo\|null` | Detailed information about slots which we were the leader for. Will be null if the slot is not `mine` |

Slots are published when they are first determined and the same slot
will never be published twice (it would mean the leader produced two
conflicting blocks, which is slashable and discarded at an earlier layer
of the system).

#### `slot.update`
| frequency   | type   | example     |
|-------------|--------|-------------|
| Live        | `SlotUpdate` | below |

:::details Example

:::

**`SlotUpdate`**
| Field      | Type      | Description |
|------------|-----------|-------------|
| slot       | `number`  | Identity of the slot, counting up from zero for the first slot in the chain |
| skipped    | `boolean` | True if the slot was skipped. The skipped state is the state in the currently active fork of the validator. The skipped state can change if the validator switches active fork, in which case an update will be published in a `slot.update` message |
| status     | `string`  | One of `rooted`, `optimistically_confirmed`, `completed`, or `unpublished`. The state is the state in the currently active fork of the validator. The state can change normally (for example, a completed slot becoming optimisitically confirmed or rooted), or also because the validator switched forks |

A slot was either completed (not confirmed) on the currently active
fork, or it was updated and the state changed. Published immediately
once we know information about the slot. If a slot is skipped, and we
receive the following slot a slot_update will be published first for the
skipped slot. When first connecting the prior 1024 prior slots will be
published, along with up to 1024 additional leader slots prior to that.

A slot can change skipped state or status, usually because it was
optimistically confirmed or became rooted, but sometimes because the
active fork of the valdiator was switched. The typical lifetime of a
slot (assuming no forks occur) is that it first appears with a
`slot_new` message, has a status of `completed` and is either skipped or
not skipped. A few slots later, once two thirds of the network has voted
to confirm the slot, it transitions to `optimistically_confirmed`
status, and then once the slot becomes rooted it transitions to
`rooted`. Once a slot is `rooted` it cannot receive any more slot
updates.

A slot might become `unpublished` if it is present on one fork, and we
switch to a fork where the slot has not yet been completed (the fork we
are switching to is running behind). This is different from a slot
changing from being skipped to unskipped, which is represented by the
`skipped` field. The `transactions`, `failed_transactions`, and other
similar fields can change, but only between the amount if the block for
that slot is not skipped, and zero if it is skipped. A block cannot
change from having, for example, five transactions to having ten.

Certain fields prefixed with `leader_` are information that can only be
derived locally and will only be non-null for slots that are `mine`
(published by this validator). These fields will never chnge with a
`slot_update`, even if we switch to a fork that is skipping our slot.

FORWARDED ??
