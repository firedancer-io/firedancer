---
outline: deep
---

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

## Keeping Up
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
The Solana network may occasionally fork, in which case there will be
more than one active chain. When showing information derived from the
chain, the API will (unless specified otherwise) show information
reflecting the current fork choice of this validator. The current fork
choice of this validator might not be the newest, or the heaviest (most
voted on, or most likely to be chosen) fork.

For example, when showing the transactions per second (TPS) rate under
`summary.estimated_tps`, it will be calculated using the transactions
and block timings observed in the current fork. Similarly, the
`completed_slot` is the last completed slot on the current fork choice.

When the validator switches fork choice, certain of this information
will be republished to make sure it reflects the new fork choice.

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
running on. The cluster is guessed by looking at the genesis hash of the
chain and entrypoints that the validator connects to.

#### `summary.identity_key`
| frequency | type     | example        |
|-----------|----------|----------------|
| Once      | `string` | `"Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF"` |

The public identity key assigned to the running validator, encoded in
base58. Firedancer does not support changing the identity key of the
validator while it is running and this value does not change.

#### `summary.uptime_nanos`
| frequency | type     | example           |
|-----------|----------|-------------------|
| Once      | `number` |  `21785299176204` |

The length of time in nanoseconds that the validator has been running.
Running time is approximately measured since application startup, and
includes time to download a snapshot and catch up to the cluster.

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

Although rare, the `optimistically_confirmed_slot` could decrease if a
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
| Once + Live | `number` | `6048` |

The estimated number of transactions per second the network is running
at. This includes vote, non-vote, and failed transactions. This is a
moving average from the prior 150 slots, or around one minute. For a
more precise view of transactions per second, the client can calculate
it from the stream of new slot data.

#### `summary.estimated_nonvote_tps`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `2145` |

The estimated number of non-vote transactions per second the network is
running at. The sum of the estimated vote and non-vote transactions will
be equal to the estimated total tranasactions per second. This includes
failed transactions. It is a moving average from the prior 150 slots, or
around one minute. For a more precise view of non-vote transactions per
second, the client can calculate it from the stream of new slot data.

#### `summary.estimated_vote_tps`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `3903` |

The estimated number of vote transactions per second the network is
running at. The sum of the estimated vote and non-vote transactions will
be equal to the estimated total tranasactions per second. This includes
failed vote transactions. It is a moving average from the prior 150
slots, or around one minute. For a more precise view of non-vote
transactions per second, the client can calculate it from the stream of
new slot data.

#### `summary.estimated_failed_tps`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + Live | `number` | `2145` |

The estimated number of failed vote and non-vote transactions per second
the network is running at. This is a moving average from the prior 150
slots, or around one minute. For a more precise view of non-vote
transactions per second, the client can calculate it from the stream of
new slot data.

#### `summary.upcoming_slot_txn_info`
| frequency   | type     | example     |
|-------------|----------|-------------|
| Once + 100ms | `SlotTxnInfo` | below |

::: details Example

```json
{
    "topic": "summary",
    "key": "upcoming_slot_txn_info",
    "value": {
        "slot": 18446744073709551615,
        "acquired_txns": 66893,
        "acquired_txns_leftover": 0,
        "acquired_txns_quic": 66767,
        "acquired_txns_nonquic": 1,
        "acquired_txns_gossip": 2,
        "dropped_txns": 49091,
        "dropped_txns_net": {
            "count": 0,
            "breakdown": {
                "net_overrun": 0,
                "net_invalid": 0
            }
        },
        "dropped_txns_quic": {
            "count": 0,
            "breakdown": {
                "quic_overrun": 0,
                "quic_reasm": 0
            }
        },
        "dropped_txns_verify": {
            "count": 49152,
            "breakdown": {
                "verify_overrun": 49152,
                "verify_drop": 0
            }
        },
        "dropped_txns_dedup": {
            "count": 1,
            "breakdown": {
                "dedup_drop": 1
            }
        },
        "dropped_txns_pack": {
            "count": 0,
            "breakdown": {
                "pack_nonleader": 0,
                "pack_invalid": 0,
                "pack_priority": 0
            }
        },
        "dropped_txns_bank": {
            "count": 0,
            "breakdown": {
                "bank_invalid": 0
            }
        },
        "executed_txns_failure": 0,
        "executed_txns_success": 27993,
        "buffered_txns": 3
    }
}
```

:::

The number of transactions of that have been acquired or dropped in the
lead up to our next leader slot. If we are currently in a leader slot
but have not completed it, this includes transactions acquired and
dropped during the leader slot. The values are reset to zero when the
leader slot completes and begin counting up again.  The slot number is
always ULONG_MAX (18446744073709551615) for live txn_info.

##### On-demand query

::: details Example query

```json
{
    "seq": 32,
    "query": "txn_info",
    "args": [
        20
    ]
}
```

:::

::: details Example response

```json
{
    "topic": "summary",
    "key": "upcoming_slot_txn_info",
    "value": {
        "slot": 20,
        "acquired_txns": 66586,
        "acquired_txns_leftover": 0,
        "acquired_txns_quic": 66580,
        "acquired_txns_nonquic": 1,
        "acquired_txns_gossip": 2,
        "dropped_txns": 12280,
        "dropped_txns_net": {
            "count": 0,
            "breakdown": {
                "net_overrun": 0,
                "net_invalid": 0
            }
        },
        "dropped_txns_quic": {
            "count": 0,
            "breakdown": {
                "quic_overrun": 0,
                "quic_reasm": 0
            }
        },
        "dropped_txns_verify": {
            "count": 12288,
            "breakdown": {
                "verify_overrun": 12288,
                "verify_drop": 0
            }
        },
        "dropped_txns_dedup": {
            "count": 2,
            "breakdown": {
                "dedup_drop": 2
            }
        },
        "dropped_txns_pack": {
            "count": 0,
            "breakdown": {
                "pack_nonleader": 0,
                "pack_invalid": 0,
                "pack_priority": 0
            }
        },
        "dropped_txns_bank": {
            "count": 0,
            "breakdown": {
                "bank_invalid": 0
            }
        },
        "executed_txns_failure": 0,
        "executed_txns_success": 28074,
        "buffered_txns": 4
    }
}
```

:::

Requests are sent as JSON messages over the websocket connection.
`seq` is simply an integer identifier that ties response to request.
`query` is a string that specifies the data being queried.
`args` is an array of input arguments.  For a `txn_info` query, it should contain exactly one integer, specifying the slot number.
When the query is invalid, the client will either get no response at all if the backend cannot extract a `seq` number, or, in the case that the backend manages to extract a `seq` number, a response JSON that has the corresponding `seq` and a `null` `response` field rather than an array.
If successful, `response` will be an array containing JSON objects that conform to the same layout as the live stream data.

#### `summary.topology`
| frequency | type       | example |
|-----------|------------|---------|
| Once      | `Topology` | below   |

::: details Example

```json
{
    "topic": "summary",
    "key": "topology",
    "value": {
        "tile_counts": {
            "net": 1,
            "quic": 1,
            "verify": 4,
            "dedup": 1,
            "pack": 1,
            "bank": 2,
            "poh": 1,
            "shred": 2
        }
    }
}
```

:::

**`Topology`**
| Field       | Type    | Description
|-------------|---------|------------
| tile_counts | `{string: number}` | Maps tile name/type to the number of running tiles of this type.

On establishing connection we send the tile topology of the running
Firedancer.

#### `summary.tile_info`
| frequency    | type     | example     |
|--------------|----------|-------------|
| Once + 100ms | `TileInfo` | below     |

::: details Example

```json
{
    "topic": "summary",
    "key": "tile_info",
    "value": {
        "net": {
            "idle": [
                44.97
            ]
        },
        "quic": {
            "idle": [
                90.86
            ]
        },
        "verify": {
            "idle": [
                0.00,
                0.00,
                0.00,
                0.00
            ]
        },
        "dedup": {
            "idle": [
                98.85
            ]
        },
        "pack": {
            "idle": [
                95.51
            ]
        },
        "bank": {
            "idle": [
                35.4,
                98.65
            ]
        },
        "poh": {
            "idle": [
                98.23
            ]
        },
        "shred": {
            "idle": [
                97.43,
                97.47
            ]
        }
    }
}
```

:::

**`TileInfo`**
| Field      | Type    | Description
|------------|---------|------------
| Networking | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| QUIC       | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| Verify     | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| Dedup      | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| Pack       | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| Bank       | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| PoH        | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.
| Shred      | `{"idle": number[]}` | Per-tile idleness percentage since the last sample.

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
| staked_lamports | `number[]` | A list with the same length as the `staked_pubkeys` field. `stake_lamports[ i ]` is the number of lamports staked on the pubkey `staked_pubkeys[ i ]` as of this epoch
| leader_slots | `number[]` | An array, one entry per four slots, of which pubkey in the `leader_pubkeys` array is leader for those slots. On `mainnet-beta` this array will always have a length of 108,000, which is the number of slots in an epoch divded by four.  Leader slots are in groups of four because the leader schedule is generated in such a way as to guarantee each leader gets at least four consecutive slots.  For example, to find the pubkey of the leader in slot 1000 of the epoch, it is `staked_pubkeys[ leader_slots[ 1000/4 ] ]` |

On establishing a connection two epochs are sent to the client. The
current epoch that the cluster is in, and the next epoch. From then on,
new epochs are published live as they are calculated by the validator. For
epoch T, it is published as `end_slot` in epoch T-2 is rooted. The
epoch is speculatively known as soon as `end_slot` in epoch T-2 is
compelted, rather than rooted, but no speculative epoch information is
published until the epoch is finalized by rooting the slot.

### peers
Information about validator peers from the cluster. Peer data is sourced
from gossip, the accounts database, and the on-chain configuration
program. All peer information is authenticated meaning it can only be
reported from the holder of the private key, however not all peer data
is validated or checked for correctness. In particular, data from the
gossip network and the config program is self reported by the validator
and could be empty, corrupt, filled with garbage, or malicious.

Peer information is keyed by the validator identity key. Multiple vote
accounts could in theory use the same identity keypair, although it is
not likely. Not all identities reported will have gossip data, a vote
account, or validator information published to the config program, but
all identities will have at least one of these fields reported. Once an
identity is no longer in these three data sources, it will be removed.

#### `peers.update`
| frequency   | type   | example     |
|-------------|--------|-------------|
| Once + 5s   | `PeerUpdate` | below |

::: details Example

```json
{
    "update": [
        {
            "identity_pubkey": "Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF",
            "gossip": {
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
            "vote": [
                {
                    "vote_pubkey": "8ri9HeWZv4Dcf4BD46pVPjmefzJLpbtfdAtyxyeG4enL",
                    "activated_stake": 5812,
                    "last_vote": 281795801,
                    "root_slot": 281795770,
                    "epoch_credits": 5917,
                    "commission": 5,
                    "delinquent": false
                }
            ],
            "info": {
                "name": "ExampleStake Firedancer 🔥💃",
                "details": "A longer description of the validator, perhaps describing the team behind it or how the node is operated",
                "website": "https://github.com/firedancer-io/firedancer",
                "icon_url": "https://firedancer-io.github.io/firedancer/fire.svg"
            }
        }
    ],
    "remove": [
        { "identity_pubkey": "8ri9HeWZv4Dcf4BD46pVPjmefzJLpbtfdAtyxyeG4enL" }
    ]
}
```

:::

**`PeerUpdateGossip`**
| Field       | Type     | Description
|-------------|----------|------------
| wallclock | `number` | Not entirely sure yet TODO |
| shred_version | `number` | A `u16` representing the shred version the validator is configured to use. The shred version is changed when the cluster restarts, and is used to make sure the validator is talking to nodes that have participated in the same cluster restart |
| version | `string\|null` | Software version being advertised by the validator. Might be `null` if the validator is not gossiping a version, or we have received the contact information but not the version yet. The version string, if not null, will always be formatted like `major`.`minor`.`patch` where `major`, `minor`, and `patch` are `u16`s |
| feature_set | `number\|null` | First four bytes of the `FeatureSet` hash interpreted as a little endian `u32`. Might be `null` if the validator is not gossiping a feature set, or we have received the contact information but not the feature set yet |
| sockets | `[key: string]: string` | A dictionary of sockets that are advertised by the validator. `key` will be one of `gossip`, `repair`, `rpc`, `rpc_pubsub`, `serve_repair`, `serve_repair_quic`, `tpu`, `tpu_forwards`, `tpu_forwards_quic`, `tpu_quic`, `tpu_vote`, `tvu`, or `tvu_forwards`. The value is an address like `<addr>:<port>`: the location to send traffic to for this validator with the given protocol. Address might be either an IPv4 or an IPv6 address |

**`PeerUpdateVoteAccount`**
| Field       | Type     | Description
|-------------|----------|------------
| vote_pubkey | `string` | The public key of vote account, encoded in base58 |
| activated_stake | `number` | The amount of stake in lamports that is activated on this vote account for the current epoch. Warming up or cooling down stake that was delegating during this epoch is not included |
| last_vote | `number\|null` | The last vote by the vote account that was landed on chain, as seen by this validator. If the vote account has not yet landed any votes on the chain this will be `null` |
| root_slot | `number\|null` | The last slot that was rooted by the vote account, based on the vote history. If the vote account has not yet rooted any slots this will be `null` |
| epoch_credits | `number` | The number of credits earned by the vote account during the current epoch |
| delinquent | `boolean` | Whether the vote account is delinquent or not. A vote account is considered delinquent if it has not had a vote land on chain for any of the last 127 (inclusive) confirmed slots, according to this validator. If there have been less than 128 confirmed slots on the chain (it is a new chain), a validator is considered delinquent only if it has not voted yet at all |

**`PeerUpdateInfo`**
| Field       | Type     | Description
|-------------|----------|------------
| name        | `string\|null` | Self reported name of the validator, could be any string or null if there is no name set |
| details     | `string\|null` | Self reported detailed description of the validator, could be any string or null if there is no details set |
| website     | `string\|null` | Self reported website of the validator, could be any string and need not be a valid URI, or could be null if there is no website set |
| icon_url    | `string\|null` | Self reported URL of the validator icon, could be any string and need not be a valid URI, or could be null if there is no icon URI set |

**`PeerUpdate`**
| Field      | Type   | Description
|------------|--------|------------
| identity | `string` | Identity public key of the validator, encoded in base58 |
| gossip | `PeerUpdateGossip\|null` | Information reported for the validator identity over the gossip network. This is authenticated and the gossip node must have been in possession of the private key to publish gossip data as this identity. Gossip information is not validated or checked for correctness and could be set to any values by the peer |
| vote | `PeerUpdateVoteAccount[]` | Information about the vote account(s) associated with this identity key, if there are any. It is extremely unusual for multiple vote accounts to report the same identity key. Vote account information like stake and commission is derived from the accounts on chain and cannot be corrupt, invalid, or incorrect |
| info | `PeerUpdateInfo\|null` | If the validator has published self reported identifying information to the chain. This is authenticated and the operator must have been in possession of the private key to publish info as this identity. Information is not validated or checked for correctness and could be set to any values by the peer |

**`PeerRemove`**
| Field    | Type   | Description
|----------|--------|------------
| identity | `string` | Identity public key of the validator, encoded in base58 |

**`PeersUpdate`**
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
Slots are opportunities for a leader to produce a block. A slot can be
in one of five levels, and in typical operation a slot moves through
them in normal order, starting as `incomplete` and finishing as
`finalized`.

**`SlotLevel`**
| level        | description |
|--------------|-------------|
| `incomplete` | The slot does not exist, either because the chain has not yet reached the slot or because it is still in the process of being replayed by our validator |
| `completed`  | The slot has been fully received and successfully replayed by our validator |
| `optimistically_confirmed` | The slot has been finished and successfully replayed by our validator, and more than two-thirds of stake have voted to confirm the slot |
| `rooted` | Our validator has rooted the slot and considers the slot final. This occurs when 32 subsequent slots have been built on top of it |
| `finalized` | Our validator has rooted the slot, and more than two-thirds of stake has rooted the slot, the network considers it final |

Slots are `incomplete` by default as most slots exist far in the future,
and the `incomplete` level update is not typically published. A slot
will only be explicitly marked as `incomplete` if it exists on the
currently active fork, and we switch to a fork that is slower, which has
not yet reached the slot so it no longer exists.

A slot that has become `rooted` or `finalized` cannot go backwards, and
will not become `incomplete`, `completed`, or `optimistically_confirmed`
(nor will a `finalized` slot become `rooted`), but otherwise all
transitions are valid. An `optimistically_confirmed` slot, for example,
could become `incomplete` if the validator switches to a fork where the
slot has not yet been received, although it should be exceedingly rare.
Switching from `completed` to `incomplete` is more common. Levels can
also be skipped, for example going from `incomplete` straight to
`optimistically_confirmed` (if we switched from a fork that was running
behind, to the cluster majority fork including the slot).

In addition to a level, a slot can also be either skipped or included.
All levels can be in either the skipped or included state, for example
a skipped slot that is `rooted` means that the slot is skipped and
cannot be changed. A slot in the future could be skipped, because we
know it does not build on top of the fork we have currently selected,
in which case it would be both `incomplete` and `skipped`.

Slots are either `mine` (created by this validator), or not, in which
case we are replaying a block from another validator. Slots that are
`mine` contain additional information about our performance creating the
block for that slot.

Some information is only known for blocks that have been replayed
successfully (reached the `completed` state), for example the number of
transactions in the block. This number can still be known even if we are
on a fork which skips that slot. It's possible that we are on a fork
where the slot does not yet exist, a slot could be both `skipped`, and
have a status of `incomplete`, and yet we still know a valid number of
`transactions` in the slot. Once we know information like `transactions`
it does not typically change, although can in extremely rare cases where
a leader publishes two different blocks for their leader slot, and we
initially replay one but the cluster votes on the other one.

**`SlotPublish`**
| Field      | Type      | Description |
|------------|-----------|-------------|
| slot       | `number`  | Identity of the slot, counting up from zero for the first slot in the chain |
| mine       | `boolean` | True if this validator was the leader for this slot. This will never change for a slot once it has been published, and will be aligned with the epoch information |
| skipped    | `boolean` | True if the slot was skipped. The skipped state is the state in the currently active fork of the validator. The skipped state can change if the validator switches active fork |
| level      | `string`  | One of `incomplete`, `completed`, `optimistically_confirmed`, `rooted`, or `finalized` as described above. The state is the state in the currently active fork of this validator. The state can change normally (for example, a completed slot becoming optimisitically confirmed or rooted), or also because the validator switched forks |
| transactions | `number\|null` | Total number of transactions (vote and non-vote) in the block. If the slot is not skipped, this will be non-null, but in some cases it will also be non-null even if the slot was skipped. That's because we replayed the block but selected a fork without it, but we still know how many transactions were in it |
| vote_transactions | `number\|null` | Total number of vote transactions in the block. Will always be less than or equal to `transactions`. The number of non-vote transactions is given by `transactions - vote_transactions`
| failed_transactions | `number\|null` | Total number of failed transactions (vote and non-vote) in the block. Failed transactions are those which are included in the block and were charged fees, but failed to execute successfully. This is different from dropped transations which do not pay fees and are not included in the block |
| compute_units | `number\|null` | Total number of compute units used by the slot |
| leader_info | `SlotTxnInfo\|null` | Detailed information about slots which we were the leader for. Will be null if the slot is not `mine` |

#### `slot.update`
| frequency   | type   | example     |
|-------------|--------|-------------|
| Live        | `SlotUpdate` | below |

:::details Example

:::

**`DropInfo`**
| Field      | Type           | Description |
|------------|----------------|-------------|
| count      | `number`                             | The total number of transactions that were dropped.
| breakdown  | `{key(string): value(number)}`       | A breakdown of various causes of transaction drops.  The values in this breakdown, if available, should sum up to the total count above.  We currently supply the following keys.  The keys are subject to change.

| Field            | Description |
|------------------|-------------|
| "net_overrun"    | Transactions were dropped because the net tile couldn't keep up.  It is technically unclear how many transactions would have been produced by the packets that net couldn't process in time.  So for the purpose of this counter, we pretend that each overrun fragment corresponds to one transaction.  Overruns of the net tile shouldn't happen a lot, if at all, and this makes it abundantly clear when it does happen.  Pay attention to per-tile utilization stats for more evidence of whether the net tile is keeping up with incoming traffic.
| "net_invalid"    | Transactions were dropped because the net tile decided that the network packet was invalid.  It is technically unclear how many transactions would have been produced by the packets that net dropped.  So for the purpose of this counter, we pretend that each overrun fragment corresponds to one transaction.  This makes it abundantly clear if we are receiving invalid packets.
| "quic_overrun"   | Transactions were dropped because the quic tile couldn't keep up and were overrun by the net tile.  It is technically unclear how many transactions would have been produced by the fragments from net that were overrun.  So for the purpose of this counter, we pretend that each overrun fragment corresponds to one transaction.  Overruns of the quic tile shouldn't happen a lot, if at all, and this makes it abundantly clear when it does happen.  Pay attention to per-tile utilization stats for more evidence of whether the quic tile is keeping up with the net tile.
| "quic_reasm"     | Transactions were dropped because the quic tile failed to reassemble a full transaction out of a stream.
| "verify_overrun" | Transactions were dropped because the system could not verify incoming transactions quickly enough, and a verify tile was overrun.  This could be because the verify tiles themselves couldn't keep up.  It could also be due to backpressure from downstream tiles.  The link between the quic tile and the verify tile is unreliable and is allowed to be overrun, whereas the downstream links after the verify tile are reliable and backpressures.
| "verify_drop"    | Transactions were dropped because signature verification failed or because of verify's simple dedup.
| "dedup_drop"     | Transactions were dropped because they were a duplicate of another recently received transaction.
| "pack_nonleader" | Transactions were dropped because the pack buffer was filled prior to becoming leader, and we had to start dropping transactions.
| "pack_invalid"   | Transactions were dropped because pack determined they would never execute.  Reasons can include the transaction expired, requested too many compute units, or was too large to fit in a block.
| "pack_priority"  | Transactions were dropped because the system could not execute incoming transactions quickly enough, and pack had to drop lower priority transactions.
| "bank_invalid"   | Transactions were dropped and didn't make their way into the block.

**`SlotTxnInfo`**
| Field      | Type           | Description |
|------------|----------------|-------------|
| slot                        | `number`    | Slot number. 
| acquired_txns               | `number`    | The total number of transactions that were acquired since the end of our prior leader slot, until the end of this leader slot. Transactions can be acquired for many reasons, which are given individually below.
| acquired_txns_leftover      | `number`    | The transactions were received during or prior to an earlier leader slot, but weren't executed yet so they stayed available to execute in this slot.  This value is sampled and hence changes only at the ending boundary of our leader slots, and stays constant otherwise.
| acquired_txns_quic          | `number`    | A transaction stream was received via QUIC.  The stream does not have to successfully complete.  Streams that fail to complete are counted by dropped_txns_quic_dropped.  A single stream, if successful, produces a single transaction.
| acquired_txns_nonquic       | `number`    | A transaction stream was received via regular UDP.
| acquired_txns_gossip        | `number`    | A gossipped vote transaction was received from a gossip peer.
| dropped_txns                | `number`    | The total number of transactions that were dropped from the end of our prior leader slot, until the end of this leader slot. Transactions can be dropped for many reasons, which are given individually below.
| dropped_txns_net            | `DropInfo`  | Transactions were dropped due to the net tile.
| dropped_txns_quic           | `DropInfo`  | Transactions were dropped due to the quic tile.
| dropped_txns_verify         | `DropInfo`  | Transactions were dropped due to the verify tile.
| dropped_txns_dedup          | `DropInfo`  | Transactions were dropped due to the dedup tile.
| dropped_txns_pack           | `DropInfo`  | Transactions were dropped due to the pack tile.
| dropped_txns_bank           | `DropInfo`  | Transactions were dropped due to the bank tile.
| executed_txns_failure       | `number`    | Transactions made their way into the block but execution failed.
| executed_txns_success       | `number`    | Transactions made their way into the block and execution succeeded.
| buffered_txns               | `number`    | Transactions currently buffered.  Roughly, `acquired_txns = dropped_txns + executed_txns_failure + executed_txns_success + buffered_txns`.
