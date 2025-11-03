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
    [tiles.gui]
        listen_port = 80
```

:::

The port to connect to is specified in the validator configuration TOML
file.

The API is split into various topics which will be streamed to any and
all connected clients.

## Compression
If configured properly, the server can optionally compress messages
larger than 200 bytes. In order to enable this feature, the client must
specify the `compress-zstd` subprotocol in the opening websocket
handshake.

::: code-group

```js [client.js]
client = new WebSocket("ws://localhost:80/websocket", protocols=['compress-zstd']);
client.binaryType = "arraybuffer";
```

```
ws.onmessage = function onmessage(ev: MessageEvent<unknown>) {
  if (typeof ev.data === 'string') {
    ... parse string
  } else if (ev.data instanceof ArrayBuffer) {
    ... decompress then parse
  }
};
```

:::

In order to distinguish between compressed and non-compressed messages,
the server will send compressed messages as a binary websocket frame
(i.e. opcode=0x2) and regular messages as a text websocket frame (i.e.
opcode=0x1).

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
| *Once*                      | The message is published only once, immediately after a connection is established |
| *Live*                      | The message is published live, immediately after the underlying data in the validator is changed |
| *Request*                   | The message is published in response to a specific client request |
| *1s*                        | The message is republished at regular one second intervals |
| *Once* + *Live*             | The message is published immediately after a connection is established, and then republished whenever the data is changed |

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

## Queries
Some messages are published on-demand in response to a request, and are
marked with a frequency of *Request*. To issue a query, send a websocket
frame to the server with an envelope like:

```json
{
    "topic": "slot",
    "key": "query",
    "id": 42,
    "params": {
        "slot": 285291521
    }
}
```

The `topic` and `key` correspond to the request method you wish to call.
The `id` value is an unsigned integer (must fit in `u64`) that will be
echoed back in the envelope of the response object. `params` are request
specific parameters documented for each on-demand query.

If the client issues a malformed request, it will be forcibly
disconnected. If the client issues a well-formed request for data that
the validator does not have (for example, an old slot), the query will
receive a response with a value of `null`.

```json
{
    "topic": "slot",
    "key": "query",
    "id": 42,
    "value": null
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

#### `summary.ping`
| frequency   | type           | example |
|-------------|----------------|---------|
| *Request*   | `null`         | below   |

Sends a ping to the server, which will respond with a pong.  This is an
application level ping/pong and not a WebSocket control frame.

::: details Example

```json
{
    "topic": "summary",
    "key": "ping",
    "id": 42,
}
```

```json
{
    "topic": "summary",
    "key": "ping",
    "id": 42,
    "value": null
}
```

:::

#### `summary.version`
| frequency | type     | example         |
|-----------|----------|-----------------|
| *Once*    | `string` | `"0.106.11814"` |

The current version of the running validator.

#### `summary.cluster`
| frequency       | type     | example        |
|-----------------|----------|----------------|
| *Once* + *Live* | `string` | `"mainnet-beta"` |

One of `mainnet-beta`, `devnet`, `testnet`, `pythtest`, `pythnet`,
`development`, or `unknown`. Indicates the cluster that the validator is
likely to be running on. The cluster is guessed by looking at the
genesis hash of the chain and comparing it to known cluster genesis
hashes. The cluster cannot change once the validator is running, but
because it may not be known when the validator first starts, you
might get two cluster messages. One `unknown` immediately when the
validator is booted, and then a message with `mainnet` (or other
known cluster) when the validator learns its cluster from a downloaded
snapshot.

#### `summary.commit_hash`
| frequency | type     | example         |
|-----------|----------|-----------------|
| *Once*    | `string` | `"78eefec7c779ef138aaaf4afe76cd6eaf4807006"` |

The commit hash used to build the validator.

#### `summary.identity_key`
| frequency       | type     | example        |
|-----------------|----------|----------------|
| *Once* + *Live* | `string` | `"Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF"` |

The public identity key assigned to the running validator, encoded in
base58. Firedancer support changing the identity key of the validator
while it is running through a `set-identity` command, and if this
happens a new `identity_key` will be published.

Summary information in this API is tied to the validator instance and
not the identity key, for example, the skip rate is the skip rate of all
blocks produced by this validator, regardless of what identity key they
were published with. The `mine` field of blocks similarly indicates if
this validator published the block, not whether it had the same identity
key as the validator has now.

Because of this, when changing identity key, no other information will
be republished. It will simply continue counting for blocks published
with the new key.

#### `summary.vote_state`
| frequency       | type     | example  |
|-----------------|----------|----------|
| *Once* + *Live* | `string` | `voting` |

One of `voting`, `non-voting`, or `delinquent`, indicating the current
vote status of the validator. The validator considers itself delinquent
if the last vote it has landed on its own currently chosen fork is 150
or more slots behind that fork.

#### `summary.vote_distance`
| frequency       | type     | example |
|-----------------|----------|---------|
| *Once* + *Live* | `number` | `2`     |

A number showing the distance between the highest slot the validator has
landed a vote for, and the current highest replayed slot on the
validators fork choice. A distance of more than 150 means the validator
is considered delinquent.

#### `summary.turbine_slot`
| frequency       | type           | example |
|-----------------|----------------|---------|
| *Once* + *Live* | `number\|null` | `100`   |

The largest slot that is known by the validator to have been published
to the blockchain. This is typically going to be the largest slot we've
seen in a received turbine shred, but can also be a slot for which we
were just leader. During boot, the max known slot may not be known yet
if we haven't received any shreds. In this case this message will
publish `null`.

It is worth nothing that `turbine_slot` might be momentarily
inaccurate (too large). If this happens, it should self-correct after
about 4.8 seconds. This happens because `turbine_slot` is derived from
the header on incoming shreds. In the worst case, a malicious leader
shred can create an arbitrarily large slot on a new fork. All slot
numbers received from shreds, including any malicious shreds, are
forgotten after 4.8 seconds. This ensures our estimate self-corrects
over time.

NOTE: this message is only supported on the Firedancer client, the
Frankendancer client will always publish `null` for this message

#### `summary.repair_slot`
| frequency       | type           | example |
|-----------------|----------------|---------|
| *Once* + *Live* | `number\|null` | `100`   |

The largest slot for which the validator sent out a repair request.
This slot has the same problem as `summary.turbine_slot` (it might
sporadically become unboundedly large) and provides the same guarantees.

#### `summary.caught_up_slot`
| frequency       | type           | example |
|-----------------|----------------|---------|
| *Once* + *Live* | `number\|null` | `100`   |

The slot when this validator caught up to the tip of the blockchain.
This slot is recorded when replay slot is within 4 slots (one leader
rotation) of `summary.turbine_slot`. If the WebSocket client connects
before the validator has caught up, then this message will be published
with `null`. The message would then be published once when the validator
actually catches up.

Since `summary.turbine_slot` can be sometimes arbitrarily larger that
the ground truth, that affects the accuracy of the catch-up slot as
well. If a maliciously large shred arrives within 3 leader rotations of
the validator catchup event, then `summary.turbine_slot` will be
wrong, and `summary.slot_caught_up` will not be recorded until after 4.8
seconds when the malicious slot is forgotten. Functionally, this means
that `summary.slot_caught_up` could be arbitrarily larger than the true
catchup slot. The likelihood of this is low, and decreases for larger
errors.

NOTE: this message is only supported on the Firedancer client, the
Frankendancer client will always publish `null` for this message

#### `summary.catch_up_history`
| frequency | type             | example   |
|-----------|------------------|-----------|
| *Once*    | `CatchUpHistory` | see below |

This validator records a history of all slots that were received from
turbine as well as slots for which a repair request was made while it is
catching up.  After catching up, slots are no longer recorded in this
history.

::: details Example

```json
{
	"topic": "summary",
	"key": "catch_up_history",
	"value": {
        "repair": [11, 12, 13, ...],
        "turbine": [21, 22, 23, ...]
	}
}
```

:::

#### `summary.startup_time_nanos`
| frequency | type     | example             |
|-----------|----------|---------------------|
| *Once*    | `string` |  `"1719910299914232"` |

A UNIX timestamp in nanoseconds of the validator's startup. The
timestamp is taken by the gui tile during boot, so it occurs before the
validator downloads a snapshot and fully catches up to the cluster.

#### `summary.startup_progress`
| frequency       | type              | example |
|-----------------|-------------------|---------|
| *Once* + *Live* | `StartupProgress` |  below  |

Information about the validators progress in starting up. There are
various stages of starting up which the validator goes through in order
before it is ready. Typically, the phase will only move forward except
for a special case: the validator can go from
`downloading_full_snapshot` back to `searching_for_full_snapshot` if the
snapshot peer found is downloading too slow and we would like to try a
different one (and the same applies for the incremental snapshot).

The phases are,

| Phase                              | Description |
|------------------------------------|-------------|
| initializing                       | The validator has just booted and has not yet started looking for RPC services to download snapshots from |
| searching_for_full_snapshot        | The validator is searching over gossip for an RPC node to download a full snapshot from |
| downloading_full_snapshot          | The validator has found an RPC peer to download a full snapshot from and the download is now in progress |
| searching_for_incremental_snapshot | The validator is searching over gossip for an RPC node to download an incremental snapshot from |
| downloading_incremental_snapshot   | The validator has found an RPC peer to download an incremental snapshot from and the download is now in progress. The incremental snapshot is a smaller snapshot taken more regularly, which builds on top of a full snapshot |
| cleaning_blockstore                | Removes stale data from the blockstore |
| cleaning_accounts                  | Removes stale data from the accounts database |
| loading_ledger                     | Loads the ledger data from disk into memory |
| processing_ledger                  | The blockstore is replayed to get to the current slot |
| starting_services                  | RPC, the leader TPU, the replay TVU, snapshots, and all other services are being started |
| halted                             | The validator is halted at a specific slot because of a development option provided at boot, and will not proceed further |
| waiting_for_supermajority          | The validator is waiting at a specific slot for a supermajority of stake to come online on the gossip network so it can proceed. This is used during cluster restarts |
| running                            | The validator is fully booted and running normally |

::: details Example

```json
{
	"topic": "summary",
	"key": "startup_progress",
	"value": {
		"phase": "downloading_full_snapshot",
		"downloading_full_snapshot_peer": "145.40.125.99:8899",
		"downloading_full_snapshot_slot": 291059318,
		"downloading_full_snapshot_elapsed_secs": 24.01,
		"downloading_full_snapshot_remaining_secs": 254.26,
		"downloading_full_snapshot_throughput": 17193374.00,
		"downloading_full_snapshot_total_bytes": 4746970624,
		"downloading_full_snapshot_current_bytes": 375455480,
		"downloading_incremental_snapshot_peer": null,
		"downloading_incremental_snapshot_slot": null,
		"downloading_incremental_snapshot_elapsed_secs": null,
		"downloading_incremental_snapshot_remaining_secs": null,
		"downloading_incremental_snapshot_throughput": null,
		"downloading_incremental_snapshot_total_bytes": null,
		"downloading_incremental_snapshot_current_bytes": null,
		"ledger_slot": null,
		"ledger_max_slot": null,
		"waiting_for_supermajority_slot": null,
		"waiting_for_supermajority_stake_percent": null
	}
}
```

:::

**`StartupProgress`**
| Field                                           | Type           | Description |
|-------------------------------------------------|----------------|-------------|
| phase                                           | `string`       | One of `initializing`, `searching_for_full_snapshot`, `downloading_full_snapshot`, `searching_for_incremental_snapshot`, `downldownloading_incremental_snapshot`, `cleaning_blockstore`, `cleaning_accounts`, `loading_ledger`, `processing_ledger`, `starting_services`, `halted`, `waiting_for_supermajority`, or `running` |
| downloading_full_snapshot_slot                  | `number\|null` | If the phase is at least `downloading_full_snapshot` or later, this is the slot that is being (or was) downloaded from the snapshot provider. Otherwise it is `null` |
| downloading_full_snapshot_peer                  | `string\|null` | If the phase is at least `downloading_full_snapshot` or later, this is the peer RPC address that the snapshot is being downlaoded from. Otherwise it is `null` |
| downloading_full_snapshot_elapsed_secs          | `number\|null` | If the phase is at least `downloading_full_snapshot` or later, this is the duration, in seconds that the validator has been downloading the snapshot for. Otherwise it is `null` |
| downloading_full_snapshot_remaining_secs        | `number\|null` | If the phase is at least `downloading_full_snapshot` or later, this is the estimated duration, in seconds that the validator has left to download the snapshot. Otherwise it is `null` |
| downloading_full_snapshot_throughput            | `number\|null` | If the phase is currently `downloading_full_snapshot`, this is the current download throughput in bytes per second. Otherwise it is `null` |
| downloading_full_snapshot_total_bytes           | `number\|null` | If the phase is at least `downloading_full_snapshot` or later, this is the total size of the snapshot being downloaded in bytes. Otherwise it is `null` |
| downloading_full_snapshot_current_bytes         | `number\|null` | If the phase is at least `downloading_full_snapshot` or later, this is the current size of the snapshot that has been downloaded in bytes. Otherwise it is `null` |
| downloading_incremental_snapshot_slot           | `number\|null` | If the phase is at least `downloading_incremental_snapshot` or later, this is the slot that is being (or was) downloaded from the snapshot provider. Otherwise it is `null` |
| downloading_incremental_snapshot_peer           | `string\|null` | If the phase is at least `downloading_incremental_snapshot` or later, this is the peer RPC address that the snapshot is being downlaoded from. Otherwise it is `null` |
| downloading_incremental_snapshot_elapsed_secs   | `number\|null` | If the phase is at least `downloading_incremental_snapshot` or later, this is the duration, in seconds that the validator has been downloading the snapshot for. Otherwise it is `null` |
| downloading_incremental_snapshot_remaining_secs | `number\|null` | If the phase is at least `downloading_incremental_snapshot` or later, this is the estimated duration, in seconds that the validator has left to download the snapshot. Otherwise it is `null` |
| downloading_incremental_snapshot_throughput     | `number\|null` | If the phase is currently `downloading_incremental_snapshot`, this is the current download throughput in bytes per second. Otherwise it is `null` |
| downloading_incremental_snapshot_total_bytes    | `number\|null` | If the phase is at least `downloading_incremental_snapshot` or later, this is the total size of the snapshot being downloaded in bytes. Otherwise it is `null` |
| downloading_incremental_snapshot_current_bytes  | `number\|null` | If the phase is at least `downloading_incremental_snapshot` or later, this is the current size of the snapshot that has been downloaded in bytes. Otherwise it is `null` |
| ledger_slot                                     | `number\|null` | If the phase is at least `processing_ledger` or later, this is the current slot that we have replayed up to in the ledger. Otherwise it is `null` |
| ledger_max_slot                                 | `number\|null` | If the phase is at least `processing_ledger` or later, this is the maximum slot we need to replay up to in the ledger. Otherwise it is `null` |
| waiting_for_supermajority_slot                  | `number\|null` | If the phase is at least `waiting_for_supermajority` or later, and we are stopped waiting for supermajority, this is the slot that we are stopped at. Otherwise it is `null` |
| waiting_for_supermajority_stake_percent         | `number\|null` | If the phase is at least `waiting_for_supermajority` or later, and we are stopped waiting for supermajority, this is the percentage of stake that is currently online and gossiping to our node. Otherwise it is `null`. The validator will proceed with starting up once the stake percent reaches 80 |

#### `summary.boot_progress`
| frequency       | type              | example |
|-----------------|-------------------|---------|
| *Once* + *Live* | `BootProgress`    |  below  |

Information about the validators progress in starting up. There are
various stages of starting up which the validator goes through in order
before it is ready.

The phases form a state machine, and the validator can progress through
them in interesting ways,

```txt
                   +--+      +------------------------------+
                   |  v      |                              v
joining_gossip -> loading_full_snapshot -> catching_up -> running
                        v        ^          ^
             loading_incremental_snapshot --+
```

Some interesting transitions are,

 * The validator may skip joining gossip and go straight to loading a
   snapshot if it was instructed to load from a specific file or source
 * The full snapshot may be restarted many times, if a snapshot is
   corrupt or fails to download
 * The incremental snapshot may be skipped if the full snapshot is
   sufficient
 * The incremental snapshot may be abandoned and the phase returns to a
   new full snapshot, if the incremental snapshot is corrupt or fails to
   download
 * The validator may skip the catching up phase if the snapshot brings
   it fully up to date, although this is extremely rare and unlikely to
   happen on mainnet except if the chain is halted or restarting

| Phase                              | Description |
|------------------------------------|-------------|
| joining_gossip                     | The validator has just booted and has started looking for RPC services to download snapshots from |
| loading_full_snapshot              | The validator has found an RPC peer to download a full snapshot, or a local snapshot to read from disk.  The snapshot is being downloaded, decompressed, and inserted into the account database |
| loading_incremental_snapshot       | The validator has found an RPC peer to download a incremental snapshot.  The snapshot is being downloaded, decompressed, and inserted into the client database |
| catching_up                        | The validator is replaying / repairing an missing slots up to the move tip of the chain |
| running                            | The validator is fully booted and running normally |

::: details Example

```json
{
	"topic": "summary",
	"key": "boot_progress",
    "value": {
        "phase": "loading_full_snapshot",
        "joining_gossip_elapsed_seconds": 5,
        "loading_full_snapshot_elapsed_seconds": 7.8,
        "loading_full_snapshot_reset_count": 0,
        "loading_full_snapshot_slot": 359396820,
        "loading_full_snapshot_total_bytes_compressed": "5004677960",
        "loading_full_snapshot_read_bytes_compressed": "960692224",
        "loading_full_snapshot_read_path": "/path/to/snapshot-359396820-EuXH88VnugHwoeusjHFXAg1Fp1VucJp2Z3SSjmrpBcam.tar.zst",
        "loading_full_snapshot_decompress_bytes_decompressed": "4961009663",
        "loading_full_snapshot_decompress_bytes_compressed": "826495323",
        "loading_full_snapshot_insert_bytes_decompressed": "4864409599",
        "loading_full_snapshot_insert_accounts": 10634591,
        "loading_incremental_snapshot_elapsed_seconds": null,
        "loading_incremental_snapshot_reset_count": null,
        "loading_incremental_snapshot_slot": null,
        "loading_incremental_snapshot_total_bytes_compressed": null,
        "loading_incremental_snapshot_read_bytes_compressed": null,
        "loading_incremental_snapshot_read_path": null,
        "loading_incremental_snapshot_decompress_bytes_decompressed": null,
        "loading_incremental_snapshot_decompress_bytes_compressed": null,
        "loading_incremental_snapshot_insert_bytes_decompressed": null,
        "loading_incremental_snapshot_insert_accounts": null,
        "catching_up_elapsed": null,
        "catching_up_first_replay_slot": null,
    }
}
```

:::

**`BootProgress`**
| Field                                                                 | Type            | Description |
|-----------------------------------------------------------------------|-----------------|-------------|
| phase                                                                 | `string`        | One of `joining_gossip`, `loading_full_snapshot`, `loading_incremental_snapshot`, `catching_up`, or `running`. This indicates the current phase of the boot process |
| joining_gossip_elapsed_seconds                                        | `number`        | If the phase is `joining_gossip`, this is the duration, in seconds, spent joining the gossip network |
| loading_{full\|incremental}_snapshot_elapsed_seconds                  | `number`        | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the elapsed time, in seconds, spent reading (either downloading or reading from disk) the snapshot since the last reset |
| loading_{full\|incremental}_snapshot_reset_count                      | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot` or later, this is the number of times the load for the snapshot failed and the phase was restarted from scratch. A snapshot load may fail due to an unreliable or underperforming network connection. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_slot                             | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot` or later, this is the slot of the snapshot being loaded. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_total_bytes_compressed           | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the (compressed) total size of the snapshot being loaded, in bytes. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_read_bytes_compressed            | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the (compressed) total number of bytes read from disk for the snapshot. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_read_path                        | `string\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is either the remote url or local file path from which the snapshot is being read. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_decompress_bytes_decompressed    | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the (decompressed) number of bytes processed by decompress from the snapshot so far. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_decompress_bytes_compressed      | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the (compressed) number of bytes processed by decompress from the snapshot so far. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_insert_bytes_decompressed        | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the (decompressed) number of bytes processed from the snapshot by the snapshot insert time so far. Otherwise, `null` |
| loading_{full\|incremental}_snapshot_insert_accounts                  | `number\|null`  | If the phase is at least `loading_{full\|incremental}_snapshot`, this is the current number of inserted accounts from the snapshot into the validator's accounts database. Otherwise, `null` |
| catching_up_elapsed_seconds                                           | `number`        | If the phase is `catching_up`, this is the duration, in seconds, the validator has spent catching up to the current slot |
| catching_up_first_replay_slot                                         | `number`        | If the phase is `catching_up`, this is the first slot that exited the replay pipeline after booting |


#### `summary.schedule_strategy`
| frequency  | type     | example |
|------------|----------|---------|
| *Once*     | `string` | below   |

An description of the configured operational mode of the transaction
scheduler. The following modes are possible:

- "perf"
- "balanced"
- "revenue"

The scheduler mode determines how eager / greedy the scheduler is when
filling a block.  "perf" means the scheduler tries to fill the block as
quickly as possible while "revenue" means the scheduler will wait as
long as possible before filling the block. "balanced" is somewhere in
the middle.

::: details Example

```json
{
    "topic": "summary",
    "key": "schedule_strategy",
    "value": "balanced"
}
```

:::

#### `summary.tiles`
| frequency  | type     | example |
|------------|----------|---------|
| *Once*     | `Tile[]` | below   |

Information about the tile topology of Firedancer. This is a list of
tiles in the system.

**`Tile`**
| Field   | Type    | Description
|---------|---------|------------
| kind    | `string` | What kind of tile it is. One of `net`, `sock`, `quic`, `verify`, `dedup`, `pack`, `bank`, `poh`, `shred`, `store`, `sign`, `plugin`, or `http`.
| kind_id | `number` | The index of the tile in its kind. For example, if there are four `verify` tiles they have `kind_id` values of 0, 1, 2, and 3 respectively.

::: details Example

```json
{
    "topic": "summary",
    "key": "tiles",
    "value": [
        { "tile": "net", "kind_id": 0 },
        { "tile": "quic", "kind_id": 0 },
        { "tile": "verify", "kind_id": 0 },
        { "tile": "verify", "kind_id": 1 },
        { "tile": "verify", "kind_id": 2 },
        { "tile": "verify", "kind_id": 3 },
        { "tile": "dedup", "kind_id": 0 },
        { "tile": "pack", "kind_id": 0 },
        { "tile": "bank", "kind_id": 0 },
        { "tile": "bank", "kind_id": 1 },
        { "tile": "poh", "kind_id": 0 },
        { "tile": "shred", "kind_id": 0 },
        { "tile": "store", "kind_id": 0 },
        { "tile": "sign", "kind_id": 0 },
        { "tile": "plugin", "kind_id": 0 }
        { "tile": "http", "kind_id": 0 }
    ]
}
```

:::

#### `summary.identity_balance`
| frequency      | type     | example      |
|----------------|----------|--------------|
| *Once* + *60s* | `string` | `"21125572"` |

Account balance of this validators identity account in lamports. The
balance is on the highest slot of the currently active fork of the validator.

#### `summary.vote_balance`
| frequency      | type     | example      |
|----------------|----------|--------------|
| *Once* + *60s* | `string` | `"21125572"` |

Account balance of this validators vote account in lamports. The balance
is on the highest slot of the currently active fork of the validator.

#### `summary.root_slot`
| frequency       | type     | example     |
|-----------------|----------|-------------|
| *Once* + *Live* | `number` | `275138349` |

The last slot that was rooted. Rooted slots are fully confirmed and
irreversible, and the rooted slot will never decrease as switching fork
cannot unroot the slot. The number will not always increase by one, as
skipped slots do not update the root slot. For example, if the root slot
goes from `1001` to `1003` it means slot `1002` was skipped.

#### `summary.optimistically_confirmed_slot`
| frequency       | type     | example     |
|-----------------|----------|-------------|
| *Once* + *Live* | `number` | `275138349` |

The highest slot on the current fork that was optimistically confirmed.
Optimistic confirmation means that over two-thirds of stake have voted
to confirm the slot, and it is unlikely (although still possible, if
validators switch vote) to not become rooted.

Although rare, the `optimistically_confirmed_slot` could decrease if a
validator switches to another fork that does not have this slot.

#### `summary.completed_slot`
| frequency       | type     | example     |
|-----------------|----------|-------------|
| *Once* + *Live* | `number` | `275138349` |

The highest completed slot on the current fork choice of the validator.
The completed slot may decrease if the validator is switching forks, or
could stay the same for much more than the slot production time (400
milliseconds) if leaders are offline and not producing blocks.

#### `summary.estimated_slot`
| frequency       | type     | example     |
|-----------------|----------|-------------|
| *Once* + *Live* | `number` | `275138349` |

The estimated slot is the same as the completed slot, except it still
progresses forward even if the current leaders are skipping (not
producing) their slot. For example, if the last completed slot was
`1001` and it has been 800 milliseconds since that slot, the estimated
slot is likely to be `1003`.

#### `summary.estimated_slot_duration_nanos`
| frequency       | type     | example     |
|-----------------|----------|-------------|
| *Once* + *Live* | `number` | `450267129` |

The estimated duration of each slot on the network. This is a moving
average from the prior 750 slots, or around five minutes. Live here
means the estimate is republished whenever it changes, which is when
a new slot is confirmed on the currently active fork.

#### `summary.skip_rate`
| frequency       | type       | example                                 |
|-----------------|------------|-----------------------------------------|
| *Once* + *Live* | `SkipRate` | `{"epoch": 522, "skip_rate": 0.456172}` |

The skip rate of an epoch is the ratio of `skipped_slots/total_slots`
for our leader slots in that epoch.  The skip rate is only known for
slots that have happened since the validator was started, and we do
not incorporate slots from before boot, as we cannot know if they were
skipped or not.  If this validator has not had any leader slots since it
was booted, the skip rate reported will be zero.

The skip rate is specific to this running validator, and not any
given identity key. If the validator identity is changed with
`set-identity`, the skip rate will remain the same at first, and then
start incorporating skips for the new identity key.

**`SkipRate`**
| Field     | Type     | Description |
|-----------|----------|-------------|
| epoch     | `number` | The epoch that the skip rate is being published for |
| skip_rate | `number` | The updated skip rate for the provided epoch |

#### `summary.tps_history`
| frequency | type         | example |
|-----------|--------------|---------|
| *Once*    | `number[][]` | `[[5492.2,4578.841,914.24,0],[6134.44419,5149.23,985,0]]` |

A list of the last 150 TPS samples taken by the validator. Currently the
spacing between samples is poorly defined, but it's roughly one sample
per slot. Each element in the outer array represents a sample, and the
outer array will have up to 150 samples. Each sample will have 4
elements, which are `total_tps`, `vote_tps`, `nonvote_success_tps`, and
`nonvote_failed_tps` as defined below. Samples are listed from oldest
first.

#### `summary.estimated_tps`
| frequency       | type     | example     |
|-----------------|----------|-------------|
| *Once* + *Live* | `number` | below |

The estimated number of transactions per second the network is running
at. This includes total, vote, non-vote successful, and non-vote failed
transactions. This is a moving average from the prior 150 slots, or
around one minute. For a more precise view of transactions per second,
the client can calculate it from the stream of new slot data.

The sum of the non-vote successful and the non-vote failed transactions
represent the number of non-vote transactions. The sum of the estimated
vote and non-vote transactions will be equal to the estimated total
transactions per second.

::: details Example

```json
{
    "topic": "summary",
    "key": "estimated_tps",
    "value": {
        "total": 8348,
        "vote": 6875,
        "nonvote_success": 1473,
        "nonvote_failed": 0
    }
}
```

#### `summary.live_txn_waterfall`
| frequency        | type               | example |
|------------------|--------------------|---------|
| *Once* + *100ms* | `LiveTxnWaterfall` | below   |

::: details Example

```json
{
    "topic": "summary",
    "key": "live_txn_waterfall",
    "value": {
        "next_leader_slot": 285228774,
        "waterfall": {
            "in": {
                "pack_cranked": 1,
                "pack_retained": 2011,
                "resolv_retained": 13,
                "quic": 66767,
                "udp": 1054,
                "gossip": 517
            },
            "out": {
                "net_overrun": 1,
                "quic_overrun": 44,
                "quic_frag_drop": 13,
                "quic_abandoned": 15,
                "tpu_quic_invalid": 16,
                "tpu_udp_invalid": 17,
                "verify_overrun": 2059,
                "verify_parse": 14,
                "verify_failed": 4092,
                "verify_duplicate": 128,
                "dedup_duplicate": 87,
                "resolv_lut_failed": 4,
                "resolv_expired": 0,
                "resolv_ancient": 2,
                "resolv_no_ledger": 0,
                "resolv_retained": 0,
                "pack_invalid": 6,
                "pack_expired": 2,
                "pack_retained": 1985,
                "pack_overrun": 54,
                "pack_priority": 58422,
                "bank_invalid": 14,
                "block_success": 2976,
                "block_fail": 419
            }
        }
    }
}
```

:::

**`LiveTxnWaterfall`**
| Field            | Type           | Description
|------------------|----------------|------------
| next_leader_slot | `number\|null` | The next leader slot that the transactions are being accumulated for |
| waterfall        | `TxnWaterfall` | A waterfall of transactions received since the end of the previous leader slot |

A transaction waterfall describes the transactions that are received
before and during a leader slot, and what happened to them. A typical
waterfall is that we acquire transactions from QUIC or gossip in the
lead up to (before) our leader slot, drop a few of them that fail to
verify, drop a few duplicates, drop some low priority ones that won't
fit into our block, and then successfully place some transactions into
a block. Transactions can also be received and dropped during the leader
slot, but it's important to note: the waterfall shows statistics for all
transactions since the end of our last leader slot. These are
transactions that are now eligible for placement into the next one.

The waterfall is typically useful when viewing what happened in a past
leader slot: we want to know where transactions came from, and for what
reasons they didn't make it into the block. For example, if we received
100,000 transactions leading up to the slot, but only 6000 made it in,
what happened to the other 94,000?

The live waterfall is a special case: it's for the next slot of the
validator, rather than one that is in the past. Because the slot hasn't
happened yet, we know certain information: how many transactions we have
received so far from users that we could pack into our next block, how
many have expired, how many failed to verify, and so on, but we probably
won't know how many made it into the block yet, as we do when looking at
the waterfall for a block that has been published.

The waterfall should generally be balanced: total transactions in and
total transactions out will be the roughly the same, but not always
strictly. Transactions in could be more or less than transactions out
due to sampling jitter. When subtracting, be sure to account for
potential underflow.

#### `summary.live_tile_primary_metric`
| frequency        | type                    | example |
|------------------|-------------------------|---------|
| *Once* + *100ms* | `LiveTilePrimaryMetric` | below   |

::: details Example

```json
{
    "topic": "summary",
    "key": "live_tile_primary_metric",
    "value": {
        "next_leader_slot": 285228774,
        "tile_primary_metric": {
            "quic": 3,
            "bundle_rtt_smoothed_millis": 30,
            "bundle_rx_delay_millis_p90": 101,
            "net_in": 37803082,
            "net_out": 4982399,
            "verify": 0,
            "dedup": 0,
            "bank": 89407,
            "pack": 0,
            "poh": 0,
            "shred": 0,
            "store": 0
        }
    }
}
```

:::

**`LiveTilePrimaryMetric`**
| Field               | Type                | Description
|---------------------|---------------------|------------
| next_leader_slot    | `number\|null`      | The next leader slot |
| tile_primary_metric | `TilePrimaryMetric` | Per-tile-type primary metrics.  Some of these are point-in-time values (P), and some are 1-second moving window averages (W) |

**`TilePrimaryMetric`**
| Field                      | Type     | Description |
|----------------------------|----------|-------------|
| net_in                     | `number` | Network ingress bytes per second (W) |
| quic                       | `number` | Active QUIC connections (P) |
| bundle_rtt_smoothed_millis | `number` | The round-trip time for grpc messages sent to the bundle server.  These are mostly ping-pong messages.  An exponential moving average ( avg = 1/8 val + 7/8 avg ) is used to filter the signal (W) |
| bundle_rx_delay_millis_p90 | `number` | An estimate of the 90th percentile of the one-way delay of a bundle dispatched from the bundle server (W) |
| verify                     | `number` | Fraction of transactions that failed sigverify (W) |
| dedup                      | `number` | Fraction of transactions deduplicated (W) |
| pack                       | `number` | Fraction of pack buffer filled (P) |
| bank                       | `number` | Execution TPS (W) |
| net_out                    | `number` | Network egress bytes per second (W) |


#### `summary.live_tile_timers`
| frequency        | type       | example |
|------------------|------------|---------|
| *Once* + *10ms*  | `number[]` | below   |

Live tile timers is an array, one entry per tile, of how idle the tile
was in the preceding 10 millisecond sampling window. A value of `-1`
indicates no sample was taken in the window, typically because the tile
was context switched out by the kernel or it is hung.

The tiles appear in the same order here that they are reported when you
first connect by the `summary.tiles` message.

::: details Example

```json
{
    "topic": "summary",
    "key": "live_tile_timers",
    "value": [
        44.972112412,
        90.12,
        5.42148,
        6.24870,
        5.00158,
        8.1111556,
        76.585,
        44.225,
        12.98,
        16.2981,
        43.857,
        14.1,
        3.15716,
        93.2456,
        87.998
    ]
}
```

:::

### block_engine
Block engines are providers of additional transactions to the validator,
which are configurable by the operator. The validator may not be
configured to use any block engines, in which case no update will be
provided. For now, at most one block engine can be configured, and the
name and url will not change during the lifetime of the validator.

#### `block_engine.update`
| frequency       | type          | example |
|-----------------|---------------|-------- |
| *Once* + *Live* | `BlockEngine` | below   |

::: details Example

```json
{
    "name": "jito",
    "url": "https://mainnet.block-engine.jito.wtf",
    "status": "connected"
}
```

:::

**`BlockEngine`**
| Field      | Type     | Description |
|------------|----------|-------------|
| name       | `string` | A short, descriptive name for the block engine |
| url        | `string` | An HTTP URL for the block engine which the validator client connects to |
| status     | `string` | One of `disconnected`, `connecting`, or `connected` indicating the state of the connection to the block engine |

### epoch
Information about an epoch. Epochs are never modified once they have
been determined, so the topic only publishes a continuous stream of new
epochs as they are known. When connecting, the current and next epoch
are known, unless the validator has recently booted in which case they
may not be known and no epochs will be sent until the snapshot is loaded.
Epochs become known one epoch in advance, and will only be published
once they are confirmed (the prior epoch has fully rooted).

#### `epoch.new`
| frequency       | type            | example |
|-----------------|-----------------|-------- |
| *Once* + *Live* | `EpochSchedule` | below   |

::: details Example

```json
{
    "epoch": 636,
    "start_time_nanos": "12412481240412",
    "end_time_nanos": "1719910299914232",
    "start_slot": 274752000,
    "end_slot": 275183999,
    "excluded_stake_lamports": "0",
    "staked_pubkeys": [
        "Fe4StcZSQ228dKK2hni7aCP7ZprNhj8QKWzFe5usGFYF",
        "2CeCyRoYQcctDmbXWrSUfTT4aQkGVCnArAmbdmQ5QGFi",
        "6JPDr4URdEDP5MqPgmDT6jk2nToyMUzNU27qsGxrRgKz",
        "8ri9HeWZv4Dcf4BD46pVPjmefzJLpbtfdAtyxyeG4enL",
        // ... many more ...
    ],
    "staked_lamports": [
        "360",
        "240",
        "180",
        "9991",
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
| start_time_nanos | `string` | A UNIX timestamp, in nanoseconds, of when the epoch started. This is the time the last non-skipped block of the prior epoch finished replaying locally on this validator, if the validator was online when that happened, otherwise it is null |
| end_time_nanos | ` string` | A UNIX timestamp, in nanoseconds, of when the epoch ended. This is the time the last non-skipped block of the epoch finished replaying locally on this validator, if the validator was online when that happened, otherwise it is null |
| start_slot | `number` | The first slot (inclusive) in the epoch |
| end_slot   | `number` | The last slot (inclusive) in the epoch |
| excluded_stake_lamports | `string` | This number is almost always zero. Firedancer has a limit of 40,200 for the number of staked peer validators it can keep track of. In the unlikely event that this number is exceeded, the lowest staked peers will be forgotten, and their stake will not appear in the below lists. But it is useful to know the total stake in the epoch, so this value represents the leftover/excluded ("poisoned") amount of stake that we do not know which validator it belongs to
| staked_pubkeys | `string[]` | A list of all of validator identity keys for validators which have are staked in this epoch.  There will be at most 40,200 staked keys, after which lower staked keys will not be included |
| staked_lamports | `string[]` | A list with the same length as the `staked_pubkeys` field. `stake_lamports[ i ]` is the number of lamports staked on the pubkey `staked_pubkeys[ i ]` as of this epoch
| leader_slots | `number[]` | An array, one entry per four slots, of which pubkey in the `leader_pubkeys` array is leader for those slots. On `mainnet-beta` this array will always have a length of 108,000, which is the number of slots in an epoch divided by four.  Leader slots are in groups of four because the leader schedule is generated in such a way as to guarantee each leader gets at least four consecutive slots.  For example, to find the pubkey of the leader in slot 1000 of the epoch, it is `staked_pubkeys[ leader_slots[ 1000/4 ] ]` |

On establishing a connection two epochs are sent to the client. The
current epoch that the cluster is in, and the next epoch. From then on,
new epochs are published live as they are calculated by the validator. For
epoch T, it is published as `end_slot` in epoch T-2 is rooted. The
epoch is speculatively known as soon as `end_slot` in epoch T-2 is
completed, rather than rooted, but no speculative epoch information is
published until the epoch is finalized by rooting the slot.

### gossip
Information about the validator's connection to the gossip network.
Gossip is a distributed database which maintains a single underlying
store called the Cluster Replicated Data Store (CRDS), which this
documentation will simply call the "Gossip Table". The Gossip Table has
"CRDS values", which are store entries that take the form of one of
several different structured variants specified in the protocol. This
documentation will simply call these "table entries".

Note that "Gossip messages" and "Gossip Table entries" are distinct
measures and therefore cannot be compared coherently. A typical Gossip
message may contain several table entries, or none at all.

The server maintains a table called the "Peer Table" with per-peer
Gossip connection metrics. This table is large and updates frequently.
Instead of sending a new copy of the table to every client periodically,
the node maintains a viewport of a sorted instance of the Peer Table.
The `gossip.query_scroll`, `gossip.query_sort`,
`gossip.peers_size_update`, and `gossip.view_update` allow the client to
synchronize with and update their viewport.

A viewport is parameterized by the following attributes:

- sort_key: a list of (column, direction) tuples which describe a
possible ordering of the Peer Table. Earlier columns in the sort key
have higher precedence, meaning that are "stable sorted" later. This
increases the visual impact of their ordering.
- start_row: the Peer Table index of the first row in the viewport
- row_cnt: the number of rows in the viewport

The server imposes a limit of a maximum of 200 rows per viewport. When a
client first connects, the server assigns them a default viewport state,
which is specified below.

#### `gossip.network_stats`
| frequency       | type                 | example     |
|-----------------|----------------------|-------------|
| *Once* + *10ms* | `GossipNetworkStats` | below       |

::: details Example

```json
{
    "health": {
        "num_push_messages_rx_success": 1234,
        "num_push_messages_rx_failure": 0,
        "num_push_entries_rx_success": 0,
        "num_push_entries_rx_failure": 0,
        "num_push_entries_rx_duplicate": 0,
        "num_pull_response_messages_rx_success": 0,
        "num_pull_response_messages_rx_failure": 0,
        "num_pull_response_entries_rx_success": 0,
        "num_pull_response_entries_rx_failure": 0,
        "num_pull_response_entries_rx_duplicate": 0,
        "total_stake": "411123000000000000",
        "total_staked_peers": "911",
        "total_unstaked_peers": "5334",
        "connected_stake": "123456789",
        "connected_staked_peers": 623,
        "connected_unstaked_peers": 1432,
    },
    "ingress": {
        "total_throughput": 131204210,
        "peer_names": ["Coinbase 02", "Figment", "Jupiter", ... ],
        "peer_identities": ["FDpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21FD", "FD7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69FD", "FDXWcZ7T1wP4bW9SB4XgNNwjnFEJ982nE8aVbbNuwFD", ... ],
        "peer_throughput": [15121541, 11697591, 9131124 ]
    },
    "egress": {
        "total_throughput": 131204210,
        "peer_names": ["Coinbase 02", "Figment", "Jupiter", ... ],
        "peer_identities": ["FDpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21FD", "FD7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69FD", "FDXWcZ7T1wP4bW9SB4XgNNwjnFEJ982nE8aVbbNuwFD", ... ],
        "peer_throughput": [15121541, 11697591, 9131124 ]
    },
    "storage": {
        "capacity": 2097152,
        "expired_total": 1234,
        "evicted_total": 0,
        "count": [0, 10608, 95, ...],
        "count_tx": [0, 10608, 95, ...],
        "bytes_tx": [0, 9827342, 9723, ...],
    },
    "messages": {
        "num_bytes_rx": [857419, 8839524, 43480758, ...],
        "num_bytes_tx": [28938, 2416123, 72351557, ...],
        "num_messages_rx": [1364, 20477, 456094, ...],
        "num_messages_tx": [26, 2490, 73599, ...],
    }
}
```

:::

**`GossipNetworkStats`**
| Field      | Type                   | Description |
|------------|------------------------|-------------|
| health     | `GossipNetworkStake`   | Aggregate statistics related to the health of the gossip network and the amount of connected peers / stake |
| ingress    | `GossipNetworkTraffic` | Ingress network traffic and peer metrics |
| egress     | `GossipNetworkTraffic` | Egress network traffic and peer metrics |
| storage    | `GossipStorageStats`   | Storage statistics showing the storage utilization for the Gossip Table. Inner arrays are ordered according to the following `tables_entries` array `["ContactInfoV1","Vote","LowestSlot","SnapshotHashes","AccountsHashes","EpochSlots","VersionV1","VersionV2","NodeInstance","DuplicateShred","IncrementalSnapshotHashes","ContactInfoV2","RestartLastVotedForkSlots","RestartHeaviestFork"]` |
| messages   | `GossipMessageStats`   | Message statistics showing the message traffic for the Gossip Table. Inner arrays are ordered according to the following `message_types` array ["pull_request","pull_response","push","ping","pong","prune"] |


**`GossipNetworkHealth`**
| Field                                                              | Type     | Description |
|--------------------------------------------------------------------|----------|-------------|
| num_{push\|pull_response}\_entries_rx_{success\|failure\|duplicate} | `number` | The number of Gossip Table entries that this node has ever received. `success` means only entries that were fully received and included in the Table are counted. `failure` means only entries that was dropped for any reason, including parsing failures or invariant violations, are counted. `duplicate` refers to entries that were dropped as duplicates. {push\|pull_request} means that only entries received via Gossip {push\|pull_request} messages are counted |
| num_{push\|pull_response}\_messages_rx_{success\|failure}           | `number` | The number of Gossip messages that this node has ever received. `success` means only messages that were fully valid, even if any entries they contain were dropped. `failure` means only messages that was dropped for any reason, including parsing failures or invariant violations, are counted. `duplicate` refers to messages that were dropped as duplicates. {push\|pull_request} is the type of Gossip message counted |
| total_stake                                                        | `number` | The total active stake on the Solana network for the current epoch. The information is derived from the getLeaderSchedule rpc call at startup and is fixed for the duration of the epoch |
| total_staked_peers                                                 | `number` | The total number of peers on the current epoch leader schedule also active on Gossip.  This information is derived from `getClusterNodes` and `getLeaderSchedule` rpc calls at startup |
| total_unstaked_peers                                               | `number` | The total number of peers active on gossip, not including peers on the leader schedule.  This information is derived from `getClusterNodes` and `getLeaderSchedule` rpc calls at startup |
| connected_stake                                                    | `number` | The sum of active stake across all peers with a ContactInfo entry in the Gossip Table.  The stake quantity is taken from the leader schedule, and reflects the activate stake at the start of the current epoch |
| connected_staked_peers                                             | `number` | The number of currently connected peers that have nonzero active stake |
| connected_unstaked_peers                                           | `number` | The number of currently connected peers without any stake currently active |

**`GossipNetworkTraffic`**
| Field            | Type       | Description |
|------------------|------------|-------------|
| total_throughput | `number`   | The Gossip network throughput in bytes per second |
| peer_names       | `string[]` | The names of the 64 peers on the Gossip network with the largest contribution to our traffic |
| peer_identities  | `string[]` | The base58 identity pubkey of the 64 peers on the Gossip network with the largest contribution to our traffic |
| peer_throughput  | `number[]` | A list of network throughputs in bytes per second. The peer name for each entry is the corresponding entry in `peer_names` |

**`GossipStorageStats`**
| Field         | Type       | Description |
|---------------|------------|-------------|
| capacity      | `number`   | The total number of entries that can be stored in the Gossip Table before old entries start being evicted |
| expired_total | `number`   | The cumulative number of Gossip Table entries that have expired and been removed |
| evicted_total | `number`   | The cumulative number of Gossip Table entries that have been evicted due to insufficient space |
| count         | `number[]` | `count[i]` is the number of currently active `table_entries[i]` entries currently in the Gossip Table |
| count_tx      | `number[]` | `count_tx[i]` is the number of egress `table_entries[i]` entries transmitted until now |
| bytes_tx      | `number[]` | `bytes_tx[i]` is the number of egress `table_entries[i]` bytes transmitted until now |

**`GossipMessageStats`**
| Field           | Type       | Description |
|-----------------|------------|-------------|
| num_bytes_rx    | `number[]` | `num_bytes_rx[i]` is the ingress cumulative byte amount received as `message_types[i]` messages |
| num_bytes_tx    | `number[]` | `num_bytes_tx[i]` is the ingress cumulative byte amount sent for `message_types[i]` messages |
| num_messages_rx | `number[]` | `num_messages_rx[i]` is the egress cumulative message count sent as `message_types[i]` messages |
| num_messages_tx | `number[]` | `num_messages_tx[i]` is the egress cumulative message count sent for `message_types[i]` messages |

#### `gossip.query_scroll`
| frequency | type             | example     |
|-----------|------------------|-------------|
| *Request* | `GossipViewData` | below       |

| param     | type     | description |
|-----------|----------|-------------|
| start_row | `number` | The first row in the contiguous chunk of rows from the Peer Table in the client's view |
| end_row   | `number` | The last row in the contiguous chunk of rows from the Peer Table in the client's view |

The client's view of the peer table changes when they scroll.  This
request includes the bounds for the updated view, which lets the server
respond with the view's data. If the requested rows are outside the
bounds of the table, only the active rows are included in the response.

When a client first connects, before a `query_scroll` request has been
made, their viewport state will be initialized with `start_row=0` and
`row_cnt=0` (i.e. an empty viewport), meaning they will get no updates
until their viewport grows to a non-zero size.

Note that the default client view is an empty viewport, meaning no
updates will be published to the client until after the first
`query_scroll` received by the server.

::: details Example

```json
{
    "topic": "gossip",
    "key": "query_scroll",
    "id": 16,
    "params": {
        "start_row": 10,
        "row_cnt": 12,
    }
}
```

```json
{
    "topic": "gossip",
    "key": "query_scroll",
    "id": 16,
    "value": {
        "10": {"IP Address": "192.168.0.1", "col2": 2},
        "11": {"IP Address": "192.168.0.2", "col2": 4},
        "12": {"IP Address": "192.168.0.3", "col2": 6}
    }
}
```

:::

**`GossipViewData`**
The tabular data in the clients view, as a 2D dictionary. The dictionary is keyed by row index (object keys are always strings). Each value is a dictionary that represents a table row. Each row is keyed by column name, and each row value is the value of the cell for the corresponding (rowIndex, column_name)

#### `gossip.query_sort`
| frequency | type             | example     |
|-----------|------------------|-------------|
| *Request* | `GossipViewData` | below       |

| param | type       | description |
|-------|------------|-------------|
| col   | `string[]` | `col[ i ]` is the name of the column with the `i`th sort precedence in the reqeusted view |
| dir   | `number[]` | `dir[ i ]` is sort direction `col[ i ]` in the requested view |

The server maintains a copy of each client's active sort key. This
message allows clients to change their sort key which will in change the
ordering of their view. Since updating the sort key changes the client's
view completely, the response will be a fresh copy of all the data in
the client's new view.

When a client first connects, the start with the following sort key by
default, until an update is made.

- ("Stake", desc)
- ("Pubkey", desc)
- ("IP Addr", desc)
- ("Ingress Push", desc)
- ("Ingress Pull", desc)
- ("Egress Push", desc)
- ("Egress Pull", desc)

The provided sort key is a list of column names and a corresponding list
of column directions. Directions are provided as signed integers with
the following meanings:

- ascending: 1
- descending: -1
- no sort / ignore: 0

All columns in the table must be present in the provided sort key. If
the column doesn't affect the ordering of the view, it should have a
direction of `0`. Not that the relative ordering of columns with
`dir==0` can be arbitrary as it does not change the view ordering.

::: details Example

```json
{
    "topic": "gossip",
    "key": "query_sort",
    "id": 32,
    "params": {
        "col": ["IP Addr", "Pubkey", "Stake", "Egress Pull", "Egress Push", "Ingress Pull", "Ingress Push"],
        "dir": [1, 0, 0, 0, 0, 0, 0],
    }
}
```

```json
{
    "topic": "gossip",
    "key": "query_sort",
    "id": 32,
    "value": {
        "10": {"IP Address": "192.168.0.1", ...},
        "11": {"IP Address": "192.168.0.2", ...},
        "12": {"IP Address": "192.168.0.3", ...}
    }
}
```

:::

#### `gossip.peers_size_update`
| frequency | type     | example     |
|-----------|----------|-------------|
| *Request* | `number` | below       |

The latest known count of the number of rows in the gossip peer table.
This is sent every time the total number of rows in the gossip peer
table changes.

::: details Example

```json
{
    "topic": "gossip",
    "key": "peers_size_update",
    "value": 1234
}
```

:::


#### `gossip.view_update`
| frequency       | type                   | example     |
|-----------------|------------------------|-------------|
| *Once* + *Live* | `GossipPeerViewUpdate` | below       |

Sent every time the content of the client's view changes (i.e. cell
values).

::: details Example

```json
{
    "changes": [
        {
            "row_index": 10,
            "column_name": "IP Address",
            "new_value": "192.168.0.1"
        },
        {
            "row_index": 10,
            "column_name": "Port",
            "new_value": 12345
        }
    ]
}
```

:::

**`GossipPeerViewUpdate`**
| Field   | Type                         | Description |
|---------|------------------------------|-------------|
| changes | `GossipPeerViewCellUpdate[]` | An list of cells in the client's view that changed values since the last `GossipPeerViewUpdate` message |

**`GossipPeerViewCellUpdate`**
| Field       | Type     | Description |
|-------------|----------|-------------|
| row_index   | `number` | The index of the updated cell's row |
| column_name | `string` | The name of the updated cell's column |
| new_value   | `any`    | The new value display in the cell |

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
| frequency      | type         | example     |
|----------------|--------------|-------------|
| *Once* + *60s* | `PeerUpdate` | below       |

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
                    "activated_stake": "5812",
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
                "icon_url": "https://docs.firedancer.io/fire.svg"
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
| Field         | Type           | Description |
|---------------|----------------|-------------|
| wallclock     | `number`       | Not entirely sure yet TODO |
| shred_version | `number`       | A `u16` representing the shred version the validator is configured to use. The shred version is changed when the cluster restarts, and is used to make sure the validator is talking to nodes that have participated in the same cluster restart |
| version       | `string\|null` | Software version being advertised by the validator. Might be `null` if the validator is not gossiping a version, or we have received the contact information but not the version yet. The version string, if not null, will always be formatted like `major`.`minor`.`patch` where `major`, `minor`, and `patch` are `u16`s |
| feature_set   | `number\|null` | First four bytes of the `FeatureSet` hash interpreted as a little endian `u32`. Might be `null` if the validator is not gossiping a feature set, or we have received the contact information but not the feature set yet |
| sockets       | `[key: string]: string` | A dictionary of sockets that are advertised by the validator. `key` will be one of gossip `serve_repair_quic`, `rpc`, `rpc_pubsub`, `serve_repair`, `tpu`, `tpu_forwards`, `tpu_forwards_quic`, `tpu_quic`, `tpu_vote`, `tvu`, `tvu_quic`, `tpu_vote_quic`, or `alpenglow`. The value is an address like `<addr>:<port>`: the location to send traffic to for this validator with the given protocol. Address might be either an IPv4 or an IPv6 address |

**`PeerUpdateVoteAccount`**
| Field           | Type           | Description |
|-----------------|----------------|-------------|
| vote_pubkey     | `string`       | The public key of vote account, encoded in base58 |
| activated_stake | `string`       | The amount of stake in lamports that is activated on this vote account for the current epoch. Warming up or cooling down stake that was delegating during this epoch is not included |
| last_vote       | `number\|null` | The last vote by the vote account that was landed on chain, as seen by this validator. If the vote account has not yet landed any votes on the chain this will be `null` |
| root_slot       | `number\|null` | The last slot that was rooted by the vote account, based on the vote history. If the vote account has not yet rooted any slots this will be `null` |
| epoch_credits   | `number`       | The number of credits earned by the vote account during the current epoch |
| delinquent      | `boolean`      | Whether the vote account is delinquent or not. A vote account is considered delinquent if it has not had a vote land on chain for any of the last 127 (inclusive) confirmed slots, according to this validator. If there have been less than 128 confirmed slots on the chain (it is a new chain), a validator is considered delinquent only if it has not voted yet at all |

**`PeerUpdateInfo`**
| Field    | Type     | Description |
|----------|----------|-------------|
| name     | `string\|null` | Self reported name of the validator, could be any string or null if there is no name set |
| details  | `string\|null` | Self reported detailed description of the validator, could be any string or null if there is no details set |
| website  | `string\|null` | Self reported website of the validator, could be any string and need not be a valid URI, or could be null if there is no website set |
| icon_url | `string\|null` | Self reported URL of the validator icon, could be any string and need not be a valid URI, or could be null if there is no icon URI set |

**`PeerUpdate`**
| Field    | Type   | Description
|----------|--------|------------
| identity | `string` | Identity public key of the validator, encoded in base58 |
| gossip   | `PeerUpdateGossip\|null` | Information reported for the validator identity over the gossip network. This is authenticated and the gossip node must have been in possession of the private key to publish gossip data as this identity. Gossip information is not validated or checked for correctness and could be set to any values by the peer |
| vote     | `PeerUpdateVoteAccount[]` | Information about the vote account(s) associated with this identity key, if there are any. It is extremely unusual for multiple vote accounts to report the same identity key. Vote account information like stake and commission is derived from the accounts on chain and cannot be corrupt, invalid, or incorrect |
| info     | `PeerUpdateInfo\|null` | If the validator has published self reported identifying information to the chain. This is authenticated and the operator must have been in possession of the private key to publish info as this identity. Information is not validated or checked for correctness and could be set to any values by the peer |

**`PeerRemove`**
| Field    | Type   | Description |
|----------|--------|-------------|
| identity | `string` | Identity public key of the validator, encoded in base58 |

**`PeersUpdate`**
| Field  | Type   | Description |
|--------|--------|-------------|
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
| `rooted`     | Our validator has rooted the slot and considers the slot final. This occurs when 32 subsequent slots have been built on top of it |
| `finalized`  | Our validator has rooted the slot, and more than two-thirds of stake has rooted the slot, the network considers it final |

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
block for that slot. The `mine` field means that this specific validator
published the block. It might happen that a block is published by a
leader with our identity key, but not this specific validator (for
example, if the block was published by another computer, and then this
validator took over the identity key with a `set-identity` operation)
in which case the `mine` field will be set to false, even though the
block has our key.

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
| Field                        | Type           | Description |
|------------------------------|----------------|-------------|
| slot                         | `number`       | Identity of the slot, counting up from zero for the first slot in the chain |
| mine                         | `boolean`      | True if this validator was the leader for this slot. This will never change for a slot once it has been published, and will be aligned with the epoch information, except in cases where the validator identity is changed while the validator is running |
| start_timestamp_nanos        | `string`       | A UNIX timestamp, in nanoseconds, representing the time that the validator is first aware that it is leader. At this point the poh tile will signal the pack tile to begin filling the block for this slot with transactions |
| target_end_timestamp_nanos   | `string`       | A UNIX timestamp, in nanoseconds, representing the target time in nanoeconds that the pack tile should stop scheduling transactions for the slot. Transactions might still finish executing after this end time, if they started executing before it and ran over the deadline. In rare cases, transactions may also appear to begin after this timestamp due to slight clock drift between execution cores |
| skipped                      | `boolean`      | True if the slot was skipped. The skipped state is the state in the currently active fork of the validator. The skipped state can change if the validator switches active fork |
| duration_nanos               | `number\|null` | A duration in nanoseconds of how long it took us to receive and replay the slot. This is the time as measured since we completed replay of the parent slot locally on this validator, til the time we replayed this slot locally on this validator |
| completed_time_nanos         | `string\|null` |  UNIX timestamp in nanoseconds of when this validator finished replaying the slot locally. If the slot was skipped, this may be `null` which indicates the block for this slot did not finish replaying on this validator. In some cases, a skipped slot will still have a completed time, if we received the data for the block, replayed it, and then decided to use a different fork |
| level                        | `string`       | One of `incomplete`, `completed`, `optimistically_confirmed`, `rooted`, or `finalized` as described above. The state is the state in the currently active fork of this validator. The state can change normally (for example, a completed slot becoming optimisitically confirmed or rooted), or also because the validator switched forks |
| success_nonvote_transactions | `number\|null` | Total number of successfully executed non-vote transactions in the block. If the slot is not skipped, this will be non-null, but in some cases it will also be non-null even if the slot was skipped. That's because we replayed the block but selected a fork without it, but we still know how many transactions were in it |
| failed_nonvote_transactions  | `number\|null` | Total number of failed non-vote transactions in the block. If the slot is not skipped, this will be non-null, but in some cases it will also be non-null even if the slot was skipped. That's because we replayed the block but selected a fork without it, but we still know how many transactions were in it |
| success_vote_transactions    | `number\|null` | Total number of successfully executed vote transactions in the block |
| failed_vote_transactions     | `number\|null` | Total number of failed vote transactions in the block.  This should be near-zero in a healthy cluster |
| max_compute_units            | `number\|null` | The maximum number of compute units that can be packed into the slot.  This limit is one of many consensus-critical limits defined by the solana protocol, and helps keeps blocks small enough for validators consume them quickly.  It may grow occasionally via on-chain feature activations |
| compute_units                | `number\|null` | Total number of compute units used by the slot.  Compute units are a synthetic metric that attempt to capture, based on the content of the block, the various costs that go into processing that block (i.e. cpu, memory, and disk utilization).  They are based on certain transaction features, like the number of included signatures, the number of included signature verfication programs, the number of included writeable accounts, the size of the instruction data, the size of the on-chain loaded account data, and the number of computation steps.  NOTE: "compute units" is an overloaded term that is often used in misleading contexts to refer to only a single part of the whole consensus-critical cost formula. For example, the getBlock RPC call includes a "computeUnitsConsumed" which actually only refers only the execution compute units associated with a transaction, but excludes other costs like signature costs, data costs, etc.  This API will always use compute units in a way that includes ALL consensus-relevant costs, unless otherwise specified |
| shreds                       | `number\|null` | Total number of shreds in the successfully replayed block. Note value is only available in the Firedancer client and will be 0 or null in the Frankendancer client |
| transaction_fee              | `string\|null` | Total amount of transaction fees that this slot collects in lamports after any burning |
| priority_fee                 | `string\|null` | Total amount of priority fees that this slot collects in lamports after any burning |
| tips                         | `string\|null` | Total amount of tips that this slot collects in lamports, across all block builders, after any commission to the block builder is subtracted |

#### `slot.skipped_history`
| frequency      | type       | example |
|----------------|------------|---------|
 *Once* + *Live* | `number[]` | `[286576808, 286576809, 286576810, 286576811, 286625025, 286625026, 286625027]` |

A list of all of the recent leader slots of the validator which were
skipped. Only two epochs of leader slots are tracked, and skips prior
to this are not retrieved.

The skipped slots include unrooted and unconfirmed slots of ours which
are skipped on the currently active fork.

If the validator identity is changed with a `set-identity` operation,
the skipped history is republished with a list of skipped slots for the
new validator identity.

#### `slot.skipped_history_cluster`
| frequency | type       | example |
|-----------|------------|---------|
 *Once*     | `number[]` | `[286576808, 286576809, 286576810, 286576811, 286625025, 286625026, 286625027]` |

A list of all of the leader slots which were skipped in the current and
immediately prior epoch.  Recent non-rooted slots may be included, and
included skipped slots will not become unskipped as a later slot has
rooted.

#### `slot.live_shreds`
| frequency   | type          | example |
|-------------|---------------|---------|
| *10ms*      | `SlotShred[]` | below   |

The validator sends a continous stream of update messages with detailed
information about the time and duration of different shred state
transitions (i.e. shred events). A given event is only ever sent once
and is broadcast to all WebSocket clients.

:::details Example

```json
{
	"topic": "slot",
	"key": "shreds",
	"value": {
        "reference_slot": 289245044,
        "reference_ts": "1739657041588242791",
        "slot_delta": [0, 0],
        "shred_idx": [1234, null],
        "event": [0, 1],
        "event_ts_delta": ["1000000", "2000000"]
    }
}
```

:::

**`SlotShred`**
| Field           | Type               | Description |
|-----------------|--------------------|-------------|
| reference_slot  | `number`           | The smallest slot number across all the shreds in a given message |
| reference_ts    | `number`           | The smallest UNIX nanosecond event timestamp number across all the events in a given message |
| slot_delta      | `number[]`         | `reference_slot + slot_delta[i]` is the slot to which shred event `i` belongs |
| shred_idxs      | `(number\|null)[]` | `shred_idxs[i]` is the slot shred index of the shred for shred event `i`.  If null, then shred event `i` applies to all shreds in the slot (i.e. this is used for `slot_complete`) |
| events          | `string[]`         | `events[i]` is the name of shred event `i`. Possible values are `repair_request`, `shred_received`, `shred_replayed`, and `slot_complete` |
| events_ts_delta | `string[]`         | `reference_ts + events_ts_delta[i]` is the UNIX nanosecond timestamp when shred event `i` occured |

#### `slot.query_shreds`
| frequency   | type          | example |
|-------------|---------------|---------|
| *Request*   | `SlotShred[]\null` | below   |

| param | type     | description |
|-------|----------|-------------|
| slot  | `number` | The requested slot for which the reponse will provide shred timing data |

WebSocket clients may request historical shred metadata on a per-slot
basis. For slots that are too old (i.e. they've been expired from an
in-memory store) or too new (i.e. they haven't been finalized yet), the
response value will be `null`.

::: details Example

```json
{
    "topic": "slot",
    "key": "query_shreds",
    "id": 32,
    "params": {
        "slot": 289245044
    }
}
```

```json
{
    "topic": "slot",
    "key": "query_shreds",
    "id": 32,
    "value": {
        "reference_slot": 289245044,
        "reference_ts": "1739657041588242791",
        "slot_delta": [0, 0],
        "shred_idx": [1234, null],
        "event": [0, 1],
        "event_ts_delta": ["1000000", "2000000"]
    }
}
```

:::

#### `slot.update`
| frequency   | type          | example |
|-------------|---------------|---------|
| *Live*      | `SlotUpdate`  | below   |

:::details Example

:::

**`SlotUpdate`**
| Field               | Type                      | Description |
|---------------------|---------------------------|-------------|
| publish             | `SlotPublish`             | General information about the slot.  Contains several nullable fields in case a future slot is queried and he information is not known yet |
| waterfall           | `TxnWaterfall\|null`      | If the slot is not `mine`, will be `null`. Otherwise, a waterfall showing reasons transactions were acquired since the end of the prior leader slot |
| tile_primary_metric | `TilePrimaryMetric\|null` | If the slot is not `mine`, will be `null`. Otherwise, max value of per-tile-type primary metrics since the end of the prior leader slot |

#### `slot.query_rankings`
| frequency   | type           | example |
|-------------|----------------|---------|
| *Request*   | `SlotRankings` | below   |

| param | type   | description |
|-------|--------|-------------|
| mine  | `bool` | If `mine` is true, only include slots produced by this validator in the result.  Otherwise, any slot from the current epoch may be included |

::: details Example

```json
{
    "topic": "slot",
    "key": "query_rankings",
    "id": 32,
    "params": {
        "mine": false
    }
}
```

```json
{
    "topic": "slot",
    "key": "query_rankings",
    "id": 32,
    "value": {
      "slots_largest_tips": [1, 2, 3],
      "vals_largest_tips": [12345678, 1234567, 123456],
      "slots_largest_fees": [1, 2, 3],
      "vals_largest_fees": [12345678, 1234567, 123456],
      "slots_largest_rewards": [1, 2, 3],
      "vals_largest_rewards": [12345678, 1234567, 123456],
      "slots_largest_duration": [1, 2, 3],
      "vals_largest_duration": [450000000, 440000000, 430000000],
      "slots_largest_compute_units": [1, 2, 3],
      "vals_largest_compute_units": [47000000, 46000000, 45000000],
      "slots_largest_skipped": [7, 8, 9],
      "vals_largest_skipped": [7, 8, 9],
      "slots_smallest_tips": [1, 2, 3],
      "vals_smallest_tips": [0, 0, 0],
      "slots_smallest_fees": [1, 2, 3],
      "vals_smallest_fees": [0, 0, 0],
      "slots_smallest_rewards": [1, 2, 3],
      "vals_smallest_rewards": [0, 0, 0],
      "slots_smallest_duration": [1, 2, 3],
      "vals_smallest_duration": [100000000, 120000000, 160000000],
      "slots_smallest_compute_units": [1, 2, 3],
      "vals_smallest_compute_units": [15000000, 16000000, 17000000],
      "slots_smallest_skipped": [4, 5, 6],
      "vals_smallest_skipped": [4, 5, 6]
    }
}
```

:::

**`SlotRankings`**
| Field                                            | Type       | Description |
|--------------------------------------------------|------------|-------------|
| {slots\|vals}_{smallest\|largest}_tips           | `number[]` | Rankings for the {smallest\|largest} tips this epoch |
| {slots\|vals}_{smallest\|largest}_fees           | `number[]` | Rankings for the {smallest\|largest} fees this epoch |
| {slots\|vals}_{smallest\|largest}_rewards        | `number[]` | Rankings for the {smallest\|largest} rewards this epoch |
| {slots\|vals}_{smallest\|largest}_rewards_per_cu | `number[]` | Rankings for the {smallest\|largest} rewards/cu ratio this epoch |
| {slots\|vals}_{smallest\|largest}_duration       | `number[]` | Rankings for the {smallest\|largest} slot durations this epoch |
| {slots\|vals}_{smallest\|largest}_compute_units  | `number[]` | Rankings for the {smallest\|largest} compute units this epoch |
| {slots\|vals}_{smallest\|largest}_skipped        | `number[]` | Rankings for the {earliest\|latest} skipped slots this epoch |

Each metric in this message will have four associated arrays.

- vals_smallest_metric: Metric value for the lowest ranked slots (sorted ascending)
- slots_smallest_metric: Slot numbers for vals_smallest_metric source slots
- slots_largest_metric: Metric value for the highest ranked slots (sorted descending)
- vals_largest_metric: Slot numbers for vals_largest_metric source slots

Slots before boot time are not included in these rankings. Unless
explicitly mentioned, skipped slots are not included.

#### `slot.query`
| frequency   | type           | example |
|-------------|----------------|---------|
| *Request*   | `SlotResponse` | below   |

| param | type     | description |
|-------|----------|-------------|
| slot  | `number` | The slot to query for information about |

::: details Example

```json
{
    "topic": "slot",
    "key": "query",
    "id": 32,
    "params": {
        "slot": 289245044
    }
}
```

```json
{
    "topic": "slot",
    "key": "query",
    "id": 32,
    "value": {
        "publish": {
            "slot": 289245044,
            "mine": true,
            "start_timestamp_nanos": null,
            "target_end_timestamp_nanos": null,
            "skipped": false,
            "level": "rooted",
            "transactions": 6821,
            "vote_transactions": 6746,
            "failed_transactions": 3703,
            "max_compute_units": 48000000,
            "compute_units": 0,
            "shreds": 123
        }
    }
}
```

:::

#### `slot.query_detailed`
| frequency   | type           | example |
|-------------|----------------|---------|
| *Request*   | `SlotResponse` | below   |

| param | type     | description |
|-------|----------|-------------|
| slot  | `number` | The slot to query for information about |

::: details Example

```json
{
    "topic": "slot",
    "key": "query",
    "id": 32,
    "params": {
        "slot": 289245044
    }
}
```

```json
{
    "topic": "slot",
    "key": "query_detailed",
    "id": 32,
    "value": {
        "publish": {
            "slot": 289245044,
            "mine": true,
            "start_timestamp_nanos": null,
            "target_end_timestamp_nanos": null,
            "skipped": false,
            "level": "rooted",
            "transactions": 6821,
            "vote_transactions": 6746,
            "failed_transactions": 3703,
            "max_compute_units": 48000000,
            "compute_units": 0,
            "shreds": 123
        },
        "waterfall": {
            "in": {
                "pack_cranked": 1,
                "pack_retained": 0,
                "resolv_retained": 0,
                "quic": 28159,
                "udp": 14323,
                "gossip": 4646,
                "block_engine": 13
            },
            "out": {
                "net_overrun": 0,
                "quic_overrun": 0,
                "quic_frag_drop": 0,
                "quic_abandoned": 0,
                "tpu_quic_invalid": 0,
                "tpu_udp_invalid": 0,
                "verify_overrun": 0,
                "verify_parse": 0,
                "verify_failed": 0,
                "verify_duplicate": 114,
                "dedup_duplicate": 19384,
                "resolv_lut_failed": 3,
                "resolv_expired": 0,
                "resolv_ancient": 0,
                "resolv_retained": 0,
                "resolv_no_ledger": 0,
                "pack_invalid": 0,
                "pack_expired": 0,
                "pack_retained": 2225,
                "pack_wait_full": 0,
                "pack_leader_slow": 0,
                "bank_invalid": 10253,
                "block_success": 3101,
                "block_fail": 3720
            }
        },
        "tile_primary_metric": {
            "quic": 3,
            "net_in": 37803082,
            "net_out": 4982399,
            "verify": 0,
            "dedup": 0,
            "bank": 89407,
            "pack": 0,
            "poh": 0,
            "shred": 0,
            "store": 0
        },
        "tile_timers": [
            {
                "timestamp_nanos": "1739657041688242791",
                "tile_timers": [
                    44.972112412,
                    90.12,
                    5.42148,
                    6.24870,
                    5.00158,
                    8.1111556,
                    76.585,
                    44.225,
                    12.98,
                    16.2981,
                    43.857,
                    14.1,
                    3.15716,
                    93.2456,
                    87.998
                ]
            },
            {
                "timestamp_nanos": "1739657041688342791",
                "tile_timers": [
                    44.972112412,
                    90.12,
                    5.42148,
                    6.24870,
                    5.00158,
                    8.1111556,
                    76.585,
                    44.225,
                    12.98,
                    16.2981,
                    43.857,
                    14.1,
                    3.15716,
                    93.2456,
                    87.998
                ]
            },
            // ... many more ...
        ],
        "scheduler_counts": [
            {
                "timestamp_nanos": "1739657041688242791",
                "regular": 123,
                "votes": 123,
                "conflicting": 123,
                "bundles": 123
            },
            {
                "timestamp_nanos": "1739657041688342791",
                "regular": 124,
                "votes": 120,
                "conflicting": 123,
                "bundles": 123
            }
            // ... many more ...
        ]
    }
}
```

#### `slot.query_transactions`
| frequency   | type           | example |
|-------------|----------------|---------|
| *Request*   | `SlotTransactionsResponse` | below   |

| param | type     | description |
|-------|----------|-------------|
| slot  | `number` | The slot to query for information about |

::: details Example

```json
{
    "topic": "slot",
    "key": "query_transactions",
    "id": 32,
    "params": {
        "slot": 289245044
    }
}
```

```json
{
    "topic": "slot",
    "key": "query_transactions",
    "id": 32,
    "value": {
        "publish": {
            "slot": 289245044,
            "mine": true,
            "start_timestamp_nanos": "1739657041688346791",
            "target_end_timestamp_nanos": "1739657042088346880",
            "skipped": false,
            "level": "rooted",
            "transactions": 6821,
            "vote_transactions": 6746,
            "failed_transactions": 3703,
            "max_compute_units": 48000000,
            "compute_units": 0,
            "shreds": 123
        },
        "transactions": {
            "start_timestamp_nanos": "1739657041688346791",
            "target_end_timestamp_nanos": "1739657042088346880",
            "txn_arrival_timestamps_nanos": ["1754409729593613895"],
            "txn_bank_idx": [0],
            "txn_compute_units_consumed": [3428],
            "txn_compute_units_requested": [3428],
            "txn_end_timstamps_nanos": ["1754409729594477657"],
            "txn_error_code": [0],
            "txn_from_bundle": [false],
            "txn_is_simple_vote": [true],
            "txn_landed": [true],
            "txn_load_end_timstamps_nanos": ["1754409729594455631"],
            "txn_mb_end_timestamps_nanos": ["1754409729594625003"],
            "txn_mb_start_timestamps_nanos": ["1754409729594431327"],
            "txn_microblock_id": [0],
            "txn_preload_end_timstamps_nanos": ["1754409729594432846"],
            "txn_priority_fee": ["0"],
            "txn_signature": ["2BfWBnhTP1ZZwFZutwThj5VT1hX71X9otbgFr21W2XJfcppXakbPCvJ2eCh8eBcS74Lfjar5AuowuppAjsEceSuW"],
            "txn_start_timstamps_nanos": ["1754409729594451074"],
            "txn_transaction_fee": [0],
            "txn_tips": ["0"],
            "txn_source_ipv4": ["123.123.123.123"],
            "txn_source_tpu": ["gossip"],
        }
    }
}
```

:::

**`SlotResponse`**
| Field               | Type                      | Description |
|---------------------|---------------------------|-------------|
| publish             | `SlotPublish`             | General information about the slot.  Contains several nullable fields in case a future slot is queried and he information is not known yet |
| waterfall           | `TxnWaterfall\|null`      | If the slot is not `mine`, will be `null`. Otherwise, a waterfall showing reasons transactions were acquired since the end of the prior leader slot |
| tile_primary_metric | `TilePrimaryMetric\|null` | If the slot is not `mine`, will be `null`. Otherwise, max value of per-tile-type primary metrics since the end of the prior leader slot |
| tile_timers         | `TsTileTimers[]\|null`    | If the slot is not `mine`, will be `null`. Otherwise, an array of `TsTileTimers` samples from the slot, sorted earliest to latest. We store this information for the most recently completed 4096 leader slots. This will be `null` for leader slots before that |
| scheduler_counts    | `SchedulerCounts[]\|null` | If the slot is not `mine`, will be `null`. Otherwise, an array of `SchedulerCounts` samples from the slot, sorted earliest to latest. We store this information for the most recently completed 4096 leader slots. This will be `null` for leader slots before that  |

**`SlotTransactionsResponse`**
| Field               | Type                      | Description |
|---------------------|---------------------------|-------------|
| publish             | `SlotPublish`             | General information about the slot.  Contains several nullable fields in case a future slot is queried and he information is not known yet |
| transactions        | `Transactions\|null`      | If the slot is not `mine`, will be `null`. Otherwise, metrics for the transactions in this slot. Arrays have a seperate entry for each scheduled transaction that was packed in this slot, and are ordered in the same order the transactions appear in the block. Note that not all scheduled transactions will land in the produced block (e.g. failed bundles are ignored), but these arrays nonetheless include metrics for excluded transactions |

**`TxnWaterfall`**
| Field | Type              | Description |
|-------|-------------------|-------------|
| in    | `TxnWaterfallIn`  | Transactions received into the waterfall |
| out   | `TxnWaterfallOut` | Transactions sent out of the waterfall |

**`TxnWaterfallIn`**
| Field           | Type     | Description |
|-----------------|----------|-------------|
| pack_cranked    | `number` | Transactions were created as part of an initializer bundle. Initializer bundles are special bundles created by pack that manage block engine state on the chain. They contain crank transactions, which create and update tip distribution accounts. There is typically one crank transaction per leader rotation |
| pack_retained   | `number` | Transactions were received during or prior to an earlier leader slot, but weren't executed because they weren't a high enough priority, and were retained inside the validator to potentially be included in a later slot |
| resolv_retained | `number` | Transactions were received during or prior to an earlier leader slot, but weren't executed because we did not know the blockhash they referenced. They were instead kept in a holding area in case we learn the blockhash later |
| quic            | `number` | A QUIC transaction was received. The stream does not have to successfully complete |
| udp             | `number` | A non-QUIC UDP transaction was received |
| gossip          | `number` | A gossipped vote transaction was received from a gossip peer |
| block_engine    | `number` | A transaction received from a block engine, for example Jito. The transaction might or might not have been part of a bundle |

**`TxnWaterfallOut`**
| Field             | Type     | Description |
|-------------------|----------|-------------|
| net_overrun       | `number` | Transactions were dropped because the net tile couldn't keep with incoming network packets. It is unclear how many transactions would have been produced by the packets that were dropped, and this counter (along with the corresponding counter for the `in` side) assumes one transaction per dropped packet |
| quic_overrun      | `number` | Transactions were dropped because the QUIC tile couldn't keep with incoming network packets. It is unclear how many transactions would have been produced by the fragments from net that were overrun, and this counter (along with the corresponding counter for the `in` side) assumes one transaction per dropped packet |
| quic_frag_drop    | `number` | Transactions were dropped because there are more ongoing receive operations than buffer space |
| quic_abandoned    | `number` | Transactions were dropped because a connection closed before all bytes were received |
| tpu_quic_invalid  | `number` | Transactions were dropped because the QUIC tile decided that incoming QUIC packets were not valid. It is unclear how many transactions would have been produced by the packets that were invalid, and this counter (along with the corresponding counter for the `in` side) assumes one transaction per invalid packet |
| tpu_udp_invalid   | `number` | Transactions were dropped because the QUIC tile decided that incoming non-QUIC (regular UDP) packets were not valid |
| verify_overrun    | `number` | Transactions were dropped because the verify tiles could not verify them quickly enough |
| verify_parse      | `number` | Transactions were dropped because they were malformed and failed to parse |
| verify_failed     | `number` | Transactions were dropped because signature verification failed |
| verify_duplicate  | `number` | Transactions were dropped because the verify tiles determined that they had already been processed |
| dedup_duplicate   | `number` | Transactions were dropped because the dedup tile determined that they had already been processed |
| resolv_retained   | `number` | Transactions were retained inside the validator memory because they referenced a blockhash we do not yet know. We might include the transactions in a future block, if we learn about the blockhash they reference |
| resolv_lut_failed | `number` | Transactions were dropped because they contained invalid address lookup tables (LUTs) |
| resolv_expired    | `number` | Transactions were dropped because they contained a transaction that was already expired |
| resolv_no_ledger  | `number` | Transactions were dropped because they contained a LUT but we didn't yet have a ledger to look them up in |
| resolv_ancient    | `number` | Transactions were dropped because they referenced a blockhash we didn't recognize, and while waiting to see if the blockhash would arrive, the buffer became full |
| pack_invalid      | `number` | Transactions were dropped because pack determined they would never execute. Reasons can include the transaction requested too many compute units, or was too large to fit in a block |
| pack_expired      | `number` | Transactions were dropped because pack determined that their TTL expired |
| pack_retained     | `number` | Transactions were retained inside the validator memory because they were not high enough priority to make it into a prior block we produced, but have not yet expired. We might include the transactions in a future block |
| pack_leader_slow  | `number` | Transactions were dropped while leader because the bank tiles could not execute them quickly enough, pack will drop the lowest priority transactions first |
| pack_wait_full    | `number` | Transactions were dropped while we were waiting for our leader slot because we ran out of memory to store them. All incoming transactions are dropped without regard for the priority |
| bank_invalid      | `number` | Transactions were dropped because a bank tile could not execute them enough to charge fees. Failed transactions can still pay fees and be included in a block, but invalid transactions do not make it to a block. Reasons can include insufficient fee payer balance, or invalid address lookup tables |
| block_success     | `number` | Transactions made it into a block, and execution succeeded |
| block_failure     | `number` | Transactions made it into a block, but execution failed |

**`SchedulerCounts`**
| Field           | Type     | Description |
|-----------------|----------|-------------|
| timestamp_nanos | `string` | A UNIX nanosecond timestamp representing the time when these counts were sampled by the gui tile. |
| regular         | `number` | The number of transactions stored in the "regular" treap (i.e. the primary buffer) at `timestamp_nanos` |
| votes           | `number` | The number of transactions stored in the "votes" treap (i.e. the buffer dedicated for vote transactions) at `timestamp_nanos` |
| conflicting     | `number` | The number of transactions stored in the "conflicting" treap (i.e. the buffer for transations with percieved account write conflicts, which recieve slightly less priority) at `timestamp_nanos` |
| bundles         | `number` | The number of transactions stored in the "bundles" treap (i.e. the buffer dedicated for bundle transactions) at `timestamp_nanos` |

**`TsTileTimers`**
| Field             | Type          | Description |
|-------------------|---------------|-------------|
| timestamp_nanos   | `string`      | A timestamp of when the tile timers were sampled, nanoseconds since the UNIX epoch |
| tile_timers       | `TileTimer[]` | A list of all tile timing information at the given sample timestamp |

**`Transactions`**
| Field                             | Type        | Description |
|-----------------------------------|-------------|-------------|
| start_timestamp_nanos             | `string`    | A UNIX timestamp, in nanoseconds, representing the time that the validator is first aware that it is leader. At this point the poh tile will signal the pack tile to begin filling the block for this slot with transactions |
| target_end_timestamp_nanos        | `string`    | A UNIX timestamp, in nanoseconds, representing the target time in nanoeconds that the pack tile should stop scheduling transactions for the slot. Transactions might still finish executing after this end time, if they started executing before it and ran over the deadline. In rare cases, transactions may also appear to begin after this timestamp due to slight clock drift between execution cores |
| txn_arrival_timestamps_nanos      | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_arrival_timestamps_nanos[i]` is the time when the `i`-th transaction in the slot arrived at the transaction scheduler (i.e. pack) |
| txn_mb_start_timestamps_nanos     | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_mb_start_timestamps_nanos[i]` is the time when the microblock for the `i`-th transaction in the slot was successfully scheduled for execution by pack.  At this point, the microblock was sent off to a bank tile for execution.  Since a microblock may contain multiple transactions (e.g. a bundle), all transactions from the same microblock will share the same start timestamp |
| txn_preload_end_timstamps_nanos   | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_preload_end_timstamps_nanos[i]` is the time when the `i`-th transaction in the slot was succesfully dispatched into an execution environemnt and is about to start validation checks, which include a final deduplication check as well as an expiration check |
| txn_start_timstamps_nanos         | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_start_timstamps_nanos[i]` is the time when the `i`-th transaction in the slot started loading |
| txn_load_end_timstamps_nanos      | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_load_end_timstamps_nanos[i]` is the time when the `i`-th transaction in the slot finished loading and started executing. At this point, relevant on-chain data has been loaded for the transaction and it is ready to be fed into the Solana Virtual Machine (SVM) |
| txn_end_timstamps_nanos           | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_end_timstamps_nanos[i]` is the time when the `i`-th transaction in the slot finished executing |
| txn_mb_end_timestamps_nanos       | `string[]`  | An array of UNIX timestamps, in nanoseconds. `txn_mb_end_timestamps_nanos[i]` is the time when the microblock for the `i`-th transaction in the slot completed executing.  At this point, the bank tile for this microblock was ready to communicate the execution result back to the pack. pack uses this result to track the progress of the growing block and also repurposes any unused compute units for other microblocks.  The current implementation splits microblocks which originally contained multiple transactions (i.e. bundles) apart so that consumers always receive one transaction per microblock, so unlike `txn_mb_start_timestamps_nanos` this timestamp may be unique for a given transaction |
| txn_compute_units_requested       | `number[]`  | `txn_compute_units_estimated[i]` is a strict upper bound on the total cost for the `i`-th transaction in the slot.  The transaction cannot have succeeded if its incurred cost (known after execution) exceeds this bound.  This bound is used by the pack tile to estimate the pace at which the block is being filled, and to filter out transactions that it knows will fail ahead of time |
| txn_compute_units_consumed        | `number[]`  | `txn_compute_units_consumed[i]` is the actual post-execution cost of `i`-th transaction in the slot.  While some transactions costs are known from the transaction payload itself (such as the cost incurred by the amount of instruction data), other costs (like execution costs or the cost due to loaded on-chain account data) are a function of the state of the blockchain at the time of execution. This value represents the actual cost after a transaction is executed.  Consensus requires that all validators agree on this value for a given transaction in a slot. There are two special cases to consider for scheduled transactions that were not added to the produced block. Failed bundle transactions that successfully executed up to the point of failure will show actual consumed CUs. Subsequent failed bundle transactions will show 0 cus consumed.  Non-bundle transactions that were not added to the block will also show 0 cus consumed |
| txn_transaction_fee               | `string[]`  | `txn_non_execution_fee[i]` is the signature fee for the `i`-th transaction in the slot. Currenlty, this is the number of signatures in the transaction times 5000 lamports. This fee used to (and may in the future) include rewards from other parts of the transaction, which is why a more general name is used.  50% of this fee is burned and the other 50% is included in validator block rewards. The provided values reflect the fee balance after burning |
| txn_priority_fee                  | `string[]`  | `txn_priority_fee[i]` is the priority fee in lamports for the `i`-th transaction in the slot.  The priority fee is a static metric computed by multiplying the requested execution cost (derived from a provided computeBudget instruction, or from a protocol defined default) by the compute unit price (derived from a seperate computeBudget instruction) |
| txn_tips                          | `string[]`  | `txn_tips[i]` is the total tip in lamports for the `i`-th transaction in the slot. The tip is the increase (due to this transaction) in the total balance of all tip payment accounts across all block builders after any commission to the block builder is subtracted.  This implies that both the validator and staker portions of the tip are included in this value.  Non-bundle transactions may have a non-zero tip.  Tips for transactions in failed bundles are included up to the point of failure |
| txn_error_code                    | `number[]`  | `txn_error_code[i]` is the error code that explains the failure for the `i`-th transaction in the slot. See below for more details |
| txn_from_bundle                   | `boolean[]` | `txn_from_bundle[i]` is `true` if the `i`-th transaction in the slot came from a bundle and `false` otherwise.  A bundle is a microblock with 1-5 transactions that atomically fail or succeed. It is sent to the validator from a compatible block engine (e.g. jito) that can additionally collect MEV rewards that are distributed to stakers (i.e. tips) |
| txn_is_simple_vote                | `boolean[]` | `txn_is_simple_vote[i]` is `true` if the `i`-th transaction in the slot is a simple vote and `false` otherwise |
| txn_landed                        | `boolean[]` | `txn_landed[i]` is `true` if the `i`-th transaction in the slot was included in the produced block. A scheduled transaction may not be included in the block for any number of reasons (e.g. a failed bundle, a duplicate transaction, invalid fee-payer) |
| txn_bank_idx                      | `number[]`  | `txn_bank_idx[i]` is the index of the bank tile that executed the `i`-th transaction in the slot |
| txn_microblock_id                 | `string[]`  | `txn_microblock_id[i]` is the index of the microblock for the `i`-th transaction in the slot.  Microblocks are collections of 1+ transactions.  All of the transactions from a bundle share the same microblock. Microblock ids are monotonically increasing in the order they appear in the block and start at 0 for each slot |
| txn_signature                     | `string[]`  | `txn_signature[i]` is the base58 signature of the `i`-th transaction in the slot |
| txn_source_ipv4                   | `string[]`  | `txn_source_ipv4[i]` is the source ipv4 address for the `i`-th transaction in the slot |
| txn_source_tpu                    | `string[]`  | `txn_source_tpu[i]` is the transaction processing unit (TPU) which handled the `i`-th transaction in the slot |

The source tpu for a transaction can be one of the following

| TPU    | Description |
|--------|-------------|
| quic   | the primary ingress tpu for user transactions.  Utilizes the quic protocol to receive packets |
| udp    | ingress transactions received as simple UDP packets |
| gossip | vote transactions received from the gossip network |
| bundle | bundle transacionts received by the bundle tile from a block builder.  Utilizes a grpc connection to receive packets |
| send   | vote transactions procuded by this validator received from the send tile. These transactions are meant for the active cluster leader |

These are the possible error codes that might be included in `txn_error_code` and their meanings.

| Code Name                             | Code | Description |
|---------------------------------------|------|-------------|
| Success                               | 0    | The transaction successfully executed |
| AccountInUse                          | 1    | Includes a writable account that was already in use at the time this transaction was executed |
| AccountLoadedTwice                    | 2    | Lists at least one account pubkey more than once |
| AccountNotFound                       | 3    | Lists at least one account pubkey that was not found in the accounts database |
| ProgramAccountNotFound                | 4    | Could not find or parse a listed program account |
| InsufficientFundsForFee               | 5    | Lists a fee payer that does not have enough SOL to fund this transaction |
| InvalidAccountForFee                  | 6    | Lists a fee payer that may not be used to pay transaction fees |
| AlreadyProcessed                      | 7    | This transaction has been processed before (e.g. the transaction was sent twice) |
| BlockhashNotFound                     | 8    | Provides a block hash of a `recent` block in the chain, `b`, that this validator has not seen yet, or that is so old it has been discarded |
| InstructionError                      | 9    | Includes an instruction that failed to process |
| CallChainTooDeep                      | 10   | Includes a cross program invocation (CPI) chain that exceeds the maximum depth allowed |
| MissingSignatureForFee                | 11   | Requires a fee but has no signature present |
| InvalidAccountIndex                   | 12   | Contains an invalid account reference in one of its instructions |
| SignatureFailure                      | 13   | Includes a signature that did not pass verification |
| InvalidProgramForExecution            | 14   | Includes a program that may not be used for executing transactions |
| SanitizeFailure                       | 15   | Failed to parse a portion of the transaction payload |
| ClusterMaintenance                    | 16   | Cluster is undergoing an active maintenance window |
| AccountBorrowOutstanding              | 17   | Transaction processing left an account with an outstanding borrowed reference |
| WouldExceedMaxBlockCostLimit          | 18   | Exceeded the maximum compute unit cost allowed for this slot |
| UnsupportedVersion                    | 19   | Includes a transaction version that is not supported by this validator |
| InvalidWritableAccount                | 20   | Includes an account marked as writable that is not in fact writable |
| WouldExceedMaxAccountCostLimit        | 21   | Exceeded the maximum per-account compute unit cost allowed for this slot |
| WouldExceedAccountDataBlockLimit      | 22   | Retreived accounts data size exceeds the limit imposed for this slot |
| TooManyAccountLocks                   | 23   | Locked too many accounts |
| AddressLookupTableNotFound            | 24   | Loads an address table account that doesn't exist |
| InvalidAddressLookupTableOwner        | 25   | Loads an address table account with an invalid owner |
| InvalidAddressLookupTableData         | 26   | Loads an address table account with invalid data |
| InvalidAddressLookupTableIndex        | 27   | Address table lookup uses an invalid index |
| InvalidRentPayingAccount              | 28   | Deprecated |
| WouldExceedMaxVoteCostLimit           | 29   | Exceeded the maximum vote compute unit cost allowed for this slot |
| WouldExceedAccountDataTotalLimit      | 30   | Deprecated |
| DuplicateInstruction                  | 31   | Contains duplicate instructions |
| InsufficientFundsForRent              | 32   | Deprecated |
| MaxLoadedAccountsDataSizeExceeded     | 33   | Retreived accounts data size exceeds the limit imposed for this transaction |
| InvalidLoadedAccountsDataSizeLimit    | 34   | Requested an invalid data size (i.e. 0) |
| ResanitizationNeeded                  | 35   | Sanitized transaction differed before/after feature activiation. Needs to be resanitized |
| ProgramExecutionTemporarilyRestricted | 36   | Execution of a program referenced by this transaciton is restricted |
| UnbalancedTransaction                 | 37   | The total accounts balance before the transaction does not equal the total balance after |
| ProgramCacheHitMaxLimit               | 38   | The program cache allocated for transaction batch for this transaction hit its load limit |
| CommitCancelled                       | 39   | This transaction was aborted during the commit stage |
| BundlePeer                            | 40   | This transaction was part of a bundle that failed |