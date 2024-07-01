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

```js
client = new WebSocket("ws://localhost:port/websocket");
```

The port to connect to is specified in the validator configuration TOML
file, it is the same as the GUI port under
`[tiles.http.gui_listen_port]`

The API is split into various topics which will be streamed to any and
all connected clients. Except where specifically noted below, all data
is live and any time a piece of data changes the client will immediately
receive a new WebSocket message indicating what changed.

The server does not drop information, slow down, or stop publishing the
stream of information if the client cannot keep up. A client that is
reading too slow and cannot keep up with incoming data stream will have
its connection forcibly closed by the server.

Most data updates are streamed in real time as the changes occur except
certain updates (performance counters like packet counters) which would
change too quickly, which are instead republished on a regular frequency
described below.

When first connecting, all currently known data will be pushed over the
connection, and once this data has been sent, streaming updates for
changes will start. The initial data that is pushed is itself presented
in the form of streaming updates. For example, when listing all the
gossip peers when first connecting, you will receive a long sequence of
`peer_add` messages.

All data is encoded in JSON, with a containing envelope as follows:

```json
{
    "topic": "summary",
    "key":   "cluster",
    "value": "mainnet-beta",
}
```

Data is always sent in full for messages in a topic, even if nothing
changed for a particular field, and the data is encoded in JSON.

## Forks
The WebSocket API does not communicate information for all forks tracked
by the validator. Instead, only information about the currently active
fork is represented and streamed. For example, the `completed_slot` is
the last completed slot on the current active fork, and `slot_update`
messages are only received for slots changing on the currently active
fork.

## Topics

### summary
A set of high level informational fields about the validator.

| Key     | Type   | Description
|---------|--------|------------
| cluster | String | One of `mainnet-beta`, `devnet`, `testnet`, `pythtest`, `pythnet`, or `unknown`. Indicates the cluster that the validator is likely to be running on. If a validator is misconfigured and, for example, connects to multiple networks, the first (highest priority) network in the above list will be displayed.
| identity_key | String | The public identity key assigned to the running validator, encoded in base58.
| rooted_slot | Number | The last slot that was rooted. Rooted slots are fully confirmed and irreversible, and the rooted slot will never decrease.
| optimistically_confirmed_slot | Number | The highest slot on the current fork that was optimistically confirmed. This may decrease when switching forks.
| completed_slot | Number | The highest completed slot on the current fork choice of the validator. The completed slot may decrease or stay the same for a long time, if the validator is switching forks.
| estimated_slot | Number | The estimated slot of the network. Note that if many slots are skipped in a row, the estimated slot keeps advancing while the completed slot stays the same. The estimated slot may decrease if the validator is switching forks, or we overestimated slot progress.
| estimated_transactions_per_second | Number | The estimated number of transactions per second the network is running at. This is a moving average from the prior 150 slots, or around one minute. For a more precise view of transactions per second, the client can calculate it from the stream of new slot data.
| estimated_nonvote_transactions_per_second | Number | The estimated number of non-vote transactions per second the network is running at. This is a moving average from the prior 150 slots, or around one minute. For a more precise view of non-vote transactions per second, the client can calculate it from the stream of new slot data.

## epoch_new
Information about an epoch. Epochs are never modified once they have been determined, so the topic only publishes a continuous stream of new epochs as they are known. When connecting, the current and next epoch are known. Epochs become known one epoch in advance, and will only be published once they are confirmed (the prior epoch has fully rooted).

| Field | Type | Description
|-------|------|------------
| id    | Number | An identity counter for each epoch, starting at zero for the first epoch and going up.
| start_slot | Number | The first slot (inclusive) in the epoch.
| end_slot | Number | The last slot (inclusive) in the epoch.
| estimated_start_time| Number | Unix timestamp of when the epoch began. Epoch start times are only known if the validator was running when the epoch began, otherwise it is estimated by extending the average slot time for the past 1000 slots backward to the start of the epoch.
| estimated_end_time| Number | Unix timestamp of when we estiamte the epoch will complete. Slot times vary and the estimate is calculated by extending the average slot time for the past 1000 slots forward to end of the epoch.
| leader_slots | Array[Number] | An array of all the leader slots in the epoch that are ours. Might be empty if we have no leader slots. This cannot currently change, as the validator identity key cannot change.

## epoch_update
Once every ten seconds, the validator re-estimates the epoch start and end times and republishes them under this topic. No other information about an epoch can change and will not be present here.

| Field | Type | Description
|-------|------|------------
| id    | Number | An identity counter for each epoch, starting at zero for the first epoch and going up.
| estimated_start_time | Number | See `epoch_new`
| estimated_end_time | Number | See `epoch_new`

## peer_update
Either new peer joined the cluster and started gossiping, or an existing peer was changed and has new information.

| Field    | Type   | Description
|----------|--------|------------
| identity | String | Identity public key of the validator, encoded in base58.
| stake_lamports | Number | Stake of the validator in Lamports. A stake of zero indicates a non-staked or non-voting validator.

## peer_remove
A peer was removed from the cluster and is no longer being gossiped.

| Field | Type | Description
|-------|------|------------
| identity | String | Identity public key of the validator, encoded in base58.

## slot_update
A slot was either completed (not confirmed) on the currently active
fork, or it was updated and the satate changed. Published immediately
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

| Field      | Type    | Description
|------------|---------|------------
| slot       | Number  | Identity of the slot, counting up from zero for the first slot in the chain.
| mine       | Boolean | True if this validator was the leader for this slot. This will never change for a slot once it has been published, and will be aligned with the epoch information.
| skipped    | Boolean | True if the slot was skipped. The skipped state is the state in the currently active fork of the validator. The skipped state can change if the validator switches active fork, in which case an update will be published in a `slot_update` message.
| status     | String  | One of `rooted`, `optimistically_confirmed`, `completed`, or `unpublished`. The state is the state in the currently active fork of the validator. The state can change normally (for example, a completed slot becoming optimisitically confirmed or rooted), or also because the validator switched forks.
| transactions | Number | Total number of transactions (vote and non-vote) in the block. Zero for skipped slots.
| failed_transactions | Number | Total number of failed transactions (vote and non-vote) in the block. Zero for skipped slots. Failed transactions are those which are included in the block and were charged fees, but failed to execute successfully. This is different from dropped transations which do not pay fees and are not included in the  block.
| failed_vote_transactions | Number | Total number of failed vote transactions.
| vote_transactions | Number | Total number of vote transactions in the block. Zero for skipped slots. Will always be less than or equal to `transactions`. The number of non-vote transactions is given by `transactions - vote_transactions`.
| compute_units | Number | Total number of compute units used by the slot
| leader_start_time | Number  | Unix timestamp of when the slot was started, locally on this validator. This is the time we became leader.
| leader_end_time   | Number  | Unix timestamp of when the slot was finished, locally on this validator. This is the time we finished being leader.
| leader_acquired_transactions | Number | The total number of transactions that were acquired since the end of our prior leader slot, until the end of this leader slot. Transactions can be acquired for many reasons, which are given individually below.
| leader_acquired_transactions_leftover | Number | The transactions were received during or prior to an earlier leader slot, but weren't executed yet so they stayed available to execute in this slot.
| leader_acquired_transactions_quic | Number | A transaction stream was received via. QUIC.  The stream does not have to successfully complete.
| leader_acquired_transactions_nonquic | Number | A transaction stream was received via. regular UDP.
| leader_acquired_transactions_gossip | Number | A gossipped vote was received from a gossip peer.
| leader_dropped_transactions | Number | The total number of transactions that were dropped from the end of our prior leader slot, until the end of this leader slot. Transactions can be dropped for many reasons, which are given individually below.
| leader_dropped_transactions_verify_overrun | Number | Count of transactions that were dropped because the system could not verify incoming transactions quickly enough, and a verify tile was overrun.
| leader_dropped_transactions_verify_failed | Number | Count of transactions that were dropped because signature verification failed.
| leader_dropped_transactions_dedup_failed | Number | Count of transactions that were dropped because they were a duplicate of another recently received transaction.
| leader_dropped_transactions_pack_overrun | Number | Count of transactions that were dropped because the pack buffer was filled prior to becoming leader, and we had to start dropping lower priority transactions.
| leader_dropped_transactions_pack_invalid | Number | Count of transactions that were dropped because pack determined they would never execute. Reasons can include the transaction expired, requested too many compute units, or was too large to fit in a block.
| leader_dropped_transactions_bank_overrun | Number | Count of transactions that were dropped because the system could not execute incoming transactions quickly enough, and pack was overrun while it was trying to execute transaxtions.
| leader_dropped_transactions_fee_payer | Number | Count of transactions that were dropped because the fee payer did not have enough balance.
| leader_dropped_transactions_lookup_table | Number | Count of transactions that were dropped because there was an error loading an account lookup table.

FORWARDED ??
