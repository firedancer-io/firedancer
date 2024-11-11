
## All Links
<!--@include: ./metrics-link-preamble.md-->
| Metric | Type | Description |
|--------|------|-------------|
| link_&#8203;slow_&#8203;count | `counter` | The number of times the consumer was detected as rate limiting consumer by the producer. |
| link_&#8203;consumed_&#8203;count | `counter` | The number of times the link reader has consumed a fragment. |
| link_&#8203;consumed_&#8203;size_&#8203;bytes | `counter` | The total number of bytes read by the link consumer. |
| link_&#8203;filtered_&#8203;count | `counter` | The number of fragments that were filtered and not consumed. |
| link_&#8203;filtered_&#8203;size_&#8203;bytes | `counter` | The total number of bytes read by the link consumer that were filtered. |
| link_&#8203;overrun_&#8203;polling_&#8203;count | `counter` | The number of times the link has been overrun while polling. |
| link_&#8203;overrun_&#8203;polling_&#8203;frag_&#8203;count | `counter` | The number of fragments the link has not processed because it was overrun while polling. |
| link_&#8203;overrun_&#8203;reading_&#8203;count | `counter` | The number of input overruns detected while reading metadata by the consumer. |
| link_&#8203;overrun_&#8203;reading_&#8203;frag_&#8203;count | `counter` | The number of fragments the link has not processed because it was overrun while reading. |

## All Tiles
<!--@include: ./metrics-tile-preamble.md-->
| Metric | Type | Description |
|--------|------|-------------|
| tile_&#8203;pid | `gauge` | The process ID of the tile. |
| tile_&#8203;tid | `gauge` | The thread ID of the tile. Always the same as the Pid in production, but might be different in development. |
| tile_&#8203;context_&#8203;switch_&#8203;involuntary_&#8203;count | `counter` | The number of involuntary context switches. |
| tile_&#8203;context_&#8203;switch_&#8203;voluntary_&#8203;count | `counter` | The number of voluntary context switches. |
| stem_&#8203;status | `gauge` | The current status of the tile. 0 is booting, 1 is running. |
| stem_&#8203;heartbeat | `gauge` | The last UNIX timestamp in nanoseconds that the tile heartbeated. |
| stem_&#8203;in_&#8203;backpressure | `gauge` | Whether the tile is currently backpressured or not, either 1 or 0. |
| stem_&#8203;backpressure_&#8203;count | `counter` | Number of times the times the tile has had to wait for one of more consumers to catch up to resume publishing. |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;caught_&#8203;up_&#8203;housekeeping | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Caught up + Housekeeping) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;processing_&#8203;housekeeping | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Processing + Housekeeping) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;backpressure_&#8203;housekeeping | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Backpressure + Housekeeping) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;caught_&#8203;up_&#8203;prefrag | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Caught up + Prefrag) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;processing_&#8203;prefrag | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Processing + Prefrag) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;backpressure_&#8203;prefrag | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Backpressure + Prefrag) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;caught_&#8203;up_&#8203;postfrag | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Caught up + Postfrag) |
| stem_&#8203;regime_&#8203;duration_&#8203;nanos_&#8203;processing_&#8203;postfrag | `counter` | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Processing + Postfrag) |

## Net Tile
| Metric | Type | Description |
|--------|------|-------------|
| net_&#8203;tile_&#8203;received_&#8203;packets | `counter` | Number of IP packets received. |
| net_&#8203;tile_&#8203;received_&#8203;bytes | `counter` | Total bytes received (including IP, UDP headers). |
| net_&#8203;tile_&#8203;sent_&#8203;packets | `counter` | Number of IP packets sent. |
| net_&#8203;tile_&#8203;sent_&#8203;bytes | `counter` | Total bytes sent (including IP, UDP headers). |
| net_&#8203;tile_&#8203;xdp_&#8203;rx_&#8203;dropped_&#8203;ring_&#8203;full | `counter` | Number of packets dropped because the RX completion queue was empty. This is only reported for net tile 0, since the measurement is across all RX queues. |
| net_&#8203;tile_&#8203;xdp_&#8203;rx_&#8203;dropped_&#8203;other | `counter` | Number of packets dropped for other reasons. This is only reported for net tile 0, since the measurement is across all RX queues. |
| net_&#8203;tile_&#8203;tx_&#8203;dropped | `counter` | Number of packets dropped because the TX submission queue was empty. This is reported for all net tiles. |

## Quic Tile
| Metric | Type | Description |
|--------|------|-------------|
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;append_&#8203;success | `counter` | Result of fragment reassembly for a non-QUIC UDP transaction. (Success) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;append_&#8203;error_&#8203;oversize | `counter` | Result of fragment reassembly for a non-QUIC UDP transaction. (Oversize message) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;append_&#8203;error_&#8203;skip | `counter` | Result of fragment reassembly for a non-QUIC UDP transaction. (Out-of-order data within QUIC stream) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;append_&#8203;error_&#8203;state | `counter` | Result of fragment reassembly for a non-QUIC UDP transaction. (Unexpected slot state) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;publish_&#8203;success | `counter` | Result of publishing reassmbled fragment for a non-QUIC UDP transaction. (Success) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;publish_&#8203;error_&#8203;oversize | `counter` | Result of publishing reassmbled fragment for a non-QUIC UDP transaction. (Oversize message) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;publish_&#8203;error_&#8203;skip | `counter` | Result of publishing reassmbled fragment for a non-QUIC UDP transaction. (Out-of-order data within QUIC stream) |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;reassembly_&#8203;publish_&#8203;error_&#8203;state | `counter` | Result of publishing reassmbled fragment for a non-QUIC UDP transaction. (Unexpected slot state) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;append_&#8203;success | `counter` | Result of fragment reassembly for a QUIC transaction. (Success) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;append_&#8203;error_&#8203;oversize | `counter` | Result of fragment reassembly for a QUIC transaction. (Oversize message) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;append_&#8203;error_&#8203;skip | `counter` | Result of fragment reassembly for a QUIC transaction. (Out-of-order data within QUIC stream) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;append_&#8203;error_&#8203;state | `counter` | Result of fragment reassembly for a QUIC transaction. (Unexpected slot state) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;publish_&#8203;success | `counter` | Result of publishing reassmbled fragment for a QUIC transaction. (Success) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;publish_&#8203;error_&#8203;oversize | `counter` | Result of publishing reassmbled fragment for a QUIC transaction. (Oversize message) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;publish_&#8203;error_&#8203;skip | `counter` | Result of publishing reassmbled fragment for a QUIC transaction. (Out-of-order data within QUIC stream) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;publish_&#8203;error_&#8203;state | `counter` | Result of publishing reassmbled fragment for a QUIC transaction. (Unexpected slot state) |
| quic_&#8203;tile_&#8203;reassembly_&#8203;notify_&#8203;aborted | `counter` | Reassembly slot was aborted before it was notified. |
| quic_&#8203;tile_&#8203;reassembly_&#8203;notify_&#8203;clobbered | `counter` | Reassembly slot was clobbered before it was notified. |
| quic_&#8203;tile_&#8203;quic_&#8203;packet_&#8203;too_&#8203;small | `counter` | Count of packets received on the QUIC port that were too small to be a valid IP packet. |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;packet_&#8203;too_&#8203;small | `counter` | Count of packets received on the non-QUIC port that were too small to be a valid IP packet. |
| quic_&#8203;tile_&#8203;non_&#8203;quic_&#8203;packet_&#8203;too_&#8203;large | `counter` | Count of packets received on the non-QUIC port that were too large to be a valid transaction. |
| quic_&#8203;received_&#8203;packets | `counter` | Number of IP packets received. |
| quic_&#8203;received_&#8203;bytes | `counter` | Total bytes received (including IP, UDP, QUIC headers). |
| quic_&#8203;sent_&#8203;packets | `counter` | Number of IP packets sent. |
| quic_&#8203;sent_&#8203;bytes | `counter` | Total bytes sent (including IP, UDP, QUIC headers). |
| quic_&#8203;connections_&#8203;active | `gauge` | The number of currently active QUIC connections. |
| quic_&#8203;connections_&#8203;created | `counter` | The total number of connections that have been created. |
| quic_&#8203;connections_&#8203;closed | `counter` | Number of connections gracefully closed. |
| quic_&#8203;connections_&#8203;aborted | `counter` | Number of connections aborted. |
| quic_&#8203;connections_&#8203;timed_&#8203;out | `counter` | Number of connections timed out. |
| quic_&#8203;connections_&#8203;retried | `counter` | Number of connections established with retry. |
| quic_&#8203;connection_&#8203;error_&#8203;no_&#8203;slots | `counter` | Number of connections that failed to create due to lack of slots. |
| quic_&#8203;connection_&#8203;error_&#8203;tls_&#8203;fail | `counter` | Number of connections that aborted due to TLS failure. |
| quic_&#8203;connection_&#8203;error_&#8203;retry_&#8203;fail | `counter` | Number of connections that failed during retry (e.g. invalid token). |
| quic_&#8203;handshakes_&#8203;created | `counter` | Number of handshake flows created. |
| quic_&#8203;handshake_&#8203;error_&#8203;alloc_&#8203;fail | `counter` | Number of handshakes dropped due to alloc fail. |
| quic_&#8203;stream_&#8203;opened | `counter` | Number of streams opened. |
| quic_&#8203;stream_&#8203;closed_&#8203;end | `counter` | Number of streams closed. (gracefully closed) |
| quic_&#8203;stream_&#8203;closed_&#8203;peer_&#8203;reset | `counter` | Number of streams closed. (RESET_STREAM event received) |
| quic_&#8203;stream_&#8203;closed_&#8203;peer_&#8203;stop | `counter` | Number of streams closed. (STOP_SENDING events received) |
| quic_&#8203;stream_&#8203;closed_&#8203;drop | `counter` | Number of streams closed. (dropped due to excessive concurrency) |
| quic_&#8203;stream_&#8203;closed_&#8203;conn_&#8203;abort | `counter` | Number of streams closed. (connection abort) |
| quic_&#8203;stream_&#8203;active | `gauge` | Number of active streams. |
| quic_&#8203;stream_&#8203;received_&#8203;events | `counter` | Number of stream RX events. |
| quic_&#8203;stream_&#8203;received_&#8203;bytes | `counter` | Total stream payload bytes received. |
| quic_&#8203;received_&#8203;frames_&#8203;unknown | `counter` | Number of QUIC frames received. (Unknown frame type) |
| quic_&#8203;received_&#8203;frames_&#8203;ack | `counter` | Number of QUIC frames received. (ACK frame) |
| quic_&#8203;received_&#8203;frames_&#8203;reset_&#8203;stream | `counter` | Number of QUIC frames received. (RESET_STREAM frame) |
| quic_&#8203;received_&#8203;frames_&#8203;stop_&#8203;sending | `counter` | Number of QUIC frames received. (STOP_SENDING frame) |
| quic_&#8203;received_&#8203;frames_&#8203;crypto | `counter` | Number of QUIC frames received. (CRYPTO frame) |
| quic_&#8203;received_&#8203;frames_&#8203;new_&#8203;token | `counter` | Number of QUIC frames received. (NEW_TOKEN frame) |
| quic_&#8203;received_&#8203;frames_&#8203;stream | `counter` | Number of QUIC frames received. (STREAM frame) |
| quic_&#8203;received_&#8203;frames_&#8203;max_&#8203;data | `counter` | Number of QUIC frames received. (MAX_DATA frame) |
| quic_&#8203;received_&#8203;frames_&#8203;max_&#8203;stream_&#8203;data | `counter` | Number of QUIC frames received. (MAX_STREAM_DATA frame) |
| quic_&#8203;received_&#8203;frames_&#8203;max_&#8203;streams | `counter` | Number of QUIC frames received. (MAX_STREAMS frame) |
| quic_&#8203;received_&#8203;frames_&#8203;data_&#8203;blocked | `counter` | Number of QUIC frames received. (DATA_BLOCKED frame) |
| quic_&#8203;received_&#8203;frames_&#8203;stream_&#8203;data_&#8203;blocked | `counter` | Number of QUIC frames received. (STREAM_DATA_BLOCKED frame) |
| quic_&#8203;received_&#8203;frames_&#8203;streams_&#8203;blocked | `counter` | Number of QUIC frames received. (STREAMS_BLOCKED(bidi) frame) |
| quic_&#8203;received_&#8203;frames_&#8203;new_&#8203;conn_&#8203;id | `counter` | Number of QUIC frames received. (NEW_CONN_ID frame) |
| quic_&#8203;received_&#8203;frames_&#8203;retire_&#8203;conn_&#8203;id | `counter` | Number of QUIC frames received. (RETIRE_CONN_ID frame) |
| quic_&#8203;received_&#8203;frames_&#8203;path_&#8203;challenge | `counter` | Number of QUIC frames received. (PATH_CHALLENGE frame) |
| quic_&#8203;received_&#8203;frames_&#8203;path_&#8203;response | `counter` | Number of QUIC frames received. (PATH_RESPONSE frame) |
| quic_&#8203;received_&#8203;frames_&#8203;conn_&#8203;close_&#8203;quic | `counter` | Number of QUIC frames received. (CONN_CLOSE(transport) frame) |
| quic_&#8203;received_&#8203;frames_&#8203;conn_&#8203;close_&#8203;app | `counter` | Number of QUIC frames received. (CONN_CLOSE(app) frame) |
| quic_&#8203;received_&#8203;frames_&#8203;handshake_&#8203;done | `counter` | Number of QUIC frames received. (HANDSHAKE_DONE frame) |
| quic_&#8203;received_&#8203;frames_&#8203;ping | `counter` | Number of QUIC frames received. (PING frame) |
| quic_&#8203;received_&#8203;frames_&#8203;padding | `counter` | Number of QUIC frames received. (PADDING frame) |

## Verify Tile
| Metric | Type | Description |
|--------|------|-------------|
| verify_&#8203;transaction_&#8203;parse_&#8203;failure | `counter` | Count of transactions that failed to parse |
| verify_&#8203;transaction_&#8203;dedup_&#8203;failure | `counter` | Count of transactions that failed to deduplicate in the verify stage |
| verify_&#8203;transaction_&#8203;verify_&#8203;failure | `counter` | Count of transactions that failed to deduplicate in the verify stage |

## Dedup Tile
| Metric | Type | Description |
|--------|------|-------------|
| dedup_&#8203;transaction_&#8203;dedup_&#8203;failure | `counter` | Count of transactions that failed to deduplicate in the dedup stage |
| dedup_&#8203;gossiped_&#8203;votes_&#8203;received | `counter` | Count of simple vote transactions received over gossip instead of via the normal TPU path |

## Pack Tile
| Metric | Type | Description |
|--------|------|-------------|
| pack_&#8203;schedule_&#8203;microblock_&#8203;duration_&#8203;seconds | `histogram` | Duration of scheduling one microblock |
| pack_&#8203;insert_&#8203;transaction_&#8203;duration_&#8203;seconds | `histogram` | Duration of inserting one transaction into the pool of available transactions |
| pack_&#8203;total_&#8203;transactions_&#8203;per_&#8203;microblock_&#8203;count | `histogram` | Count of transactions in a scheduled microblock, including both votes and non-votes |
| pack_&#8203;votes_&#8203;per_&#8203;microblock_&#8203;count | `histogram` | Count of simple vote transactions in a scheduled microblock |
| pack_&#8203;normal_&#8203;transaction_&#8203;received | `counter` | Count of transactions received via the normal TPU path |
| pack_&#8203;transaction_&#8203;inserted_&#8203;bundle_&#8203;blacklist | `counter` | Result of inserting a transaction into the pack object (Transaction uses an account on the bundle blacklist) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;write_&#8203;sysvar | `counter` | Result of inserting a transaction into the pack object (Transaction tries to write to a sysvar) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;estimation_&#8203;fail | `counter` | Result of inserting a transaction into the pack object (Estimating compute cost and/or fee failed) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;duplicate_&#8203;account | `counter` | Result of inserting a transaction into the pack object (Transaction included an account address twice) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;too_&#8203;many_&#8203;accounts | `counter` | Result of inserting a transaction into the pack object (Transaction tried to load too many accounts) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;too_&#8203;large | `counter` | Result of inserting a transaction into the pack object (Transaction requests too many CUs) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;expired | `counter` | Result of inserting a transaction into the pack object (Transaction already expired) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;addr_&#8203;lut | `counter` | Result of inserting a transaction into the pack object (Transaction loaded accounts from a lookup table) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;unaffordable | `counter` | Result of inserting a transaction into the pack object (Fee payer's balance below transaction fee) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;duplicate | `counter` | Result of inserting a transaction into the pack object (Pack aware of transaction with same signature) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;priority | `counter` | Result of inserting a transaction into the pack object (Transaction's fee was too low given its compute unit requirement and other competing transactions) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;nonvote_&#8203;add | `counter` | Result of inserting a transaction into the pack object (Transaction that was not a simple vote added to pending transactions) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;vote_&#8203;add | `counter` | Result of inserting a transaction into the pack object (Simple vote transaction was added to pending transactions) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;nonvote_&#8203;replace | `counter` | Result of inserting a transaction into the pack object (Transaction that was not a simple vote replaced a lower priority transaction) |
| pack_&#8203;transaction_&#8203;inserted_&#8203;vote_&#8203;replace | `counter` | Result of inserting a transaction into the pack object (Simple vote transaction replaced a lower priority transaction) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had no transactions available, and wasn't leader) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had transactions available, but wasn't leader or had hit a limit) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had no transactions available, had banks but wasn't leader?) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had transactions available, had banks but wasn't leader?) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had no transactions available, and was leader but had no available banks) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had transactions available, was leader, but had no available banks) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had available banks but no transactions) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack had banks and transactions available but couldn't schedule anything non-conflicting) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader?) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader?) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader?) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader?) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock but all banks were busy?) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock but all banks were busy?) |
| pack_&#8203;metric_&#8203;timing_&#8203;no_&#8203;txn_&#8203;bank_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock and now has no transactions) |
| pack_&#8203;metric_&#8203;timing_&#8203;txn_&#8203;bank_&#8203;leader_&#8203;microblock | `counter` | Time in nanos spent in each state (Pack scheduled a non-empty microblock) |
| pack_&#8203;transaction_&#8203;dropped_&#8203;from_&#8203;extra | `counter` | Transactions dropped from the extra transaction storage because it was full |
| pack_&#8203;transaction_&#8203;inserted_&#8203;to_&#8203;extra | `counter` | Transactions inserted into the extra transaction storage because pack's primary storage was full |
| pack_&#8203;transaction_&#8203;inserted_&#8203;from_&#8203;extra | `counter` | Transactions pulled from the extra transaction storage and inserted into pack's primary storage |
| pack_&#8203;transaction_&#8203;expired | `counter` | Transactions deleted from pack because their TTL expired |
| pack_&#8203;available_&#8203;transactions | `gauge` | The total number of pending transactions in pack's pool that are available to be scheduled |
| pack_&#8203;available_&#8203;vote_&#8203;transactions | `gauge` | The number of pending simple vote transactions in pack's pool that are available to be scheduled |
| pack_&#8203;pending_&#8203;transactions_&#8203;heap_&#8203;size | `gauge` | The maximum number of pending transactions that pack can consider.  This value is fixed at Firedancer startup but is a useful reference for AvailableTransactions and AvailableVoteTransactions. |
| pack_&#8203;microblock_&#8203;per_&#8203;block_&#8203;limit | `counter` | The number of times pack did not pack a microblock because the limit on microblocks/block had been reached |
| pack_&#8203;data_&#8203;per_&#8203;block_&#8203;limit | `counter` | The number of times pack did not pack a microblock because it reached reached the data per block limit at the start of trying to schedule a microblock |
| pack_&#8203;transaction_&#8203;schedule_&#8203;taken | `counter` | Result of trying to consider a transaction for scheduling (Pack included the transaction in the microblock) |
| pack_&#8203;transaction_&#8203;schedule_&#8203;cu_&#8203;limit | `counter` | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the block CU limit) |
| pack_&#8203;transaction_&#8203;schedule_&#8203;fast_&#8203;path | `counter` | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because of account conflicts using the fast bitvector check) |
| pack_&#8203;transaction_&#8203;schedule_&#8203;byte_&#8203;limit | `counter` | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the block data size limit) |
| pack_&#8203;transaction_&#8203;schedule_&#8203;write_&#8203;cost | `counter` | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have caused a writable account to exceed the per-account block write cost limit) |
| pack_&#8203;transaction_&#8203;schedule_&#8203;slow_&#8203;path | `counter` | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because of account conflicts using the full slow check) |
| pack_&#8203;cus_&#8203;consumed_&#8203;in_&#8203;block | `gauge` | The number of cost units consumed in the current block, or 0 if pack is not currently packing a block |
| pack_&#8203;cus_&#8203;scheduled | `histogram` | The number of cost units scheduled for each block pack produced.  This can be higher than the block limit because of returned CUs. |
| pack_&#8203;cus_&#8203;rebated | `histogram` | The number of compute units rebated for each block pack produced.  Compute units are rebated when a transaction fails prior to execution or requests more compute units than it uses. |
| pack_&#8203;cus_&#8203;net | `histogram` | The net number of cost units (scheduled - rebated) in each block pack produced. |
| pack_&#8203;delete_&#8203;missed | `counter` | Count of attempts to delete a transaction that wasn't found |
| pack_&#8203;delete_&#8203;hit | `counter` | Count of attempts to delete a transaction that was found and deleted |

## Bank Tile
| Metric | Type | Description |
|--------|------|-------------|
| bank_&#8203;tile_&#8203;transaction_&#8203;sanitize_&#8203;failure | `counter` | Number of transactions that failed to sanitize. |
| bank_&#8203;tile_&#8203;transaction_&#8203;not_&#8203;executed_&#8203;failure | `counter` | Number of transactions that did not execute. This is different than transactions which fail to execute, which make it onto the chain. |
| bank_&#8203;tile_&#8203;precompile_&#8203;verify_&#8203;failure | `counter` | Number of transactions that failed precompile verification and thus will not execute. |
| bank_&#8203;tile_&#8203;slot_&#8203;acquire_&#8203;success | `counter` | Result of acquiring a slot. (Success) |
| bank_&#8203;tile_&#8203;slot_&#8203;acquire_&#8203;too_&#8203;high | `counter` | Result of acquiring a slot. (Too high) |
| bank_&#8203;tile_&#8203;slot_&#8203;acquire_&#8203;too_&#8203;low | `counter` | Result of acquiring a slot. (Too low) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables_&#8203;success | `counter` | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (Success) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables_&#8203;slot_&#8203;hashes_&#8203;sysvar_&#8203;not_&#8203;found | `counter` | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The slot hashes syvar could not be found.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables_&#8203;account_&#8203;not_&#8203;found | `counter` | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account storing the address lookup table was deactivated or could not be found.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables_&#8203;invalid_&#8203;account_&#8203;owner | `counter` | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account that owns the referenced lookup table is not the address lookup table program.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables_&#8203;invalid_&#8203;account_&#8203;data | `counter` | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The data for the referenced address lookup table is malformed.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables_&#8203;invalid_&#8203;index | `counter` | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The referenced index in the address lookup table does not exist.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;success | `counter` | Result of loading a transaction. (Success) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;account_&#8203;in_&#8203;use | `counter` | Result of loading a transaction. (An account is already being processed in another transaction in a way that does not support parallelism.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;account_&#8203;loaded_&#8203;twice | `counter` | Result of loading a transaction. (A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference `Pubkey`s more than once but the message must contain a list with no duplicate keys.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;account_&#8203;not_&#8203;found | `counter` | Result of loading a transaction. (Attempt to debit an account but found no record of a prior credit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;program_&#8203;account_&#8203;not_&#8203;found | `counter` | Result of loading a transaction. (Attempt to load a program that does not exist.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;insufficient_&#8203;funds_&#8203;for_&#8203;fee | `counter` | Result of loading a transaction. (The fee payer `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;account_&#8203;for_&#8203;fee | `counter` | Result of loading a transaction. (This account may not be used to pay transaction fees.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;already_&#8203;processed | `counter` | Result of loading a transaction. (The bank has seen this transaction before. This can occur under normal operation when a UDP packet is duplicated, as a user error from a client not updating its `recent_blockhash`, or as a double-spend attack.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;blockhash_&#8203;not_&#8203;found | `counter` | Result of loading a transaction. (The bank has not seen the given `recent_blockhash` or the transaction is too old and the `recent_blockhash` has been discarded.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;instruction_&#8203;error | `counter` | Result of loading a transaction. (An error occurred while processing an instruction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;call_&#8203;chain_&#8203;too_&#8203;deep | `counter` | Result of loading a transaction. (Loader call chain is too deep.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;missing_&#8203;signature_&#8203;for_&#8203;fee | `counter` | Result of loading a transaction. (Transaction requires a fee but has no signature present.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;account_&#8203;index | `counter` | Result of loading a transaction. (Transaction contains an invalid account reference.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;signature_&#8203;failure | `counter` | Result of loading a transaction. (Transaction did not pass signature verification.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;program_&#8203;for_&#8203;execution | `counter` | Result of loading a transaction. (This program may not be used for executing instructions.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;sanitize_&#8203;failure | `counter` | Result of loading a transaction. (Transaction failed to sanitize accounts offsets correctly implies that account locks are not taken for this TX, and should not be unlocked.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;cluster_&#8203;maintenance | `counter` | Result of loading a transaction. (Transactions are currently disabled due to cluster maintenance.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;account_&#8203;borrow_&#8203;outstanding | `counter` | Result of loading a transaction. (Transaction processing left an account with an outstanding borrowed reference.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;would_&#8203;exceed_&#8203;max_&#8203;block_&#8203;cost_&#8203;limit | `counter` | Result of loading a transaction. (Transaction would exceed max Block Cost Limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;unsupported_&#8203;version | `counter` | Result of loading a transaction. (Transaction version is unsupported.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;writable_&#8203;account | `counter` | Result of loading a transaction. (Transaction loads a writable account that cannot be written.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;would_&#8203;exceed_&#8203;max_&#8203;account_&#8203;cost_&#8203;limit | `counter` | Result of loading a transaction. (Transaction would exceed max account limit within the block.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;block_&#8203;limit | `counter` | Result of loading a transaction. (Transaction would exceed account data limit within the block.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;too_&#8203;many_&#8203;account_&#8203;locks | `counter` | Result of loading a transaction. (Transaction locked too many accounts.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found | `counter` | Result of loading a transaction. (Address lookup table not found.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner | `counter` | Result of loading a transaction. (Attempted to lookup addresses from an account owned by the wrong program.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data | `counter` | Result of loading a transaction. (Attempted to lookup addresses from an invalid account.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index | `counter` | Result of loading a transaction. (Address table lookup uses an invalid index.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;rent_&#8203;paying_&#8203;account | `counter` | Result of loading a transaction. (Transaction leaves an account with a lower balance than rent-exempt minimum.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;would_&#8203;exceed_&#8203;max_&#8203;vote_&#8203;cost_&#8203;limit | `counter` | Result of loading a transaction. (Transaction would exceed max Vote Cost Limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;total_&#8203;limit | `counter` | Result of loading a transaction. (Transaction would exceed total account data limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;duplicate_&#8203;instruction | `counter` | Result of loading a transaction. (Transaction contains a duplicate instruction that is not allowed.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;insufficient_&#8203;funds_&#8203;for_&#8203;rent | `counter` | Result of loading a transaction. (Transaction results in an account with insufficient funds for rent.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded | `counter` | Result of loading a transaction. (Transaction exceeded max loaded accounts data size cap.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit | `counter` | Result of loading a transaction. (LoadedAccountsDataSizeLimit set for transaction must be greater than 0.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;resanitization_&#8203;needed | `counter` | Result of loading a transaction. (Sanitized transaction differed before/after feature activiation. Needs to be resanitized.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;program_&#8203;execution_&#8203;temporarily_&#8203;restricted | `counter` | Result of loading a transaction. (Program execution is temporarily restricted on an account.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;unbalanced_&#8203;transaction | `counter` | Result of loading a transaction. (The total balance before the transaction does not equal the total balance after the transaction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;load_&#8203;program_&#8203;cache_&#8203;hit_&#8203;max_&#8203;limit | `counter` | Result of loading a transaction. (The total program cache size hit the maximum allowed limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;success | `counter` | Result of executing a transaction. Could be a failure or success. (Success) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;account_&#8203;in_&#8203;use | `counter` | Result of executing a transaction. Could be a failure or success. (An account is already being processed in another transaction in a way that does not support parallelism.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;account_&#8203;loaded_&#8203;twice | `counter` | Result of executing a transaction. Could be a failure or success. (A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference `Pubkey`s more than once but the message must contain a list with no duplicate keys.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;account_&#8203;not_&#8203;found | `counter` | Result of executing a transaction. Could be a failure or success. (Attempt to debit an account but found no record of a prior credit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;program_&#8203;account_&#8203;not_&#8203;found | `counter` | Result of executing a transaction. Could be a failure or success. (Attempt to load a program that does not exist.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;insufficient_&#8203;funds_&#8203;for_&#8203;fee | `counter` | Result of executing a transaction. Could be a failure or success. (The fee payer `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;account_&#8203;for_&#8203;fee | `counter` | Result of executing a transaction. Could be a failure or success. (This account may not be used to pay transaction fees.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;already_&#8203;processed | `counter` | Result of executing a transaction. Could be a failure or success. (The bank has seen this transaction before. This can occur under normal operation when a UDP packet is duplicated, as a user error from a client not updating its `recent_blockhash`, or as a double-spend attack.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;blockhash_&#8203;not_&#8203;found | `counter` | Result of executing a transaction. Could be a failure or success. (The bank has not seen the given `recent_blockhash` or the transaction is too old and the `recent_blockhash` has been discarded.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;instruction_&#8203;error | `counter` | Result of executing a transaction. Could be a failure or success. (An error occurred while processing an instruction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;call_&#8203;chain_&#8203;too_&#8203;deep | `counter` | Result of executing a transaction. Could be a failure or success. (Loader call chain is too deep.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;missing_&#8203;signature_&#8203;for_&#8203;fee | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction requires a fee but has no signature present.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;account_&#8203;index | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction contains an invalid account reference.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;signature_&#8203;failure | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction did not pass signature verification.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;program_&#8203;for_&#8203;execution | `counter` | Result of executing a transaction. Could be a failure or success. (This program may not be used for executing instructions.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;sanitize_&#8203;failure | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction failed to sanitize accounts offsets correctly implies that account locks are not taken for this TX, and should not be unlocked.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;cluster_&#8203;maintenance | `counter` | Result of executing a transaction. Could be a failure or success. (Transactions are currently disabled due to cluster maintenance.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;account_&#8203;borrow_&#8203;outstanding | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction processing left an account with an outstanding borrowed reference.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;would_&#8203;exceed_&#8203;max_&#8203;block_&#8203;cost_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction would exceed max Block Cost Limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;unsupported_&#8203;version | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction version is unsupported.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;writable_&#8203;account | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction loads a writable account that cannot be written.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;would_&#8203;exceed_&#8203;max_&#8203;account_&#8203;cost_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction would exceed max account limit within the block.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;block_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction would exceed account data limit within the block.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;too_&#8203;many_&#8203;account_&#8203;locks | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction locked too many accounts.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found | `counter` | Result of executing a transaction. Could be a failure or success. (Address lookup table not found.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner | `counter` | Result of executing a transaction. Could be a failure or success. (Attempted to lookup addresses from an account owned by the wrong program.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data | `counter` | Result of executing a transaction. Could be a failure or success. (Attempted to lookup addresses from an invalid account.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index | `counter` | Result of executing a transaction. Could be a failure or success. (Address table lookup uses an invalid index.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;rent_&#8203;paying_&#8203;account | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction leaves an account with a lower balance than rent-exempt minimum.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;would_&#8203;exceed_&#8203;max_&#8203;vote_&#8203;cost_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction would exceed max Vote Cost Limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;total_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction would exceed total account data limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;duplicate_&#8203;instruction | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction contains a duplicate instruction that is not allowed.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;insufficient_&#8203;funds_&#8203;for_&#8203;rent | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction results in an account with insufficient funds for rent.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded | `counter` | Result of executing a transaction. Could be a failure or success. (Transaction exceeded max loaded accounts data size cap.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (LoadedAccountsDataSizeLimit set for transaction must be greater than 0.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;resanitization_&#8203;needed | `counter` | Result of executing a transaction. Could be a failure or success. (Sanitized transaction differed before/after feature activiation. Needs to be resanitized.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;program_&#8203;execution_&#8203;temporarily_&#8203;restricted | `counter` | Result of executing a transaction. Could be a failure or success. (Program execution is temporarily restricted on an account.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;unbalanced_&#8203;transaction | `counter` | Result of executing a transaction. Could be a failure or success. (The total balance before the transaction does not equal the total balance after the transaction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executing_&#8203;program_&#8203;cache_&#8203;hit_&#8203;max_&#8203;limit | `counter` | Result of executing a transaction. Could be a failure or success. (The total program cache size hit the maximum allowed limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;success | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Success) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;account_&#8203;in_&#8203;use | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (An account is already being processed in another transaction in a way that does not support parallelism.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;account_&#8203;loaded_&#8203;twice | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference `Pubkey`s more than once but the message must contain a list with no duplicate keys.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;account_&#8203;not_&#8203;found | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Attempt to debit an account but found no record of a prior credit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;program_&#8203;account_&#8203;not_&#8203;found | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Attempt to load a program that does not exist.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;insufficient_&#8203;funds_&#8203;for_&#8203;fee | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (The fee payer `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;account_&#8203;for_&#8203;fee | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (This account may not be used to pay transaction fees.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;already_&#8203;processed | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (The bank has seen this transaction before. This can occur under normal operation when a UDP packet is duplicated, as a user error from a client not updating its `recent_blockhash`, or as a double-spend attack.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;blockhash_&#8203;not_&#8203;found | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (The bank has not seen the given `recent_blockhash` or the transaction is too old and the `recent_blockhash` has been discarded.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;instruction_&#8203;error | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (An error occurred while processing an instruction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;call_&#8203;chain_&#8203;too_&#8203;deep | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Loader call chain is too deep.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;missing_&#8203;signature_&#8203;for_&#8203;fee | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction requires a fee but has no signature present.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;account_&#8203;index | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction contains an invalid account reference.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;signature_&#8203;failure | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction did not pass signature verification.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;program_&#8203;for_&#8203;execution | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (This program may not be used for executing instructions.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;sanitize_&#8203;failure | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction failed to sanitize accounts offsets correctly implies that account locks are not taken for this TX, and should not be unlocked.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;cluster_&#8203;maintenance | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transactions are currently disabled due to cluster maintenance.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;account_&#8203;borrow_&#8203;outstanding | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction processing left an account with an outstanding borrowed reference.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;would_&#8203;exceed_&#8203;max_&#8203;block_&#8203;cost_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction would exceed max Block Cost Limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;unsupported_&#8203;version | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction version is unsupported.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;writable_&#8203;account | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction loads a writable account that cannot be written.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;would_&#8203;exceed_&#8203;max_&#8203;account_&#8203;cost_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction would exceed max account limit within the block.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;block_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction would exceed account data limit within the block.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;too_&#8203;many_&#8203;account_&#8203;locks | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction locked too many accounts.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Address lookup table not found.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Attempted to lookup addresses from an account owned by the wrong program.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Attempted to lookup addresses from an invalid account.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Address table lookup uses an invalid index.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;rent_&#8203;paying_&#8203;account | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction leaves an account with a lower balance than rent-exempt minimum.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;would_&#8203;exceed_&#8203;max_&#8203;vote_&#8203;cost_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction would exceed max Vote Cost Limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;total_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction would exceed total account data limit.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;duplicate_&#8203;instruction | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction contains a duplicate instruction that is not allowed.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;insufficient_&#8203;funds_&#8203;for_&#8203;rent | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction results in an account with insufficient funds for rent.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Transaction exceeded max loaded accounts data size cap.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (LoadedAccountsDataSizeLimit set for transaction must be greater than 0.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;resanitization_&#8203;needed | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Sanitized transaction differed before/after feature activiation. Needs to be resanitized.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;program_&#8203;execution_&#8203;temporarily_&#8203;restricted | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (Program execution is temporarily restricted on an account.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;unbalanced_&#8203;transaction | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (The total balance before the transaction does not equal the total balance after the transaction.) |
| bank_&#8203;tile_&#8203;transaction_&#8203;executed_&#8203;program_&#8203;cache_&#8203;hit_&#8203;max_&#8203;limit | `counter` | When a transaction executes (makes it onto the chain), result of executing a transaction. The transaction can still fail. (The total program cache size hit the maximum allowed limit.) |
| bank_&#8203;tile_&#8203;cost_&#8203;model_&#8203;undercount | `counter` | Count of transactions that used more CUs than the cost model should have permitted them to |

## Poh Tile
| Metric | Type | Description |
|--------|------|-------------|
| poh_&#8203;tile_&#8203;begin_&#8203;leader_&#8203;delay_&#8203;seconds | `histogram` | Delay between when we become leader in a slot and when we receive the bank. |
| poh_&#8203;tile_&#8203;first_&#8203;microblock_&#8203;delay_&#8203;seconds | `histogram` | Delay between when we become leader in a slot and when we receive the first microblock. |
| poh_&#8203;tile_&#8203;slot_&#8203;done_&#8203;delay_&#8203;seconds | `histogram` | Delay between when we become leader in a slot and when we finish the slot. |

## Store Tile
| Metric | Type | Description |
|--------|------|-------------|
| store_&#8203;tile_&#8203;transactions_&#8203;inserted | `counter` | Count of transactions produced while we were leader in the shreds that have been inserted so far |

## Shred Tile
| Metric | Type | Description |
|--------|------|-------------|
| shred_&#8203;cluster_&#8203;contact_&#8203;info_&#8203;cnt | `histogram` | Number of contact infos in the cluster contact info message |
| shred_&#8203;microblocks_&#8203;abandoned | `counter` | The number of microblocks that were abandoned because we switched slots without finishing the current slot |
| shred_&#8203;batch_&#8203;sz | `histogram` | The size (in bytes) of each microblock batch that is shredded |
| shred_&#8203;batch_&#8203;microblock_&#8203;cnt | `histogram` | The number of microblocks in each microblock batch that is shredded |
| shred_&#8203;shredding_&#8203;duration_&#8203;seconds | `histogram` | Duration of producing one FEC set from the shredder |
| shred_&#8203;add_&#8203;shred_&#8203;duration_&#8203;seconds | `histogram` | Duration of verifying and processing one shred received from the network |
| shred_&#8203;shred_&#8203;processed_&#8203;bad_&#8203;slot | `counter` | The result of processing a thread from the network (Shred was for a slot for which we don't know the leader) |
| shred_&#8203;shred_&#8203;processed_&#8203;parse_&#8203;failed | `counter` | The result of processing a thread from the network (Shred parsing failed) |
| shred_&#8203;shred_&#8203;processed_&#8203;rejected | `counter` | The result of processing a thread from the network (Shred was invalid for one of many reasons) |
| shred_&#8203;shred_&#8203;processed_&#8203;ignored | `counter` | The result of processing a thread from the network (Shred was ignored because we had already received or reconstructed it) |
| shred_&#8203;shred_&#8203;processed_&#8203;okay | `counter` | The result of processing a thread from the network (Shred accepted to an incomplete FEC set) |
| shred_&#8203;shred_&#8203;processed_&#8203;completes | `counter` | The result of processing a thread from the network (Shred accepted and resulted in a valid, complete FEC set) |
| shred_&#8203;fec_&#8203;set_&#8203;spilled | `counter` | The number of FEC sets that were spilled because they didn't complete in time and we needed space |
| shred_&#8203;shred_&#8203;rejected_&#8203;initial | `counter` | The number shreds that were rejected before any resources were allocated for the FEC set |
| shred_&#8203;fec_&#8203;rejected_&#8203;fatal | `counter` | The number of FEC sets that were rejected for reasons that cause the whole FEC set to become invalid |
