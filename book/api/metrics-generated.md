
## All Links
<!--@include: ./metrics-link-preamble.md-->

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">link_&#8203;slow_&#8203;count</span> | counter | The number of times the consumer was detected as rate limiting consumer by the producer. |
| <span class="metrics-name">link_&#8203;consumed_&#8203;count</span> | counter | The number of times the link reader has consumed a fragment. |
| <span class="metrics-name">link_&#8203;consumed_&#8203;size_&#8203;bytes</span> | counter | The total number of bytes read by the link consumer. |
| <span class="metrics-name">link_&#8203;filtered_&#8203;count</span> | counter | The number of fragments that were filtered and not consumed. |
| <span class="metrics-name">link_&#8203;filtered_&#8203;size_&#8203;bytes</span> | counter | The total number of bytes read by the link consumer that were filtered. |
| <span class="metrics-name">link_&#8203;overrun_&#8203;polling_&#8203;count</span> | counter | The number of times the link has been overrun while polling. |
| <span class="metrics-name">link_&#8203;overrun_&#8203;polling_&#8203;frag_&#8203;count</span> | counter | The number of fragments the link has not processed because it was overrun while polling. |
| <span class="metrics-name">link_&#8203;overrun_&#8203;reading_&#8203;count</span> | counter | The number of input overruns detected while reading metadata by the consumer. |
| <span class="metrics-name">link_&#8203;overrun_&#8203;reading_&#8203;frag_&#8203;count</span> | counter | The number of fragments the link has not processed because it was overrun while reading. |
</div>

## All Tiles
<!--@include: ./metrics-tile-preamble.md-->

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">tile_&#8203;pid</span> | gauge | The process ID of the tile. |
| <span class="metrics-name">tile_&#8203;tid</span> | gauge | The thread ID of the tile. Always the same as the Pid in production, but might be different in development. |
| <span class="metrics-name">tile_&#8203;context_&#8203;switch_&#8203;involuntary_&#8203;count</span> | counter | The number of involuntary context switches. |
| <span class="metrics-name">tile_&#8203;context_&#8203;switch_&#8203;voluntary_&#8203;count</span> | counter | The number of voluntary context switches. |
| <span class="metrics-name">tile_&#8203;status</span> | gauge | The current status of the tile. 0 is booting, 1 is running. 2 is shutdown |
| <span class="metrics-name">tile_&#8203;heartbeat</span> | gauge | The last UNIX timestamp in nanoseconds that the tile heartbeated. |
| <span class="metrics-name">tile_&#8203;in_&#8203;backpressure</span> | gauge | Whether the tile is currently backpressured or not, either 1 or 0. |
| <span class="metrics-name">tile_&#8203;backpressure_&#8203;count</span> | counter | Number of times the tile has had to wait for one of more consumers to catch up to resume publishing. |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">caught_&#8203;up_&#8203;housekeeping</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Caught up + Housekeeping) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">processing_&#8203;housekeeping</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Processing + Housekeeping) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">backpressure_&#8203;housekeeping</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Backpressure + Housekeeping) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">caught_&#8203;up_&#8203;prefrag</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Caught up + Prefrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">processing_&#8203;prefrag</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Processing + Prefrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">backpressure_&#8203;prefrag</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Backpressure + Prefrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">caught_&#8203;up_&#8203;postfrag</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Caught up + Postfrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">processing_&#8203;postfrag</span>"} | counter | Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes. (Processing + Postfrag) |

</div>

## Net Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">net_&#8203;rx_&#8203;pkt_&#8203;cnt</span> | counter | Packet receive count. |
| <span class="metrics-name">net_&#8203;rx_&#8203;bytes_&#8203;total</span> | counter | Total number of bytes received (including Ethernet header). |
| <span class="metrics-name">net_&#8203;rx_&#8203;undersz_&#8203;cnt</span> | counter | Number of incoming packets dropped due to being too small. |
| <span class="metrics-name">net_&#8203;rx_&#8203;fill_&#8203;blocked_&#8203;cnt</span> | counter | Number of incoming packets dropped due to fill ring being full. |
| <span class="metrics-name">net_&#8203;rx_&#8203;backpressure_&#8203;cnt</span> | counter | Number of incoming packets dropped due to backpressure. |
| <span class="metrics-name">net_&#8203;rx_&#8203;busy_&#8203;cnt</span> | gauge | Number of receive buffers currently busy. |
| <span class="metrics-name">net_&#8203;rx_&#8203;idle_&#8203;cnt</span> | gauge | Number of receive buffers currently idle. |
| <span class="metrics-name">net_&#8203;tx_&#8203;submit_&#8203;cnt</span> | counter | Number of packet transmit jobs submitted. |
| <span class="metrics-name">net_&#8203;tx_&#8203;complete_&#8203;cnt</span> | counter | Number of packet transmit jobs marked as completed by the kernel. |
| <span class="metrics-name">net_&#8203;tx_&#8203;bytes_&#8203;total</span> | counter | Total number of bytes transmitted (including Ethernet header). |
| <span class="metrics-name">net_&#8203;tx_&#8203;route_&#8203;fail_&#8203;cnt</span> | counter | Number of packet transmit jobs dropped due to route failure. |
| <span class="metrics-name">net_&#8203;tx_&#8203;neighbor_&#8203;fail_&#8203;cnt</span> | counter | Number of packet transmit jobs dropped due to unresolved neighbor. |
| <span class="metrics-name">net_&#8203;tx_&#8203;full_&#8203;fail_&#8203;cnt</span> | counter | Number of packet transmit jobs dropped due to XDP TX ring full or missing completions. |
| <span class="metrics-name">net_&#8203;tx_&#8203;busy_&#8203;cnt</span> | gauge | Number of transmit buffers currently busy. |
| <span class="metrics-name">net_&#8203;tx_&#8203;idle_&#8203;cnt</span> | gauge | Number of transmit buffers currently idle. |
| <span class="metrics-name">net_&#8203;xsk_&#8203;tx_&#8203;wakeup_&#8203;cnt</span> | counter | Number of XSK sendto syscalls dispatched. |
| <span class="metrics-name">net_&#8203;xsk_&#8203;rx_&#8203;wakeup_&#8203;cnt</span> | counter | Number of XSK recvmsg syscalls dispatched. |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;dropped_&#8203;other</span> | counter | xdp_statistics_v0.rx_dropped: Dropped for other reasons |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;invalid_&#8203;descs</span> | counter | xdp_statistics_v0.rx_invalid_descs: Dropped due to invalid descriptor |
| <span class="metrics-name">net_&#8203;xdp_&#8203;tx_&#8203;invalid_&#8203;descs</span> | counter | xdp_statistics_v0.tx_invalid_descs: Dropped due to invalid descriptor |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;ring_&#8203;full</span> | counter | xdp_statistics_v1.rx_ring_full: Dropped due to rx ring being full |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;fill_&#8203;ring_&#8203;empty_&#8203;descs</span> | counter | xdp_statistics_v1.rx_fill_ring_empty_descs: Failed to retrieve item from fill ring |
| <span class="metrics-name">net_&#8203;xdp_&#8203;tx_&#8203;ring_&#8203;empty_&#8203;descs</span> | counter | xdp_statistics_v1.tx_ring_empty_descs: Failed to retrieve item from tx ring |
| <span class="metrics-name">net_&#8203;rx_&#8203;gre_&#8203;cnt</span> | counter | Number of valid GRE packets received |
| <span class="metrics-name">net_&#8203;rx_&#8203;gre_&#8203;invalid_&#8203;cnt</span> | counter | Number of invalid GRE packets received |
| <span class="metrics-name">net_&#8203;rx_&#8203;gre_&#8203;ignored_&#8203;cnt</span> | counter | Number of received but ignored GRE packets |
| <span class="metrics-name">net_&#8203;tx_&#8203;gre_&#8203;cnt</span> | counter | Number of GRE packet transmit jobs submitted |
| <span class="metrics-name">net_&#8203;tx_&#8203;gre_&#8203;route_&#8203;fail_&#8203;cnt</span> | counter | Number of GRE packets transmit jobs dropped due to route failure |

</div>

## Quic Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">quic_&#8203;txns_&#8203;overrun</span> | counter | Count of txns overrun before reassembled (too small txn_reassembly_count). |
| <span class="metrics-name">quic_&#8203;txn_&#8203;reasms_&#8203;started</span> | counter | Count of fragmented txn receive ops started. |
| <span class="metrics-name">quic_&#8203;txn_&#8203;reasms_&#8203;active</span> | gauge | Number of fragmented txn receive ops currently active. |
| <span class="metrics-name">quic_&#8203;frags_&#8203;ok</span> | counter | Count of txn frags received |
| <span class="metrics-name">quic_&#8203;frags_&#8203;gap</span> | counter | Count of txn frags dropped due to data gap |
| <span class="metrics-name">quic_&#8203;frags_&#8203;dup</span> | counter | Count of txn frags dropped due to dup (stream already completed) |
| <span class="metrics-name">quic_&#8203;txns_&#8203;received</span><br/>{tpu_&#8203;recv_&#8203;type="<span class="metrics-enum">udp</span>"} | counter | Count of txns received via TPU. (TPU/UDP) |
| <span class="metrics-name">quic_&#8203;txns_&#8203;received</span><br/>{tpu_&#8203;recv_&#8203;type="<span class="metrics-enum">quic_&#8203;fast</span>"} | counter | Count of txns received via TPU. (TPU/QUIC unfragmented) |
| <span class="metrics-name">quic_&#8203;txns_&#8203;received</span><br/>{tpu_&#8203;recv_&#8203;type="<span class="metrics-enum">quic_&#8203;frag</span>"} | counter | Count of txns received via TPU. (TPU/QUIC fragmented) |
| <span class="metrics-name">quic_&#8203;txns_&#8203;abandoned</span> | counter | Count of txns abandoned because a conn was lost. |
| <span class="metrics-name">quic_&#8203;txn_&#8203;undersz</span> | counter | Count of txns received via QUIC dropped because they were too small. |
| <span class="metrics-name">quic_&#8203;txn_&#8203;oversz</span> | counter | Count of txns received via QUIC dropped because they were too large. |
| <span class="metrics-name">quic_&#8203;legacy_&#8203;txn_&#8203;undersz</span> | counter | Count of packets received on the non-QUIC port that were too small to be a valid IP packet. |
| <span class="metrics-name">quic_&#8203;legacy_&#8203;txn_&#8203;oversz</span> | counter | Count of packets received on the non-QUIC port that were too large to be a valid transaction. |
| <span class="metrics-name">quic_&#8203;received_&#8203;packets</span> | counter | Number of IP packets received. |
| <span class="metrics-name">quic_&#8203;received_&#8203;bytes</span> | counter | Total bytes received (including IP, UDP, QUIC headers). |
| <span class="metrics-name">quic_&#8203;sent_&#8203;packets</span> | counter | Number of IP packets sent. |
| <span class="metrics-name">quic_&#8203;sent_&#8203;bytes</span> | counter | Total bytes sent (including IP, UDP, QUIC headers). |
| <span class="metrics-name">quic_&#8203;connections_&#8203;alloc</span> | gauge | The number of currently allocated QUIC connections. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">invalid</span>"} | gauge | The number of QUIC connections in each state. (freed) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake</span>"} | gauge | The number of QUIC connections in each state. (handshaking peer) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake_&#8203;complete</span>"} | gauge | The number of QUIC connections in each state. (handshake complete, confirming with peer) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">active</span>"} | gauge | The number of QUIC connections in each state. (active connection) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">peer_&#8203;close</span>"} | gauge | The number of QUIC connections in each state. (peer requested close) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">abort</span>"} | gauge | The number of QUIC connections in each state. (connection terminating due to error) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">close_&#8203;pending</span>"} | gauge | The number of QUIC connections in each state. (connection is closing) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">dead</span>"} | gauge | The number of QUIC connections in each state. (connection about to be freed) |
| <span class="metrics-name">quic_&#8203;connections_&#8203;created</span> | counter | The total number of connections that have been created. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;closed</span> | counter | Number of connections gracefully closed. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;aborted</span> | counter | Number of connections aborted. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;timed_&#8203;out</span> | counter | Number of connections timed out. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;retried</span> | counter | Number of connections established with retry. |
| <span class="metrics-name">quic_&#8203;connection_&#8203;error_&#8203;no_&#8203;slots</span> | counter | Number of connections that failed to create due to lack of slots. |
| <span class="metrics-name">quic_&#8203;connection_&#8203;error_&#8203;retry_&#8203;fail</span> | counter | Number of connections that failed during retry (e.g. invalid token). |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">initial</span>"} | counter | Number of packets with an unknown connection ID. (initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">retry</span>"} | counter | Number of packets with an unknown connection ID. (retry) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">handshake</span>"} | counter | Number of packets with an unknown connection ID. (handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">one_&#8203;rtt</span>"} | counter | Number of packets with an unknown connection ID. (1-RTT) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;tx_&#8203;alloc</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Results of attempts to acquire QUIC frame metadata. (Success) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;tx_&#8203;alloc</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;empty_&#8203;pool</span>"} | counter | Results of attempts to acquire QUIC frame metadata. (PktMetaPoolEmpty) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;tx_&#8203;alloc</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;conn_&#8203;max</span>"} | counter | Results of attempts to acquire QUIC frame metadata. (ConnMaxedInflightFrames) |
| <span class="metrics-name">quic_&#8203;initial_&#8203;token_&#8203;len</span><br/>{quic_&#8203;initial_&#8203;token_&#8203;len="<span class="metrics-enum">zero</span>"} | counter | Number of Initial packets grouped by token length. (No token) |
| <span class="metrics-name">quic_&#8203;initial_&#8203;token_&#8203;len</span><br/>{quic_&#8203;initial_&#8203;token_&#8203;len="<span class="metrics-enum">fd_&#8203;quic_&#8203;len</span>"} | counter | Number of Initial packets grouped by token length. (fd_quic retry token length) |
| <span class="metrics-name">quic_&#8203;initial_&#8203;token_&#8203;len</span><br/>{quic_&#8203;initial_&#8203;token_&#8203;len="<span class="metrics-enum">invalid_&#8203;len</span>"} | counter | Number of Initial packets grouped by token length. (Invalid token length) |
| <span class="metrics-name">quic_&#8203;handshakes_&#8203;created</span> | counter | Number of handshake flows created. |
| <span class="metrics-name">quic_&#8203;handshake_&#8203;error_&#8203;alloc_&#8203;fail</span> | counter | Number of handshakes dropped due to alloc fail. |
| <span class="metrics-name">quic_&#8203;handshake_&#8203;evicted</span> | counter | Number of handshakes dropped due to eviction. |
| <span class="metrics-name">quic_&#8203;stream_&#8203;received_&#8203;events</span> | counter | Number of stream RX events. |
| <span class="metrics-name">quic_&#8203;stream_&#8203;received_&#8203;bytes</span> | counter | Total stream payload bytes received. |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">unknown</span>"} | counter | Number of QUIC frames received. (Unknown frame type) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ack</span>"} | counter | Number of QUIC frames received. (ACK frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">reset_&#8203;stream</span>"} | counter | Number of QUIC frames received. (RESET_STREAM frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stop_&#8203;sending</span>"} | counter | Number of QUIC frames received. (STOP_SENDING frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">crypto</span>"} | counter | Number of QUIC frames received. (CRYPTO frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;token</span>"} | counter | Number of QUIC frames received. (NEW_TOKEN frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream</span>"} | counter | Number of QUIC frames received. (STREAM frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;data</span>"} | counter | Number of QUIC frames received. (MAX_DATA frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;stream_&#8203;data</span>"} | counter | Number of QUIC frames received. (MAX_STREAM_DATA frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;streams</span>"} | counter | Number of QUIC frames received. (MAX_STREAMS frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">data_&#8203;blocked</span>"} | counter | Number of QUIC frames received. (DATA_BLOCKED frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream_&#8203;data_&#8203;blocked</span>"} | counter | Number of QUIC frames received. (STREAM_DATA_BLOCKED frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">streams_&#8203;blocked</span>"} | counter | Number of QUIC frames received. (STREAMS_BLOCKED(bidi) frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;conn_&#8203;id</span>"} | counter | Number of QUIC frames received. (NEW_CONN_ID frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">retire_&#8203;conn_&#8203;id</span>"} | counter | Number of QUIC frames received. (RETIRE_CONN_ID frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;challenge</span>"} | counter | Number of QUIC frames received. (PATH_CHALLENGE frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;response</span>"} | counter | Number of QUIC frames received. (PATH_RESPONSE frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">conn_&#8203;close_&#8203;quic</span>"} | counter | Number of QUIC frames received. (CONN_CLOSE(transport) frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">conn_&#8203;close_&#8203;app</span>"} | counter | Number of QUIC frames received. (CONN_CLOSE(app) frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">handshake_&#8203;done</span>"} | counter | Number of QUIC frames received. (HANDSHAKE_DONE frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ping</span>"} | counter | Number of QUIC frames received. (PING frame) |
| <span class="metrics-name">quic_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">padding</span>"} | counter | Number of QUIC frames received. (PADDING frame) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">noop</span>"} | counter | ACK events (non-ACK-eliciting packet) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">new</span>"} | counter | ACK events (new ACK range) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">merged</span>"} | counter | ACK events (merged into existing ACK range) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">drop</span>"} | counter | ACK events (out of buffers) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">cancel</span>"} | counter | ACK events (ACK suppressed by handler) |
| <span class="metrics-name">quic_&#8203;service_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent in service |
| <span class="metrics-name">quic_&#8203;receive_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent processing packets |
| <span class="metrics-name">quic_&#8203;frame_&#8203;fail_&#8203;parse</span> | counter | Number of QUIC frames failed to parse. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Number of packets that failed decryption. (initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Number of packets that failed decryption. (early data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Number of packets that failed decryption. (handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Number of packets that failed decryption. (app data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Number of packets that failed decryption due to missing key. (initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Number of packets that failed decryption due to missing key. (early data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Number of packets that failed decryption due to missing key. (handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Number of packets that failed decryption due to missing key. (app data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;net_&#8203;header_&#8203;invalid</span> | counter | Number of packets dropped due to weird IP or UDP header. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;quic_&#8203;header_&#8203;invalid</span> | counter | Number of packets dropped due to weird QUIC header. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;undersz</span> | counter | Number of QUIC packets dropped due to being too small. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;oversz</span> | counter | Number of QUIC packets dropped due to being too large. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;verneg</span> | counter | Number of QUIC version negotiation packets received. |
| <span class="metrics-name">quic_&#8203;retry_&#8203;sent</span> | counter | Number of QUIC Retry packets sent. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Number of QUIC packets that retransmitted. (initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Number of QUIC packets that retransmitted. (early data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Number of QUIC packets that retransmitted. (handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Number of QUIC packets that retransmitted. (app data) |

</div>

## Bundle Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">bundle_&#8203;transaction_&#8203;received</span> | counter | Total count of transactions received, including transactions within bundles |
| <span class="metrics-name">bundle_&#8203;packet_&#8203;received</span> | counter | Total count of packets received |
| <span class="metrics-name">bundle_&#8203;proto_&#8203;received_&#8203;bytes</span> | counter | Total count of bytes from received grpc protobuf payloads |
| <span class="metrics-name">bundle_&#8203;bundle_&#8203;received</span> | counter | Total count of bundles received |
| <span class="metrics-name">bundle_&#8203;errors</span><br/>{bundle_&#8203;error="<span class="metrics-enum">protobuf</span>"} | counter | Number of gRPC errors encountered (Protobuf decode/encode error) |
| <span class="metrics-name">bundle_&#8203;errors</span><br/>{bundle_&#8203;error="<span class="metrics-enum">transport</span>"} | counter | Number of gRPC errors encountered (Transport error) |
| <span class="metrics-name">bundle_&#8203;errors</span><br/>{bundle_&#8203;error="<span class="metrics-enum">timeout</span>"} | counter | Number of gRPC errors encountered (I/O timeout) |
| <span class="metrics-name">bundle_&#8203;errors</span><br/>{bundle_&#8203;error="<span class="metrics-enum">no_&#8203;fee_&#8203;info</span>"} | counter | Number of gRPC errors encountered (Bundle dropped due to missing fee info) |
| <span class="metrics-name">bundle_&#8203;errors</span><br/>{bundle_&#8203;error="<span class="metrics-enum">ssl_&#8203;alloc</span>"} | counter | Number of gRPC errors encountered (OpenSSL alloc fail) |
| <span class="metrics-name">bundle_&#8203;heap_&#8203;size</span> | gauge | Workspace heap size |
| <span class="metrics-name">bundle_&#8203;heap_&#8203;free_&#8203;bytes</span> | gauge | Approx free space in workspace |
| <span class="metrics-name">bundle_&#8203;shredstream_&#8203;heartbeats</span> | counter | Number of ShredStream heartbeats successfully sent |
| <span class="metrics-name">bundle_&#8203;keepalives</span> | counter | Number of HTTP/2 PINGs acknowledged by server |
| <span class="metrics-name">bundle_&#8203;connected</span> | gauge | 1 if connected to the bundle server, 0 if not |
| <span class="metrics-name">bundle_&#8203;rtt_&#8203;sample</span> | gauge | Latest RTT sample at scrape time (nanoseconds) |
| <span class="metrics-name">bundle_&#8203;rtt_&#8203;smoothed</span> | gauge | RTT moving average (nanoseconds) |
| <span class="metrics-name">bundle_&#8203;rtt_&#8203;var</span> | gauge | RTT variance (nanoseconds) |
| <span class="metrics-name">bundle_&#8203;message_&#8203;rx_&#8203;delay_&#8203;nanos</span> | histogram | Message receive delay in nanoseconds from bundle server to bundle client |

</div>

## Verify Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">verify_&#8203;transaction_&#8203;bundle_&#8203;peer_&#8203;failure</span> | counter | Count of transactions that failed to verify because a peer transaction in the bundle failed |
| <span class="metrics-name">verify_&#8203;transaction_&#8203;parse_&#8203;failure</span> | counter | Count of transactions that failed to parse |
| <span class="metrics-name">verify_&#8203;transaction_&#8203;dedup_&#8203;failure</span> | counter | Count of transactions that failed to deduplicate in the verify stage |
| <span class="metrics-name">verify_&#8203;transaction_&#8203;verify_&#8203;failure</span> | counter | Count of transactions that failed to deduplicate in the verify stage |
| <span class="metrics-name">verify_&#8203;gossiped_&#8203;votes_&#8203;received</span> | counter | Count of simple vote transactions received over gossip instead of via the normal TPU path |

</div>

## Dedup Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">dedup_&#8203;transaction_&#8203;bundle_&#8203;peer_&#8203;failure</span> | counter | Count of transactions that failed to dedup because a peer transaction in the bundle failed |
| <span class="metrics-name">dedup_&#8203;transaction_&#8203;dedup_&#8203;failure</span> | counter | Count of transactions that failed to deduplicate in the dedup stage |
| <span class="metrics-name">dedup_&#8203;gossiped_&#8203;votes_&#8203;received</span> | counter | Count of simple vote transactions received over gossip instead of via the normal TPU path |

</div>

## Resolv Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">resolv_&#8203;no_&#8203;bank_&#8203;drop</span> | counter | Count of transactions dropped because the bank was not available |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">inserted</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was added to the stash) |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">overrun</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was dropped because the stash was full) |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">published</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was published as the blockhash became known) |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">removed</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was removed from the stash without publishing, due to a bad LUT resolved failure, or no bank. These errors are double counted with the respective metrics for those categories.) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;lookup_&#8203;index</span>"} | counter | Count of address lookup tables resolved (The transaction referenced an index in a LUT that didn't exist) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;uninitialized</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT hasn't been initialized) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT couldn't be parsed) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT wasn't owned by the ALUT program ID) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT couldn't be found) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Count of address lookup tables resolved (Resolved successfully) |
| <span class="metrics-name">resolv_&#8203;blockhash_&#8203;expired</span> | counter | Count of transactions that failed to resolve because the blockhash was expired |
| <span class="metrics-name">resolv_&#8203;transaction_&#8203;bundle_&#8203;peer_&#8203;failure</span> | counter | Count of transactions that failed to resolve because a peer transaction in the bundle failed |

</div>

## Pack Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">pack_&#8203;schedule_&#8203;microblock_&#8203;duration_&#8203;seconds</span> | histogram | Duration of scheduling one microblock |
| <span class="metrics-name">pack_&#8203;no_&#8203;sched_&#8203;microblock_&#8203;duration_&#8203;seconds</span> | histogram | Duration of discovering that there are no schedulable transactions |
| <span class="metrics-name">pack_&#8203;insert_&#8203;transaction_&#8203;duration_&#8203;seconds</span> | histogram | Duration of inserting one transaction into the pool of available transactions |
| <span class="metrics-name">pack_&#8203;complete_&#8203;microblock_&#8203;duration_&#8203;seconds</span> | histogram | Duration of the computation associated with marking one microblock as complete |
| <span class="metrics-name">pack_&#8203;total_&#8203;transactions_&#8203;per_&#8203;microblock_&#8203;count</span> | histogram | Count of transactions in a scheduled microblock, including both votes and non-votes |
| <span class="metrics-name">pack_&#8203;votes_&#8203;per_&#8203;microblock_&#8203;count</span> | histogram | Count of simple vote transactions in a scheduled microblock |
| <span class="metrics-name">pack_&#8203;normal_&#8203;transaction_&#8203;received</span> | counter | Count of transactions received via the normal TPU path |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;conflict</span>"} | counter | Result of inserting a transaction into the pack object (Bundle with two conflicting durable nonce transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">bundle_&#8203;blacklist</span>"} | counter | Result of inserting a transaction into the pack object (Transaction uses an account on the bundle blacklist) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">invalid_&#8203;nonce</span>"} | counter | Result of inserting a transaction into the pack object (Transaction is an invalid durable nonce transaction) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">write_&#8203;sysvar</span>"} | counter | Result of inserting a transaction into the pack object (Transaction tries to write to a sysvar) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">estimation_&#8203;fail</span>"} | counter | Result of inserting a transaction into the pack object (Estimating compute cost and/or fee failed) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">duplicate_&#8203;account</span>"} | counter | Result of inserting a transaction into the pack object (Transaction included an account address twice) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">too_&#8203;many_&#8203;accounts</span>"} | counter | Result of inserting a transaction into the pack object (Transaction tried to load too many accounts) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">too_&#8203;large</span>"} | counter | Result of inserting a transaction into the pack object (Transaction requests too many CUs) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">expired</span>"} | counter | Result of inserting a transaction into the pack object (Transaction already expired) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">addr_&#8203;lut</span>"} | counter | Result of inserting a transaction into the pack object (Transaction loaded accounts from a lookup table) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">unaffordable</span>"} | counter | Result of inserting a transaction into the pack object (Fee payer's balance below transaction fee) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">duplicate</span>"} | counter | Result of inserting a transaction into the pack object (Pack aware of transaction with same signature) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;priority</span>"} | counter | Result of inserting a transaction into the pack object (Transaction's fee was too low given its compute unit requirement and another competing transactions that uses the same durable nonce) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">priority</span>"} | counter | Result of inserting a transaction into the pack object (Transaction's fee was too low given its compute unit requirement and other competing transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonvote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Transaction that was not a simple vote added to pending transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">vote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Simple vote transaction was added to pending transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonvote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Transaction that was not a simple vote replaced a lower priority transaction) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">vote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Simple vote transaction replaced a lower priority transaction) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;nonvote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Durable nonce transaction added to pending transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">unused</span>"} | counter | Result of inserting a transaction into the pack object (Unused because durable nonce transactions can't be simple votes) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;nonvote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Durable nonce transaction replaced a lower priority transaction, likely one that uses the same durable nonce) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had no transactions available, and wasn't leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had transactions available, but wasn't leader or had hit a limit) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had no transactions available, had banks but wasn't leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had transactions available, had banks but wasn't leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had no transactions available, and was leader but had no available banks) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had transactions available, was leader, but had no available banks) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had available banks but no transactions) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;bank_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack had banks and transactions available but couldn't schedule anything non-conflicting) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;bank_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock while not leader) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock but all banks were busy) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;bank_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock but all banks were busy) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;bank_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock and now has no transactions) |
| <span class="metrics-name">pack_&#8203;metric_&#8203;timing</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;bank_&#8203;leader_&#8203;microblock</span>"} | counter | Time in nanos spent in each state (Pack scheduled a non-empty microblock) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;dropped_&#8203;from_&#8203;extra</span> | counter | Transactions dropped from the extra transaction storage because it was full |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted_&#8203;to_&#8203;extra</span> | counter | Transactions inserted into the extra transaction storage because pack's primary storage was full |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted_&#8203;from_&#8203;extra</span> | counter | Transactions pulled from the extra transaction storage and inserted into pack's primary storage |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;expired</span> | counter | Transactions deleted from pack because their TTL expired |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;deleted</span> | counter | Transactions dropped from pack because they were requested to be deleted |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;already_&#8203;executed</span> | counter | Transactions dropped from pack because they were already executed (in either the replay or leader pipeline) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;dropped_&#8203;partial_&#8203;bundle</span> | counter | Transactions dropped from pack because they were part of a partial bundle |
| <span class="metrics-name">pack_&#8203;available_&#8203;transactions</span><br/>{avail_&#8203;txn_&#8203;type="<span class="metrics-enum">all</span>"} | gauge | The total number of pending transactions in pack's pool that are available to be scheduled (All transactions in any treap) |
| <span class="metrics-name">pack_&#8203;available_&#8203;transactions</span><br/>{avail_&#8203;txn_&#8203;type="<span class="metrics-enum">regular</span>"} | gauge | The total number of pending transactions in pack's pool that are available to be scheduled (Non-votes in the main treap) |
| <span class="metrics-name">pack_&#8203;available_&#8203;transactions</span><br/>{avail_&#8203;txn_&#8203;type="<span class="metrics-enum">votes</span>"} | gauge | The total number of pending transactions in pack's pool that are available to be scheduled (Simple votes) |
| <span class="metrics-name">pack_&#8203;available_&#8203;transactions</span><br/>{avail_&#8203;txn_&#8203;type="<span class="metrics-enum">conflicting</span>"} | gauge | The total number of pending transactions in pack's pool that are available to be scheduled (Non-votes that write to a hotly-contended account) |
| <span class="metrics-name">pack_&#8203;available_&#8203;transactions</span><br/>{avail_&#8203;txn_&#8203;type="<span class="metrics-enum">bundles</span>"} | gauge | The total number of pending transactions in pack's pool that are available to be scheduled (Transactions that are part of a bundle) |
| <span class="metrics-name">pack_&#8203;pending_&#8203;transactions_&#8203;heap_&#8203;size</span> | gauge | The maximum number of pending transactions that pack can consider.  This value is fixed at Firedancer startup but is a useful reference for AvailableTransactions. |
| <span class="metrics-name">pack_&#8203;smallest_&#8203;pending_&#8203;transaction</span> | gauge | A lower bound on the smallest non-vote transaction (in cost units) that is immediately available for scheduling |
| <span class="metrics-name">pack_&#8203;microblock_&#8203;per_&#8203;block_&#8203;limit</span> | counter | The number of times pack did not pack a microblock because the limit on microblocks/block had been reached |
| <span class="metrics-name">pack_&#8203;data_&#8203;per_&#8203;block_&#8203;limit</span> | counter | The number of times pack did not pack a microblock because it reached the data per block limit at the start of trying to schedule a microblock |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">taken</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack included the transaction in the microblock) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">cu_&#8203;limit</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the block CU limit) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">fast_&#8203;path</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because of account conflicts using the fast bitvector check) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">byte_&#8203;limit</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the block data size limit) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">write_&#8203;cost</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have caused a writable account to exceed the per-account block write cost limit) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">slow_&#8203;path</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because of account conflicts using the full slow check) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;schedule</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">defer_&#8203;skip</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction it previously exceeded the per-account block write cost limit too many times) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;status</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">not_&#8203;needed</span>"} | counter | Result of considering whether bundle cranks are needed (On-chain state in the correct state) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;status</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">inserted</span>"} | counter | Result of considering whether bundle cranks are needed (Inserted an initializer bundle to update the on-chain state) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;status</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">creation_&#8203;failed</span>"} | counter | Result of considering whether bundle cranks are needed (Tried to insert an initializer bundle to update the on-chain state, but creation failed) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;status</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">insertion_&#8203;failed</span>"} | counter | Result of considering whether bundle cranks are needed (Tried to insert an initializer bundle to update the on-chain state, but insertion failed) |
| <span class="metrics-name">pack_&#8203;cus_&#8203;consumed_&#8203;in_&#8203;block</span> | gauge | The number of cost units consumed in the current block, or 0 if pack is not currently packing a block |
| <span class="metrics-name">pack_&#8203;cus_&#8203;scheduled</span> | histogram | The number of cost units scheduled for each block pack produced.  This can be higher than the block limit because of returned CUs. |
| <span class="metrics-name">pack_&#8203;cus_&#8203;rebated</span> | histogram | The number of compute units rebated for each block pack produced.  Compute units are rebated when a transaction fails prior to execution or requests more compute units than it uses. |
| <span class="metrics-name">pack_&#8203;cus_&#8203;net</span> | histogram | The net number of cost units (scheduled - rebated) in each block pack produced. |
| <span class="metrics-name">pack_&#8203;cus_&#8203;pct</span> | histogram | The percent of the total block cost limit used for each block pack produced. |
| <span class="metrics-name">pack_&#8203;delete_&#8203;missed</span> | counter | Count of attempts to delete a transaction that wasn't found |
| <span class="metrics-name">pack_&#8203;delete_&#8203;hit</span> | counter | Count of attempts to delete a transaction that was found and deleted |

</div>

## Bank Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">bank_&#8203;transaction_&#8203;sanitize_&#8203;failure</span> | counter | Number of transactions that failed to sanitize. |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;not_&#8203;executed_&#8203;failure</span> | counter | Number of transactions that did not execute. This is different than transactions which fail to execute, which make it onto the chain. |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;lookup_&#8203;index</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The transaction referenced an index in a LUT that didn't exist) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;uninitialized</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account referenced as a LUT hasn't been initialized) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account referenced as a LUT couldn't be parsed) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account referenced as a LUT wasn't owned by the ALUT program ID) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account referenced as a LUT couldn't be found) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (Resolved successfully) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">success</span>"} | counter | Result of loading and executing a transaction. (Success) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;in_&#8203;use</span>"} | counter | Result of loading and executing a transaction. (An account is already being processed in another transaction in a way that does not support parallelism.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;loaded_&#8203;twice</span>"} | counter | Result of loading and executing a transaction. (A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference `Pubkey`s more than once but the message must contain a list with no duplicate keys.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (Attempt to debit an account but found no record of a prior credit.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">program_&#8203;account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (Attempt to load a program that does not exist.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction. (The fee payer `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;account_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction. (This account may not be used to pay transaction fees.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">already_&#8203;processed</span>"} | counter | Result of loading and executing a transaction. (The bank has seen this transaction before. This can occur under normal operation when a UDP packet is duplicated, as a user error from a client not updating its `recent_blockhash`, or as a double-spend attack.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">blockhash_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (The bank has not seen the given `recent_blockhash` or the transaction is too old and the `recent_blockhash` has been discarded.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">instruction_&#8203;error</span>"} | counter | Result of loading and executing a transaction. (An error occurred while processing an instruction.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">call_&#8203;chain_&#8203;too_&#8203;deep</span>"} | counter | Result of loading and executing a transaction. (Loader call chain is too deep.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">missing_&#8203;signature_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction. (Transaction requires a fee but has no signature present.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;account_&#8203;index</span>"} | counter | Result of loading and executing a transaction. (Transaction contains an invalid account reference.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">signature_&#8203;failure</span>"} | counter | Result of loading and executing a transaction. (Transaction did not pass signature verification.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;program_&#8203;for_&#8203;execution</span>"} | counter | Result of loading and executing a transaction. (This program may not be used for executing instructions.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">sanitize_&#8203;failure</span>"} | counter | Result of loading and executing a transaction. (Transaction failed to sanitize accounts offsets correctly implies that account locks are not taken for this TX, and should not be unlocked.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">cluster_&#8203;maintenance</span>"} | counter | Result of loading and executing a transaction. (Transactions are currently disabled due to cluster maintenance.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;borrow_&#8203;outstanding</span>"} | counter | Result of loading and executing a transaction. (Transaction processing left an account with an outstanding borrowed reference.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;max_&#8203;block_&#8203;cost_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (Transaction would exceed max Block Cost Limit.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">unsupported_&#8203;version</span>"} | counter | Result of loading and executing a transaction. (Transaction version is unsupported.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;writable_&#8203;account</span>"} | counter | Result of loading and executing a transaction. (Transaction loads a writable account that cannot be written.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;max_&#8203;account_&#8203;cost_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (Transaction would exceed max account limit within the block.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;block_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (Transaction would exceed account data limit within the block.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">too_&#8203;many_&#8203;account_&#8203;locks</span>"} | counter | Result of loading and executing a transaction. (Transaction locked too many accounts.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (Address lookup table not found.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner</span>"} | counter | Result of loading and executing a transaction. (Attempted to lookup addresses from an account owned by the wrong program.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data</span>"} | counter | Result of loading and executing a transaction. (Attempted to lookup addresses from an invalid account.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index</span>"} | counter | Result of loading and executing a transaction. (Address table lookup uses an invalid index.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;rent_&#8203;paying_&#8203;account</span>"} | counter | Result of loading and executing a transaction. (Transaction leaves an account with a lower balance than rent-exempt minimum.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;max_&#8203;vote_&#8203;cost_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (Transaction would exceed max Vote Cost Limit.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;total_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (Transaction would exceed total account data limit.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">duplicate_&#8203;instruction</span>"} | counter | Result of loading and executing a transaction. (Transaction contains a duplicate instruction that is not allowed.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;rent</span>"} | counter | Result of loading and executing a transaction. (Transaction results in an account with insufficient funds for rent.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded</span>"} | counter | Result of loading and executing a transaction. (Transaction exceeded max loaded accounts data size cap.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (LoadedAccountsDataSizeLimit set for transaction must be greater than 0.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">resanitization_&#8203;needed</span>"} | counter | Result of loading and executing a transaction. (Sanitized transaction differed before/after feature activation. Needs to be resanitized.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">program_&#8203;execution_&#8203;temporarily_&#8203;restricted</span>"} | counter | Result of loading and executing a transaction. (Program execution is temporarily restricted on an account.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">unbalanced_&#8203;transaction</span>"} | counter | Result of loading and executing a transaction. (The total balance before the transaction does not equal the total balance after the transaction.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">program_&#8203;cache_&#8203;hit_&#8203;max_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (The total program cache size hit the maximum allowed limit.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">commit_&#8203;cancelled</span>"} | counter | Result of loading and executing a transaction. (The process for committing the transaction was cancelled internally.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">bundle_&#8203;peer</span>"} | counter | Result of loading and executing a transaction. (Transaction is part of a bundle and one of the peer transactions failed.) |
| <span class="metrics-name">bank_&#8203;processing_&#8203;failed</span> | counter | Count of transactions for which the processing stage failed and won't land on chain |
| <span class="metrics-name">bank_&#8203;fee_&#8203;only_&#8203;transactions</span> | counter | Count of transactions that will land on chain but without executing |
| <span class="metrics-name">bank_&#8203;executed_&#8203;failed_&#8203;transactions</span> | counter | Count of transactions that execute on chain but failed |
| <span class="metrics-name">bank_&#8203;successful_&#8203;transactions</span> | counter | Count of transactions that execute on chain and succeed |
| <span class="metrics-name">bank_&#8203;cost_&#8203;model_&#8203;undercount</span> | counter | Count of transactions that used more CUs than the cost model should have permitted them to |

</div>

## Poh Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">poh_&#8203;begin_&#8203;leader_&#8203;delay_&#8203;seconds</span> | histogram | Delay between when we become leader in a slot and when we receive the bank. |
| <span class="metrics-name">poh_&#8203;first_&#8203;microblock_&#8203;delay_&#8203;seconds</span> | histogram | Delay between when we become leader in a slot and when we receive the first microblock. |
| <span class="metrics-name">poh_&#8203;slot_&#8203;done_&#8203;delay_&#8203;seconds</span> | histogram | Delay between when we become leader in a slot and when we finish the slot. |
| <span class="metrics-name">poh_&#8203;bundle_&#8203;initialize_&#8203;delay_&#8203;seconds</span> | histogram | Delay in starting the slot caused by loading the information needed to generate the bundle crank transactions |

</div>

## Shred Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">shred_&#8203;cluster_&#8203;contact_&#8203;info_&#8203;cnt</span> | histogram | Number of contact infos in the cluster contact info message |
| <span class="metrics-name">shred_&#8203;microblocks_&#8203;abandoned</span> | counter | The number of microblocks that were abandoned because we switched slots without finishing the current slot |
| <span class="metrics-name">shred_&#8203;invalid_&#8203;block_&#8203;id</span> | counter | The number of times a block was created with unknown parent block_id |
| <span class="metrics-name">shred_&#8203;batch_&#8203;sz</span> | histogram | The size (in bytes) of each microblock batch that is shredded |
| <span class="metrics-name">shred_&#8203;batch_&#8203;microblock_&#8203;cnt</span> | histogram | The number of microblocks in each microblock batch that is shredded |
| <span class="metrics-name">shred_&#8203;shredding_&#8203;duration_&#8203;seconds</span> | histogram | Duration of producing one FEC set from the shredder |
| <span class="metrics-name">shred_&#8203;add_&#8203;shred_&#8203;duration_&#8203;seconds</span> | histogram | Duration of verifying and processing one shred received from the network |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">bad_&#8203;slot</span>"} | counter | The result of processing a shred from the network (Shred was for a slot for which we don't know the leader) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">parse_&#8203;failed</span>"} | counter | The result of processing a shred from the network (Shred parsing failed) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">rejected</span>"} | counter | The result of processing a shred from the network (Shred was invalid for one of many reasons) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">ignored</span>"} | counter | The result of processing a shred from the network (Shred was ignored because we had already received or reconstructed it) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">okay</span>"} | counter | The result of processing a shred from the network (Shred accepted to an incomplete FEC set) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">completes</span>"} | counter | The result of processing a shred from the network (Shred accepted and resulted in a valid, complete FEC set) |
| <span class="metrics-name">shred_&#8203;fec_&#8203;set_&#8203;spilled</span> | counter | The number of FEC sets that were spilled because they didn't complete in time and we needed space |
| <span class="metrics-name">shred_&#8203;shred_&#8203;rejected_&#8203;initial</span> | counter | The number of shreds that were rejected before any resources were allocated for the FEC set |
| <span class="metrics-name">shred_&#8203;shred_&#8203;rejected_&#8203;unchained</span> | counter | The number of shreds that were rejected because they're not chained merkle shreds |
| <span class="metrics-name">shred_&#8203;fec_&#8203;rejected_&#8203;fatal</span> | counter | The number of FEC sets that were rejected for reasons that cause the whole FEC set to become invalid |
| <span class="metrics-name">shred_&#8203;force_&#8203;complete_&#8203;request</span> | counter | The number of times we received a FEC force complete message |
| <span class="metrics-name">shred_&#8203;force_&#8203;complete_&#8203;failure</span> | counter | The number of times we failed to force complete a FEC set on request |
| <span class="metrics-name">shred_&#8203;force_&#8203;complete_&#8203;success</span> | counter | The number of times we successfully forced completed a FEC set on request |
| <span class="metrics-name">shred_&#8203;shred_&#8203;repair_&#8203;rcv</span> | counter | The number of times we received a repair shred |
| <span class="metrics-name">shred_&#8203;shred_&#8203;repair_&#8203;rcv_&#8203;bytes</span> | counter | The number bytes received from network packets with repair shreds. Bytes include network headers. |
| <span class="metrics-name">shred_&#8203;shred_&#8203;turbine_&#8203;rcv</span> | counter | The number of times we received a turbine shred |
| <span class="metrics-name">shred_&#8203;shred_&#8203;turbine_&#8203;rcv_&#8203;bytes</span> | counter | The number bytes received from network packets with turbine shreds. Bytes include network headers. |
| <span class="metrics-name">shred_&#8203;store_&#8203;insert_&#8203;wait</span> | histogram | Time in seconds spent waiting for the store to insert a new FEC set |
| <span class="metrics-name">shred_&#8203;store_&#8203;insert_&#8203;work</span> | histogram | Time in seconds spent on inserting a new FEC set |

</div>

## Store Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">store_&#8203;transactions_&#8203;inserted</span> | counter | Count of transactions produced while we were leader in the shreds that have been inserted so far |

</div>

## Sign Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">sign_&#8203;sign_&#8203;duration_&#8203;seconds</span> | histogram | Duration of signing a message |

</div>

## Metric Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">metric_&#8203;boot_&#8203;timestamp_&#8203;nanos</span> | gauge | Timestamp when validator was started (nanoseconds since epoch) |
| <span class="metrics-name">metric_&#8203;connection_&#8203;count</span> | gauge | The number of active http connections to the Prometheus endpoint |
| <span class="metrics-name">metric_&#8203;bytes_&#8203;written</span> | counter | The total number of bytes written to all responses on the Prometheus endpoint |
| <span class="metrics-name">metric_&#8203;bytes_&#8203;read</span> | counter | The total number of bytes read from all requests to the Prometheus endpoint |

</div>

## Gui Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">gui_&#8203;connection_&#8203;count</span> | gauge | The number of active http connections to the GUI service, excluding connections that have been upgraded to a WebSocket connection |
| <span class="metrics-name">gui_&#8203;websocket_&#8203;connection_&#8203;count</span> | gauge | The number of active websocket connections to the GUI service |
| <span class="metrics-name">gui_&#8203;websocket_&#8203;frames_&#8203;sent</span> | counter | The total number of websocket frames sent to all connections to the GUI service |
| <span class="metrics-name">gui_&#8203;websocket_&#8203;frames_&#8203;received</span> | counter | The total number of websocket frames received from all connections to the GUI service |
| <span class="metrics-name">gui_&#8203;bytes_&#8203;written</span> | counter | The total number of bytes written to all connections to the GUI service |
| <span class="metrics-name">gui_&#8203;bytes_&#8203;read</span> | counter | The total number of bytes read from all connections to the GUI service |

</div>

## Replay Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">replay_&#8203;store_&#8203;link_&#8203;wait</span> | histogram | Time in seconds spent waiting for the store to link a new FEC set |
| <span class="metrics-name">replay_&#8203;store_&#8203;link_&#8203;work</span> | histogram | Time in seconds spent on linking a new FEC set |
| <span class="metrics-name">replay_&#8203;store_&#8203;read_&#8203;wait</span> | histogram | Time in seconds spent waiting for the store to read a FEC set |
| <span class="metrics-name">replay_&#8203;store_&#8203;read_&#8203;work</span> | histogram | Time in seconds spent on reading a FEC set |
| <span class="metrics-name">replay_&#8203;store_&#8203;publish_&#8203;wait</span> | histogram | Time in seconds spent waiting for the store to publish a new FEC set |
| <span class="metrics-name">replay_&#8203;store_&#8203;publish_&#8203;work</span> | histogram | Time in seconds spent on publishing a new FEC set |
| <span class="metrics-name">replay_&#8203;root_&#8203;slot</span> | gauge | The slot at which our node has most recently rooted |
| <span class="metrics-name">replay_&#8203;root_&#8203;distance</span> | gauge | The distance in slots between our current root and the current reset slot |
| <span class="metrics-name">replay_&#8203;leader_&#8203;slot</span> | gauge | The slot at which we are currently leader, or 0 if none |
| <span class="metrics-name">replay_&#8203;next_&#8203;leader_&#8203;slot</span> | gauge | The slot at which we are next leader, or 0 if none. If we are currently leader, this is the same as the current leader slot |
| <span class="metrics-name">replay_&#8203;reset_&#8203;slot</span> | gauge | The slot at which we last reset the replay stage, or 0 if unknown |
| <span class="metrics-name">replay_&#8203;max_&#8203;live_&#8203;banks</span> | gauge | The maximum number of banks we can have alive |
| <span class="metrics-name">replay_&#8203;live_&#8203;banks</span> | gauge | The number of banks we currently have alive |
| <span class="metrics-name">replay_&#8203;slots_&#8203;total</span> | counter | Count of slots replayed successfully |
| <span class="metrics-name">replay_&#8203;transactions_&#8203;total</span> | counter | Count of transactions processed overall on the current fork |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;rooted</span> | counter | Number of program cache entries rooted |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;gc_&#8203;root</span> | counter | Number of program cache entries garbage collected while rooting |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;rooted</span> | counter | Number of account database entries rooted |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;gc_&#8203;root</span> | counter | Number of account database entries garbage collected |

</div>

## Storei Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">storei_&#8203;first_&#8203;turbine_&#8203;slot</span> | gauge |  |
| <span class="metrics-name">storei_&#8203;current_&#8203;turbine_&#8203;slot</span> | gauge |  |

</div>

## Gossip Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;capacity</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;count</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">unpinged</span>"} | gauge |  (Peer is known but has not been pinged yet) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;count</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">invalid</span>"} | gauge |  (Peer was pinged but has not yet responded, or responded with an invalid pong) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;count</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">valid</span>"} | gauge |  (Peer was pinged and is currently valid) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;count</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">valid_&#8203;refreshing</span>"} | gauge |  (Peer was pinged and is currently valid, and is being refreshed with a new ping) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">staked</span>"} | counter |  (Pong ignored as node is staked) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">entrypoint</span>"} | counter |  (Pong ignored as node is an entrypoint) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">untracked</span>"} | counter |  (Pong ignored as node has no outstanding ping) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">address</span>"} | counter |  (Pong ignored as responding node doesn't match pinged address) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">token</span>"} | counter |  (Pong ignored as token was not valid) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">success</span>"} | counter |  (Pong accepted) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;evicted_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracked_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;stake_&#8203;changed_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;address_&#8203;changed_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;capacity</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | gauge |  (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | gauge |  (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | gauge |  (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | gauge |  (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | gauge |  (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | gauge |  (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | gauge |  (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | gauge |  (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | gauge |  (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | gauge |  (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | gauge |  (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | gauge |  (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | gauge |  (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | gauge |  (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;expired_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;evicted_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;capacity</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;staked_&#8203;count</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;unstaked_&#8203;count</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;total_&#8203;stake</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;evicted_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;capacity</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;count</span> | gauge |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;expired_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;evicted_&#8203;count</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;contact_&#8203;info_&#8203;unrecognized_&#8203;socket_&#8203;tags</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;contact_&#8203;info_&#8203;ipv6</span> | counter |  |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">upserted_&#8203;pull_&#8203;response</span>"} | counter |  (Pull Response (upserted)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">upserted_&#8203;push</span>"} | counter |  (Push (upserted)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;stale</span>"} | counter |  (Pull Response (newer entry already present in table)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;wallclock</span>"} | counter |  (Pull Response (outside expiry window and no contact info entry)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;duplicate</span>"} | counter |  (Pull Response (duplicate)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;stale</span>"} | counter |  (Push (newer entry already present in table)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;duplicate</span>"} | counter |  (Push (duplicate)) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;count</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;request</span>"} | counter |  (Pull Request) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;count</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;response</span>"} | counter |  (Pull Response) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;count</span><br/>{gossip_&#8203;message="<span class="metrics-enum">push</span>"} | counter |  (Push) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;count</span><br/>{gossip_&#8203;message="<span class="metrics-enum">prune</span>"} | counter |  (Prune) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;count</span><br/>{gossip_&#8203;message="<span class="metrics-enum">ping</span>"} | counter |  (Ping) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;count</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pong</span>"} | counter |  (Pong) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;request</span>"} | counter |  (Pull Request) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;response</span>"} | counter |  (Pull Response) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">push</span>"} | counter |  (Push) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">prune</span>"} | counter |  (Prune) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">ping</span>"} | counter |  (Ping) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pong</span>"} | counter |  (Pong) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter |  (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter |  (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter |  (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter |  (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter |  (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter |  (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter |  (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter |  (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter |  (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter |  (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter |  (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter |  (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter |  (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter |  (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter |  (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter |  (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter |  (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter |  (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter |  (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter |  (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter |  (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter |  (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter |  (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter |  (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter |  (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter |  (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter |  (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;push_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter |  (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter |  (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter |  (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter |  (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter |  (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter |  (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter |  (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter |  (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter |  (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter |  (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter |  (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter |  (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter |  (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter |  (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;count</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter |  (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter |  (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter |  (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter |  (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter |  (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter |  (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter |  (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter |  (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter |  (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter |  (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter |  (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter |  (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter |  (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter |  (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;tx_&#8203;pull_&#8203;response_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter |  (Restart Heaviest Fork) |

</div>

## Netlnk Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">netlnk_&#8203;drop_&#8203;events</span> | counter | Number of netlink drop events caught |
| <span class="metrics-name">netlnk_&#8203;link_&#8203;full_&#8203;syncs</span> | counter | Number of full link table syncs done |
| <span class="metrics-name">netlnk_&#8203;route_&#8203;full_&#8203;syncs</span> | counter | Number of full route table syncs done |
| <span class="metrics-name">netlnk_&#8203;updates</span><br/>{netlink_&#8203;msg="<span class="metrics-enum">link</span>"} | counter | Number of netlink live updates processed (Link) |
| <span class="metrics-name">netlnk_&#8203;updates</span><br/>{netlink_&#8203;msg="<span class="metrics-enum">neigh</span>"} | counter | Number of netlink live updates processed (Neighbor Table Entry) |
| <span class="metrics-name">netlnk_&#8203;updates</span><br/>{netlink_&#8203;msg="<span class="metrics-enum">ipv4_&#8203;route</span>"} | counter | Number of netlink live updates processed (IPv4 Route Table Entry) |
| <span class="metrics-name">netlnk_&#8203;interface_&#8203;count</span> | gauge | Number of network interfaces |
| <span class="metrics-name">netlnk_&#8203;route_&#8203;count</span><br/>{route_&#8203;table="<span class="metrics-enum">local</span>"} | gauge | Number of IPv4 routes (Local) |
| <span class="metrics-name">netlnk_&#8203;route_&#8203;count</span><br/>{route_&#8203;table="<span class="metrics-enum">main</span>"} | gauge | Number of IPv4 routes (Main) |
| <span class="metrics-name">netlnk_&#8203;neigh_&#8203;probe_&#8203;sent</span> | counter | Number of neighbor solicit requests sent to kernel |
| <span class="metrics-name">netlnk_&#8203;neigh_&#8203;probe_&#8203;fails</span> | counter | Number of neighbor solicit requests that failed to send (kernel too slow) |
| <span class="metrics-name">netlnk_&#8203;neigh_&#8203;probe_&#8203;rate_&#8203;limit_&#8203;host</span> | counter | Number of neighbor solicit that exceeded the per-host rate limit |
| <span class="metrics-name">netlnk_&#8203;neigh_&#8203;probe_&#8203;rate_&#8203;limit_&#8203;global</span> | counter | Number of neighbor solicit that exceeded the global rate limit |

</div>

## Sock Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;sendmmsg</span><br/>{sock_&#8203;err="<span class="metrics-enum">no_&#8203;error</span>"} | counter | Number of sendmmsg syscalls dispatched (No error) |
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;sendmmsg</span><br/>{sock_&#8203;err="<span class="metrics-enum">slow</span>"} | counter | Number of sendmmsg syscalls dispatched (ENOBUFS, EAGAIN error) |
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;sendmmsg</span><br/>{sock_&#8203;err="<span class="metrics-enum">perm</span>"} | counter | Number of sendmmsg syscalls dispatched (EPERM error (blocked by netfilter)) |
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;sendmmsg</span><br/>{sock_&#8203;err="<span class="metrics-enum">unreach</span>"} | counter | Number of sendmmsg syscalls dispatched (ENETUNREACH, EHOSTUNREACH error) |
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;sendmmsg</span><br/>{sock_&#8203;err="<span class="metrics-enum">down</span>"} | counter | Number of sendmmsg syscalls dispatched (ENONET, ENETDOWN, EHOSTDOWN error) |
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;sendmmsg</span><br/>{sock_&#8203;err="<span class="metrics-enum">other</span>"} | counter | Number of sendmmsg syscalls dispatched (Unrecognized error code) |
| <span class="metrics-name">sock_&#8203;syscalls_&#8203;recvmmsg</span> | counter | Number of recvmsg syscalls dispatched |
| <span class="metrics-name">sock_&#8203;rx_&#8203;pkt_&#8203;cnt</span> | counter | Number of packets received |
| <span class="metrics-name">sock_&#8203;tx_&#8203;pkt_&#8203;cnt</span> | counter | Number of packets sent |
| <span class="metrics-name">sock_&#8203;tx_&#8203;drop_&#8203;cnt</span> | counter | Number of packets failed to send |
| <span class="metrics-name">sock_&#8203;tx_&#8203;bytes_&#8203;total</span> | counter | Total number of bytes transmitted (including Ethernet header). |
| <span class="metrics-name">sock_&#8203;rx_&#8203;bytes_&#8203;total</span> | counter | Total number of bytes received (including Ethernet header). |

</div>

## Repair Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">repair_&#8203;total_&#8203;pkt_&#8203;count</span> | counter | How many network packets we have sent, including reqs, pings, pongs, etc. |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">needed_&#8203;window</span>"} | counter | What types of client messages are we sending (Need Window) |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">needed_&#8203;highest_&#8203;window</span>"} | counter | What types of client messages are we sending (Need Highest Window) |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">needed_&#8203;orphan</span>"} | counter | What types of client messages are we sending (Need Orphans) |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">pong</span>"} | counter | What types of client messages are we sending (Pong) |
| <span class="metrics-name">repair_&#8203;repaired_&#8203;slots</span> | counter | Until which slots have we fully repaired |
| <span class="metrics-name">repair_&#8203;current_&#8203;slot</span> | counter | Our view of the current cluster slot, max slot received |
| <span class="metrics-name">repair_&#8203;request_&#8203;peers</span> | counter | How many peers have we requested |
| <span class="metrics-name">repair_&#8203;sign_&#8203;tile_&#8203;unavail</span> | counter | How many times no sign tiles were available to send request |
| <span class="metrics-name">repair_&#8203;eager_&#8203;repair_&#8203;aggresses</span> | counter | How many times we pass eager repair threshold |
| <span class="metrics-name">repair_&#8203;rerequest_&#8203;queue</span> | counter | How many times we re-request a shred from the inflights queue |
| <span class="metrics-name">repair_&#8203;malformed_&#8203;ping</span> | counter | How many times we received a malformed ping |
| <span class="metrics-name">repair_&#8203;slot_&#8203;complete_&#8203;time</span> | histogram | Time in seconds it took to complete a slot |
| <span class="metrics-name">repair_&#8203;response_&#8203;latency</span> | histogram | Time in nanoseconds it took to receive a repair request response |
| <span class="metrics-name">repair_&#8203;sign_&#8203;duration_&#8203;seconds</span> | histogram | Duration of signing a message |

</div>

## Send Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">send_&#8203;leader_&#8203;not_&#8203;found</span> | counter | Total number of times slot leader not found |
| <span class="metrics-name">send_&#8203;unstaked_&#8203;ci</span> | counter | Total number of times we received contact info for an unstaked node |
| <span class="metrics-name">send_&#8203;ci_&#8203;removed</span> | counter | Total number of times we removed contact info |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">unroutable</span>"} | counter | Total number of contact infos received and handled for QUIC Vote port (Skipped (unroutable)) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">initialized</span>"} | counter | Total number of contact infos received and handled for QUIC Vote port (Initialized) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">changed</span>"} | counter | Total number of contact infos received and handled for QUIC Vote port (Contact info changed) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">no_&#8203;change</span>"} | counter | Total number of contact infos received and handled for QUIC Vote port (Contact info unchanged) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">unroutable</span>"} | counter | Total number of contact infos received and handled for QUIC TPU port (Skipped (unroutable)) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">initialized</span>"} | counter | Total number of contact infos received and handled for QUIC TPU port (Initialized) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">changed</span>"} | counter | Total number of contact infos received and handled for QUIC TPU port (Contact info changed) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;quic_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">no_&#8203;change</span>"} | counter | Total number of contact infos received and handled for QUIC TPU port (Contact info unchanged) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">unroutable</span>"} | counter | Total number of contact infos received and handled for UDP Vote port (Skipped (unroutable)) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">initialized</span>"} | counter | Total number of contact infos received and handled for UDP Vote port (Initialized) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">changed</span>"} | counter | Total number of contact infos received and handled for UDP Vote port (Contact info changed) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;vote</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">no_&#8203;change</span>"} | counter | Total number of contact infos received and handled for UDP Vote port (Contact info unchanged) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">unroutable</span>"} | counter | Total number of contact infos received and handled for UDP TPU port (Skipped (unroutable)) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">initialized</span>"} | counter | Total number of contact infos received and handled for UDP TPU port (Initialized) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">changed</span>"} | counter | Total number of contact infos received and handled for UDP TPU port (Contact info changed) |
| <span class="metrics-name">send_&#8203;new_&#8203;contact_&#8203;info_&#8203;udp_&#8203;tpu</span><br/>{new_&#8203;contact_&#8203;outcome="<span class="metrics-enum">no_&#8203;change</span>"} | counter | Total number of contact infos received and handled for UDP TPU port (Contact info unchanged) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Total count of results from trying to send via QUIC Vote port (Success) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;ci</span>"} | counter | Total count of results from trying to send via QUIC Vote port (No contact info) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;conn</span>"} | counter | Total count of results from trying to send via QUIC Vote port (No QUIC connection) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;stream</span>"} | counter | Total count of results from trying to send via QUIC Vote port (No QUIC stream) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Total count of results from trying to send via QUIC TPU port (Success) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;ci</span>"} | counter | Total count of results from trying to send via QUIC TPU port (No contact info) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;conn</span>"} | counter | Total count of results from trying to send via QUIC TPU port (No QUIC connection) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;stream</span>"} | counter | Total count of results from trying to send via QUIC TPU port (No QUIC stream) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Total count of results from trying to send via UDP Vote port (Success) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;ci</span>"} | counter | Total count of results from trying to send via UDP Vote port (No contact info) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;conn</span>"} | counter | Total count of results from trying to send via UDP Vote port (No QUIC connection) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;vote</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;stream</span>"} | counter | Total count of results from trying to send via UDP Vote port (No QUIC stream) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Total count of results from trying to send via UDP TPU port (Success) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;ci</span>"} | counter | Total count of results from trying to send via UDP TPU port (No contact info) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;conn</span>"} | counter | Total count of results from trying to send via UDP TPU port (No QUIC connection) |
| <span class="metrics-name">send_&#8203;send_&#8203;result_&#8203;udp_&#8203;tpu</span><br/>{txn_&#8203;send_&#8203;result="<span class="metrics-enum">no_&#8203;stream</span>"} | counter | Total count of results from trying to send via UDP TPU port (No QUIC stream) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">no_&#8203;leader</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC Vote port (No QUIC connection) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">no_&#8203;ci</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC Vote port (No contact info) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">new_&#8203;connection</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC Vote port (Initiated connection) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">conn_&#8203;failed</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC Vote port (Connection failed) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">connected</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC Vote port (Connection exists) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;vote</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">cooldown</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC Vote port (Connection cooldown) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">no_&#8203;leader</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC TPU port (No QUIC connection) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">no_&#8203;ci</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC TPU port (No contact info) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">new_&#8203;connection</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC TPU port (Initiated connection) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">conn_&#8203;failed</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC TPU port (Connection failed) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">connected</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC TPU port (Connection exists) |
| <span class="metrics-name">send_&#8203;ensure_&#8203;conn_&#8203;result_&#8203;quic_&#8203;tpu</span><br/>{send_&#8203;ensure_&#8203;conn_&#8203;result="<span class="metrics-enum">cooldown</span>"} | counter | Total count of results from trying to ensure a connection for a leader for QUIC TPU port (Connection cooldown) |
| <span class="metrics-name">send_&#8203;handshake_&#8203;complete</span><br/>{send_&#8203;quic_&#8203;ports="<span class="metrics-enum">quic_&#8203;vote</span>"} | counter | Total number of times we completed a handshake (QUIC Vote port) |
| <span class="metrics-name">send_&#8203;handshake_&#8203;complete</span><br/>{send_&#8203;quic_&#8203;ports="<span class="metrics-enum">quic_&#8203;tpu</span>"} | counter | Total number of times we completed a handshake (QUIC TPU port) |
| <span class="metrics-name">send_&#8203;quic_&#8203;conn_&#8203;final</span><br/>{send_&#8203;quic_&#8203;ports="<span class="metrics-enum">quic_&#8203;vote</span>"} | counter | Total number of times QUIC connection closed (QUIC Vote port) |
| <span class="metrics-name">send_&#8203;quic_&#8203;conn_&#8203;final</span><br/>{send_&#8203;quic_&#8203;ports="<span class="metrics-enum">quic_&#8203;tpu</span>"} | counter | Total number of times QUIC connection closed (QUIC TPU port) |
| <span class="metrics-name">send_&#8203;received_&#8203;packets</span> | counter | Total count of QUIC packets received |
| <span class="metrics-name">send_&#8203;received_&#8203;bytes</span> | counter | Total bytes received via QUIC |
| <span class="metrics-name">send_&#8203;sent_&#8203;packets</span> | counter | Total count of QUIC packets sent |
| <span class="metrics-name">send_&#8203;sent_&#8203;bytes</span> | counter | Total bytes sent via QUIC |
| <span class="metrics-name">send_&#8203;retry_&#8203;sent</span> | counter | Total count of QUIC retry packets sent |
| <span class="metrics-name">send_&#8203;connections_&#8203;alloc</span> | gauge | Number of currently allocated QUIC connections |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">invalid</span>"} | gauge | Number of QUIC connections in each state (freed) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake</span>"} | gauge | Number of QUIC connections in each state (handshaking peer) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake_&#8203;complete</span>"} | gauge | Number of QUIC connections in each state (handshake complete, confirming with peer) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">active</span>"} | gauge | Number of QUIC connections in each state (active connection) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">peer_&#8203;close</span>"} | gauge | Number of QUIC connections in each state (peer requested close) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">abort</span>"} | gauge | Number of QUIC connections in each state (connection terminating due to error) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">close_&#8203;pending</span>"} | gauge | Number of QUIC connections in each state (connection is closing) |
| <span class="metrics-name">send_&#8203;connections_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">dead</span>"} | gauge | Number of QUIC connections in each state (connection about to be freed) |
| <span class="metrics-name">send_&#8203;connections_&#8203;created</span> | counter | Total count of QUIC connections created |
| <span class="metrics-name">send_&#8203;connections_&#8203;closed</span> | counter | Total count of QUIC connections closed |
| <span class="metrics-name">send_&#8203;connections_&#8203;aborted</span> | counter | Total count of QUIC connections aborted |
| <span class="metrics-name">send_&#8203;connections_&#8203;timed_&#8203;out</span> | counter | Total count of QUIC connections timed out |
| <span class="metrics-name">send_&#8203;connections_&#8203;retried</span> | counter | Total count of QUIC connections retried |
| <span class="metrics-name">send_&#8203;connection_&#8203;error_&#8203;no_&#8203;slots</span> | counter | Total count of connection errors due to no slots |
| <span class="metrics-name">send_&#8203;connection_&#8203;error_&#8203;retry_&#8203;fail</span> | counter | Total count of connection retry failures |
| <span class="metrics-name">send_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Total count of packets with crypto failures (initial) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Total count of packets with crypto failures (early data) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Total count of packets with crypto failures (handshake) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Total count of packets with crypto failures (app data) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Total count of packets with no key (initial) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Total count of packets with no key (early data) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Total count of packets with no key (handshake) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Total count of packets with no key (app data) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">initial</span>"} | counter | Total count of packets with no connection (initial) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">retry</span>"} | counter | Total count of packets with no connection (retry) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">handshake</span>"} | counter | Total count of packets with no connection (handshake) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">one_&#8203;rtt</span>"} | counter | Total count of packets with no connection (1-RTT) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;tx_&#8203;alloc_&#8203;fail</span> | counter | Total count of packet TX allocation failures |
| <span class="metrics-name">send_&#8203;pkt_&#8203;net_&#8203;header_&#8203;invalid</span> | counter | Total count of packets with invalid network headers |
| <span class="metrics-name">send_&#8203;pkt_&#8203;quic_&#8203;header_&#8203;invalid</span> | counter | Total count of packets with invalid QUIC headers |
| <span class="metrics-name">send_&#8203;pkt_&#8203;undersz</span> | counter | Total count of undersized packets |
| <span class="metrics-name">send_&#8203;pkt_&#8203;oversz</span> | counter | Total count of oversized packets |
| <span class="metrics-name">send_&#8203;pkt_&#8203;verneg</span> | counter | Total count of version negotiation packets |
| <span class="metrics-name">send_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Total count of QUIC packet retransmissions. (initial) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Total count of QUIC packet retransmissions. (early data) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Total count of QUIC packet retransmissions. (handshake) |
| <span class="metrics-name">send_&#8203;pkt_&#8203;retransmissions</span><br/>{quic_&#8203;enc_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Total count of QUIC packet retransmissions. (app data) |
| <span class="metrics-name">send_&#8203;handshakes_&#8203;created</span> | counter | Total count of QUIC handshakes created |
| <span class="metrics-name">send_&#8203;handshake_&#8203;error_&#8203;alloc_&#8203;fail</span> | counter | Total count of handshake allocation failures |
| <span class="metrics-name">send_&#8203;handshake_&#8203;evicted</span> | counter | Total count of handshakes evicted |
| <span class="metrics-name">send_&#8203;stream_&#8203;received_&#8203;events</span> | counter | Total count of stream events received |
| <span class="metrics-name">send_&#8203;stream_&#8203;received_&#8203;bytes</span> | counter | Total bytes received via streams |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">unknown</span>"} | counter | Total count of QUIC frames received (Unknown frame type) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ack</span>"} | counter | Total count of QUIC frames received (ACK frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">reset_&#8203;stream</span>"} | counter | Total count of QUIC frames received (RESET_STREAM frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stop_&#8203;sending</span>"} | counter | Total count of QUIC frames received (STOP_SENDING frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">crypto</span>"} | counter | Total count of QUIC frames received (CRYPTO frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;token</span>"} | counter | Total count of QUIC frames received (NEW_TOKEN frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream</span>"} | counter | Total count of QUIC frames received (STREAM frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;data</span>"} | counter | Total count of QUIC frames received (MAX_DATA frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;stream_&#8203;data</span>"} | counter | Total count of QUIC frames received (MAX_STREAM_DATA frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;streams</span>"} | counter | Total count of QUIC frames received (MAX_STREAMS frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">data_&#8203;blocked</span>"} | counter | Total count of QUIC frames received (DATA_BLOCKED frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream_&#8203;data_&#8203;blocked</span>"} | counter | Total count of QUIC frames received (STREAM_DATA_BLOCKED frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">streams_&#8203;blocked</span>"} | counter | Total count of QUIC frames received (STREAMS_BLOCKED(bidi) frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;conn_&#8203;id</span>"} | counter | Total count of QUIC frames received (NEW_CONN_ID frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">retire_&#8203;conn_&#8203;id</span>"} | counter | Total count of QUIC frames received (RETIRE_CONN_ID frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;challenge</span>"} | counter | Total count of QUIC frames received (PATH_CHALLENGE frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;response</span>"} | counter | Total count of QUIC frames received (PATH_RESPONSE frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">conn_&#8203;close_&#8203;quic</span>"} | counter | Total count of QUIC frames received (CONN_CLOSE(transport) frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">conn_&#8203;close_&#8203;app</span>"} | counter | Total count of QUIC frames received (CONN_CLOSE(app) frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">handshake_&#8203;done</span>"} | counter | Total count of QUIC frames received (HANDSHAKE_DONE frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ping</span>"} | counter | Total count of QUIC frames received (PING frame) |
| <span class="metrics-name">send_&#8203;received_&#8203;frames</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">padding</span>"} | counter | Total count of QUIC frames received (PADDING frame) |
| <span class="metrics-name">send_&#8203;frame_&#8203;fail_&#8203;parse</span> | counter | Total count of frame parse failures |
| <span class="metrics-name">send_&#8203;frame_&#8203;tx_&#8203;alloc</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Results of attempts to acquire QUIC frame metadata. (Success) |
| <span class="metrics-name">send_&#8203;frame_&#8203;tx_&#8203;alloc</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;empty_&#8203;pool</span>"} | counter | Results of attempts to acquire QUIC frame metadata. (PktMetaPoolEmpty) |
| <span class="metrics-name">send_&#8203;frame_&#8203;tx_&#8203;alloc</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;conn_&#8203;max</span>"} | counter | Results of attempts to acquire QUIC frame metadata. (ConnMaxedInflightFrames) |
| <span class="metrics-name">send_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">noop</span>"} | counter | Total count of ACK frames transmitted (non-ACK-eliciting packet) |
| <span class="metrics-name">send_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">new</span>"} | counter | Total count of ACK frames transmitted (new ACK range) |
| <span class="metrics-name">send_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">merged</span>"} | counter | Total count of ACK frames transmitted (merged into existing ACK range) |
| <span class="metrics-name">send_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">drop</span>"} | counter | Total count of ACK frames transmitted (out of buffers) |
| <span class="metrics-name">send_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">cancel</span>"} | counter | Total count of ACK frames transmitted (ACK suppressed by handler) |
| <span class="metrics-name">send_&#8203;service_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent in service |
| <span class="metrics-name">send_&#8203;receive_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent processing packets |
| <span class="metrics-name">send_&#8203;sign_&#8203;duration_&#8203;nanos</span> | histogram | Duration spent waiting for tls_cv signatures |

</div>

## Snapct Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapct_&#8203;state</span> | gauge | State of the tile |
| <span class="metrics-name">snapct_&#8203;full_&#8203;num_&#8203;retries</span> | counter | Number of times we aborted and retried full snapshot download because the peer was too slow |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;num_&#8203;retries</span> | counter | Number of times we aborted and retried incremental snapshot download because the peer was too slow |
| <span class="metrics-name">snapct_&#8203;full_&#8203;bytes_&#8203;read</span> | gauge | Number of bytes read so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;full_&#8203;bytes_&#8203;written</span> | gauge | Number of bytes written so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;full_&#8203;bytes_&#8203;total</span> | gauge | Total size of the full snapshot file. Might change if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;full_&#8203;download_&#8203;retries</span> | gauge | Number of times we retried the full snapshot download because the peer was too slow |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;bytes_&#8203;read</span> | gauge | Number of bytes read so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;bytes_&#8203;written</span> | gauge | Number of bytes written so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;bytes_&#8203;total</span> | gauge | Total size of the incremental snapshot file. Might change if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;download_&#8203;retries</span> | gauge | Number of times we retried the incremental snapshot download because the peer was too slow |
| <span class="metrics-name">snapct_&#8203;predicted_&#8203;slot</span> | gauge | The predicted slot from which replay starts after snapshot loading finishes. Might change if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;gossip_&#8203;fresh_&#8203;count</span> | gauge | Number of fresh gossip peers seen when collecting gossip peers.  |
| <span class="metrics-name">snapct_&#8203;gossip_&#8203;total_&#8203;count</span> | gauge | Number of total gossip peers seen when collecting gossip peers.  |
| <span class="metrics-name">snapct_&#8203;ssl_&#8203;alloc_&#8203;errors</span> | counter | Number of SSL allocation errors encountered.  |

</div>

## Snapld Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapld_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 2=FINISHING, 3=ERROR, 4=SHUTDOWN |
| <span class="metrics-name">snapld_&#8203;ssl_&#8203;alloc_&#8203;errors</span> | counter | Number of SSL allocation errors encountered.  |

</div>

## Snapdc Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapdc_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 2=FINISHING, 3=ERROR, 4=SHUTDOWN |
| <span class="metrics-name">snapdc_&#8203;full_&#8203;compressed_&#8203;bytes_&#8203;read</span> | gauge | Number of bytes read so far from the compressed full snapshot file. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapdc_&#8203;full_&#8203;decompressed_&#8203;bytes_&#8203;written</span> | gauge | Number of bytes decompressed so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapdc_&#8203;incremental_&#8203;compressed_&#8203;bytes_&#8203;read</span> | gauge | Number of bytes read so far from the compressed incremental snapshot file. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapdc_&#8203;incremental_&#8203;decompressed_&#8203;bytes_&#8203;written</span> | gauge | Number of bytes decompressed so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |

</div>

## Snapin Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapin_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 2=FINISHING, 3=ERROR, 4=SHUTDOWN |
| <span class="metrics-name">snapin_&#8203;full_&#8203;bytes_&#8203;read</span> | gauge | Number of bytes read so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapin_&#8203;incremental_&#8203;bytes_&#8203;read</span> | gauge | Number of bytes read so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapin_&#8203;accounts_&#8203;inserted</span> | gauge | Number of accounts inserted during snapshot loading. Might decrease if snapshot load is aborted and restarted |

</div>

## Ipecho Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">ipecho_&#8203;shred_&#8203;version</span> | gauge | The current shred version used by the validator |
| <span class="metrics-name">ipecho_&#8203;connection_&#8203;count</span> | gauge | The number of active connections to the ipecho service |
| <span class="metrics-name">ipecho_&#8203;connections_&#8203;closed_&#8203;ok</span> | counter | The number of connections to the ipecho service that have been made and closed normally |
| <span class="metrics-name">ipecho_&#8203;connections_&#8203;closed_&#8203;error</span> | counter | The number of connections to the ipecho service that have been made and closed abnormally |
| <span class="metrics-name">ipecho_&#8203;bytes_&#8203;read</span> | counter | The total number of bytes read from all connections to the ipecho service |
| <span class="metrics-name">ipecho_&#8203;bytes_&#8203;written</span> | counter | The total number of bytes written to all connections to the ipecho service |

</div>

## Gossvf Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;request</span>"} | counter |  (Pull Request (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter |  (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter |  (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;prune</span>"} | counter |  (Prune (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;ping</span>"} | counter |  (Ping (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pong</span>"} | counter |  (Pong (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;unparseable</span>"} | counter |  (Unparseable) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;not_&#8203;contact_&#8203;info</span>"} | counter |  (Pull Request (not contact info)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;loopback</span>"} | counter |  (Pull Request (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;inactive</span>"} | counter |  (Pull Request (inactive)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;wallclock</span>"} | counter |  (Pull Request (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;signature</span>"} | counter |  (Pull Request (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;shred_&#8203;version</span>"} | counter |  (Pull Request (shred version)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;destination</span>"} | counter |  (Prune (destination)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;wallclock</span>"} | counter |  (Prune (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;signature</span>"} | counter |  (Prune (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter |  (Push (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter |  (Pull Response (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;ping_&#8203;signature</span>"} | counter |  (Ping (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pong_&#8203;signature</span>"} | counter |  (Pong (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;request</span>"} | counter |  (Pull Request (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter |  (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter |  (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;prune</span>"} | counter |  (Prune (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;ping</span>"} | counter |  (Ping (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pong</span>"} | counter |  (Pong (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;unparseable</span>"} | counter |  (Unparseable) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;not_&#8203;contact_&#8203;info</span>"} | counter |  (Pull Request (not contact info)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;loopback</span>"} | counter |  (Pull Request (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;inactive</span>"} | counter |  (Pull Request (inactive)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;wallclock</span>"} | counter |  (Pull Request (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;signature</span>"} | counter |  (Pull Request (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;shred_&#8203;version</span>"} | counter |  (Pull Request (shred version)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;destination</span>"} | counter |  (Prune (destination)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;wallclock</span>"} | counter |  (Prune (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;signature</span>"} | counter |  (Prune (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter |  (Push (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter |  (Pull Response (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;ping_&#8203;signature</span>"} | counter |  (Ping (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pong_&#8203;signature</span>"} | counter |  (Pong (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter |  (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter |  (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;duplicate</span>"} | counter |  (Pull Response (duplicate)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;signature</span>"} | counter |  (Pull Response (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;relayer_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Pull Response (relayer no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;relayer_&#8203;shred_&#8203;version</span>"} | counter |  (Pull Response (relayer shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Pull Response (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter |  (Pull Response (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;inactive</span>"} | counter |  (Pull Response (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;signature</span>"} | counter |  (Push (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;relayer_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Push (relayer no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;relayer_&#8203;shred_&#8203;version</span>"} | counter |  (Push (relayer shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Push (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter |  (Push (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;inactive</span>"} | counter |  (Push (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;count</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;wallclock</span>"} | counter |  (Push (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter |  (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter |  (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;duplicate</span>"} | counter |  (Pull Response (duplicate)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;signature</span>"} | counter |  (Pull Response (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;relayer_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Pull Response (relayer no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;relayer_&#8203;shred_&#8203;version</span>"} | counter |  (Pull Response (relayer shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Pull Response (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter |  (Pull Response (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;inactive</span>"} | counter |  (Pull Response (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;signature</span>"} | counter |  (Push (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;relayer_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Push (relayer no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;relayer_&#8203;shred_&#8203;version</span>"} | counter |  (Push (relayer shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter |  (Push (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter |  (Push (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;inactive</span>"} | counter |  (Push (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;wallclock</span>"} | counter |  (Push (wallclock)) |

</div>

## Bankf Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of loading and executing a transaction. (Transaction executed successfully) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">instructon_&#8203;error</span>"} | counter | Result of loading and executing a transaction. (An error occurred while processing an instruction) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (The transaction fee payer address was not found) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">program_&#8203;account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (A program account referenced by the transaction was not found) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction. (The transaction fee payer did not have balance to pay the fee) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction. (The transaction fee payer account is not owned by the system program, or has data that is not a nonce) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">already_&#8203;processed</span>"} | counter | Result of loading and executing a transaction. (The transaction has already been processed in a recent block) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">blockhash_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (The transaction references a blockhash that is not recent, or advances a nonce with the wrong value) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;program_&#8203;for_&#8203;execution</span>"} | counter | Result of loading and executing a transaction. (A program account referenced by the transaction was no executable. TODO: No longer needed with SIMD-0162) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction. (The transaction references an ALUT account that does not exist or is inactive) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner</span>"} | counter | Result of loading and executing a transaction. (The transaction references an ALUT account that is not owned by the ALUT program account) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data</span>"} | counter | Result of loading and executing a transaction. (The transaction references an ALUT account that contains data which is not a valid ALUT) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index</span>"} | counter | Result of loading and executing a transaction. (The transaction references an account offset from the ALUT which does not exist) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded</span>"} | counter | Result of loading and executing a transaction. (The total account data size of the loaded accounts exceeds the consensus limit) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">duplicate_&#8203;instruction</span>"} | counter | Result of loading and executing a transaction. (A compute budget program instruction was invoked more than once) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit</span>"} | counter | Result of loading and executing a transaction. (The compute budget program was invoked and set the loaded accounts data size to zero) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;already_&#8203;advanced</span>"} | counter | Result of loading and executing a transaction. (The transaction references a nonce account that is already advanced) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;advance_&#8203;failed</span>"} | counter | Result of loading and executing a transaction. (The transaction is a nonce transaction but the advance instruction was not valid or failed) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;wrong_&#8203;blockhash</span>"} | counter | Result of loading and executing a transaction. (The transaction is a nonce transaction but the blockhash is not the correct one) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;in_&#8203;use</span>"} | counter | Result of loading and executing a transaction. (The transaction conflicts with another transaction in the microblock. TODO: No longer possible with smart dispatcher) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;loaded_&#8203;twice</span>"} | counter | Result of loading and executing a transaction. (The transaction references the same account twice) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">signature_&#8203;failure</span>"} | counter | Result of loading and executing a transaction. (The transaction had an invalid signature) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">too_&#8203;many_&#8203;account_&#8203;locks</span>"} | counter | Result of loading and executing a transaction. (The transaction references too many accounts. TODO: No longer possible with smart dispatcher) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;rent</span>"} | counter | Result of loading and executing a transaction. (The transaction would leave an account with a lower balance than the rent-exempt minimum) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">unbalanced_&#8203;transaction</span>"} | counter | Result of loading and executing a transaction. (The total referenced account lamports before and after the transaction was unbalanced) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">bundle_&#8203;peer</span>"} | counter | Result of loading and executing a transaction. (The transaction was part of a bundle and an earlier transaction in the bundle failed) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">landed_&#8203;success</span>"} | counter | Whether a transaction landed in the block or not. (Transaction landed) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">landed_&#8203;fees_&#8203;only</span>"} | counter | Whether a transaction landed in the block or not. (Transaction landed, but was fees only and did not execute) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">landed_&#8203;failed</span>"} | counter | Whether a transaction landed in the block or not. (Transaction landed, but failed to execute) |
| <span class="metrics-name">bankf_&#8203;transaction_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">unlanded</span>"} | counter | Whether a transaction landed in the block or not. (Transaction did not land) |

</div>

## Resolf Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">resolf_&#8203;no_&#8203;bank_&#8203;drop</span> | counter | Count of transactions dropped because the bank was not available |
| <span class="metrics-name">resolf_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">inserted</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was added to the stash) |
| <span class="metrics-name">resolf_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">overrun</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was dropped because the stash was full) |
| <span class="metrics-name">resolf_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">published</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was published as the blockhash became known) |
| <span class="metrics-name">resolf_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">removed</span>"} | counter | Count of operations that happened on the transaction stash (A transaction with an unknown blockhash was removed from the stash without publishing, due to a bad LUT resolved failure, or no bank. These errors are double counted with the respective metrics for those categories.) |
| <span class="metrics-name">resolf_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;lookup_&#8203;index</span>"} | counter | Count of address lookup tables resolved (The transaction referenced an index in a LUT that didn't exist) |
| <span class="metrics-name">resolf_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;uninitialized</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT hasn't been initialized) |
| <span class="metrics-name">resolf_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT couldn't be parsed) |
| <span class="metrics-name">resolf_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT wasn't owned by the ALUT program ID) |
| <span class="metrics-name">resolf_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Count of address lookup tables resolved (The account referenced as a LUT couldn't be found) |
| <span class="metrics-name">resolf_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Count of address lookup tables resolved (Resolved successfully) |
| <span class="metrics-name">resolf_&#8203;blockhash_&#8203;expired</span> | counter | Count of transactions that failed to resolve because the blockhash was expired |
| <span class="metrics-name">resolf_&#8203;transaction_&#8203;bundle_&#8203;peer_&#8203;failure</span> | counter | Count of transactions that failed to resolve because a peer transaction in the bundle failed |
| <span class="metrics-name">resolf_&#8203;db_&#8203;races</span> | counter | Number of database races encountered (diagnostic counter, not indicative of issues) |

</div>

## Backt Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">backt_&#8203;final_&#8203;slot</span> | gauge | The slot after which the backtest will complete |
| <span class="metrics-name">backt_&#8203;start_&#8203;slot</span> | gauge | The slot at which the backtest started |

</div>

## Exec Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">exec_&#8203;progcache_&#8203;misses</span> | counter | Number of program cache misses |
| <span class="metrics-name">exec_&#8203;progcache_&#8203;hits</span> | counter | Number of program cache hits |
| <span class="metrics-name">exec_&#8203;progcache_&#8203;fills</span> | counter | Number of program cache insertions |
| <span class="metrics-name">exec_&#8203;progcache_&#8203;fill_&#8203;tot_&#8203;sz</span> | counter | Total number of bytes inserted into program cache |
| <span class="metrics-name">exec_&#8203;progcache_&#8203;fill_&#8203;fails</span> | counter | Number of program cache load fails (tombstones inserted) |
| <span class="metrics-name">exec_&#8203;progcache_&#8203;dup_&#8203;inserts</span> | counter | Number of time two tiles raced to insert the same cache entry |
| <span class="metrics-name">exec_&#8203;progcache_&#8203;invalidations</span> | counter | Number of program cache invalidations |

</div>

## Snapwr Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapwr_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 4=SHUTDOWN |
| <span class="metrics-name">snapwr_&#8203;vinyl_&#8203;bytes_&#8203;written</span> | gauge | Number of bytes written so far to the vinyl snapshot file. Might decrease if snapshot creation is aborted and restarted |

</div>

## Benchs Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">benchs_&#8203;transactions_&#8203;sent</span> | counter | Number of benchmark packets sent |

</div>

## Snapwh Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapwh_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 4=SHUTDOWN |

</div>

## Snapla Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapla_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 2=FINISHING, 3=ERROR, 4=SHUTDOWN |
| <span class="metrics-name">snapla_&#8203;full_&#8203;accounts_&#8203;hashed</span> | gauge | Number of accounts hashed for the full snapshot during snapshot loading. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapla_&#8203;incremental_&#8203;accounts_&#8203;hashed</span> | gauge | Number of accounts hashed for the incremental snapshot during snapshot loading. Might decrease if snapshot load is aborted and restarted |

</div>

## Snapls Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapls_&#8203;state</span> | gauge | State of the tile. 0=IDLE, 1=PROCESSING, 2=FINISHING, 3=ERROR, 4=SHUTDOWN |
| <span class="metrics-name">snapls_&#8203;full_&#8203;accounts_&#8203;hashed</span> | gauge | Number of accounts hashed for the full snapshot during snapshot loading. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapls_&#8203;incremental_&#8203;accounts_&#8203;hashed</span> | gauge | Number of accounts hashed for the incremental snapshot during snapshot loading. Might decrease if snapshot load is aborted and restarted |

</div>

## Tower Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn_&#8203;invalid</span> | counter | Number of times we dropped a vote txn because it was invalid (malformed, bad signature, etc.) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn_&#8203;ignored</span> | counter | Number of times we ignored all or part of a vote txn because we didn't recognize a slot (eg. our replay was behind) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn_&#8203;mismatch</span> | counter | Number of times a vote txn mismatched our own block id |
| <span class="metrics-name">tower_&#8203;ancestor_&#8203;rollback</span> | counter | Rollback to an ancestor of our prev vote (can't vote) |
| <span class="metrics-name">tower_&#8203;sibling_&#8203;confirmed</span> | counter | Duplicate sibling got confirmed (can't vote) |
| <span class="metrics-name">tower_&#8203;same_&#8203;fork</span> | counter | Same fork as prev vote (can vote) |
| <span class="metrics-name">tower_&#8203;switch_&#8203;pass</span> | counter | Prev vote was on a different fork, but we are allowed to switch (can vote) |
| <span class="metrics-name">tower_&#8203;switch_&#8203;fail</span> | counter | Prev vote was on a different fork, and we are not allowed to switch (can't vote) |
| <span class="metrics-name">tower_&#8203;lockout_&#8203;fail</span> | counter | Locked out (can't vote) |
| <span class="metrics-name">tower_&#8203;threshold_&#8203;fail</span> | counter | Did not pass threshold check (can't vote) |
| <span class="metrics-name">tower_&#8203;propagated_&#8203;fail</span> | counter | Prev leader block did not propagate (can't vote) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;forks_&#8203;seen</span> | counter | Number of hard forks we've seen (block ids with multiple candidate bank hashes) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;forks_&#8203;pruned</span> | counter | Number of hard forks (candidate bank hashes) we've pruned |
| <span class="metrics-name">tower_&#8203;hard_&#8203;forks_&#8203;active</span> | gauge | Currently active hard forks |

</div>
