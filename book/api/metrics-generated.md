
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
| <span class="metrics-name">tile_&#8203;status</span> | gauge | The current status of the tile. 0 is booting, 1 is running. |
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
| <span class="metrics-name">quic_&#8203;connections_&#8203;active</span> | gauge | The number of currently active QUIC connections. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;created</span> | counter | The total number of connections that have been created. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;closed</span> | counter | Number of connections gracefully closed. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;aborted</span> | counter | Number of connections aborted. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;timed_&#8203;out</span> | counter | Number of connections timed out. |
| <span class="metrics-name">quic_&#8203;connections_&#8203;retried</span> | counter | Number of connections established with retry. |
| <span class="metrics-name">quic_&#8203;connection_&#8203;error_&#8203;no_&#8203;slots</span> | counter | Number of connections that failed to create due to lack of slots. |
| <span class="metrics-name">quic_&#8203;connection_&#8203;error_&#8203;retry_&#8203;fail</span> | counter | Number of connections that failed during retry (e.g. invalid token). |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span> | counter | Number of packets with an unknown connection ID. |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;alloc_&#8203;fail</span> | counter | Number of packets failed to send because of metadata alloc fail. |
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
| <span class="metrics-name">quic_&#8203;receive_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent receiving packets |
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
| <span class="metrics-name">quic_&#8203;pkt_&#8203;retransmissions</span> | counter | Number of QUIC packets that retransmitted. |

</div>

## Bundle Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">bundle_&#8203;transaction_&#8203;received</span> | counter | Total count of transactions received, including transactions within bundles |
| <span class="metrics-name">bundle_&#8203;packet_&#8203;received</span> | counter | Total count of packets received |
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

</div>

## Verify Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">verify_&#8203;transaction_&#8203;bundle_&#8203;peer_&#8203;failure</span> | counter | Count of transactions that failed to verify because a peer transaction in the bundle failed |
| <span class="metrics-name">verify_&#8203;transaction_&#8203;parse_&#8203;failure</span> | counter | Count of transactions that failed to parse |
| <span class="metrics-name">verify_&#8203;transaction_&#8203;dedup_&#8203;failure</span> | counter | Count of transactions that failed to deduplicate in the verify stage |
| <span class="metrics-name">verify_&#8203;transaction_&#8203;verify_&#8203;failure</span> | counter | Count of transactions that failed to deduplicate in the verify stage |

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
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">bundle_&#8203;blacklist</span>"} | counter | Result of inserting a transaction into the pack object (Transaction uses an account on the bundle blacklist) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">write_&#8203;sysvar</span>"} | counter | Result of inserting a transaction into the pack object (Transaction tries to write to a sysvar) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">estimation_&#8203;fail</span>"} | counter | Result of inserting a transaction into the pack object (Estimating compute cost and/or fee failed) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">duplicate_&#8203;account</span>"} | counter | Result of inserting a transaction into the pack object (Transaction included an account address twice) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">too_&#8203;many_&#8203;accounts</span>"} | counter | Result of inserting a transaction into the pack object (Transaction tried to load too many accounts) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">too_&#8203;large</span>"} | counter | Result of inserting a transaction into the pack object (Transaction requests too many CUs) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">expired</span>"} | counter | Result of inserting a transaction into the pack object (Transaction already expired) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">addr_&#8203;lut</span>"} | counter | Result of inserting a transaction into the pack object (Transaction loaded accounts from a lookup table) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">unaffordable</span>"} | counter | Result of inserting a transaction into the pack object (Fee payer's balance below transaction fee) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">duplicate</span>"} | counter | Result of inserting a transaction into the pack object (Pack aware of transaction with same signature) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">priority</span>"} | counter | Result of inserting a transaction into the pack object (Transaction's fee was too low given its compute unit requirement and other competing transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonvote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Transaction that was not a simple vote added to pending transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">vote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Simple vote transaction was added to pending transactions) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonvote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Transaction that was not a simple vote replaced a lower priority transaction) |
| <span class="metrics-name">pack_&#8203;transaction_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">vote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Simple vote transaction replaced a lower priority transaction) |
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
| <span class="metrics-name">bank_&#8203;precompile_&#8203;verify_&#8203;failure</span> | counter | Number of transactions that failed precompile verification and thus will not execute. |
| <span class="metrics-name">bank_&#8203;slot_&#8203;acquire</span><br/>{bank_&#8203;slot_&#8203;acquire="<span class="metrics-enum">success</span>"} | counter | Result of acquiring a slot. (Success) |
| <span class="metrics-name">bank_&#8203;slot_&#8203;acquire</span><br/>{bank_&#8203;slot_&#8203;acquire="<span class="metrics-enum">too_&#8203;high</span>"} | counter | Result of acquiring a slot. (Too high) |
| <span class="metrics-name">bank_&#8203;slot_&#8203;acquire</span><br/>{bank_&#8203;slot_&#8203;acquire="<span class="metrics-enum">too_&#8203;low</span>"} | counter | Result of acquiring a slot. (Too low) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{bank_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table="<span class="metrics-enum">success</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (Success) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{bank_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table="<span class="metrics-enum">slot_&#8203;hashes_&#8203;sysvar_&#8203;not_&#8203;found</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The slot hashes syvar could not be found.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{bank_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account storing the address lookup table was deactivated or could not be found.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{bank_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The account that owns the referenced lookup table is not the address lookup table program.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{bank_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The data for the referenced address lookup table is malformed.) |
| <span class="metrics-name">bank_&#8203;transaction_&#8203;load_&#8203;address_&#8203;tables</span><br/>{bank_&#8203;load_&#8203;address_&#8203;lookup_&#8203;table="<span class="metrics-enum">invalid_&#8203;index</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported. (The referenced index in the address lookup table does not exist.) |
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
| <span class="metrics-name">bank_&#8203;transaction_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">commit_&#8203;cancelled</span>"} | counter | Result of loading and executing a transaction. (The process for comitting the transaction was cancelled internaly.) |
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
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">bad_&#8203;slot</span>"} | counter | The result of processing a thread from the network (Shred was for a slot for which we don't know the leader) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">parse_&#8203;failed</span>"} | counter | The result of processing a thread from the network (Shred parsing failed) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">rejected</span>"} | counter | The result of processing a thread from the network (Shred was invalid for one of many reasons) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">ignored</span>"} | counter | The result of processing a thread from the network (Shred was ignored because we had already received or reconstructed it) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">okay</span>"} | counter | The result of processing a thread from the network (Shred accepted to an incomplete FEC set) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">completes</span>"} | counter | The result of processing a thread from the network (Shred accepted and resulted in a valid, complete FEC set) |
| <span class="metrics-name">shred_&#8203;fec_&#8203;set_&#8203;spilled</span> | counter | The number of FEC sets that were spilled because they didn't complete in time and we needed space |
| <span class="metrics-name">shred_&#8203;shred_&#8203;rejected_&#8203;initial</span> | counter | The number shreds that were rejected before any resources were allocated for the FEC set |
| <span class="metrics-name">shred_&#8203;fec_&#8203;rejected_&#8203;fatal</span> | counter | The number of FEC sets that were rejected for reasons that cause the whole FEC set to become invalid |
| <span class="metrics-name">shred_&#8203;force_&#8203;complete_&#8203;request</span> | counter | The number of times we recieved a FEC force complete message |
| <span class="metrics-name">shred_&#8203;force_&#8203;complete_&#8203;failure</span> | counter | The number of times we failed to force complete a FEC set on request |
| <span class="metrics-name">shred_&#8203;force_&#8203;complete_&#8203;success</span> | counter | The number of times we successfully forced completed a FEC set on request |

</div>

## Store Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">store_&#8203;transactions_&#8203;inserted</span> | counter | Count of transactions produced while we were leader in the shreds that have been inserted so far |

</div>

## Replay Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">replay_&#8203;slot</span> | gauge |  |
| <span class="metrics-name">replay_&#8203;last_&#8203;voted_&#8203;slot</span> | gauge |  |

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
| <span class="metrics-name">gossip_&#8203;last_&#8203;crds_&#8203;push_&#8203;contact_&#8203;info_&#8203;publish_&#8203;timestamp_&#8203;nanos</span> | gauge | Time (in nanoseconds) of last CRDS Push ContactInfo message publish |
| <span class="metrics-name">gossip_&#8203;mismatched_&#8203;contact_&#8203;info_&#8203;shred_&#8203;version</span> | counter | Mismatched Contact Info Shred Version |
| <span class="metrics-name">gossip_&#8203;ipv6_&#8203;contact_&#8203;info</span><br/>{peer_&#8203;types="<span class="metrics-enum">tvu</span>"} | counter | IPv6 Contact Info (by peer type) (TVU) |
| <span class="metrics-name">gossip_&#8203;ipv6_&#8203;contact_&#8203;info</span><br/>{peer_&#8203;types="<span class="metrics-enum">repair</span>"} | counter | IPv6 Contact Info (by peer type) (Repair) |
| <span class="metrics-name">gossip_&#8203;ipv6_&#8203;contact_&#8203;info</span><br/>{peer_&#8203;types="<span class="metrics-enum">voter</span>"} | counter | IPv6 Contact Info (by peer type) (Voter) |
| <span class="metrics-name">gossip_&#8203;zero_&#8203;ipv4_&#8203;contact_&#8203;info</span><br/>{peer_&#8203;types="<span class="metrics-enum">tvu</span>"} | counter | Zero IPv4 Contact Info (by peer type) (TVU) |
| <span class="metrics-name">gossip_&#8203;zero_&#8203;ipv4_&#8203;contact_&#8203;info</span><br/>{peer_&#8203;types="<span class="metrics-enum">repair</span>"} | counter | Zero IPv4 Contact Info (by peer type) (Repair) |
| <span class="metrics-name">gossip_&#8203;zero_&#8203;ipv4_&#8203;contact_&#8203;info</span><br/>{peer_&#8203;types="<span class="metrics-enum">voter</span>"} | counter | Zero IPv4 Contact Info (by peer type) (Voter) |
| <span class="metrics-name">gossip_&#8203;peer_&#8203;counts</span><br/>{peer_&#8203;types="<span class="metrics-enum">tvu</span>"} | gauge | Number of peers of each type (TVU) |
| <span class="metrics-name">gossip_&#8203;peer_&#8203;counts</span><br/>{peer_&#8203;types="<span class="metrics-enum">repair</span>"} | gauge | Number of peers of each type (Repair) |
| <span class="metrics-name">gossip_&#8203;peer_&#8203;counts</span><br/>{peer_&#8203;types="<span class="metrics-enum">voter</span>"} | gauge | Number of peers of each type (Voter) |
| <span class="metrics-name">gossip_&#8203;shred_&#8203;version_&#8203;zero</span> | counter | Shred version zero |
| <span class="metrics-name">gossip_&#8203;value_&#8203;meta_&#8203;size</span> | gauge | Current size of the CRDS value metas map |
| <span class="metrics-name">gossip_&#8203;value_&#8203;vec_&#8203;size</span> | gauge | Current size of the CRDS value vector |
| <span class="metrics-name">gossip_&#8203;received_&#8203;packets</span> | counter | Number of all gossip packets received |
| <span class="metrics-name">gossip_&#8203;corrupted_&#8203;messages</span> | counter | Number of corrupted gossip messages received |
| <span class="metrics-name">gossip_&#8203;received_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;request</span>"} | counter | Number of gossip messages received (Pull Request) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;response</span>"} | counter | Number of gossip messages received (Pull Response) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">push</span>"} | counter | Number of gossip messages received (Push) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">prune</span>"} | counter | Number of gossip messages received (Prune) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">ping</span>"} | counter | Number of gossip messages received (Ping) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pong</span>"} | counter | Number of gossip messages received (Pong) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;unknown_&#8203;message</span> | counter | Number of gossip messages received that have an unknown discriminant |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Number of CRDS values received from push messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Number of CRDS values received from push messages (Vote) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Number of CRDS values received from push messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Number of CRDS values received from push messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Number of CRDS values received from push messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Number of CRDS values received from push messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Number of CRDS values received from push messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Number of CRDS values received from push messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Number of CRDS values received from push messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Number of CRDS values received from push messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Number of CRDS values received from push messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Number of CRDS values received from push messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Number of CRDS values received from push messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Number of CRDS values received from push messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Number of CRDS values received from pull response messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Number of CRDS values received from pull response messages (Vote) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Number of CRDS values received from pull response messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Number of CRDS values received from pull response messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Number of CRDS values received from pull response messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Number of CRDS values received from pull response messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Number of CRDS values received from pull response messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Number of CRDS values received from pull response messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Number of CRDS values received from pull response messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Number of CRDS values received from pull response messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Number of CRDS values received from pull response messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Number of CRDS values received from pull response messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Number of CRDS values received from pull response messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Number of CRDS values received from pull response messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Number of duplicate CRDS values received from push messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Number of duplicate CRDS values received from push messages (Vote) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Number of duplicate CRDS values received from push messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values received from push messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values received from push messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Number of duplicate CRDS values received from push messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Number of duplicate CRDS values received from push messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Number of duplicate CRDS values received from push messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Number of duplicate CRDS values received from push messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Number of duplicate CRDS values received from push messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values received from push messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Number of duplicate CRDS values received from push messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Number of duplicate CRDS values received from push messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;push</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Number of duplicate CRDS values received from push messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Vote) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;duplicate_&#8203;message_&#8203;pull</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Number of duplicate CRDS values received from pull response messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">success</span>"} | counter | Number of CRDS values dropped on receive (Successfully processed CRDS (not dropped)) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">duplicate</span>"} | counter | Number of CRDS values dropped on receive (Duplicate CRDS value) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">unknown_&#8203;discriminant</span>"} | counter | Number of CRDS values dropped on receive (Unknown discriminant) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">own_&#8203;message</span>"} | counter | Number of CRDS values dropped on receive (Own message) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">invalid_&#8203;signature</span>"} | counter | Number of CRDS values dropped on receive (Invalid signature) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">table_&#8203;full</span>"} | counter | Number of CRDS values dropped on receive (Table full) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">push_&#8203;queue_&#8203;full</span>"} | counter | Number of CRDS values dropped on receive (Push queue full) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">invalid_&#8203;gossip_&#8203;port</span>"} | counter | Number of CRDS values dropped on receive (Invalid gossip port) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">peer_&#8203;table_&#8203;full</span>"} | counter | Number of CRDS values dropped on receive (Peer table full) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">inactives_&#8203;queue_&#8203;full</span>"} | counter | Number of CRDS values dropped on receive (Inactives queue full) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">discarded_&#8203;peer</span>"} | counter | Number of CRDS values dropped on receive (Discarded peer) |
| <span class="metrics-name">gossip_&#8203;received_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">encoding_&#8203;failed</span>"} | counter | Number of CRDS values dropped on receive (Encoding failed) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Number of CRDS values pushed (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Number of CRDS values pushed (Vote) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Number of CRDS values pushed (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Number of CRDS values pushed (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Number of CRDS values pushed (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Number of CRDS values pushed (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Number of CRDS values pushed (Version V1) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Number of CRDS values pushed (Version V2) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Number of CRDS values pushed (Node Instance) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Number of CRDS values pushed (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Number of CRDS values pushed (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Number of CRDS values pushed (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Number of CRDS values pushed (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Number of CRDS values pushed (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Vote) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Version V1) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Version V2) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Node Instance) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;duplicate_&#8203;message</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Number of duplicate CRDS values inserted (internally) (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">success</span>"} | counter | Number of CRDS values dropped on push (Successfully processed CRDS (not dropped)) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">duplicate</span>"} | counter | Number of CRDS values dropped on push (Duplicate CRDS value) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">unknown_&#8203;discriminant</span>"} | counter | Number of CRDS values dropped on push (Unknown discriminant) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">own_&#8203;message</span>"} | counter | Number of CRDS values dropped on push (Own message) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">invalid_&#8203;signature</span>"} | counter | Number of CRDS values dropped on push (Invalid signature) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">table_&#8203;full</span>"} | counter | Number of CRDS values dropped on push (Table full) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">push_&#8203;queue_&#8203;full</span>"} | counter | Number of CRDS values dropped on push (Push queue full) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">invalid_&#8203;gossip_&#8203;port</span>"} | counter | Number of CRDS values dropped on push (Invalid gossip port) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">peer_&#8203;table_&#8203;full</span>"} | counter | Number of CRDS values dropped on push (Peer table full) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">inactives_&#8203;queue_&#8203;full</span>"} | counter | Number of CRDS values dropped on push (Inactives queue full) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">discarded_&#8203;peer</span>"} | counter | Number of CRDS values dropped on push (Discarded peer) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;drop</span><br/>{crds_&#8203;drop_&#8203;reason="<span class="metrics-enum">encoding_&#8203;failed</span>"} | counter | Number of CRDS values dropped on push (Encoding failed) |
| <span class="metrics-name">gossip_&#8203;push_&#8203;crds_&#8203;queue_&#8203;count</span> | gauge | Number of CRDS values in the queue to be pushed |
| <span class="metrics-name">gossip_&#8203;active_&#8203;push_&#8203;destinations</span> | gauge | Number of active Push destinations |
| <span class="metrics-name">gossip_&#8203;refresh_&#8203;push_&#8203;states_&#8203;fail_&#8203;count</span> | counter | Number of failures whilst refreshing push states |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;fail</span><br/>{pull_&#8203;req_&#8203;fail_&#8203;reason="<span class="metrics-enum">peer_&#8203;not_&#8203;in_&#8203;actives</span>"} | counter | Number of PullReq messages that failed (Number of PullReq messages from peers that are not in the active set) |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;fail</span><br/>{pull_&#8203;req_&#8203;fail_&#8203;reason="<span class="metrics-enum">unresponsive_&#8203;peer</span>"} | counter | Number of PullReq messages that failed (Number of PullReq messages from a peer that hasn't responded to our ping message yet) |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;fail</span><br/>{pull_&#8203;req_&#8203;fail_&#8203;reason="<span class="metrics-enum">pending_&#8203;pool_&#8203;full</span>"} | counter | Number of PullReq messages that failed (Number of PullReq messages skipped due to the pending pool being full) |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;fail</span><br/>{pull_&#8203;req_&#8203;fail_&#8203;reason="<span class="metrics-enum">encoding_&#8203;failed</span>"} | counter | Number of PullReq messages that failed (Number of PullReq messages skipped due to message encoding failed) |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;bloom_&#8203;filter</span><br/>{pull_&#8203;req_&#8203;bloom_&#8203;filter_&#8203;result="<span class="metrics-enum">hit</span>"} | counter | Result of the bloom filter check for a PullReq (Number of PullReq messages that hit the bloom filter) |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;bloom_&#8203;filter</span><br/>{pull_&#8203;req_&#8203;bloom_&#8203;filter_&#8203;result="<span class="metrics-enum">miss</span>"} | counter | Result of the bloom filter check for a PullReq (Number of PullReq messages that missed the bloom filter) |
| <span class="metrics-name">gossip_&#8203;pull_&#8203;req_&#8203;resp_&#8203;packets</span> | gauge | Number of packets used to respond to a PullReq |
| <span class="metrics-name">gossip_&#8203;prune_&#8203;fail_&#8203;count</span><br/>{prune_&#8203;failure_&#8203;reason="<span class="metrics-enum">not_&#8203;for_&#8203;me</span>"} | counter | Number of Prune messages that failed (Prune message not for me) |
| <span class="metrics-name">gossip_&#8203;prune_&#8203;fail_&#8203;count</span><br/>{prune_&#8203;failure_&#8203;reason="<span class="metrics-enum">sign_&#8203;encoding_&#8203;failed</span>"} | counter | Number of Prune messages that failed (Prune message sign encoding failed) |
| <span class="metrics-name">gossip_&#8203;prune_&#8203;fail_&#8203;count</span><br/>{prune_&#8203;failure_&#8203;reason="<span class="metrics-enum">invalid_&#8203;signature</span>"} | counter | Number of Prune messages that failed (Prune message invalid signature) |
| <span class="metrics-name">gossip_&#8203;make_&#8203;prune_&#8203;stale_&#8203;entry</span> | counter | Number of stale entries removed from the stats table while making prune messages |
| <span class="metrics-name">gossip_&#8203;make_&#8203;prune_&#8203;high_&#8203;duplicates</span> | counter | Number of origins with high duplicate counts found while making prune messages |
| <span class="metrics-name">gossip_&#8203;make_&#8203;prune_&#8203;requested_&#8203;origins</span> | gauge | Number of requested origins in the last prune message we made |
| <span class="metrics-name">gossip_&#8203;make_&#8203;prune_&#8203;sign_&#8203;data_&#8203;encode_&#8203;failed</span> | counter | Number of times we failed to encode the sign data |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;request</span>"} | counter | Number of gossip messages sent (Pull Request) |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;response</span>"} | counter | Number of gossip messages sent (Pull Response) |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">push</span>"} | counter | Number of gossip messages sent (Push) |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">prune</span>"} | counter | Number of gossip messages sent (Prune) |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">ping</span>"} | counter | Number of gossip messages sent (Ping) |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;gossip_&#8203;messages</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pong</span>"} | counter | Number of gossip messages sent (Pong) |
| <span class="metrics-name">gossip_&#8203;sent_&#8203;packets</span> | counter | Number of Packets sent |
| <span class="metrics-name">gossip_&#8203;send_&#8203;ping_&#8203;event</span><br/>{send_&#8203;ping_&#8203;event="<span class="metrics-enum">actives_&#8203;table_&#8203;full</span>"} | counter | Number of Ping messages sent with non-standard outcomes (Number of Ping messages we failed to send due to the Active Peers table being full) |
| <span class="metrics-name">gossip_&#8203;send_&#8203;ping_&#8203;event</span><br/>{send_&#8203;ping_&#8203;event="<span class="metrics-enum">actives_&#8203;table_&#8203;insert</span>"} | counter | Number of Ping messages sent with non-standard outcomes (Number of Ping messages that cause an insert into the Active Peers table) |
| <span class="metrics-name">gossip_&#8203;send_&#8203;ping_&#8203;event</span><br/>{send_&#8203;ping_&#8203;event="<span class="metrics-enum">max_&#8203;ping_&#8203;count_&#8203;exceeded</span>"} | counter | Number of Ping messages sent with non-standard outcomes (Number of times we removed a peer from the Actives table, because it repeatedly failed to respond to a ping) |
| <span class="metrics-name">gossip_&#8203;recv_&#8203;ping_&#8203;invalid_&#8203;signature</span> | counter | Number of times we received a Ping message with an invalid signature |
| <span class="metrics-name">gossip_&#8203;recv_&#8203;pong_&#8203;event</span><br/>{recv_&#8203;pong_&#8203;event="<span class="metrics-enum">new_&#8203;peer</span>"} | counter | Number of Pong messages processed with non-standard outcomes (Pong peer is not in table) |
| <span class="metrics-name">gossip_&#8203;recv_&#8203;pong_&#8203;event</span><br/>{recv_&#8203;pong_&#8203;event="<span class="metrics-enum">wrong_&#8203;token</span>"} | counter | Number of Pong messages processed with non-standard outcomes (Pong peer token mismatch) |
| <span class="metrics-name">gossip_&#8203;recv_&#8203;pong_&#8203;event</span><br/>{recv_&#8203;pong_&#8203;event="<span class="metrics-enum">invalid_&#8203;signature</span>"} | counter | Number of Pong messages processed with non-standard outcomes (Pong peer invalid signature) |
| <span class="metrics-name">gossip_&#8203;recv_&#8203;pong_&#8203;event</span><br/>{recv_&#8203;pong_&#8203;event="<span class="metrics-enum">expired</span>"} | counter | Number of Pong messages processed with non-standard outcomes (Pong peer expired) |
| <span class="metrics-name">gossip_&#8203;recv_&#8203;pong_&#8203;event</span><br/>{recv_&#8203;pong_&#8203;event="<span class="metrics-enum">table_&#8203;full</span>"} | counter | Number of Pong messages processed with non-standard outcomes (Unable to insert peer due to table full) |
| <span class="metrics-name">gossip_&#8203;gossip_&#8203;peer_&#8203;counts</span><br/>{gossip_&#8203;peer_&#8203;state="<span class="metrics-enum">total</span>"} | gauge | Number of gossip peers tracked (Total Peers Detected) |
| <span class="metrics-name">gossip_&#8203;gossip_&#8203;peer_&#8203;counts</span><br/>{gossip_&#8203;peer_&#8203;state="<span class="metrics-enum">active</span>"} | gauge | Number of gossip peers tracked (Active) |
| <span class="metrics-name">gossip_&#8203;gossip_&#8203;peer_&#8203;counts</span><br/>{gossip_&#8203;peer_&#8203;state="<span class="metrics-enum">inactive</span>"} | gauge | Number of gossip peers tracked (Inactive) |

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
| <span class="metrics-name">repair_&#8203;recv_&#8203;clnt_&#8203;pkt</span> | counter | Now many client packets have we received |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;pkt</span> | counter | How many server packets have we received |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;corrupt_&#8203;pkt</span> | counter | How many corrupt server packets have we received |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;invalid_&#8203;signature</span> | counter | How many invalid signatures have we received |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;full_&#8203;ping_&#8203;table</span> | counter | Is our ping table full and causing packet drops |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;serv_&#8203;pkt_&#8203;types="<span class="metrics-enum">pong</span>"} | counter | Server messages received (Pong) |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;serv_&#8203;pkt_&#8203;types="<span class="metrics-enum">window</span>"} | counter | Server messages received (Window) |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;serv_&#8203;pkt_&#8203;types="<span class="metrics-enum">highest_&#8203;window</span>"} | counter | Server messages received (Highest Window) |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;serv_&#8203;pkt_&#8203;types="<span class="metrics-enum">orphan</span>"} | counter | Server messages received (Orphan) |
| <span class="metrics-name">repair_&#8203;recv_&#8203;serv_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;serv_&#8203;pkt_&#8203;types="<span class="metrics-enum">unknown</span>"} | counter | Server messages received (Unknown) |
| <span class="metrics-name">repair_&#8203;recv_&#8203;pkt_&#8203;corrupted_&#8203;msg</span> | counter | How many corrupt messages have we received |
| <span class="metrics-name">repair_&#8203;send_&#8203;pkt_&#8203;cnt</span> | counter | How many packets have sent |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">needed_&#8203;window</span>"} | counter | What types of client messages are we sending (Need Window) |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">needed_&#8203;highest_&#8203;window</span>"} | counter | What types of client messages are we sending (Need Highest Window) |
| <span class="metrics-name">repair_&#8203;sent_&#8203;pkt_&#8203;types</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;types="<span class="metrics-enum">needed_&#8203;orphan</span>"} | counter | What types of client messages are we sending (Need Orphans) |

</div>
