
## All Links
<!--@include: ./metrics-link-preamble.md-->

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">link_&#8203;frag_&#8203;consumed</span> | counter | Fragments consumed by the link reader |
| <span class="metrics-name">link_&#8203;frag_&#8203;consumed_&#8203;bytes</span> | counter | Bytes read by the link consumer |
| <span class="metrics-name">link_&#8203;frag_&#8203;filtered</span> | counter | Fragments filtered and not consumed |
| <span class="metrics-name">link_&#8203;frag_&#8203;filtered_&#8203;bytes</span> | counter | Bytes read by the link consumer that were filtered |
| <span class="metrics-name">link_&#8203;link_&#8203;polling_&#8203;overrun</span> | counter | Times the link was overrun while polling |
| <span class="metrics-name">link_&#8203;frag_&#8203;polling_&#8203;overrun</span> | counter | Fragments not processed because the link was overrun while polling |
| <span class="metrics-name">link_&#8203;link_&#8203;reading_&#8203;overrun</span> | counter | Times the link was overrun while reading metadata |
| <span class="metrics-name">link_&#8203;frag_&#8203;reading_&#8203;overrun</span> | counter | Fragments not processed because the link was overrun while reading |
| <span class="metrics-name">link_&#8203;slow</span> | counter | Times the consumer was detected as slow, rate limiting the producer |
</div>

## All Tiles
<!--@include: ./metrics-tile-preamble.md-->

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">tile_&#8203;pid</span> | gauge | Process ID of the tile |
| <span class="metrics-name">tile_&#8203;tid</span> | gauge | Thread ID of the tile. Same as Pid in production, but might differ in development |
| <span class="metrics-name">tile_&#8203;last_&#8203;cpu</span> | gauge | Index of the CPU last executed on |
| <span class="metrics-name">tile_&#8203;context_&#8203;switch_&#8203;involuntary</span> | counter | Involuntary context switches |
| <span class="metrics-name">tile_&#8203;context_&#8203;switch_&#8203;voluntary</span> | counter | Voluntary context switches |
| <span class="metrics-name">tile_&#8203;page_&#8203;fault_&#8203;major</span> | counter | Major page faults |
| <span class="metrics-name">tile_&#8203;page_&#8203;fault_&#8203;minor</span> | counter | Minor page faults |
| <span class="metrics-name">tile_&#8203;status</span> | gauge | 0=booting, 1=running, 2=shutdown |
| <span class="metrics-name">tile_&#8203;heartbeat_&#8203;timestamp_&#8203;nanos</span> | gauge | Last UNIX timestamp the tile heartbeated, in nanoseconds |
| <span class="metrics-name">tile_&#8203;in_&#8203;backpressure</span> | gauge | Whether the tile is currently backpressured, 1 or 0 |
| <span class="metrics-name">tile_&#8203;backpressure</span> | counter | Times the tile waited for one or more consumers to catch up to resume publishing |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">caught_&#8203;up_&#8203;housekeeping</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Caught up + Housekeeping) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">processing_&#8203;housekeeping</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Processing + Housekeeping) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">backpressure_&#8203;housekeeping</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Backpressure + Housekeeping) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">caught_&#8203;up_&#8203;prefrag</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Caught up + Prefrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">processing_&#8203;prefrag</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Processing + Prefrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">backpressure_&#8203;prefrag</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Backpressure + Prefrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">caught_&#8203;up_&#8203;postfrag</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Caught up + Postfrag) |
| <span class="metrics-name">tile_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{tile_&#8203;regime="<span class="metrics-enum">processing_&#8203;postfrag</span>"} | counter | Mutually exclusive and exhaustive duration the tile spent in each regime, in nanoseconds (Processing + Postfrag) |
| <span class="metrics-name">tile_&#8203;cpu_&#8203;duration_&#8203;nanos</span><br/>{cpu_&#8203;regime="<span class="metrics-enum">wait</span>"} | counter | CPU time spent in each CPU regime, in nanoseconds (Wait (task was runnable but not scheduled)) |
| <span class="metrics-name">tile_&#8203;cpu_&#8203;duration_&#8203;nanos</span><br/>{cpu_&#8203;regime="<span class="metrics-enum">idle</span>"} | counter | CPU time spent in each CPU regime, in nanoseconds (Idle (task was not runnable)) |
| <span class="metrics-name">tile_&#8203;cpu_&#8203;duration_&#8203;nanos</span><br/>{cpu_&#8203;regime="<span class="metrics-enum">user</span>"} | counter | CPU time spent in each CPU regime, in nanoseconds (User (task was scheduled and executing in user mode)) |
| <span class="metrics-name">tile_&#8203;cpu_&#8203;duration_&#8203;nanos</span><br/>{cpu_&#8203;regime="<span class="metrics-enum">system</span>"} | counter | CPU time spent in each CPU regime, in nanoseconds (System (task was scheduled and executing in kernel mode)) |
| <span class="metrics-name">tile_&#8203;irq_&#8203;preempted</span> | counter | Times the tile was interrupted by an IRQ (fixed tiles only) |
| <span class="metrics-name">tile_&#8203;tlb_&#8203;shootdown</span> | counter | TLB shootdowns observed on the tile CPU (fixed tiles only) |

</div>

## Genesi Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|

</div>

## Ipecho Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">ipecho_&#8203;current_&#8203;shred_&#8203;version</span> | gauge | Current shred version used by the validator |
| <span class="metrics-name">ipecho_&#8203;conn_&#8203;active</span> | gauge | Active connections to the ipecho service |
| <span class="metrics-name">ipecho_&#8203;conn_&#8203;closed</span><br/>{conn_&#8203;close_&#8203;result="<span class="metrics-enum">ok</span>"} | counter | Connections to the ipecho service made and closed, by outcome (Closed normally) |
| <span class="metrics-name">ipecho_&#8203;conn_&#8203;closed</span><br/>{conn_&#8203;close_&#8203;result="<span class="metrics-enum">error</span>"} | counter | Connections to the ipecho service made and closed, by outcome (Closed abnormally) |
| <span class="metrics-name">ipecho_&#8203;bytes_&#8203;read</span> | counter | Bytes read from all connections to the ipecho service |
| <span class="metrics-name">ipecho_&#8203;bytes_&#8203;written</span> | counter | Bytes written to all connections to the ipecho service |

</div>

## Snapct Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapct_&#8203;state</span> | gauge | 0=init, 1=waiting for peers, 2=waiting for peers (incremental), 3=collecting peers, 4=collecting peers (incremental), 5=reading full file, 6=flushing full file fini, 7=flushing full file done, 8=flushing full file reset, 9=reading incremental file, 10=flushing incremental file fini, 11=flushing incremental file done, 12=flushing incremental file reset, 13=reading full http, 14=flushing full http fini, 15=flushing full http done, 16=flushing full http reset, 17=reading incremental http, 18=flushing incremental http fini, 19=flushing incremental http done, 20=flushing incremental http reset, 21=shutdown |
| <span class="metrics-name">snapct_&#8203;full_&#8203;bytes_&#8203;read</span> | gauge | Bytes read so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;full_&#8203;bytes_&#8203;written</span> | gauge | Bytes written so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;full_&#8203;size_&#8203;bytes</span> | gauge | Total size of the full snapshot file. Might change if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;full_&#8203;retry</span> | gauge | Retries of the full snapshot download so far because the peer was too slow |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;bytes_&#8203;read</span> | gauge | Bytes read so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;bytes_&#8203;written</span> | gauge | Bytes written so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;size_&#8203;bytes</span> | gauge | Total size of the incremental snapshot file. Might change if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;incremental_&#8203;retry</span> | gauge | Retries of the incremental snapshot download so far because the peer was too slow |
| <span class="metrics-name">snapct_&#8203;predicted_&#8203;slot</span> | gauge | Predicted slot from which replay starts after snapshot loading finishes. Might change if snapshot load is aborted and restarted |
| <span class="metrics-name">snapct_&#8203;ssl_&#8203;alloc_&#8203;failed</span> | counter | SSL allocation errors encountered |

</div>

## Snapld Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapld_&#8203;state</span> | gauge | 0=idle, 1=processing, 2=finishing, 3=error, 4=shutdown |
| <span class="metrics-name">snapld_&#8203;ssl_&#8203;alloc_&#8203;failed</span> | counter | SSL allocation errors encountered |

</div>

## Snapdc Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapdc_&#8203;state</span> | gauge | 0=idle, 1=processing, 2=finishing, 3=error, 4=shutdown |
| <span class="metrics-name">snapdc_&#8203;full_&#8203;compressed_&#8203;bytes_&#8203;read</span> | gauge | Bytes read so far from the compressed full snapshot file. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapdc_&#8203;full_&#8203;decompressed_&#8203;bytes_&#8203;written</span> | gauge | Bytes decompressed so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapdc_&#8203;incremental_&#8203;compressed_&#8203;bytes_&#8203;read</span> | gauge | Bytes read so far from the compressed incremental snapshot file. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapdc_&#8203;incremental_&#8203;decompressed_&#8203;bytes_&#8203;written</span> | gauge | Bytes decompressed so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |

</div>

## Snapin Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapin_&#8203;state</span> | gauge | 0=idle, 1=processing, 2=finishing, 3=error, 4=shutdown |
| <span class="metrics-name">snapin_&#8203;full_&#8203;bytes_&#8203;read</span> | gauge | Bytes read so far from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapin_&#8203;incremental_&#8203;bytes_&#8203;read</span> | gauge | Bytes read so far from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapin_&#8203;account_&#8203;loaded</span> | gauge | Accounts seen during snapshot loading. Includes duplicates. Resets if snapshot load restarts |
| <span class="metrics-name">snapin_&#8203;account_&#8203;replaced</span> | gauge | Previously inserted accounts replaced by a later duplicate. Resets if snapshot load restarts |
| <span class="metrics-name">snapin_&#8203;account_&#8203;ignored</span> | gauge | Stale duplicate accounts dropped because a previously inserted account was newer. Resets if snapshot load restarts |
| <span class="metrics-name">snapin_&#8203;account_&#8203;processed</span> | counter | Accounts processed across all snapshots (inserted or otherwise) |
| <span class="metrics-name">snapin_&#8203;account_&#8203;batch_&#8203;processed</span> | counter | Account batches processed across all snapshots (parallelism indicator) |

</div>

## Snapwr Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">snapwr_&#8203;full_&#8203;bytes_&#8203;read</span> | gauge | Number of decompressed snapshot bytes consumed from the full snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapwr_&#8203;incremental_&#8203;bytes_&#8203;read</span> | gauge | Number of decompressed snapshot bytes consumed from the incremental snapshot. Might decrease if snapshot load is aborted and restarted |
| <span class="metrics-name">snapwr_&#8203;bytes_&#8203;written</span> | gauge | Number of bytes written to the accounts database on disk. Monotonically increasing across snapshot loads. |
| <span class="metrics-name">snapwr_&#8203;accounts_&#8203;written</span> | gauge | Number of accounts written to the accounts database on disk. Might decrease if snapshot load is aborted and restarted |

</div>

## Netlnk Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">netlnk_&#8203;event_&#8203;dropped</span> | counter | Netlink drop events caught |
| <span class="metrics-name">netlnk_&#8203;link_&#8203;full_&#8203;sync</span> | counter | Full link table syncs done |
| <span class="metrics-name">netlnk_&#8203;route_&#8203;full_&#8203;sync</span> | counter | Full route table syncs done |
| <span class="metrics-name">netlnk_&#8203;update_&#8203;processed</span><br/>{netlink_&#8203;message="<span class="metrics-enum">link</span>"} | counter | Netlink live updates processed (Link) |
| <span class="metrics-name">netlnk_&#8203;update_&#8203;processed</span><br/>{netlink_&#8203;message="<span class="metrics-enum">neighbor</span>"} | counter | Netlink live updates processed (Neighbor Table Entry) |
| <span class="metrics-name">netlnk_&#8203;update_&#8203;processed</span><br/>{netlink_&#8203;message="<span class="metrics-enum">ipv4_&#8203;route</span>"} | counter | Netlink live updates processed (IPv4 Route Table Entry) |
| <span class="metrics-name">netlnk_&#8203;interface_&#8203;count</span> | gauge | Network interfaces |
| <span class="metrics-name">netlnk_&#8203;route_&#8203;count</span><br/>{route_&#8203;table="<span class="metrics-enum">local</span>"} | gauge | IPv4 routes (Local) |
| <span class="metrics-name">netlnk_&#8203;route_&#8203;count</span><br/>{route_&#8203;table="<span class="metrics-enum">main</span>"} | gauge | IPv4 routes (Main) |
| <span class="metrics-name">netlnk_&#8203;neighbor_&#8203;probe_&#8203;sent</span> | counter | Neighbor solicit requests sent to kernel |
| <span class="metrics-name">netlnk_&#8203;neighbor_&#8203;probe_&#8203;failed</span> | counter | Neighbor solicit requests that failed to send (kernel too slow) |
| <span class="metrics-name">netlnk_&#8203;neighbor_&#8203;probe_&#8203;rate_&#8203;limit_&#8203;host</span> | counter | Neighbor solicit requests that exceeded the per-host rate limit |
| <span class="metrics-name">netlnk_&#8203;neighbor_&#8203;probe_&#8203;rate_&#8203;limit_&#8203;global</span> | counter | Neighbor solicit requests that exceeded the global rate limit |

</div>

## Net Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">net_&#8203;pkt_&#8203;rx</span> | counter | Packets received |
| <span class="metrics-name">net_&#8203;pkt_&#8203;rx_&#8203;bytes</span> | counter | Bytes received (including Ethernet header) |
| <span class="metrics-name">net_&#8203;pkt_&#8203;rx_&#8203;undersize</span> | counter | Incoming packets dropped due to being too small |
| <span class="metrics-name">net_&#8203;pkt_&#8203;rx_&#8203;fill_&#8203;ring_&#8203;full</span> | counter | Incoming packets dropped due to fill ring being full |
| <span class="metrics-name">net_&#8203;pkt_&#8203;rx_&#8203;backpressure</span> | counter | Incoming packets dropped due to backpressure |
| <span class="metrics-name">net_&#8203;rx_&#8203;buffer_&#8203;busy</span> | gauge | Receive buffers currently busy |
| <span class="metrics-name">net_&#8203;rx_&#8203;buffer_&#8203;idle</span> | gauge | Receive buffers currently idle |
| <span class="metrics-name">net_&#8203;pkt_&#8203;tx_&#8203;submitted</span> | counter | Packet transmit jobs submitted |
| <span class="metrics-name">net_&#8203;pkt_&#8203;tx_&#8203;completed</span> | counter | Packet transmit jobs marked as completed by the kernel |
| <span class="metrics-name">net_&#8203;pkt_&#8203;tx_&#8203;bytes</span> | counter | Bytes transmitted (including Ethernet header) |
| <span class="metrics-name">net_&#8203;pkt_&#8203;tx_&#8203;no_&#8203;route</span> | counter | Packet transmit jobs dropped due to route failure |
| <span class="metrics-name">net_&#8203;pkt_&#8203;tx_&#8203;no_&#8203;neighbor</span> | counter | Packet transmit jobs dropped due to unresolved neighbor |
| <span class="metrics-name">net_&#8203;pkt_&#8203;tx_&#8203;ring_&#8203;full</span> | counter | Packet transmit jobs dropped due to XDP TX ring full or missing completions |
| <span class="metrics-name">net_&#8203;tx_&#8203;buffer_&#8203;busy</span> | gauge | Transmit buffers currently busy |
| <span class="metrics-name">net_&#8203;tx_&#8203;buffer_&#8203;idle</span> | gauge | Transmit buffers currently idle |
| <span class="metrics-name">net_&#8203;xsk_&#8203;syscall_&#8203;tx</span> | counter | XSK sendto syscalls dispatched |
| <span class="metrics-name">net_&#8203;xsk_&#8203;syscall_&#8203;rx</span> | counter | XSK recvmsg syscalls dispatched |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;other_&#8203;dropped</span> | counter | Dropped for other reasons (xdp_statistics_v0.rx_dropped) |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;invalid_&#8203;descriptor</span> | counter | Dropped due to invalid descriptor (xdp_statistics_v0.rx_invalid_descs) |
| <span class="metrics-name">net_&#8203;xdp_&#8203;tx_&#8203;invalid_&#8203;descriptor</span> | counter | Dropped due to invalid descriptor (xdp_statistics_v0.tx_invalid_descs) |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;ring_&#8203;full</span> | counter | Dropped due to rx ring being full (xdp_statistics_v1.rx_ring_full) |
| <span class="metrics-name">net_&#8203;xdp_&#8203;rx_&#8203;fill_&#8203;ring_&#8203;empty</span> | counter | Failed to retrieve item from fill ring because it was empty (xdp_statistics_v1.rx_fill_ring_empty_descs) |
| <span class="metrics-name">net_&#8203;xdp_&#8203;tx_&#8203;ring_&#8203;empty</span> | counter | Failed to retrieve item from tx ring because it was empty (xdp_statistics_v1.tx_ring_empty_descs) |
| <span class="metrics-name">net_&#8203;gre_&#8203;pkt_&#8203;rx</span> | counter | Valid GRE packets received |
| <span class="metrics-name">net_&#8203;gre_&#8203;pkt_&#8203;rx_&#8203;invalid</span> | counter | Invalid GRE packets received |
| <span class="metrics-name">net_&#8203;gre_&#8203;pkt_&#8203;rx_&#8203;ignored</span> | counter | GRE packets received but ignored |
| <span class="metrics-name">net_&#8203;gre_&#8203;pkt_&#8203;tx_&#8203;submitted</span> | counter | GRE packet transmit jobs submitted |
| <span class="metrics-name">net_&#8203;gre_&#8203;pkt_&#8203;tx_&#8203;no_&#8203;route</span> | counter | GRE packet transmit jobs dropped due to route failure |
| <span class="metrics-name">net_&#8203;pkt_&#8203;rx_&#8203;src_&#8203;invalid</span> | counter | Incoming packets dropped due to invalid source IP address |

</div>

## Sock Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">sock_&#8203;syscall_&#8203;tx</span><br/>{socket_&#8203;error="<span class="metrics-enum">no_&#8203;error</span>"} | counter | sendmmsg syscalls dispatched (No error) |
| <span class="metrics-name">sock_&#8203;syscall_&#8203;tx</span><br/>{socket_&#8203;error="<span class="metrics-enum">slow</span>"} | counter | sendmmsg syscalls dispatched (ENOBUFS, EAGAIN error) |
| <span class="metrics-name">sock_&#8203;syscall_&#8203;tx</span><br/>{socket_&#8203;error="<span class="metrics-enum">permission</span>"} | counter | sendmmsg syscalls dispatched (EPERM error (blocked by netfilter)) |
| <span class="metrics-name">sock_&#8203;syscall_&#8203;tx</span><br/>{socket_&#8203;error="<span class="metrics-enum">unreachable</span>"} | counter | sendmmsg syscalls dispatched (ENETUNREACH, EHOSTUNREACH error) |
| <span class="metrics-name">sock_&#8203;syscall_&#8203;tx</span><br/>{socket_&#8203;error="<span class="metrics-enum">down</span>"} | counter | sendmmsg syscalls dispatched (ENONET, ENETDOWN, EHOSTDOWN error) |
| <span class="metrics-name">sock_&#8203;syscall_&#8203;tx</span><br/>{socket_&#8203;error="<span class="metrics-enum">other</span>"} | counter | sendmmsg syscalls dispatched (Unrecognized error code) |
| <span class="metrics-name">sock_&#8203;syscall_&#8203;rx</span> | counter | recvmmsg syscalls dispatched |
| <span class="metrics-name">sock_&#8203;pkt_&#8203;rx</span> | counter | Packets received |
| <span class="metrics-name">sock_&#8203;pkt_&#8203;tx</span> | counter | Packets sent |
| <span class="metrics-name">sock_&#8203;pkt_&#8203;tx_&#8203;failed</span> | counter | Packets that failed to send |
| <span class="metrics-name">sock_&#8203;pkt_&#8203;tx_&#8203;bytes</span> | counter | Bytes transmitted (including Ethernet header) |
| <span class="metrics-name">sock_&#8203;pkt_&#8203;rx_&#8203;bytes</span> | counter | Bytes received (including Ethernet header) |

</div>

## Quic Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">quic_&#8203;txn_&#8203;overrun</span> | counter | Txns overrun before reassembled (too small txn_reassembly_count) |
| <span class="metrics-name">quic_&#8203;txn_&#8203;reassembly_&#8203;started</span> | counter | Fragmented txn receive ops started |
| <span class="metrics-name">quic_&#8203;txn_&#8203;reassembly_&#8203;active</span> | gauge | Fragmented txn receive ops currently active |
| <span class="metrics-name">quic_&#8203;frag_&#8203;rx</span> | counter | Txn frags received |
| <span class="metrics-name">quic_&#8203;frag_&#8203;gap</span> | counter | Txn frags dropped due to data gap |
| <span class="metrics-name">quic_&#8203;frag_&#8203;duplicate</span> | counter | Txn frags dropped due to duplicate (stream already completed) |
| <span class="metrics-name">quic_&#8203;txn_&#8203;rx</span><br/>{tpu_&#8203;rx_&#8203;type="<span class="metrics-enum">udp</span>"} | counter | Txns received via TPU (TPU/UDP) |
| <span class="metrics-name">quic_&#8203;txn_&#8203;rx</span><br/>{tpu_&#8203;rx_&#8203;type="<span class="metrics-enum">quic_&#8203;fast</span>"} | counter | Txns received via TPU (TPU/QUIC unfragmented) |
| <span class="metrics-name">quic_&#8203;txn_&#8203;rx</span><br/>{tpu_&#8203;rx_&#8203;type="<span class="metrics-enum">quic_&#8203;frag</span>"} | counter | Txns received via TPU (TPU/QUIC fragmented) |
| <span class="metrics-name">quic_&#8203;txn_&#8203;abandoned</span> | counter | Txns abandoned because a connection was lost |
| <span class="metrics-name">quic_&#8203;txn_&#8203;undersize</span> | counter | Txns received via QUIC dropped because they were too small |
| <span class="metrics-name">quic_&#8203;txn_&#8203;oversize</span> | counter | Txns received via QUIC dropped because they were too large |
| <span class="metrics-name">quic_&#8203;legacy_&#8203;txn_&#8203;undersize</span> | counter | Packets received on the non-QUIC port that were too small to be a valid IP packet |
| <span class="metrics-name">quic_&#8203;legacy_&#8203;txn_&#8203;oversize</span> | counter | Packets received on the non-QUIC port that were too large to be a valid transaction |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;rx</span> | counter | IP packets received |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;rx_&#8203;bytes</span> | counter | Bytes received (including IP, UDP, QUIC headers) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx</span> | counter | IP packets sent |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;bytes</span> | counter | Bytes sent (including IP, UDP, QUIC headers) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;in_&#8203;use</span> | gauge | QUIC connection slots currently in use (allocated from connection create until free, including handshaking connections) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">invalid</span>"} | gauge | QUIC connections in each state (Freed) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake</span>"} | gauge | QUIC connections in each state (Handshaking peer) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake_&#8203;complete</span>"} | gauge | QUIC connections in each state (Handshake complete, confirming with peer) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">active</span>"} | gauge | QUIC connections in each state (Active connection) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">peer_&#8203;close</span>"} | gauge | QUIC connections in each state (Peer requested close) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">abort</span>"} | gauge | QUIC connections in each state (Connection terminating due to error) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">close_&#8203;pending</span>"} | gauge | QUIC connections in each state (Connection is closing) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">dead</span>"} | gauge | QUIC connections in each state (Connection about to be freed) |
| <span class="metrics-name">quic_&#8203;conn_&#8203;created</span> | counter | Connections created |
| <span class="metrics-name">quic_&#8203;conn_&#8203;closed</span> | counter | Connections gracefully closed |
| <span class="metrics-name">quic_&#8203;conn_&#8203;aborted</span> | counter | Connections aborted |
| <span class="metrics-name">quic_&#8203;conn_&#8203;timed_&#8203;out</span> | counter | Connections timed out |
| <span class="metrics-name">quic_&#8203;conn_&#8203;retried</span> | counter | Connections established with retry |
| <span class="metrics-name">quic_&#8203;conn_&#8203;error_&#8203;no_&#8203;slots</span> | counter | Connections that failed to create due to lack of slots |
| <span class="metrics-name">quic_&#8203;conn_&#8203;error_&#8203;retry_&#8203;failed</span> | counter | Connections that failed during retry (e.g. invalid token) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">initial</span>"} | counter | Packets with an unknown connection ID (Initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">retry</span>"} | counter | Packets with an unknown connection ID (Retry) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">handshake</span>"} | counter | Packets with an unknown connection ID (Handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">one_&#8203;rtt</span>"} | counter | Packets with an unknown connection ID (1-RTT) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;src_&#8203;invalid</span> | counter | Packets dropped due to a wrong source IP |
| <span class="metrics-name">quic_&#8203;frame_&#8203;meta_&#8203;acquired</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Attempts to acquire QUIC frame metadata (Success) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;meta_&#8203;acquired</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;empty_&#8203;pool</span>"} | counter | Attempts to acquire QUIC frame metadata (PktMetaPoolEmpty) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;meta_&#8203;acquired</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;connection_&#8203;max</span>"} | counter | Attempts to acquire QUIC frame metadata (ConnMaxedInflightFrames) |
| <span class="metrics-name">quic_&#8203;initial_&#8203;pkt_&#8203;rx</span><br/>{quic_&#8203;initial_&#8203;token_&#8203;length="<span class="metrics-enum">zero</span>"} | counter | Initial packets grouped by token length (No token) |
| <span class="metrics-name">quic_&#8203;initial_&#8203;pkt_&#8203;rx</span><br/>{quic_&#8203;initial_&#8203;token_&#8203;length="<span class="metrics-enum">fd_&#8203;quic_&#8203;length</span>"} | counter | Initial packets grouped by token length (fd_quic retry token length) |
| <span class="metrics-name">quic_&#8203;initial_&#8203;pkt_&#8203;rx</span><br/>{quic_&#8203;initial_&#8203;token_&#8203;length="<span class="metrics-enum">invalid_&#8203;length</span>"} | counter | Initial packets grouped by token length (Invalid token length) |
| <span class="metrics-name">quic_&#8203;handshake_&#8203;created</span> | counter | Handshake flows created |
| <span class="metrics-name">quic_&#8203;handshake_&#8203;error_&#8203;alloc_&#8203;fail</span> | counter | Handshakes dropped due to alloc fail |
| <span class="metrics-name">quic_&#8203;handshake_&#8203;evicted</span> | counter | Handshakes dropped due to eviction |
| <span class="metrics-name">quic_&#8203;stream_&#8203;rx</span> | counter | Stream receive events |
| <span class="metrics-name">quic_&#8203;stream_&#8203;rx_&#8203;bytes</span> | counter | Stream payload bytes received |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">unknown</span>"} | counter | QUIC frames received (Unknown frame type) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ack</span>"} | counter | QUIC frames received (ACK frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">reset_&#8203;stream</span>"} | counter | QUIC frames received (RESET_STREAM frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stop_&#8203;sending</span>"} | counter | QUIC frames received (STOP_SENDING frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">crypto</span>"} | counter | QUIC frames received (CRYPTO frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;token</span>"} | counter | QUIC frames received (NEW_TOKEN frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream</span>"} | counter | QUIC frames received (STREAM frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;data</span>"} | counter | QUIC frames received (MAX_DATA frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;stream_&#8203;data</span>"} | counter | QUIC frames received (MAX_STREAM_DATA frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;streams</span>"} | counter | QUIC frames received (MAX_STREAMS frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">data_&#8203;blocked</span>"} | counter | QUIC frames received (DATA_BLOCKED frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream_&#8203;data_&#8203;blocked</span>"} | counter | QUIC frames received (STREAM_DATA_BLOCKED frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">streams_&#8203;blocked</span>"} | counter | QUIC frames received (STREAMS_BLOCKED(bidi) frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;connection_&#8203;id</span>"} | counter | QUIC frames received (NEW_CONN_ID frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">retire_&#8203;connection_&#8203;id</span>"} | counter | QUIC frames received (RETIRE_CONN_ID frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;challenge</span>"} | counter | QUIC frames received (PATH_CHALLENGE frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;response</span>"} | counter | QUIC frames received (PATH_RESPONSE frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">connection_&#8203;close_&#8203;quic</span>"} | counter | QUIC frames received (CONN_CLOSE(transport) frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">connection_&#8203;close_&#8203;app</span>"} | counter | QUIC frames received (CONN_CLOSE(app) frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">handshake_&#8203;done</span>"} | counter | QUIC frames received (HANDSHAKE_DONE frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ping</span>"} | counter | QUIC frames received (PING frame) |
| <span class="metrics-name">quic_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">padding</span>"} | counter | QUIC frames received (PADDING frame) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">noop</span>"} | counter | ACK events (Non-ACK-eliciting packet) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">new</span>"} | counter | ACK events (New ACK range) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">merged</span>"} | counter | ACK events (Merged into existing ACK range) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">drop</span>"} | counter | ACK events (Out of buffers) |
| <span class="metrics-name">quic_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">cancel</span>"} | counter | ACK events (ACK suppressed by handler) |
| <span class="metrics-name">quic_&#8203;service_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent in service |
| <span class="metrics-name">quic_&#8203;rx_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent processing packets |
| <span class="metrics-name">quic_&#8203;frame_&#8203;parse_&#8203;failed</span> | counter | QUIC frames that failed to parse |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Packets that failed decryption (Initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Packets that failed decryption (Early data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Packets that failed decryption (Handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Packets that failed decryption (App data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Packets that failed decryption due to missing key (Initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Packets that failed decryption due to missing key (Early data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Packets that failed decryption due to missing key (Handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Packets that failed decryption due to missing key (App data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;net_&#8203;header_&#8203;invalid</span> | counter | Packets dropped due to weird IP or UDP header |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;header_&#8203;invalid</span> | counter | Packets dropped due to weird QUIC header |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;undersize</span> | counter | QUIC packets dropped due to being too small |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;oversize</span> | counter | QUIC packets dropped due to being too large |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;rx_&#8203;version_&#8203;negotiation</span> | counter | QUIC version negotiation packets received |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;retry</span> | counter | QUIC Retry packets sent |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | QUIC packets retransmitted (Initial) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">early</span>"} | counter | QUIC packets retransmitted (Early data) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | QUIC packets retransmitted (Handshake) |
| <span class="metrics-name">quic_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">app</span>"} | counter | QUIC packets retransmitted (App data) |

</div>

## Bundle Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">bundle_&#8203;txn_&#8203;rx</span> | counter | Transactions received, including transactions within bundles |
| <span class="metrics-name">bundle_&#8203;pkt_&#8203;rx</span> | counter | Packets received |
| <span class="metrics-name">bundle_&#8203;protobuf_&#8203;rx_&#8203;bytes</span> | counter | Bytes from received gRPC protobuf payloads |
| <span class="metrics-name">bundle_&#8203;bundle_&#8203;rx</span> | counter | Bundles received |
| <span class="metrics-name">bundle_&#8203;conn_&#8203;error</span><br/>{bundle_&#8203;error="<span class="metrics-enum">protobuf</span>"} | counter | gRPC errors encountered (Protobuf decode/encode error) |
| <span class="metrics-name">bundle_&#8203;conn_&#8203;error</span><br/>{bundle_&#8203;error="<span class="metrics-enum">transport</span>"} | counter | gRPC errors encountered (Transport error) |
| <span class="metrics-name">bundle_&#8203;conn_&#8203;error</span><br/>{bundle_&#8203;error="<span class="metrics-enum">timeout</span>"} | counter | gRPC errors encountered (I/O timeout) |
| <span class="metrics-name">bundle_&#8203;conn_&#8203;error</span><br/>{bundle_&#8203;error="<span class="metrics-enum">no_&#8203;fee_&#8203;info</span>"} | counter | gRPC errors encountered (Bundle dropped due to missing fee info) |
| <span class="metrics-name">bundle_&#8203;conn_&#8203;error</span><br/>{bundle_&#8203;error="<span class="metrics-enum">ssl_&#8203;alloc</span>"} | counter | gRPC errors encountered (OpenSSL alloc fail) |
| <span class="metrics-name">bundle_&#8203;heap_&#8203;size_&#8203;bytes</span> | gauge | Workspace heap size |
| <span class="metrics-name">bundle_&#8203;heap_&#8203;free_&#8203;bytes</span> | gauge | Approximate free space in workspace |
| <span class="metrics-name">bundle_&#8203;shredstream_&#8203;heartbeat_&#8203;sent</span> | counter | ShredStream heartbeats successfully sent |
| <span class="metrics-name">bundle_&#8203;ping_&#8203;acked</span> | counter | HTTP/2 PINGs acknowledged by server |
| <span class="metrics-name">bundle_&#8203;state</span> | gauge | 0=disconnected, 1=connecting, 2=connected, 3=sleeping |
| <span class="metrics-name">bundle_&#8203;rtt_&#8203;sample_&#8203;nanos</span> | gauge | Latest RTT sample at scrape time, in nanoseconds |
| <span class="metrics-name">bundle_&#8203;rtt_&#8203;smoothed_&#8203;nanos</span> | gauge | RTT moving average, in nanoseconds |
| <span class="metrics-name">bundle_&#8203;rtt_&#8203;variance_&#8203;nanos</span> | gauge | RTT variance, in nanoseconds |
| <span class="metrics-name">bundle_&#8203;message_&#8203;rx_&#8203;delay_&#8203;nanos</span> | histogram | Message receive delay from bundle server to bundle client, in nanoseconds |
| <span class="metrics-name">bundle_&#8203;txn_&#8203;pending</span> | gauge | Transactions buffered and waiting to be published |
| <span class="metrics-name">bundle_&#8203;txn_&#8203;buffer_&#8203;full</span> | counter | Transactions dropped because the pending transaction buffer was full (should never happen) |

</div>

## Verify Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">verify_&#8203;txn_&#8203;result</span><br/>{verify_&#8203;tile_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Transaction results through verify tile (Transaction verified successfully) |
| <span class="metrics-name">verify_&#8203;txn_&#8203;result</span><br/>{verify_&#8203;tile_&#8203;result="<span class="metrics-enum">bundle_&#8203;peer_&#8203;failure</span>"} | counter | Transaction results through verify tile (Peer transaction in the bundle failed) |
| <span class="metrics-name">verify_&#8203;txn_&#8203;result</span><br/>{verify_&#8203;tile_&#8203;result="<span class="metrics-enum">parse_&#8203;failure</span>"} | counter | Transaction results through verify tile (Transaction failed to parse) |
| <span class="metrics-name">verify_&#8203;txn_&#8203;result</span><br/>{verify_&#8203;tile_&#8203;result="<span class="metrics-enum">dedup_&#8203;failure</span>"} | counter | Transaction results through verify tile (Transaction failed deduplication) |
| <span class="metrics-name">verify_&#8203;txn_&#8203;result</span><br/>{verify_&#8203;tile_&#8203;result="<span class="metrics-enum">verify_&#8203;failure</span>"} | counter | Transaction results through verify tile (Transaction failed signature verification) |
| <span class="metrics-name">verify_&#8203;vote_&#8203;gossip_&#8203;rx</span> | counter | Simple vote transactions received over gossip instead of via the normal TPU path |

</div>

## Dedup Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">dedup_&#8203;txn_&#8203;result</span><br/>{dedup_&#8203;tile_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Transaction results through dedup tile (Transaction deduplicated successfully) |
| <span class="metrics-name">dedup_&#8203;txn_&#8203;result</span><br/>{dedup_&#8203;tile_&#8203;result="<span class="metrics-enum">bundle_&#8203;peer_&#8203;failure</span>"} | counter | Transaction results through dedup tile (Peer transaction in the bundle failed) |
| <span class="metrics-name">dedup_&#8203;txn_&#8203;result</span><br/>{dedup_&#8203;tile_&#8203;result="<span class="metrics-enum">dedup_&#8203;failure</span>"} | counter | Transaction results through dedup tile (Transaction failed deduplication) |
| <span class="metrics-name">dedup_&#8203;vote_&#8203;gossip_&#8203;rx</span> | counter | Simple vote transactions received over gossip instead of via the normal TPU path |

</div>

## Resolv Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">resolv_&#8203;txn_&#8203;no_&#8203;bank</span> | counter | Transactions dropped because the bank was not available |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">inserted</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was added to the stash) |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">overrun</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was dropped because the stash was full) |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">published</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was published as the blockhash became known) |
| <span class="metrics-name">resolv_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">removed</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was removed from the stash without publishing, due to a bad LUT resolved failure, or no bank. These errors are double counted with the respective metrics for those categories) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;lookup_&#8203;index</span>"} | counter | Address lookup tables resolved (The transaction referenced an index in a LUT that didn't exist) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;uninitialized</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT hasn't been initialized) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT couldn't be parsed) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT wasn't owned by the ALUT program ID) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT couldn't be found) |
| <span class="metrics-name">resolv_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Address lookup tables resolved (Resolved successfully) |
| <span class="metrics-name">resolv_&#8203;blockhash_&#8203;expired</span> | counter | Transactions that failed to resolve because the blockhash was expired |
| <span class="metrics-name">resolv_&#8203;txn_&#8203;bundle_&#8203;peer_&#8203;failed</span> | counter | Transactions that failed to resolve because a peer transaction in the bundle failed |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts read from the account database (one per address lookup table account fetched), attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (0-128 B) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (129-512 B) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;account_&#8203;waited</span> | counter | Number of accounts that had to wait for a concurrent writer to publish a disk offset before being read |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;batch_&#8203;acquired</span> | counter | Number of fd_accdb_acquire (batch acquire) calls made by this tile |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;read_&#8203;operation</span> | counter | Number of read operations performed on the account database |
| <span class="metrics-name">resolv_&#8203;accdb_&#8203;bytes_&#8203;copied</span> | counter | Number of bytes copied out of the account database cache on a cache hit |

</div>

## Pack Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">pack_&#8203;schedule_&#8203;microblock_&#8203;duration_&#8203;seconds</span> | histogram | Duration of scheduling one microblock |
| <span class="metrics-name">pack_&#8203;no_&#8203;schedule_&#8203;microblock_&#8203;duration_&#8203;seconds</span> | histogram | Duration of discovering that there are no schedulable transactions |
| <span class="metrics-name">pack_&#8203;insert_&#8203;transaction_&#8203;duration_&#8203;seconds</span> | histogram | Duration of inserting one transaction into the pool of available transactions |
| <span class="metrics-name">pack_&#8203;complete_&#8203;microblock_&#8203;duration_&#8203;seconds</span> | histogram | Duration of the computation associated with marking one microblock as complete |
| <span class="metrics-name">pack_&#8203;txn_&#8203;per_&#8203;microblock</span> | histogram | Transactions in a scheduled microblock, including both votes and non-votes |
| <span class="metrics-name">pack_&#8203;vote_&#8203;per_&#8203;microblock</span> | histogram | Simple vote transactions in a scheduled microblock |
| <span class="metrics-name">pack_&#8203;txn_&#8203;normal_&#8203;rx</span> | counter | Transactions received via the normal TPU path |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">instr_&#8203;acct_&#8203;cnt</span>"} | counter | Result of inserting a transaction into the pack object (Transaction has an instruction that references too many accounts) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;conflict</span>"} | counter | Result of inserting a transaction into the pack object (Bundle with two conflicting durable nonce transactions) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">acct_&#8203;blocklist</span>"} | counter | Result of inserting a transaction into the pack object (Transaction uses an account on the account blocklist) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">bundle_&#8203;blacklist</span>"} | counter | Result of inserting a transaction into the pack object (Transaction is a vote in a bundle or uses an account on the bundle blacklist) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">invalid_&#8203;nonce</span>"} | counter | Result of inserting a transaction into the pack object (Transaction is an invalid durable nonce transaction) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">write_&#8203;sysvar</span>"} | counter | Result of inserting a transaction into the pack object (Transaction tries to write to a sysvar) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">estimation_&#8203;fail</span>"} | counter | Result of inserting a transaction into the pack object (Estimating compute cost and/or fee failed) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">duplicate_&#8203;account</span>"} | counter | Result of inserting a transaction into the pack object (Transaction included an account address twice) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">too_&#8203;many_&#8203;accounts</span>"} | counter | Result of inserting a transaction into the pack object (Transaction tried to load too many accounts) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">too_&#8203;large</span>"} | counter | Result of inserting a transaction into the pack object (Transaction requests too many CUs) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">expired</span>"} | counter | Result of inserting a transaction into the pack object (Transaction already expired) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">addr_&#8203;lut</span>"} | counter | Result of inserting a transaction into the pack object (Transaction loaded accounts from a lookup table) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">unaffordable</span>"} | counter | Result of inserting a transaction into the pack object (Fee payer's balance below transaction fee) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">duplicate</span>"} | counter | Result of inserting a transaction into the pack object (Pack aware of transaction with same signature) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;priority</span>"} | counter | Result of inserting a transaction into the pack object (Transaction's fee was too low given its compute unit requirement and another competing transactions that uses the same durable nonce) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">priority</span>"} | counter | Result of inserting a transaction into the pack object (Transaction's fee was too low given its compute unit requirement and other competing transactions) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonvote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Transaction that was not a simple vote added to pending transactions) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">vote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Simple vote transaction was added to pending transactions) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonvote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Transaction that was not a simple vote replaced a lower priority transaction) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">vote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Simple vote transaction replaced a lower priority transaction) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;nonvote_&#8203;add</span>"} | counter | Result of inserting a transaction into the pack object (Durable nonce transaction added to pending transactions) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">unused</span>"} | counter | Result of inserting a transaction into the pack object (Unused because durable nonce transactions can't be simple votes) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;inserted</span><br/>{pack_&#8203;txn_&#8203;insert_&#8203;return="<span class="metrics-enum">nonce_&#8203;nonvote_&#8203;replace</span>"} | counter | Result of inserting a transaction into the pack object (Durable nonce transaction replaced a lower priority transaction, likely one that uses the same durable nonce) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;execle_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: not leader, no transactions, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;execle_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: not leader, transactions available, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;execle_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: not leader, no transactions, execle available) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;execle_&#8203;no_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: not leader, transactions available, execle available) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;execle_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: leader, no transactions, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;execle_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: leader, transactions available, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;execle_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: leader, no transactions, execle available) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;execle_&#8203;leader_&#8203;no_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (No microblock: leader, transactions available, execle available (all conflicting)) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;execle_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: not leader, no transactions, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;execle_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: not leader, transactions available, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;execle_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: not leader, no transactions, execle available) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;execle_&#8203;no_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: not leader, transactions available, execle available) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;no_&#8203;execle_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: leader, no transactions, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;no_&#8203;execle_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: leader, transactions available, no available execle) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">no_&#8203;txn_&#8203;execle_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: leader, no transactions, execle available) |
| <span class="metrics-name">pack_&#8203;state_&#8203;duration_&#8203;nanos</span><br/>{pack_&#8203;timing_&#8203;state="<span class="metrics-enum">txn_&#8203;execle_&#8203;leader_&#8203;microblock</span>"} | counter | Time spent in each state, in nanoseconds (Scheduled a microblock: leader, transactions available, execle available) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;extra_&#8203;dropped</span> | counter | Transactions dropped from the extra transaction storage because it was full |
| <span class="metrics-name">pack_&#8203;txn_&#8203;extra_&#8203;inserted</span> | counter | Transactions inserted into the extra transaction storage because pack's primary storage was full |
| <span class="metrics-name">pack_&#8203;txn_&#8203;extra_&#8203;retrieved</span> | counter | Transactions pulled from the extra transaction storage and inserted into pack's primary storage |
| <span class="metrics-name">pack_&#8203;txn_&#8203;expired</span> | counter | Transactions deleted from pack because their TTL expired |
| <span class="metrics-name">pack_&#8203;txn_&#8203;deleted</span> | counter | Transactions dropped from pack because they were requested to be deleted |
| <span class="metrics-name">pack_&#8203;txn_&#8203;already_&#8203;executed</span> | counter | Transactions dropped from pack because they were already executed (in either the replay or leader pipeline) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;partial_&#8203;bundle</span> | counter | Transactions dropped from pack because they were part of a partial bundle |
| <span class="metrics-name">pack_&#8203;txn_&#8203;available</span><br/>{available_&#8203;txn_&#8203;type="<span class="metrics-enum">all</span>"} | gauge | Pending transactions in pack's pool that are available to be scheduled (All transactions in any treap) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;available</span><br/>{available_&#8203;txn_&#8203;type="<span class="metrics-enum">regular</span>"} | gauge | Pending transactions in pack's pool that are available to be scheduled (Non-votes in the main treap) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;available</span><br/>{available_&#8203;txn_&#8203;type="<span class="metrics-enum">votes</span>"} | gauge | Pending transactions in pack's pool that are available to be scheduled (Simple votes) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;available</span><br/>{available_&#8203;txn_&#8203;type="<span class="metrics-enum">conflicting</span>"} | gauge | Pending transactions in pack's pool that are available to be scheduled (Non-votes that write to a hotly-contended account) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;available</span><br/>{available_&#8203;txn_&#8203;type="<span class="metrics-enum">bundles</span>"} | gauge | Pending transactions in pack's pool that are available to be scheduled (Transactions that are part of a bundle) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;pending_&#8203;capacity</span> | gauge | Maximum number of pending transactions that pack can consider. Fixed at Firedancer startup but a useful reference for TxnAvailable |
| <span class="metrics-name">pack_&#8203;txn_&#8203;pending_&#8203;smallest_&#8203;cu</span> | gauge | Lower bound on the smallest non-vote transaction (in cost units) that is immediately available for scheduling |
| <span class="metrics-name">pack_&#8203;microblock_&#8203;per_&#8203;block_&#8203;limit_&#8203;reached</span> | counter | Times pack did not pack a microblock because the microblocks-per-block limit had been reached |
| <span class="metrics-name">pack_&#8203;data_&#8203;per_&#8203;block_&#8203;limit_&#8203;reached</span> | counter | Times pack did not pack a microblock because it reached the data per block limit at the start of trying to schedule a microblock |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">taken</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack included the transaction in the microblock) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">cu_&#8203;limit</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the block CU limit) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">fast_&#8203;path</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because of account conflicts using the fast bitvector check) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">byte_&#8203;limit</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the block data size limit) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">alloc_&#8203;limit</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have exceeded the data allocation limit) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">write_&#8203;cost</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because it would have caused a writable account to exceed the per-account block write cost limit) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">slow_&#8203;path</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction because of account conflicts using the full slow check) |
| <span class="metrics-name">pack_&#8203;txn_&#8203;scheduled</span><br/>{pack_&#8203;txn_&#8203;schedule="<span class="metrics-enum">defer_&#8203;skip</span>"} | counter | Result of trying to consider a transaction for scheduling (Pack skipped the transaction it previously exceeded the per-account block write cost limit too many times) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;result</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">not_&#8203;needed</span>"} | counter | Result of considering whether bundle cranks are needed (On-chain state in the correct state) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;result</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">inserted</span>"} | counter | Result of considering whether bundle cranks are needed (Inserted an initializer bundle to update the on-chain state) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;result</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">creation_&#8203;failed</span>"} | counter | Result of considering whether bundle cranks are needed (Tried to insert an initializer bundle to update the on-chain state, but creation failed) |
| <span class="metrics-name">pack_&#8203;bundle_&#8203;crank_&#8203;result</span><br/>{bundle_&#8203;crank_&#8203;result="<span class="metrics-enum">insertion_&#8203;failed</span>"} | counter | Result of considering whether bundle cranks are needed (Tried to insert an initializer bundle to update the on-chain state, but insertion failed) |
| <span class="metrics-name">pack_&#8203;block_&#8203;cu_&#8203;consumed</span> | gauge | Cost units consumed in the current block, or 0 if pack is not currently packing a block |
| <span class="metrics-name">pack_&#8203;cu_&#8203;scheduled_&#8203;per_&#8203;block</span> | histogram | Cost units scheduled for each block pack produced. Can be higher than the block limit because of returned CUs |
| <span class="metrics-name">pack_&#8203;cu_&#8203;rebated_&#8203;per_&#8203;block</span> | histogram | Compute units rebated for each block pack produced. Compute units are rebated when a transaction fails prior to execution or requests more compute units than it uses |
| <span class="metrics-name">pack_&#8203;cu_&#8203;net_&#8203;per_&#8203;block</span> | histogram | Net cost units (scheduled - rebated) in each block pack produced |
| <span class="metrics-name">pack_&#8203;cu_&#8203;pct</span> | histogram | Percent of the total block cost limit used for each block pack produced |
| <span class="metrics-name">pack_&#8203;txn_&#8203;delete_&#8203;missed</span> | counter | Attempts to delete a transaction that wasn't found |
| <span class="metrics-name">pack_&#8203;txn_&#8203;delete_&#8203;hit</span> | counter | Attempts to delete a transaction that was found and deleted |

</div>

## Execle Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of loading and executing a transaction (Transaction executed successfully) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">instruction_&#8203;error</span>"} | counter | Result of loading and executing a transaction (An error occurred while processing an instruction) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The transaction fee payer address was not found) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">program_&#8203;account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (A program account referenced by the transaction was not found) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (The transaction fee payer did not have balance to pay the fee) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (The transaction fee payer account is not owned by the system program, or has data that is not a nonce) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">already_&#8203;processed</span>"} | counter | Result of loading and executing a transaction (The transaction has already been processed in a recent block) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">blockhash_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The transaction references a blockhash that is not recent, or advances a nonce with the wrong value) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;program_&#8203;for_&#8203;execution</span>"} | counter | Result of loading and executing a transaction (A program account referenced by the transaction was no executable. TODO: No longer needed with SIMD-0162) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The transaction references an ALUT account that does not exist or is inactive) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner</span>"} | counter | Result of loading and executing a transaction (The transaction references an ALUT account that is not owned by the ALUT program account) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data</span>"} | counter | Result of loading and executing a transaction (The transaction references an ALUT account that contains data which is not a valid ALUT) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index</span>"} | counter | Result of loading and executing a transaction (The transaction references an account offset from the ALUT which does not exist) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded</span>"} | counter | Result of loading and executing a transaction (The total account data size of the loaded accounts exceeds the consensus limit) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">duplicate_&#8203;instruction</span>"} | counter | Result of loading and executing a transaction (A compute budget program instruction was invoked more than once) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (The compute budget program was invoked and set the loaded accounts data size to zero) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;already_&#8203;advanced</span>"} | counter | Result of loading and executing a transaction (The transaction references a nonce account that is already advanced) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;advance_&#8203;failed</span>"} | counter | Result of loading and executing a transaction (The transaction is a nonce transaction but the advance instruction was not valid or failed) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;wrong_&#8203;blockhash</span>"} | counter | Result of loading and executing a transaction (The transaction is a nonce transaction but the blockhash is not the correct one) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">sanitize_&#8203;failure</span>"} | counter | Result of loading and executing a transaction (The process for sanitizing the transaction failed) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;in_&#8203;use</span>"} | counter | Result of loading and executing a transaction (The transaction conflicts with another transaction in the microblock. TODO: No longer possible with smart dispatcher) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;loaded_&#8203;twice</span>"} | counter | Result of loading and executing a transaction (The transaction references the same account twice) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">signature_&#8203;failure</span>"} | counter | Result of loading and executing a transaction (The transaction had an invalid signature) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">too_&#8203;many_&#8203;account_&#8203;locks</span>"} | counter | Result of loading and executing a transaction (The transaction references too many accounts. TODO: No longer possible with smart dispatcher) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;rent</span>"} | counter | Result of loading and executing a transaction (The transaction would leave an account with a lower balance than the rent-exempt minimum) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">unbalanced_&#8203;transaction</span>"} | counter | Result of loading and executing a transaction (The total referenced account lamports before and after the transaction was unbalanced) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">bundle_&#8203;peer</span>"} | counter | Result of loading and executing a transaction (The transaction was part of a bundle and an earlier transaction in the bundle failed) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">landed_&#8203;success</span>"} | counter | Whether a transaction landed in the block or not (Transaction landed) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">landed_&#8203;fees_&#8203;only</span>"} | counter | Whether a transaction landed in the block or not (Transaction landed, but was fees only and did not execute) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">landed_&#8203;failed</span>"} | counter | Whether a transaction landed in the block or not (Transaction landed, but failed to execute) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;landed</span><br/>{transaction_&#8203;landed="<span class="metrics-enum">unlanded</span>"} | counter | Whether a transaction landed in the block or not (Transaction did not land) |
| <span class="metrics-name">execle_&#8203;cu_&#8203;executed</span> | counter | Estimated compute units executed since tile start |
| <span class="metrics-name">execle_&#8203;txn_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{txn_&#8203;regime="<span class="metrics-enum">setup</span>"} | counter | Mutually exclusive and exhaustive duration spent in transaction execution regimes, in nanoseconds (Transaction setup) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{txn_&#8203;regime="<span class="metrics-enum">exec</span>"} | counter | Mutually exclusive and exhaustive duration spent in transaction execution regimes, in nanoseconds (Transaction execution (includes VM setup/execution)) |
| <span class="metrics-name">execle_&#8203;txn_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{txn_&#8203;regime="<span class="metrics-enum">commit</span>"} | counter | Mutually exclusive and exhaustive duration spent in transaction execution regimes, in nanoseconds (Transaction result commit) |
| <span class="metrics-name">execle_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">setup</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM setup) |
| <span class="metrics-name">execle_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">commit</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM commit) |
| <span class="metrics-name">execle_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">setup_&#8203;cpi</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM setup (CPI)) |
| <span class="metrics-name">execle_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">commit_&#8203;cpi</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM commit (CPI)) |
| <span class="metrics-name">execle_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">interpreter</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM interpreter execution) |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;lookup</span> | counter | Program cache lookups |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;hit</span> | counter | Program cache hits |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;miss</span> | counter | Program cache misses |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;oom_&#8203;heap</span> | counter | Program cache out-of-memory events (heap) |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;oom_&#8203;desc</span> | counter | Program cache out-of-memory events (descriptor table) |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;fill</span> | counter | Program cache insertions |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;fill_&#8203;bytes</span> | counter | Bytes inserted into program cache |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;spill</span> | counter | Program cache spills (OOM fallback mechanism) |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;spill_&#8203;bytes</span> | counter | Bytes spilled from program cache (OOM fallback mechanism) |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;eviction</span> | counter | Program cache evictions |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;eviction_&#8203;bytes</span> | counter | Bytes evicted from program cache |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;duration_&#8203;seconds</span> | counter | Time spent on program cache operations, in seconds |
| <span class="metrics-name">execle_&#8203;progcache_&#8203;load_&#8203;duration_&#8203;seconds</span> | counter | Time spent loading programs, in seconds |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (0-128 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (129-512 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (0-128 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (129-512 B) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;account_&#8203;waited</span> | counter | Number of accounts that were needed for transaction execution but were concurrently loading into cache by another transaction, causing the transaction to wait |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;batch_&#8203;acquired</span> | counter | Number of fd_accdb_acquire (batch acquire) calls made by this tile |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;acquire_&#8203;failed</span> | counter | Number of times we failed to acquire the cache lines needed for a transaction, and had to spin loop waiting |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;read_&#8203;operation</span> | counter | Number of read operations performed on the account database |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;bytes_&#8203;written</span> | counter | Number of bytes written to the account database |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;write_&#8203;operation</span> | counter | Number of write operations performed on the account database |
| <span class="metrics-name">execle_&#8203;accdb_&#8203;bytes_&#8203;copied</span> | counter | Number of bytes copied within the account database |

</div>

## Poh Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|

</div>

## Sign Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">sign_&#8203;sign_&#8203;duration_&#8203;seconds</span> | histogram | Duration of signing a message |

</div>

## Shred Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">shred_&#8203;contact_&#8203;info_&#8203;per_&#8203;message</span> | histogram | Contact infos in the cluster contact info message |
| <span class="metrics-name">shred_&#8203;microblock_&#8203;abandoned</span> | counter | Microblocks abandoned because we switched slots without finishing the current slot |
| <span class="metrics-name">shred_&#8203;block_&#8203;id_&#8203;invalid</span> | counter | Times a block was created with unknown parent block_id |
| <span class="metrics-name">shred_&#8203;batch_&#8203;size_&#8203;bytes</span> | histogram | Size of each microblock batch that is shredded, in bytes |
| <span class="metrics-name">shred_&#8203;microblock_&#8203;per_&#8203;batch</span> | histogram | Microblocks in each microblock batch that is shredded |
| <span class="metrics-name">shred_&#8203;shredding_&#8203;duration_&#8203;seconds</span> | histogram | Duration of producing one FEC set from the shredder |
| <span class="metrics-name">shred_&#8203;add_&#8203;shred_&#8203;duration_&#8203;seconds</span> | histogram | Duration of verifying and processing one shred received from the network |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">bad_&#8203;slot</span>"} | counter | Result of processing a shred from the network (Shred was for a slot for which we don't know the leader) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">parse_&#8203;failed</span>"} | counter | Result of processing a shred from the network (Shred parsing failed) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">equivocated</span>"} | counter | Result of processing a shred from the network (Shred was equivocated with another shred) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">rejected</span>"} | counter | Result of processing a shred from the network (Shred was invalid for one of many reasons) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">ignored</span>"} | counter | Result of processing a shred from the network (Shred was ignored because we had already reconstructed the FEC set, or was for an old slot) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">duplicate</span>"} | counter | Result of processing a shred from the network (Shred was a duplicate of a previously received valid shred of an incomplete FEC set) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">okay</span>"} | counter | Result of processing a shred from the network (Shred accepted to an incomplete FEC set) |
| <span class="metrics-name">shred_&#8203;shred_&#8203;processed</span><br/>{shred_&#8203;processing_&#8203;result="<span class="metrics-enum">completes</span>"} | counter | Result of processing a shred from the network (Shred accepted and resulted in a valid, complete FEC set) |
| <span class="metrics-name">shred_&#8203;fec_&#8203;spilled</span> | counter | FEC sets spilled because they didn't complete in time and we needed space |
| <span class="metrics-name">shred_&#8203;shred_&#8203;initial_&#8203;rejected</span> | counter | Shreds rejected before any resources were allocated for the FEC set |
| <span class="metrics-name">shred_&#8203;shred_&#8203;unchained_&#8203;rejected</span> | counter | Shreds rejected because they're not chained merkle shreds |
| <span class="metrics-name">shred_&#8203;fec_&#8203;fatal_&#8203;rejected</span> | counter | FEC sets rejected for reasons that cause the whole FEC set to become invalid |
| <span class="metrics-name">shred_&#8203;nonce_&#8203;invalid</span> | counter | Shreds received that seemed to be repair responses but had an incorrect nonce |
| <span class="metrics-name">shred_&#8203;shred_&#8203;repair_&#8203;rx</span> | counter | Repair shreds received |
| <span class="metrics-name">shred_&#8203;shred_&#8203;repair_&#8203;rx_&#8203;bytes</span> | counter | Bytes received from network packets with repair shreds, including network headers |
| <span class="metrics-name">shred_&#8203;shred_&#8203;turbine_&#8203;rx</span> | counter | Turbine shreds received |
| <span class="metrics-name">shred_&#8203;shred_&#8203;turbine_&#8203;rx_&#8203;bytes</span> | counter | Bytes received from network packets with turbine shreds, including network headers |

</div>

## Gossvf Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;request</span>"} | counter | Gossip messages processed (Pull Request (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter | Gossip messages processed (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter | Gossip messages processed (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;prune</span>"} | counter | Gossip messages processed (Prune (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;ping</span>"} | counter | Gossip messages processed (Ping (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pong</span>"} | counter | Gossip messages processed (Pong (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;unparseable</span>"} | counter | Gossip messages processed (Unparseable) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;not_&#8203;contact_&#8203;info</span>"} | counter | Gossip messages processed (Pull Request (not contact info)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;loopback</span>"} | counter | Gossip messages processed (Pull Request (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;inactive</span>"} | counter | Gossip messages processed (Pull Request (inactive)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;wallclock</span>"} | counter | Gossip messages processed (Pull Request (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;signature</span>"} | counter | Gossip messages processed (Pull Request (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;shred_&#8203;version</span>"} | counter | Gossip messages processed (Pull Request (shred version)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;mask_&#8203;bits</span>"} | counter | Gossip messages processed (Pull Request (mask bits)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;destination</span>"} | counter | Gossip messages processed (Prune (destination)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;wallclock</span>"} | counter | Gossip messages processed (Prune (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;signature</span>"} | counter | Gossip messages processed (Prune (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;loopback</span>"} | counter | Gossip messages processed (Push (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter | Gossip messages processed (Push (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;loopback</span>"} | counter | Gossip messages processed (Pull Response (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter | Gossip messages processed (Pull Response (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;ping_&#8203;signature</span>"} | counter | Gossip messages processed (Ping (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pong_&#8203;signature</span>"} | counter | Gossip messages processed (Pong (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;request</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter | Wire bytes of gossip messages processed (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter | Wire bytes of gossip messages processed (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;prune</span>"} | counter | Wire bytes of gossip messages processed (Prune (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;ping</span>"} | counter | Wire bytes of gossip messages processed (Ping (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">success_&#8203;pong</span>"} | counter | Wire bytes of gossip messages processed (Pong (success)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;unparseable</span>"} | counter | Wire bytes of gossip messages processed (Unparseable) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;not_&#8203;contact_&#8203;info</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (not contact info)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;loopback</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;inactive</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (inactive)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;wallclock</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;signature</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;shred_&#8203;version</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (shred version)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;request_&#8203;mask_&#8203;bits</span>"} | counter | Wire bytes of gossip messages processed (Pull Request (mask bits)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;destination</span>"} | counter | Wire bytes of gossip messages processed (Prune (destination)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;wallclock</span>"} | counter | Wire bytes of gossip messages processed (Prune (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;prune_&#8203;signature</span>"} | counter | Wire bytes of gossip messages processed (Prune (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;loopback</span>"} | counter | Wire bytes of gossip messages processed (Push (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter | Wire bytes of gossip messages processed (Push (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;loopback</span>"} | counter | Wire bytes of gossip messages processed (Pull Response (loopback)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;no_&#8203;valid_&#8203;crds</span>"} | counter | Wire bytes of gossip messages processed (Pull Response (no valid crds)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;ping_&#8203;signature</span>"} | counter | Wire bytes of gossip messages processed (Ping (signature)) |
| <span class="metrics-name">gossvf_&#8203;message_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;message_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pong_&#8203;signature</span>"} | counter | Wire bytes of gossip messages processed (Pong (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter | CRDS values processed (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter | CRDS values processed (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;duplicate</span>"} | counter | CRDS values processed (Pull Response (duplicate)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;signature</span>"} | counter | CRDS values processed (Pull Response (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter | CRDS values processed (Pull Response (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter | CRDS values processed (Pull Response (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;inactive</span>"} | counter | CRDS values processed (Pull Response (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;wallclock</span>"} | counter | CRDS values processed (Pull Response (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;signature</span>"} | counter | CRDS values processed (Push (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter | CRDS values processed (Push (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter | CRDS values processed (Push (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;inactive</span>"} | counter | CRDS values processed (Push (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;wallclock</span>"} | counter | CRDS values processed (Push (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;pull_&#8203;response</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">success_&#8203;push</span>"} | counter | Wire bytes of CRDS values processed (Push (success)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;duplicate</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (duplicate)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;signature</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;inactive</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;wallclock</span>"} | counter | Wire bytes of CRDS values processed (Pull Response (wallclock)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;signature</span>"} | counter | Wire bytes of CRDS values processed (Push (signature)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;no_&#8203;contact_&#8203;info</span>"} | counter | Wire bytes of CRDS values processed (Push (origin no contact info)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;origin_&#8203;shred_&#8203;version</span>"} | counter | Wire bytes of CRDS values processed (Push (origin shred version)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;inactive</span>"} | counter | Wire bytes of CRDS values processed (Push (inactive)) |
| <span class="metrics-name">gossvf_&#8203;crds_&#8203;rx_&#8203;bytes</span><br/>{gossvf_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;wallclock</span>"} | counter | Wire bytes of CRDS values processed (Push (wallclock)) |

</div>

## Gossip Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;capacity</span> | gauge | Peer tracking capacity of the ping tracker |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracked</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">unpinged</span>"} | gauge | Peers being tracked for ping/pong (Peer is known but has not been pinged yet) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracked</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">invalid</span>"} | gauge | Peers being tracked for ping/pong (Peer was pinged but has not yet responded, or responded with an invalid pong) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracked</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">valid</span>"} | gauge | Peers being tracked for ping/pong (Peer was pinged and is currently valid) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracked</span><br/>{ping_&#8203;tracked_&#8203;type="<span class="metrics-enum">valid_&#8203;refreshing</span>"} | gauge | Peers being tracked for ping/pong (Peer was pinged and is currently valid, and is being refreshed with a new ping) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">staked</span>"} | counter | Result of processing a pong response to a ping (Pong ignored as node is staked) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">entrypoint</span>"} | counter | Result of processing a pong response to a ping (Pong ignored as node is an entrypoint) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">untracked</span>"} | counter | Result of processing a pong response to a ping (Pong ignored as node has no outstanding ping) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">address</span>"} | counter | Result of processing a pong response to a ping (Pong ignored as responding node doesn't match pinged address) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">token</span>"} | counter | Result of processing a pong response to a ping (Pong ignored as token was not valid) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;pong_&#8203;result</span><br/>{pong_&#8203;response="<span class="metrics-enum">success</span>"} | counter | Result of processing a pong response to a ping (Pong accepted) |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;evicted</span> | counter | Peers evicted from the ping tracker to make space for new peers |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;added</span> | counter | Peers ever tracked for ping/pong |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;stake_&#8203;changed</span> | counter | Times a tracked peer was removed from tracking because it became staked |
| <span class="metrics-name">gossip_&#8203;ping_&#8203;tracker_&#8203;address_&#8203;changed</span> | counter | Times a tracked peer was removed from tracking because its gossip address changed |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;capacity</span> | gauge | Capacity of the data store |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | gauge | Entries in the data store (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | gauge | Entries in the data store (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | gauge | Entries in the data store (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | gauge | Entries in the data store (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | gauge | Entries in the data store (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | gauge | Entries in the data store (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | gauge | Entries in the data store (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | gauge | Entries in the data store (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | gauge | Entries in the data store (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | gauge | Entries in the data store (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | gauge | Entries in the data store (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | gauge | Entries in the data store (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | gauge | Entries in the data store (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;occupied</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | gauge | Entries in the data store (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;expired</span> | counter | Entries expired from the data store due to age |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;evicted</span> | counter | Entries evicted from the data store to make space for new entries |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;capacity</span> | gauge | Capacity for storing peers in the data store |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;staked</span> | gauge | Staked peers in the data store |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;unstaked</span> | gauge | Unstaked peers in the data store |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;stake</span> | gauge | Total visible stake in the data store, in lamports |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;peer_&#8203;evicted</span> | counter | Peers evicted from the data store to make space for new peers |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;capacity</span> | gauge | Capacity of the list of purged data store entries |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;occupied</span> | gauge | Purged data store entries |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;expired</span> | counter | Purged entries expired from the purged list due to age |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;purged_&#8203;evicted</span> | counter | Purged entries evicted from the data store to make space for new entries |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">upserted_&#8203;pull_&#8203;response</span>"} | counter | Outcome of incoming CRDS messages (Pull Response (upserted)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">upserted_&#8203;push</span>"} | counter | Outcome of incoming CRDS messages (Push (upserted)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;stale</span>"} | counter | Outcome of incoming CRDS messages (Pull Response (newer entry already present in table)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;pull_&#8203;response_&#8203;duplicate</span>"} | counter | Outcome of incoming CRDS messages (Pull Response (duplicate)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;stale</span>"} | counter | Outcome of incoming CRDS messages (Push (newer entry already present in table)) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;rx</span><br/>{gossip_&#8203;crds_&#8203;outcome="<span class="metrics-enum">dropped_&#8203;push_&#8203;duplicate</span>"} | counter | Outcome of incoming CRDS messages (Push (duplicate)) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;request</span>"} | counter | Gossip messages sent (Pull Request) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;response</span>"} | counter | Gossip messages sent (Pull Response) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx</span><br/>{gossip_&#8203;message="<span class="metrics-enum">push</span>"} | counter | Gossip messages sent (Push) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx</span><br/>{gossip_&#8203;message="<span class="metrics-enum">prune</span>"} | counter | Gossip messages sent (Prune) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx</span><br/>{gossip_&#8203;message="<span class="metrics-enum">ping</span>"} | counter | Gossip messages sent (Ping) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pong</span>"} | counter | Gossip messages sent (Pong) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;request</span>"} | counter | Wire bytes sent in gossip messages (Pull Request) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pull_&#8203;response</span>"} | counter | Wire bytes sent in gossip messages (Pull Response) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">push</span>"} | counter | Wire bytes sent in gossip messages (Push) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">prune</span>"} | counter | Wire bytes sent in gossip messages (Prune) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">ping</span>"} | counter | Wire bytes sent in gossip messages (Ping) |
| <span class="metrics-name">gossip_&#8203;message_&#8203;tx_&#8203;bytes</span><br/>{gossip_&#8203;message="<span class="metrics-enum">pong</span>"} | counter | Wire bytes sent in gossip messages (Pong) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | CRDS values sent in push messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | CRDS values sent in push messages (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | CRDS values sent in push messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | CRDS values sent in push messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | CRDS values sent in push messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | CRDS values sent in push messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | CRDS values sent in push messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | CRDS values sent in push messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | CRDS values sent in push messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | CRDS values sent in push messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | CRDS values sent in push messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | CRDS values sent in push messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | CRDS values sent in push messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | CRDS values sent in push messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Wire bytes of CRDS sent in push messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Wire bytes of CRDS sent in push messages (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Wire bytes of CRDS sent in push messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Wire bytes of CRDS sent in push messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Wire bytes of CRDS sent in push messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Wire bytes of CRDS sent in push messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Wire bytes of CRDS sent in push messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Wire bytes of CRDS sent in push messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Wire bytes of CRDS sent in push messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Wire bytes of CRDS sent in push messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Wire bytes of CRDS sent in push messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Wire bytes of CRDS sent in push messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Wire bytes of CRDS sent in push messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;push_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Wire bytes of CRDS sent in push messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | CRDS values sent in pull response messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | CRDS values sent in pull response messages (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | CRDS values sent in pull response messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | CRDS values sent in pull response messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | CRDS values sent in pull response messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | CRDS values sent in pull response messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | CRDS values sent in pull response messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | CRDS values sent in pull response messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | CRDS values sent in pull response messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | CRDS values sent in pull response messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | CRDS values sent in pull response messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | CRDS values sent in pull response messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | CRDS values sent in pull response messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | CRDS values sent in pull response messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v1</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Contact Info V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">vote</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Vote) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">lowest_&#8203;slot</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Lowest Slot) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">snapshot_&#8203;hashes</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">accounts_&#8203;hashes</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Accounts Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">epoch_&#8203;slots</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Epoch Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v1</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Version V1) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">version_&#8203;v2</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Version V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">node_&#8203;instance</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Node Instance) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">duplicate_&#8203;shred</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Duplicate Shred) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">incremental_&#8203;snapshot_&#8203;hashes</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Incremental Snapshot Hashes) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">contact_&#8203;info_&#8203;v2</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Contact Info V2) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;last_&#8203;voted_&#8203;fork_&#8203;slots</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Restart Last Voted Fork Slots) |
| <span class="metrics-name">gossip_&#8203;crds_&#8203;pull_&#8203;response_&#8203;tx_&#8203;bytes</span><br/>{crds_&#8203;value="<span class="metrics-enum">restart_&#8203;heaviest_&#8203;fork</span>"} | counter | Wire bytes of CRDS sent in pull response messages (Restart Heaviest Fork) |
| <span class="metrics-name">gossip_&#8203;wait_&#8203;for_&#8203;supermajority_&#8203;staked_&#8203;peer_&#8203;online</span> | gauge | Staked peers with recent gossip activity |
| <span class="metrics-name">gossip_&#8203;wait_&#8203;for_&#8203;supermajority_&#8203;staked_&#8203;peer_&#8203;total</span> | gauge | Staked peers being tracked |
| <span class="metrics-name">gossip_&#8203;wait_&#8203;for_&#8203;supermajority_&#8203;stake_&#8203;online</span> | gauge | Lamports of stake from peers with recent gossip activity |
| <span class="metrics-name">gossip_&#8203;wait_&#8203;for_&#8203;supermajority_&#8203;stake_&#8203;total</span> | gauge | Total lamports of stake being tracked |
| <span class="metrics-name">gossip_&#8203;wait_&#8203;for_&#8203;supermajority_&#8203;state</span> | gauge | 1=init, 2=wait, 3=publish, 4=done |

</div>

## Repair Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">repair_&#8203;pkt_&#8203;tx</span> | counter | Network packets sent, including reqs, pings, pongs, etc |
| <span class="metrics-name">repair_&#8203;request_&#8203;tx</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;type="<span class="metrics-enum">needed_&#8203;window</span>"} | counter | Client messages sent, by type (Need Window) |
| <span class="metrics-name">repair_&#8203;request_&#8203;tx</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;type="<span class="metrics-enum">needed_&#8203;highest_&#8203;window</span>"} | counter | Client messages sent, by type (Need Highest Window) |
| <span class="metrics-name">repair_&#8203;request_&#8203;tx</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;type="<span class="metrics-enum">needed_&#8203;orphan</span>"} | counter | Client messages sent, by type (Need Orphans) |
| <span class="metrics-name">repair_&#8203;request_&#8203;tx</span><br/>{repair_&#8203;sent_&#8203;request_&#8203;type="<span class="metrics-enum">pong</span>"} | counter | Client messages sent, by type (Pong) |
| <span class="metrics-name">repair_&#8203;slot_&#8203;highest_&#8203;repaired</span> | gauge | Highest slot up to which we have fully repaired |
| <span class="metrics-name">repair_&#8203;slot_&#8203;current</span> | gauge | Our view of the current cluster slot, max slot received |
| <span class="metrics-name">repair_&#8203;shred_&#8203;old</span> | counter | Shreds received that were older than the root |
| <span class="metrics-name">repair_&#8203;slot_&#8203;last_&#8203;requested</span> | gauge | Last slot we requested a single shred for |
| <span class="metrics-name">repair_&#8203;orphan_&#8203;last_&#8203;requested</span> | gauge | Last slot we requested an orphan for |
| <span class="metrics-name">repair_&#8203;request_&#8203;inflight</span> | gauge | Requests currently in the inflight queue, excluding orphans and highest window requests |
| <span class="metrics-name">repair_&#8203;peer_&#8203;requested</span> | counter | Peers requested |
| <span class="metrics-name">repair_&#8203;sign_&#8203;tile_&#8203;unavailable</span> | counter | Times no sign tiles were available to send a request |
| <span class="metrics-name">repair_&#8203;eager_&#8203;threshold_&#8203;exceeded</span> | counter | Times we passed the eager repair threshold |
| <span class="metrics-name">repair_&#8203;shred_&#8203;rerequested</span> | counter | Times we re-requested a shred from the inflights queue |
| <span class="metrics-name">repair_&#8203;ping_&#8203;malformed</span> | counter | Malformed pings received |
| <span class="metrics-name">repair_&#8203;ping_&#8203;unknown_&#8203;peer</span> | counter | Pings received from an unknown peer |
| <span class="metrics-name">repair_&#8203;ping_&#8203;signature_&#8203;failed</span> | counter | Pings whose signature we failed to verify |
| <span class="metrics-name">repair_&#8203;slot_&#8203;complete_&#8203;duration_&#8203;seconds</span> | histogram | Time it took to complete a slot |
| <span class="metrics-name">repair_&#8203;response_&#8203;latency_&#8203;nanos</span> | histogram | Time it took to receive a repair request response, in nanoseconds |
| <span class="metrics-name">repair_&#8203;sign_&#8203;duration_&#8203;seconds</span> | histogram | Duration of signing a message |
| <span class="metrics-name">repair_&#8203;block_&#8203;evicted</span> | counter | Blocks evicted from the forest |
| <span class="metrics-name">repair_&#8203;block_&#8203;insert_&#8203;failed</span> | counter | Blocks we failed to insert into the forest due to failed eviction |
| <span class="metrics-name">repair_&#8203;slot_&#8203;last_&#8203;evicted</span> | gauge | Most recent slot evicted from forest |
| <span class="metrics-name">repair_&#8203;slot_&#8203;last_&#8203;eviction_&#8203;cause</span> | gauge | Slot that caused the most recent eviction from forest |
| <span class="metrics-name">repair_&#8203;slot_&#8203;last_&#8203;insert_&#8203;failed</span> | gauge | Most recent slot we failed to insert into the forest |
| <span class="metrics-name">repair_&#8203;chain_&#8203;verify_&#8203;failed</span> | counter | Times any block failed chained merkle verification |
| <span class="metrics-name">repair_&#8203;slot_&#8203;last_&#8203;chain_&#8203;verify_&#8203;failed</span> | gauge | Most recent slot that failed chained merkle verification |

</div>

## Rserve Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">rserve_&#8203;received_&#8203;request_&#8203;count</span><br/>{rserve_&#8203;request_&#8203;types="<span class="metrics-enum">pong</span>"} | counter | Total repair requests received by type, before any validation (Pong) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;request_&#8203;count</span><br/>{rserve_&#8203;request_&#8203;types="<span class="metrics-enum">window_&#8203;index</span>"} | counter | Total repair requests received by type, before any validation (Window Index) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;request_&#8203;count</span><br/>{rserve_&#8203;request_&#8203;types="<span class="metrics-enum">highest_&#8203;window_&#8203;index</span>"} | counter | Total repair requests received by type, before any validation (Highest Window Index) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;request_&#8203;count</span><br/>{rserve_&#8203;request_&#8203;types="<span class="metrics-enum">orphan</span>"} | counter | Total repair requests received by type, before any validation (Orphan) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;request_&#8203;bytes</span> | counter | Total bytes of incoming repair request payloads |
| <span class="metrics-name">rserve_&#8203;received_&#8203;malformed_&#8203;count</span><br/>{rserve_&#8203;malformed_&#8203;types="<span class="metrics-enum">too_&#8203;small</span>"} | counter | Packets dropped for being malformed, broken down by reason (Too Small) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;malformed_&#8203;count</span><br/>{rserve_&#8203;malformed_&#8203;types="<span class="metrics-enum">ping</span>"} | counter | Packets dropped for being malformed, broken down by reason (Ping) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;malformed_&#8203;count</span><br/>{rserve_&#8203;malformed_&#8203;types="<span class="metrics-enum">unknown_&#8203;tag</span>"} | counter | Packets dropped for being malformed, broken down by reason (Unknown Tag) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;malformed_&#8203;count</span><br/>{rserve_&#8203;malformed_&#8203;types="<span class="metrics-enum">wrong_&#8203;size</span>"} | counter | Packets dropped for being malformed, broken down by reason (Wrong Size) |
| <span class="metrics-name">rserve_&#8203;received_&#8203;malformed_&#8203;count</span><br/>{rserve_&#8203;malformed_&#8203;types="<span class="metrics-enum">ancestor_&#8203;hashes</span>"} | counter | Packets dropped for being malformed, broken down by reason (Ancestor Hashes) |
| <span class="metrics-name">rserve_&#8203;total_&#8203;pkt_&#8203;count</span> | counter | How many network packets we have sent, including pings, responses, etc |
| <span class="metrics-name">rserve_&#8203;sent_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">ping</span>"} | counter | What types of response messages are we sending (Ping) |
| <span class="metrics-name">rserve_&#8203;sent_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">window</span>"} | counter | What types of response messages are we sending (Window) |
| <span class="metrics-name">rserve_&#8203;sent_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">highest_&#8203;window</span>"} | counter | What types of response messages are we sending (Highest Window) |
| <span class="metrics-name">rserve_&#8203;sent_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">orphan</span>"} | counter | What types of response messages are we sending (Orphan) |
| <span class="metrics-name">rserve_&#8203;sent_&#8203;response_&#8203;bytes</span> | counter | Total payload bytes sent in response packets |
| <span class="metrics-name">rserve_&#8203;sent_&#8203;ping_&#8203;back_&#8203;count</span> | counter | How many ping-back packets we sent to nodes not yet in the ping cache |
| <span class="metrics-name">rserve_&#8203;missed_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">ping</span>"} | counter | What types of response messages could we not fulfill (Ping) |
| <span class="metrics-name">rserve_&#8203;missed_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">window</span>"} | counter | What types of response messages could we not fulfill (Window) |
| <span class="metrics-name">rserve_&#8203;missed_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">highest_&#8203;window</span>"} | counter | What types of response messages could we not fulfill (Highest Window) |
| <span class="metrics-name">rserve_&#8203;missed_&#8203;response_&#8203;types</span><br/>{rserve_&#8203;sent_&#8203;response_&#8203;types="<span class="metrics-enum">orphan</span>"} | counter | What types of response messages could we not fulfill (Orphan) |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;sigverify</span> | counter | How many times we failed to verify the signature of a request |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;own_&#8203;key</span> | counter | How many requests we've received that were sent by us |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;invalid_&#8203;token</span> | counter | How many pong requests we've received with outdated or invalid tokens |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;not_&#8203;for_&#8203;us</span> | counter | How many requests we've received that were not intended for us |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;outdated</span> | counter | How many requests we've received that had outdated timestamps |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;invalid_&#8203;shred_&#8203;index</span> | counter | How many requests we've received that had invalid shred indices |
| <span class="metrics-name">rserve_&#8203;failed_&#8203;ping_&#8203;cache_&#8203;lookup</span> | counter | Requests from nodes not in the ping cache, which triggered a ping-back instead of a response |
| <span class="metrics-name">rserve_&#8203;shreds_&#8203;current</span> | gauge | The number of shreds currently in the shreds database |
| <span class="metrics-name">rserve_&#8203;shreds_&#8203;max</span> | gauge | Total capacity of shreds that can be stored in the shreds database |
| <span class="metrics-name">rserve_&#8203;disk_&#8203;current_&#8203;bytes</span> | gauge | The number of bytes currently used on disk by the database |
| <span class="metrics-name">rserve_&#8203;disk_&#8203;allocated_&#8203;bytes</span> | gauge | The current size of the database file on disk |
| <span class="metrics-name">rserve_&#8203;ping_&#8203;cache_&#8203;entries</span> | counter | How many active entries do we have in the ping cache |
| <span class="metrics-name">rserve_&#8203;ping_&#8203;cache_&#8203;evictions</span> | counter | How many entries we've evicted from the ping cache |

</div>

## Replay Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">replay_&#8203;identity_&#8203;balance_&#8203;lamports</span> | gauge | Identity account balance at the optimistically confirmed slot |
| <span class="metrics-name">replay_&#8203;active_&#8203;stake_&#8203;lamports</span> | gauge | Our active stake at the optimistically confirmed slot |
| <span class="metrics-name">replay_&#8203;cluster_&#8203;active_&#8203;stake_&#8203;lamports</span> | gauge | Total cluster active stake at the optimistically confirmed slot |
| <span class="metrics-name">replay_&#8203;epoch_&#8203;credits</span> | gauge | Our vote account epoch credits at the optimistically confirmed slot |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;acquired</span> | counter | Store slock acquires for query |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;released</span> | counter | Store slock releases for query |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;wait_&#8203;seconds</span> | histogram | Time spent waiting to acquire the slock for query |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;work_&#8203;seconds</span> | histogram | Time spent working before releasing the slock for query |
| <span class="metrics-name">replay_&#8203;store_&#8203;queried</span> | counter | Queries |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;missing</span> | counter | Queries where merkle root was missing |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;merkle_&#8203;root_&#8203;sample</span> | gauge | First 8 bytes of most recently queried merkle root |
| <span class="metrics-name">replay_&#8203;store_&#8203;query_&#8203;missing_&#8203;merkle_&#8203;root_&#8203;sample</span> | gauge | First 8 bytes of most recently queried missing merkle root |
| <span class="metrics-name">replay_&#8203;root_&#8203;slot</span> | gauge | Slot at which our node has most recently rooted |
| <span class="metrics-name">replay_&#8203;root_&#8203;distance</span> | gauge | Distance in slots between our current root and the current reset slot |
| <span class="metrics-name">replay_&#8203;leader_&#8203;slot</span> | gauge | Slot at which we are currently leader, or 0 if none |
| <span class="metrics-name">replay_&#8203;next_&#8203;leader_&#8203;slot</span> | gauge | Slot at which we are next leader, or 0 if none. If we are currently leader, this is the same as the current leader slot |
| <span class="metrics-name">replay_&#8203;reset_&#8203;slot</span> | gauge | Slot at which we last reset the replay stage, or 0 if unknown |
| <span class="metrics-name">replay_&#8203;bank_&#8203;live_&#8203;max</span> | gauge | Maximum number of banks we can have alive |
| <span class="metrics-name">replay_&#8203;bank_&#8203;live</span> | gauge | Banks we currently have alive |
| <span class="metrics-name">replay_&#8203;reassembly_&#8203;free</span> | gauge | Free FEC sets in the reassembly queue |
| <span class="metrics-name">replay_&#8203;reassembly_&#8203;latest_&#8203;slot</span> | gauge | Slot of the latest FEC set in the reassembly queue that can be replayed |
| <span class="metrics-name">replay_&#8203;reassembly_&#8203;latest_&#8203;fec_&#8203;index</span> | gauge | FEC set index of the latest FEC set in the reassembly queue that can be replayed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;active_&#8203;bank_&#8203;index</span> | gauge | Bank that the replay scheduler is currently dispatching work for |
| <span class="metrics-name">replay_&#8203;sched_&#8203;last_&#8203;dispatch_&#8203;bank_&#8203;index</span> | gauge | Bank that the replay scheduler last dispatched work for |
| <span class="metrics-name">replay_&#8203;sched_&#8203;last_&#8203;dispatch_&#8203;timestamp_&#8203;nanos</span> | gauge | Timestamp when the replay scheduler last dispatched work, in nanoseconds |
| <span class="metrics-name">replay_&#8203;sched_&#8203;staging_&#8203;lane_&#8203;occupied</span> | gauge | Staging lanes currently occupied in the replay scheduler. Up to four staging lanes can be occupied at once |
| <span class="metrics-name">replay_&#8203;sched_&#8203;staging_&#8203;lane_&#8203;occupied_&#8203;watermark</span> | gauge | High watermark of staging lanes that were at one point occupied in the replay scheduler |
| <span class="metrics-name">replay_&#8203;sched_&#8203;staging_&#8203;lane_&#8203;head_&#8203;bank_&#8203;index</span><br/>{staging_&#8203;lane="<span class="metrics-enum">lane0</span>"} | gauge | Bank at the head of each staging lane of the replay dispatcher (Staging lane 0) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;staging_&#8203;lane_&#8203;head_&#8203;bank_&#8203;index</span><br/>{staging_&#8203;lane="<span class="metrics-enum">lane1</span>"} | gauge | Bank at the head of each staging lane of the replay dispatcher (Staging lane 1) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;staging_&#8203;lane_&#8203;head_&#8203;bank_&#8203;index</span><br/>{staging_&#8203;lane="<span class="metrics-enum">lane2</span>"} | gauge | Bank at the head of each staging lane of the replay dispatcher (Staging lane 2) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;staging_&#8203;lane_&#8203;head_&#8203;bank_&#8203;index</span><br/>{staging_&#8203;lane="<span class="metrics-enum">lane3</span>"} | gauge | Bank at the head of each staging lane of the replay dispatcher (Staging lane 3) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;pool_&#8203;occupied</span> | gauge | Transactions available to be scheduled in the replay scheduler |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;pool_&#8203;size</span> | gauge | Maximum number of transactions the replay scheduler can consider. Fixed at Firedancer startup but a useful reference for SchedTxnPoolOccupied |
| <span class="metrics-name">replay_&#8203;sched_&#8203;microblock_&#8203;pool_&#8203;occupied</span> | gauge | Microblocks available to be scheduled in the replay scheduler |
| <span class="metrics-name">replay_&#8203;sched_&#8203;microblock_&#8203;pool_&#8203;size</span> | gauge | Maximum number of microblocks the replay scheduler can consider. Fixed at Firedancer startup but a useful reference for SchedMicroblockPoolOccupied |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;pool_&#8203;occupied</span> | gauge | Blocks alive in the replay scheduler |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;pool_&#8203;size</span> | gauge | Maximum number of blocks the replay scheduler can keep track of. Fixed at Firedancer startup but a useful reference for SchedBlockPoolOccupied |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;added</span><br/>{sched_&#8203;block_&#8203;staging="<span class="metrics-enum">staged</span>"} | counter | Blocks added to the replay scheduler, by staging state (Added as staged) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;added</span><br/>{sched_&#8203;block_&#8203;staging="<span class="metrics-enum">unstaged</span>"} | counter | Blocks added to the replay scheduler, by staging state (Added as unstaged) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;replayed</span> | counter | Blocks the replay scheduler considers fully replayed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;abandoned</span> | counter | Blocks the replay scheduler abandoned for any reason |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;rejected</span> | counter | Blocks the replay scheduler considers bad |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;promoted</span> | counter | Blocks the replay scheduler promoted from unstaged to a staging lane |
| <span class="metrics-name">replay_&#8203;sched_&#8203;block_&#8203;demoted</span> | counter | Blocks the replay scheduler demoted from a staging lane to unstaged |
| <span class="metrics-name">replay_&#8203;sched_&#8203;deactivate</span><br/>{sched_&#8203;deactivate_&#8203;reason="<span class="metrics-enum">no_&#8203;child</span>"} | counter | Times the replay scheduler stopped dispatching, by reason (A block fully replayed and there was no child block available yet) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;deactivate</span><br/>{sched_&#8203;deactivate_&#8203;reason="<span class="metrics-enum">no_&#8203;work</span>"} | counter | Times the replay scheduler stopped dispatching, by reason (A partially replayed block ran out of work to dispatch) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;deactivate</span><br/>{sched_&#8203;deactivate_&#8203;reason="<span class="metrics-enum">abandoned</span>"} | counter | Times the replay scheduler stopped dispatching, by reason (A block got abandoned for any reason) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;deactivate</span><br/>{sched_&#8203;deactivate_&#8203;reason="<span class="metrics-enum">minority</span>"} | counter | Times the replay scheduler stopped dispatching, by reason (A block got abandoned for being on a minority fork) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;lane_&#8203;switched</span> | counter | Times the replay scheduler switched the lane it is dispatching from |
| <span class="metrics-name">replay_&#8203;sched_&#8203;lane_&#8203;promoted</span> | counter | Times the replay scheduler promoted one or more blocks onto a staging lane |
| <span class="metrics-name">replay_&#8203;sched_&#8203;lane_&#8203;demoted</span> | counter | Times the replay scheduler demoted one or more blocks from a staging lane |
| <span class="metrics-name">replay_&#8203;sched_&#8203;fork_&#8203;observed</span> | counter | Forks the replay scheduler has observed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;alut</span><br/>{sched_&#8203;alut_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Transactions with address lookup tables the replay scheduler tried to expand, by outcome (Address lookup tables expanded successfully) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;alut</span><br/>{sched_&#8203;alut_&#8203;result="<span class="metrics-enum">failed</span>"} | counter | Transactions with address lookup tables the replay scheduler tried to expand, by outcome (Address lookup table expansion failed) |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;parsed_&#8203;abandoned</span> | counter | Transactions that were parsed but ended up being in abandoned blocks |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;executed_&#8203;abandoned</span> | counter | Transactions that were executed but ended up being in abandoned blocks |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;done_&#8203;abandoned</span> | counter | Transactions that were fully replayed but ended up being in abandoned blocks |
| <span class="metrics-name">replay_&#8203;sched_&#8203;weighted_&#8203;in_&#8203;flight</span> | counter | Cumulative transactions in-flight from the replay scheduler's point of view, weighted by the duration of each transaction. Useful as the dividend for SchedWeightedInFlightDurationNanos |
| <span class="metrics-name">replay_&#8203;sched_&#8203;weighted_&#8203;in_&#8203;flight_&#8203;duration_&#8203;nanos</span> | counter | Duration over which SchedWeightedInFlight was accumulated, in nanoseconds. Use as divisor to get the average number of in-flight transactions |
| <span class="metrics-name">replay_&#8203;sched_&#8203;none_&#8203;in_&#8203;flight_&#8203;duration_&#8203;nanos</span> | counter | Duration the replay scheduler had no transaction in-flight, in nanoseconds. Useful in a ratio against SchedWeightedInFlightDurationNanos to see how often the replay transaction execution pipeline was idle |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;parsed</span> | counter | Transactions the replay pipeline has parsed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;executed</span> | counter | Transactions the replay pipeline has executed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;signature_&#8203;verified</span> | counter | Transactions the replay pipeline has sigverified |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;poh_&#8203;mixed</span> | counter | Transactions the replay pipeline has performed PoH mixin on |
| <span class="metrics-name">replay_&#8203;sched_&#8203;txn_&#8203;done</span> | counter | Transactions that were fully replayed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;microblock_&#8203;parsed</span> | counter | Microblocks the replay pipeline has parsed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;microblock_&#8203;hashed</span> | counter | Microblocks the replay pipeline has fully hashed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;microblock_&#8203;done</span> | counter | Microblocks that were fully replayed |
| <span class="metrics-name">replay_&#8203;sched_&#8203;bytes_&#8203;ingested</span> | counter | Bytes the replay scheduler has ingested |
| <span class="metrics-name">replay_&#8203;sched_&#8203;bytes_&#8203;ingested_&#8203;padding</span> | counter | Bytes the replay scheduler ingested but did not parse for being padding |
| <span class="metrics-name">replay_&#8203;sched_&#8203;bytes_&#8203;dropped</span> | counter | Bytes the replay scheduler refused to ingest because the block is considered abandoned |
| <span class="metrics-name">replay_&#8203;sched_&#8203;fec_&#8203;ingested</span> | counter | FEC sets the replay scheduler has been given |
| <span class="metrics-name">replay_&#8203;slot_&#8203;replayed</span> | counter | Slots replayed successfully or leader slots packed and shredded successfully |
| <span class="metrics-name">replay_&#8203;txn_&#8203;processed</span> | counter | Transactions processed overall on the current fork |
| <span class="metrics-name">replay_&#8203;fec_&#8203;sched_&#8203;full</span> | counter | Times sched is full and a FEC set can't be processed |
| <span class="metrics-name">replay_&#8203;fec_&#8203;reassembly_&#8203;empty</span> | counter | Times reassembly is empty and a FEC set can't be processed |
| <span class="metrics-name">replay_&#8203;fec_&#8203;leader_&#8203;bid_&#8203;wait</span> | counter | Times replay is blocked by the PoH tile not sending an end of leader message |
| <span class="metrics-name">replay_&#8203;fec_&#8203;bank_&#8203;full</span> | counter | Times banks are full and a FEC set can't be processed |
| <span class="metrics-name">replay_&#8203;storage_&#8203;root_&#8203;behind</span> | counter | Times the storage root is behind the consensus root and can't be advanced |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;rooted</span> | counter | Program cache entries rooted |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;gc_&#8203;root</span> | counter | Number of program cache entries garbage collected while rooting |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;free_&#8203;partition</span> | gauge | Free program cache heap partitions (indicates fragmentation) |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;free_&#8203;bytes</span> | gauge | Free bytes in the program cache heap |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;size_&#8203;bytes</span> | gauge | Total size of the program cache heap |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;free_&#8203;partition_&#8203;max_&#8203;bytes</span> | gauge | Largest free heap partition in program cache |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;used_&#8203;partition_&#8203;median_&#8203;bytes</span> | gauge | Median used heap partition size in program cache |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;used_&#8203;partition_&#8203;mean_&#8203;bytes</span> | gauge | Mean used heap partition size in program cache |
| <span class="metrics-name">replay_&#8203;progcache_&#8203;duration_&#8203;seconds</span> | counter | Time spent doing program cache tasks, in seconds |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (0-128 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (129-512 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (0-128 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (129-512 B) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;account_&#8203;waited</span> | counter | Number of accounts that were needed for transaction execution but were concurrently loading into cache by another transaction, causing the transaction to wait |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;batch_&#8203;acquired</span> | counter | Number of fd_accdb_acquire (batch acquire) calls made by this tile |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;acquire_&#8203;failed</span> | counter | Number of times we failed to acquire the cache lines needed for a transaction, and had to spin loop waiting |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;read_&#8203;operation</span> | counter | Number of read operations performed on the account database |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;bytes_&#8203;written</span> | counter | Number of bytes written to the account database |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;write_&#8203;operation</span> | counter | Number of write operations performed on the account database |
| <span class="metrics-name">replay_&#8203;accdb_&#8203;bytes_&#8203;copied</span> | counter | Number of bytes copied within the account database |
| <span class="metrics-name">replay_&#8203;root_&#8203;account_&#8203;duration_&#8203;seconds</span> | histogram | Time spent updating the rooted account store (one sample per block, normalized by account count) |
| <span class="metrics-name">replay_&#8203;root_&#8203;duration_&#8203;seconds</span><br/>{root_&#8203;phase="<span class="metrics-enum">copy</span>"} | counter | Time spent rooting accounts, in seconds (Copying account data) |
| <span class="metrics-name">replay_&#8203;root_&#8203;duration_&#8203;seconds</span><br/>{root_&#8203;phase="<span class="metrics-enum">garbage_&#8203;collect</span>"} | counter | Time spent rooting accounts, in seconds (Garbage collecting old account data) |
| <span class="metrics-name">replay_&#8203;runtime_&#8203;status</span> | gauge | 0=initializing, 1=loaded |

</div>

## Execrp Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">execrp_&#8203;processing</span> | gauge | Whether the tile is currently processing a task (executing, sigverifying, or PoH hashing), either 1 or 0 |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of loading and executing a transaction (Transaction executed successfully) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">instruction_&#8203;error</span>"} | counter | Result of loading and executing a transaction (An error occurred while processing an instruction) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The transaction fee payer address was not found) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">program_&#8203;account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (A program account referenced by the transaction was not found) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (The transaction fee payer did not have balance to pay the fee) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (The transaction fee payer account is not owned by the system program, or has data that is not a nonce) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">already_&#8203;processed</span>"} | counter | Result of loading and executing a transaction (The transaction has already been processed in a recent block) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">blockhash_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The transaction references a blockhash that is not recent, or advances a nonce with the wrong value) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;program_&#8203;for_&#8203;execution</span>"} | counter | Result of loading and executing a transaction (A program account referenced by the transaction was no executable. TODO: No longer needed with SIMD-0162) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The transaction references an ALUT account that does not exist or is inactive) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner</span>"} | counter | Result of loading and executing a transaction (The transaction references an ALUT account that is not owned by the ALUT program account) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data</span>"} | counter | Result of loading and executing a transaction (The transaction references an ALUT account that contains data which is not a valid ALUT) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index</span>"} | counter | Result of loading and executing a transaction (The transaction references an account offset from the ALUT which does not exist) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded</span>"} | counter | Result of loading and executing a transaction (The total account data size of the loaded accounts exceeds the consensus limit) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">duplicate_&#8203;instruction</span>"} | counter | Result of loading and executing a transaction (A compute budget program instruction was invoked more than once) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (The compute budget program was invoked and set the loaded accounts data size to zero) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;already_&#8203;advanced</span>"} | counter | Result of loading and executing a transaction (The transaction references a nonce account that is already advanced) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;advance_&#8203;failed</span>"} | counter | Result of loading and executing a transaction (The transaction is a nonce transaction but the advance instruction was not valid or failed) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">nonce_&#8203;wrong_&#8203;blockhash</span>"} | counter | Result of loading and executing a transaction (The transaction is a nonce transaction but the blockhash is not the correct one) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">sanitize_&#8203;failure</span>"} | counter | Result of loading and executing a transaction (The process for sanitizing the transaction failed) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;in_&#8203;use</span>"} | counter | Result of loading and executing a transaction (The transaction conflicts with another transaction in the microblock. TODO: No longer possible with smart dispatcher) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">account_&#8203;loaded_&#8203;twice</span>"} | counter | Result of loading and executing a transaction (The transaction references the same account twice) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">signature_&#8203;failure</span>"} | counter | Result of loading and executing a transaction (The transaction had an invalid signature) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">too_&#8203;many_&#8203;account_&#8203;locks</span>"} | counter | Result of loading and executing a transaction (The transaction references too many accounts. TODO: No longer possible with smart dispatcher) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;rent</span>"} | counter | Result of loading and executing a transaction (The transaction would leave an account with a lower balance than the rent-exempt minimum) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">unbalanced_&#8203;transaction</span>"} | counter | Result of loading and executing a transaction (The total referenced account lamports before and after the transaction was unbalanced) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;result="<span class="metrics-enum">bundle_&#8203;peer</span>"} | counter | Result of loading and executing a transaction (The transaction was part of a bundle and an earlier transaction in the bundle failed) |
| <span class="metrics-name">execrp_&#8203;signature_&#8203;verified</span> | counter | Ed25519 signature verification jobs executed |
| <span class="metrics-name">execrp_&#8203;poh_&#8203;hashed</span> | counter | PoH SHA-256 calls executed |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{txn_&#8203;regime="<span class="metrics-enum">setup</span>"} | counter | Mutually exclusive and exhaustive duration spent in transaction execution regimes, in nanoseconds (Transaction setup) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{txn_&#8203;regime="<span class="metrics-enum">exec</span>"} | counter | Mutually exclusive and exhaustive duration spent in transaction execution regimes, in nanoseconds (Transaction execution (includes VM setup/execution)) |
| <span class="metrics-name">execrp_&#8203;txn_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{txn_&#8203;regime="<span class="metrics-enum">commit</span>"} | counter | Mutually exclusive and exhaustive duration spent in transaction execution regimes, in nanoseconds (Transaction result commit) |
| <span class="metrics-name">execrp_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">setup</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM setup) |
| <span class="metrics-name">execrp_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">commit</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM commit) |
| <span class="metrics-name">execrp_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">setup_&#8203;cpi</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM setup (CPI)) |
| <span class="metrics-name">execrp_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">commit_&#8203;cpi</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM commit (CPI)) |
| <span class="metrics-name">execrp_&#8203;vm_&#8203;regime_&#8203;duration_&#8203;nanos</span><br/>{vm_&#8203;regime="<span class="metrics-enum">interpreter</span>"} | counter | Mutually exclusive and exhaustive duration spent in virtual machine execution regimes, in nanoseconds (VM interpreter execution) |
| <span class="metrics-name">execrp_&#8203;cu_&#8203;executed</span> | counter | Estimated compute units executed since tile start |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;lookup</span> | counter | Program cache lookups |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;hit</span> | counter | Program cache hits |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;miss</span> | counter | Program cache misses |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;oom_&#8203;heap</span> | counter | Program cache out-of-memory events (heap) |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;oom_&#8203;desc</span> | counter | Program cache out-of-memory events (descriptor table) |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;fill</span> | counter | Program cache insertions |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;fill_&#8203;bytes</span> | counter | Bytes inserted into program cache |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;spill</span> | counter | Program cache spills (OOM fallback mechanism) |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;spill_&#8203;bytes</span> | counter | Bytes spilled from program cache (OOM fallback mechanism) |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;eviction</span> | counter | Program cache evictions |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;eviction_&#8203;bytes</span> | counter | Bytes evicted from program cache |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;duration_&#8203;seconds</span> | counter | Time spent on program cache operations, in seconds |
| <span class="metrics-name">execrp_&#8203;progcache_&#8203;load_&#8203;duration_&#8203;seconds</span> | counter | Time spent loading programs, in seconds |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (0-128 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (129-512 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (0-128 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (129-512 B) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;account_&#8203;waited</span> | counter | Number of accounts that were needed for transaction execution but were concurrently loading into cache by another transaction, causing the transaction to wait |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;batch_&#8203;acquired</span> | counter | Number of fd_accdb_acquire (batch acquire) calls made by this tile |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;acquire_&#8203;failed</span> | counter | Number of times we failed to acquire the cache lines needed for a transaction, and had to spin loop waiting |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;read_&#8203;operation</span> | counter | Number of read operations performed on the account database |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;bytes_&#8203;written</span> | counter | Number of bytes written to the account database |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;write_&#8203;operation</span> | counter | Number of write operations performed on the account database |
| <span class="metrics-name">execrp_&#8203;accdb_&#8203;bytes_&#8203;copied</span> | counter | Number of bytes copied within the account database |

</div>

## Accdb Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">accdb_&#8203;account_&#8203;count</span> | gauge | Total number of accounts currently in the account database |
| <span class="metrics-name">accdb_&#8203;account_&#8203;capacity</span> | gauge | Total capacity of accounts that can be stored in the account database |
| <span class="metrics-name">accdb_&#8203;account_&#8203;relocated</span> | counter | Total number of accounts moved in the account database during compaction |
| <span class="metrics-name">accdb_&#8203;disk_&#8203;allocated_&#8203;bytes</span> | gauge | Total allocated size of the account database on disk |
| <span class="metrics-name">accdb_&#8203;disk_&#8203;current_&#8203;bytes</span> | gauge | Total written-through size of the account database on disk, excluding never-written partition tail space |
| <span class="metrics-name">accdb_&#8203;disk_&#8203;used_&#8203;bytes</span> | gauge | Total size of the account database on disk that is currently used |
| <span class="metrics-name">accdb_&#8203;in_&#8203;compaction</span> | gauge | 1 if a compaction is currently in progress, 0 if not |
| <span class="metrics-name">accdb_&#8203;compaction_&#8203;requested</span> | counter | Total number of compactions requested on the account database |
| <span class="metrics-name">accdb_&#8203;compaction_&#8203;completed</span> | counter | Total number of compactions fully completed on the account database, less than or equal to the requested amount |
| <span class="metrics-name">accdb_&#8203;account_&#8203;relocated_&#8203;bytes</span> | counter | Total number of bytes moved in the account database during compaction |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (0-128 B) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (129-512 B) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">accdb_&#8203;account_&#8203;preevicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts preemptively evicted (written back) from the account database cache by the background preevict pass, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">accdb_&#8203;bytes_&#8203;written</span> | counter | Number of bytes written to the account database |
| <span class="metrics-name">accdb_&#8203;write_&#8203;operation</span> | counter | Number of write operations performed on the account database |
| <span class="metrics-name">accdb_&#8203;copy_&#8203;operation</span> | counter | Number of in-place copy_file_range operations performed on the account database during compaction |
| <span class="metrics-name">accdb_&#8203;account_&#8203;deleted</span> | counter | Number of accounts deleted from the account database |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (0-128 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (129-512 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (513 B-2 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (2-8 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (8-32 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (32-128 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (128 KiB-1 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | gauge | Number of slots currently occupied in the account database cache, broken down by size class (1-10 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (0-128 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (129-512 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (513 B-2 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (2-8 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (8-32 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (32-128 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (128 KiB-1 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;max</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | gauge | Total slot capacity of the account database cache, broken down by size class (1-10 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (0-128 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (129-512 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (513 B-2 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (2-8 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (8-32 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (32-128 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (128 KiB-1 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;reserved</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | gauge | Number of slots currently reserved by in-flight acquires (cache_class_used), or ULONG_MAX when reservation tracking is disabled for the class (1-10 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (0-128 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (129-512 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (513 B-2 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (2-8 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (8-32 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (32-128 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (128 KiB-1 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;target_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | gauge | Target used-slot count for the account database cache (max - cache_free_target). When used exceeds this, the background preevict pass tries to bring used back down to this level. (1-10 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (0-128 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (129-512 B) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (513 B-2 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (2-8 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (8-32 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (32-128 KiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (128 KiB-1 MiB) |
| <span class="metrics-name">accdb_&#8203;cache_&#8203;class_&#8203;low_&#8203;water_&#8203;used</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | gauge | Used-slot count at which the background preevict pass kicks in (max - cache_free_low_water). When used exceeds this, preevicts start. (1-10 MiB) |

</div>

## Tower Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">tower_&#8203;frag_&#8203;ignored</span> | counter | replay_slot_completed frags we ignored |
| <span class="metrics-name">tower_&#8203;slot_&#8203;last_&#8203;ignored</span> | gauge | Most recent ignored replay_slot_completed frag |
| <span class="metrics-name">tower_&#8203;frag_&#8203;eqvoc_&#8203;detected</span> | counter | replay_slot_completed frags we detect as equivocations |
| <span class="metrics-name">tower_&#8203;slot_&#8203;last_&#8203;eqvoc</span> | gauge | Most recent equivocating replay_slot_completed frag |
| <span class="metrics-name">tower_&#8203;replay_&#8203;slot</span> | gauge | Most recently replayed slot, ULONG_MAX if nothing replayed yet. Not monotonically increasing |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot</span> | gauge | Highest voted slot in the local tower, ULONG_MAX if haven't voted. Monotonically increasing |
| <span class="metrics-name">tower_&#8203;reset_&#8203;slot</span> | gauge | Most recent reset slot, ULONG_MAX if no reset yet. Not monotonically increasing |
| <span class="metrics-name">tower_&#8203;root_&#8203;slot</span> | gauge | Highest rooted slot, ULONG_MAX if no root yet. Monotonically increasing |
| <span class="metrics-name">tower_&#8203;init_&#8203;slot</span> | gauge | Init slot, either the snapshot or genesis slot. Set once and does not change |
| <span class="metrics-name">tower_&#8203;frag_&#8203;not_&#8203;ready_&#8203;dropped</span> | counter | Frags dropped because they arrived before the tower tile was initialized |
| <span class="metrics-name">tower_&#8203;eqvoc_&#8203;proof</span><br/>{eqvoc_&#8203;proof_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Equivocation proofs, by validation outcome (Valid equivocation proof) |
| <span class="metrics-name">tower_&#8203;eqvoc_&#8203;proof</span><br/>{eqvoc_&#8203;proof_&#8203;result="<span class="metrics-enum">error</span>"} | counter | Equivocation proofs, by validation outcome (Proof failed validation (gossip-only)) |
| <span class="metrics-name">tower_&#8203;ghost_&#8203;vote</span><br/>{ghost_&#8203;vote_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of counting a vote towards ghost (Vote was counted towards ghost) |
| <span class="metrics-name">tower_&#8203;ghost_&#8203;vote</span><br/>{ghost_&#8203;vote_&#8203;result="<span class="metrics-enum">not_&#8203;voted</span>"} | counter | Result of counting a vote towards ghost (Skipped because voter hasn't voted) |
| <span class="metrics-name">tower_&#8203;ghost_&#8203;vote</span><br/>{ghost_&#8203;vote_&#8203;result="<span class="metrics-enum">too_&#8203;old</span>"} | counter | Result of counting a vote towards ghost (Slot was behind the root) |
| <span class="metrics-name">tower_&#8203;ghost_&#8203;vote</span><br/>{ghost_&#8203;vote_&#8203;result="<span class="metrics-enum">already_&#8203;voted</span>"} | counter | Result of counting a vote towards ghost (Slot was not newer than previous vote) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;vote</span><br/>{hard_&#8203;fork_&#8203;vote_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of counting a vote towards hard fork detection (Vote was counted, no hard fork agreement reached) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;vote</span><br/>{hard_&#8203;fork_&#8203;vote_&#8203;result="<span class="metrics-enum">success_&#8203;matched</span>"} | counter | Result of counting a vote towards hard fork detection (52%+ of stake agreed on our bank hash) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;vote</span><br/>{hard_&#8203;fork_&#8203;vote_&#8203;result="<span class="metrics-enum">mismatched</span>"} | counter | Result of counting a vote towards hard fork detection (52%+ of stake agreed on a different bank hash than ours (we hard forked)) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;vote</span><br/>{hard_&#8203;fork_&#8203;vote_&#8203;result="<span class="metrics-enum">unknown_&#8203;voter</span>"} | counter | Result of counting a vote towards hard fork detection (Voter not in voter set) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;vote</span><br/>{hard_&#8203;fork_&#8203;vote_&#8203;result="<span class="metrics-enum">already_&#8203;voted</span>"} | counter | Result of counting a vote towards hard fork detection (Voter already voted for this block_id) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;vote</span><br/>{hard_&#8203;fork_&#8203;vote_&#8203;result="<span class="metrics-enum">too_&#8203;old</span>"} | counter | Result of counting a vote towards hard fork detection (Slot not newer than previous) |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;matched_&#8203;slot</span> | gauge | Highest slot where 52%+ of stake agreed on our bank hash |
| <span class="metrics-name">tower_&#8203;hard_&#8203;fork_&#8203;mismatched_&#8203;slot</span> | gauge | Highest slot where 52%+ of stake agreed on a different bank hash than ours (we hard forked) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">no_&#8203;vote_&#8203;not_&#8203;recent</span>"} | counter | Result of deciding which fork to vote/reset on (Haven't voted yet and best block is not recent enough to vote (can't vote)) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">empty_&#8203;tower_&#8203;vote</span>"} | counter | Result of deciding which fork to vote/reset on (Haven't voted yet, voting for best block (can vote)) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">ancestor_&#8203;rollback</span>"} | counter | Result of deciding which fork to vote/reset on (Rollback to an ancestor of our prev vote (can't vote)) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">sibling_&#8203;confirmed</span>"} | counter | Result of deciding which fork to vote/reset on (Duplicate sibling got confirmed (can vote)) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">same_&#8203;fork</span>"} | counter | Result of deciding which fork to vote/reset on (Same fork as prev vote (can vote)) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">switch_&#8203;pass</span>"} | counter | Result of deciding which fork to vote/reset on (Prev vote was on a different fork, but we are allowed to switch (can vote)) |
| <span class="metrics-name">tower_&#8203;fork_&#8203;decision</span><br/>{tower_&#8203;fork_&#8203;decision="<span class="metrics-enum">switch_&#8203;fail</span>"} | counter | Result of deciding which fork to vote/reset on (Prev vote was on a different fork, and we are not allowed to switch (can't vote)) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;gate</span><br/>{tower_&#8203;vote_&#8203;gate="<span class="metrics-enum">voted</span>"} | counter | Result of the vote gating checks after a fork was selected (Passed all vote checks and cast a vote) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;gate</span><br/>{tower_&#8203;vote_&#8203;gate="<span class="metrics-enum">lockout_&#8203;fail</span>"} | counter | Result of the vote gating checks after a fork was selected (Locked out (can't vote)) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;gate</span><br/>{tower_&#8203;vote_&#8203;gate="<span class="metrics-enum">threshold_&#8203;fail</span>"} | counter | Result of the vote gating checks after a fork was selected (Did not pass threshold check (can't vote)) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;gate</span><br/>{tower_&#8203;vote_&#8203;gate="<span class="metrics-enum">propagated_&#8203;fail</span>"} | counter | Result of the vote gating checks after a fork was selected (Prev leader block did not propagate (can't vote)) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;gate</span><br/>{tower_&#8203;vote_&#8203;gate="<span class="metrics-enum">no_&#8203;candidate</span>"} | counter | Result of the vote gating checks after a fork was selected (Fork decision did not produce a votable block) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of processing a vote txn (per txn) (Vote txn passed per-txn validation and reached slot counting (per-slot outcomes tracked by VoteSlotResult)) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">not_&#8203;simple_&#8203;vote</span>"} | counter | Result of processing a vote txn (per txn) (Txn was not a simple vote transaction) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">bad_&#8203;deser</span>"} | counter | Result of processing a vote txn (per txn) (Vote txn failed to deserialize) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">not_&#8203;tower_&#8203;sync</span>"} | counter | Result of processing a vote txn (per txn) (Vote txn was not a TowerSync instruction) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">empty_&#8203;tower</span>"} | counter | Result of processing a vote txn (per txn) (Vote txn had an empty tower (validator hasn't voted)) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">bad_&#8203;tower</span>"} | counter | Result of processing a vote txn (per txn) (Vote txn deserialized but tower was invalid) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">unknown_&#8203;block_&#8203;id</span>"} | counter | Result of processing a vote txn (per txn) (Last vote had a null block id) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">too_&#8203;old</span>"} | counter | Result of processing a vote txn (per txn) (Last vote slot was behind the votes root) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">not_&#8203;staked</span>"} | counter | Result of processing a vote txn (per txn) (Unable to query stake for vote slot) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;txn</span><br/>{vote_&#8203;txn_&#8203;result="<span class="metrics-enum">bad_&#8203;signer</span>"} | counter | Result of processing a vote txn (per txn) (Vote txn was not signed by the authorized voter for the vote account at the vote epoch) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot_&#8203;counted</span><br/>{vote_&#8203;slot_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of counting an individual vote slot from a vote txn (per slot) (Vote slot was counted) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot_&#8203;counted</span><br/>{vote_&#8203;slot_&#8203;result="<span class="metrics-enum">too_&#8203;new</span>"} | counter | Result of counting an individual vote slot from a vote txn (per slot) (Vote slot was too far ahead of the votes root) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot_&#8203;counted</span><br/>{vote_&#8203;slot_&#8203;result="<span class="metrics-enum">unknown_&#8203;voter</span>"} | counter | Result of counting an individual vote slot from a vote txn (per slot) (Vote account was not in the voter set) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot_&#8203;counted</span><br/>{vote_&#8203;slot_&#8203;result="<span class="metrics-enum">already_&#8203;voted</span>"} | counter | Result of counting an individual vote slot from a vote txn (per slot) (Voter already voted for this slot) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot_&#8203;counted</span><br/>{vote_&#8203;slot_&#8203;result="<span class="metrics-enum">too_&#8203;old</span>"} | counter | Result of counting an individual vote slot from a vote txn (per slot) (Vote slot was behind the votes root) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;slot_&#8203;counted</span><br/>{vote_&#8203;slot_&#8203;result="<span class="metrics-enum">unknown_&#8203;slot</span>"} | counter | Result of counting an individual vote slot from a vote txn (per slot) (Vote slot was for a slot we haven't replayed) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;intermediate_&#8203;gate</span><br/>{vote_&#8203;intermediate_&#8203;gate="<span class="metrics-enum">proceed</span>"} | counter | Whether the last vote slot's replay state allowed counting the intermediate vote slots (per txn that reached slot counting) (Last vote slot was replayed and matched, intermediate vote slots will be counted) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;intermediate_&#8203;gate</span><br/>{vote_&#8203;intermediate_&#8203;gate="<span class="metrics-enum">unknown_&#8203;slot</span>"} | counter | Whether the last vote slot's replay state allowed counting the intermediate vote slots (per txn that reached slot counting) (Last vote slot was not replayed, intermediate vote slots skipped) |
| <span class="metrics-name">tower_&#8203;vote_&#8203;intermediate_&#8203;gate</span><br/>{vote_&#8203;intermediate_&#8203;gate="<span class="metrics-enum">unknown_&#8203;block_&#8203;id</span>"} | counter | Whether the last vote slot's replay state allowed counting the intermediate vote slots (per txn that reached slot counting) (Last vote slot block id did not match, intermediate vote slots skipped) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;writable_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of writable accounts acquired from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (0-128 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (129-512 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;evicted</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts evicted from the account database cache to make space, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;new</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of new (non-overwrite) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (0-128 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (129-512 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (513 B-2 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (2-8 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (8-32 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (32-128 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;committed_&#8203;overwrite</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of overwrite (existing fork+generation) account versions committed to the index, broken down by destination cache size class (1-10 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (0-128 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (129-512 B) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts that were needed for transaction execution but were not found in the account database cache, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;account_&#8203;waited</span> | counter | Number of accounts that were needed for transaction execution but were concurrently loading into cache by another transaction, causing the transaction to wait |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;batch_&#8203;acquired</span> | counter | Number of fd_accdb_acquire (batch acquire) calls made by this tile |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;acquire_&#8203;failed</span> | counter | Number of times we failed to acquire the cache lines needed for a transaction, and had to spin loop waiting |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;read_&#8203;operation</span> | counter | Number of read operations performed on the account database |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;bytes_&#8203;written</span> | counter | Number of bytes written to the account database |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;write_&#8203;operation</span> | counter | Number of write operations performed on the account database |
| <span class="metrics-name">tower_&#8203;accdb_&#8203;bytes_&#8203;copied</span> | counter | Number of bytes copied within the account database |

</div>

## Txsend Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;rx</span> | counter | QUIC packets received |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;rx_&#8203;bytes</span> | counter | Bytes received via QUIC |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx</span> | counter | QUIC packets sent |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;bytes</span> | counter | Bytes sent via QUIC |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;retry</span> | counter | QUIC Retry packets sent |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;in_&#8203;use</span> | gauge | QUIC connection slots currently in use (allocated from connection create until free, including handshaking connections) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">invalid</span>"} | gauge | QUIC connections in each state (Freed) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake</span>"} | gauge | QUIC connections in each state (Handshaking peer) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">handshake_&#8203;complete</span>"} | gauge | QUIC connections in each state (Handshake complete, confirming with peer) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">active</span>"} | gauge | QUIC connections in each state (Active connection) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">peer_&#8203;close</span>"} | gauge | QUIC connections in each state (Peer requested close) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">abort</span>"} | gauge | QUIC connections in each state (Connection terminating due to error) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">close_&#8203;pending</span>"} | gauge | QUIC connections in each state (Connection is closing) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;state</span><br/>{quic_&#8203;conn_&#8203;state="<span class="metrics-enum">dead</span>"} | gauge | QUIC connections in each state (Connection about to be freed) |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;created</span> | counter | Connections created |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;closed</span> | counter | Connections gracefully closed |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;aborted</span> | counter | Connections aborted |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;timed_&#8203;out</span> | counter | Connections timed out |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;retried</span> | counter | Connections established with retry |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;error_&#8203;no_&#8203;slots</span> | counter | Connections that failed to create due to lack of slots |
| <span class="metrics-name">txsend_&#8203;conn_&#8203;error_&#8203;retry_&#8203;failed</span> | counter | Connections that failed during retry (e.g. invalid token) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Packets that failed decryption (Initial) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Packets that failed decryption (Early data) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Packets that failed decryption (Handshake) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;crypto_&#8203;failed</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Packets that failed decryption (App data) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | Packets that failed decryption due to missing key (Initial) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">early</span>"} | counter | Packets that failed decryption due to missing key (Early data) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | Packets that failed decryption due to missing key (Handshake) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;key</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">app</span>"} | counter | Packets that failed decryption due to missing key (App data) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">initial</span>"} | counter | Packets with an unknown connection ID (Initial) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">retry</span>"} | counter | Packets with an unknown connection ID (Retry) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">handshake</span>"} | counter | Packets with an unknown connection ID (Handshake) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;no_&#8203;conn</span><br/>{quic_&#8203;pkt_&#8203;handle="<span class="metrics-enum">one_&#8203;rtt</span>"} | counter | Packets with an unknown connection ID (1-RTT) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;src_&#8203;invalid</span> | counter | Packets dropped due to a wrong source IP |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;alloc_&#8203;failed</span> | counter | Packet transmit jobs dropped due to allocation failure |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;net_&#8203;header_&#8203;invalid</span> | counter | Packets dropped due to weird IP or UDP header |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;header_&#8203;invalid</span> | counter | Packets dropped due to weird QUIC header |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;undersize</span> | counter | QUIC packets dropped due to being too small |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;oversize</span> | counter | QUIC packets dropped due to being too large |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;rx_&#8203;version_&#8203;negotiation</span> | counter | QUIC version negotiation packets received |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">initial</span>"} | counter | QUIC packets retransmitted (Initial) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">early</span>"} | counter | QUIC packets retransmitted (Early data) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">handshake</span>"} | counter | QUIC packets retransmitted (Handshake) |
| <span class="metrics-name">txsend_&#8203;pkt_&#8203;tx_&#8203;retransmitted</span><br/>{quic_&#8203;encryption_&#8203;level="<span class="metrics-enum">app</span>"} | counter | QUIC packets retransmitted (App data) |
| <span class="metrics-name">txsend_&#8203;handshake_&#8203;created</span> | counter | Handshake flows created |
| <span class="metrics-name">txsend_&#8203;handshake_&#8203;error_&#8203;alloc_&#8203;fail</span> | counter | Handshakes dropped due to alloc fail |
| <span class="metrics-name">txsend_&#8203;handshake_&#8203;evicted</span> | counter | Handshakes dropped due to eviction |
| <span class="metrics-name">txsend_&#8203;stream_&#8203;rx</span> | counter | Stream receive events |
| <span class="metrics-name">txsend_&#8203;stream_&#8203;rx_&#8203;bytes</span> | counter | Stream payload bytes received |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">unknown</span>"} | counter | QUIC frames received (Unknown frame type) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ack</span>"} | counter | QUIC frames received (ACK frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">reset_&#8203;stream</span>"} | counter | QUIC frames received (RESET_STREAM frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stop_&#8203;sending</span>"} | counter | QUIC frames received (STOP_SENDING frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">crypto</span>"} | counter | QUIC frames received (CRYPTO frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;token</span>"} | counter | QUIC frames received (NEW_TOKEN frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream</span>"} | counter | QUIC frames received (STREAM frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;data</span>"} | counter | QUIC frames received (MAX_DATA frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;stream_&#8203;data</span>"} | counter | QUIC frames received (MAX_STREAM_DATA frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">max_&#8203;streams</span>"} | counter | QUIC frames received (MAX_STREAMS frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">data_&#8203;blocked</span>"} | counter | QUIC frames received (DATA_BLOCKED frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">stream_&#8203;data_&#8203;blocked</span>"} | counter | QUIC frames received (STREAM_DATA_BLOCKED frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">streams_&#8203;blocked</span>"} | counter | QUIC frames received (STREAMS_BLOCKED(bidi) frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">new_&#8203;connection_&#8203;id</span>"} | counter | QUIC frames received (NEW_CONN_ID frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">retire_&#8203;connection_&#8203;id</span>"} | counter | QUIC frames received (RETIRE_CONN_ID frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;challenge</span>"} | counter | QUIC frames received (PATH_CHALLENGE frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">path_&#8203;response</span>"} | counter | QUIC frames received (PATH_RESPONSE frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">connection_&#8203;close_&#8203;quic</span>"} | counter | QUIC frames received (CONN_CLOSE(transport) frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">connection_&#8203;close_&#8203;app</span>"} | counter | QUIC frames received (CONN_CLOSE(app) frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">handshake_&#8203;done</span>"} | counter | QUIC frames received (HANDSHAKE_DONE frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">ping</span>"} | counter | QUIC frames received (PING frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;rx</span><br/>{quic_&#8203;frame_&#8203;type="<span class="metrics-enum">padding</span>"} | counter | QUIC frames received (PADDING frame) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;parse_&#8203;failed</span> | counter | QUIC frames that failed to parse |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;meta_&#8203;acquired</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Attempts to acquire QUIC frame metadata (Success) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;meta_&#8203;acquired</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;empty_&#8203;pool</span>"} | counter | Attempts to acquire QUIC frame metadata (PktMetaPoolEmpty) |
| <span class="metrics-name">txsend_&#8203;frame_&#8203;meta_&#8203;acquired</span><br/>{frame_&#8203;tx_&#8203;alloc_&#8203;result="<span class="metrics-enum">fail_&#8203;connection_&#8203;max</span>"} | counter | Attempts to acquire QUIC frame metadata (ConnMaxedInflightFrames) |
| <span class="metrics-name">txsend_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">noop</span>"} | counter | ACK events (Non-ACK-eliciting packet) |
| <span class="metrics-name">txsend_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">new</span>"} | counter | ACK events (New ACK range) |
| <span class="metrics-name">txsend_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">merged</span>"} | counter | ACK events (Merged into existing ACK range) |
| <span class="metrics-name">txsend_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">drop</span>"} | counter | ACK events (Out of buffers) |
| <span class="metrics-name">txsend_&#8203;ack_&#8203;tx</span><br/>{quic_&#8203;ack_&#8203;tx="<span class="metrics-enum">cancel</span>"} | counter | ACK events (ACK suppressed by handler) |
| <span class="metrics-name">txsend_&#8203;service_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent in service |
| <span class="metrics-name">txsend_&#8203;rx_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent processing packets |

</div>

## Diag Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">diag_&#8203;bundle_&#8203;status</span> | gauge | Precise status of the bundle subsystem: 0=disabled (no bundle tiles configured), 1=disconnected (all bundle tiles disconnected), 2=connecting (at least one bundle tile connecting, none connected or sleeping), 3=connected (at least one bundle tile connected), 4=sleeping (at least one bundle tile sleeping, none connected) |
| <span class="metrics-name">diag_&#8203;vote_&#8203;status</span> | gauge | Precise status of the vote subsystem: 0=disabled (non-voting or no tower tile), 1=not started (tower tile not running or no votes cast yet), 2=delinquent (vote distance exceeds threshold or vote stalled), 3=voting (voting normally) |
| <span class="metrics-name">diag_&#8203;replay_&#8203;status</span> | gauge | Precise status of the replay subsystem: 0=disabled (no replay tile), 1=not started (replay tile not running or slots are zero), 2=behind (replay lagging behind turbine or reset slot stalled), 3=running (replay keeping up) |
| <span class="metrics-name">diag_&#8203;turbine_&#8203;status</span> | gauge | Precise status of the turbine subsystem: 0=disabled (no shred or replay tiles), 1=not started (tiles not all running or turbine slot is zero), 2=stalled (turbine slot not advancing), 3=repair outpacing (repair byte throughput exceeds turbine), 4=running (turbine receiving normally) |
| <span class="metrics-name">diag_&#8203;device_&#8203;irq</span> | counter | Number of device IRQs across all CPUs |
| <span class="metrics-name">diag_&#8203;device_&#8203;irq_&#8203;undesired</span> | counter | Number of device hard IRQs that stole CPU time from fixed tiles |
| <span class="metrics-name">diag_&#8203;softirq</span><br/>{softirq="<span class="metrics-enum">net</span>"} | counter | Number of soft-IRQs across all CPUs (NET_TX, NET_RX) |
| <span class="metrics-name">diag_&#8203;softirq</span><br/>{softirq="<span class="metrics-enum">disk</span>"} | counter | Number of soft-IRQs across all CPUs (BLOCK) |
| <span class="metrics-name">diag_&#8203;softirq</span><br/>{softirq="<span class="metrics-enum">other</span>"} | counter | Number of soft-IRQs across all CPUs (e.g. TIMER, HRTIMER, IRQ_POLL, TASKLET, SCHED, RCU, ...) |
| <span class="metrics-name">diag_&#8203;softirq_&#8203;undesired</span><br/>{softirq="<span class="metrics-enum">net</span>"} | counter | Number of soft-IRQs that stole CPU time from fixed tiles (NET_TX, NET_RX) |
| <span class="metrics-name">diag_&#8203;softirq_&#8203;undesired</span><br/>{softirq="<span class="metrics-enum">disk</span>"} | counter | Number of soft-IRQs that stole CPU time from fixed tiles (BLOCK) |
| <span class="metrics-name">diag_&#8203;softirq_&#8203;undesired</span><br/>{softirq="<span class="metrics-enum">other</span>"} | counter | Number of soft-IRQs that stole CPU time from fixed tiles (e.g. TIMER, HRTIMER, IRQ_POLL, TASKLET, SCHED, RCU, ...) |

</div>

## Event Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">event_&#8203;conn_&#8203;state</span> | gauge | 0=disconnected, 1=connecting, 2=connected |
| <span class="metrics-name">event_&#8203;queue_&#8203;depth</span> | gauge | Total events in the event queue (sent-but-unacknowledged plus unsent) |
| <span class="metrics-name">event_&#8203;queue_&#8203;unsent</span> | gauge | Events in the event queue not yet sent to the event service |
| <span class="metrics-name">event_&#8203;queue_&#8203;dropped</span> | counter | Events dropped because the event queue was full |
| <span class="metrics-name">event_&#8203;queue_&#8203;bytes_&#8203;used</span> | gauge | Bytes used in the event queue |
| <span class="metrics-name">event_&#8203;queue_&#8203;bytes_&#8203;capacity</span> | gauge | Total capacity of the event queue, in bytes |
| <span class="metrics-name">event_&#8203;sent</span> | counter | Events sent to the event service |
| <span class="metrics-name">event_&#8203;acked</span> | counter | Events acknowledged by the event service |
| <span class="metrics-name">event_&#8203;last_&#8203;acked_&#8203;id</span> | gauge | Event id (nonce) of the most recently acknowledged event |
| <span class="metrics-name">event_&#8203;bytes_&#8203;written</span> | counter | Bytes written to the event service |
| <span class="metrics-name">event_&#8203;bytes_&#8203;read</span> | counter | Bytes read from the event service |
| <span class="metrics-name">event_&#8203;auth_&#8203;failed</span> | counter | Authentication failures with the event service |
| <span class="metrics-name">event_&#8203;invalid_&#8203;message</span> | counter | Malformed messages received from the event service |
| <span class="metrics-name">event_&#8203;conn_&#8203;attempt</span> | counter | Connection attempts to the event service |
| <span class="metrics-name">event_&#8203;handshake_&#8203;timeout</span> | counter | Authentication handshake timeouts with the event service |

</div>

## Gui Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">gui_&#8203;conn_&#8203;active</span> | gauge | Active HTTP connections to the GUI service, excluding connections that have been upgraded to a WebSocket connection |
| <span class="metrics-name">gui_&#8203;websocket_&#8203;conn_&#8203;active</span> | gauge | Active WebSocket connections to the GUI service |
| <span class="metrics-name">gui_&#8203;websocket_&#8203;frame_&#8203;tx</span> | counter | WebSocket frames sent to all connections to the GUI service |
| <span class="metrics-name">gui_&#8203;websocket_&#8203;frame_&#8203;rx</span> | counter | WebSocket frames received from all connections to the GUI service |
| <span class="metrics-name">gui_&#8203;bytes_&#8203;written</span> | counter | Bytes written to all connections to the GUI service |
| <span class="metrics-name">gui_&#8203;bytes_&#8203;read</span> | counter | Bytes read from all connections to the GUI service |

</div>

## Metric Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">metric_&#8203;boot_&#8203;timestamp_&#8203;nanos</span> | gauge | Timestamp when validator was started, in nanoseconds since epoch |
| <span class="metrics-name">metric_&#8203;conn_&#8203;active</span> | gauge | Active HTTP connections to the Prometheus endpoint |
| <span class="metrics-name">metric_&#8203;bytes_&#8203;written</span> | counter | Bytes written to all responses on the Prometheus endpoint |
| <span class="metrics-name">metric_&#8203;bytes_&#8203;read</span> | counter | Bytes read from all requests to the Prometheus endpoint |

</div>

## Rpc Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">rpc_&#8203;request_&#8203;duration_&#8203;seconds</span> | histogram | Duration spent in service |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">genesis</span>"} | counter | Number of RPC requests served (GET /genesis.tar.bz2) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">unknown</span>"} | counter | Number of RPC requests served (Unknown or unsupported method) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getAccountInfo</span>"} | counter | Number of RPC requests served (getAccountInfo) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getBalance</span>"} | counter | Number of RPC requests served (getBalance) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getBlockHeight</span>"} | counter | Number of RPC requests served (getBlockHeight) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getClusterNodes</span>"} | counter | Number of RPC requests served (getClusterNodes) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getEpochInfo</span>"} | counter | Number of RPC requests served (getEpochInfo) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getGenesisHash</span>"} | counter | Number of RPC requests served (getGenesisHash) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getHealth</span>"} | counter | Number of RPC requests served (getHealth) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getIdentity</span>"} | counter | Number of RPC requests served (getIdentity) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getInflationGovernor</span>"} | counter | Number of RPC requests served (getInflationGovernor) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getLatestBlockhash</span>"} | counter | Number of RPC requests served (getLatestBlockhash) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getMinimumBalanceForRentExemption</span>"} | counter | Number of RPC requests served (getMinimumBalanceForRentExemption) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getMultipleAccounts</span>"} | counter | Number of RPC requests served (getMultipleAccounts) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getSlot</span>"} | counter | Number of RPC requests served (getSlot) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getTransactionCount</span>"} | counter | Number of RPC requests served (getTransactionCount) |
| <span class="metrics-name">rpc_&#8203;request_&#8203;served</span><br/>{rpc_&#8203;method="<span class="metrics-enum">getVersion</span>"} | counter | Number of RPC requests served (getVersion) |
| <span class="metrics-name">rpc_&#8203;conn_&#8203;active</span> | gauge | The number of active HTTP connections to the RPC service |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;conn_&#8203;active</span> | gauge | The number of active WebSocket connections to the RPC service |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;subscription_&#8203;active</span><br/>{rpc_&#8203;event_&#8203;type="<span class="metrics-enum">vote</span>"} | gauge | The number of active WebSocket subscriptions to the RPC service, broken down by subscription type (vote) |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;subscription_&#8203;active</span><br/>{rpc_&#8203;event_&#8203;type="<span class="metrics-enum">slot</span>"} | gauge | The number of active WebSocket subscriptions to the RPC service, broken down by subscription type (slot) |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;event_&#8203;unique_&#8203;sent</span><br/>{rpc_&#8203;event_&#8203;type="<span class="metrics-enum">vote</span>"} | counter | Number of unique WebSocket events sent by the RPC service (vote) |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;event_&#8203;unique_&#8203;sent</span><br/>{rpc_&#8203;event_&#8203;type="<span class="metrics-enum">slot</span>"} | counter | Number of unique WebSocket events sent by the RPC service (slot) |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;event_&#8203;sent</span><br/>{rpc_&#8203;event_&#8203;type="<span class="metrics-enum">vote</span>"} | counter | Number of WebSocket events sent by the RPC service across all subscriptions (vote) |
| <span class="metrics-name">rpc_&#8203;websocket_&#8203;event_&#8203;sent</span><br/>{rpc_&#8203;event_&#8203;type="<span class="metrics-enum">slot</span>"} | counter | Number of WebSocket events sent by the RPC service across all subscriptions (slot) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (0-128 B) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (129-512 B) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (513 B-2 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (2-8 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (8-32 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (32-128 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (128 KiB-1 MiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;acquired</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts read from the account database, attributed to the cache size class of the account's current data size (1-10 MiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class0</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (0-128 B) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class1</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (129-512 B) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class2</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (513 B-2 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class3</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (2-8 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class4</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (8-32 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class5</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (32-128 KiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class6</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (128 KiB-1 MiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;not_&#8203;found</span><br/>{accdb_&#8203;cache_&#8203;class="<span class="metrics-enum">class7</span>"} | counter | Number of accounts that were not found in the account database cache and had to be read from disk, broken down by cache size class (1-10 MiB) |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;account_&#8203;waited</span> | counter | Number of accounts that had to wait for a concurrent writer to publish a disk offset before being read |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;batch_&#8203;acquired</span> | counter | Number of fd_accdb_acquire (batch acquire) calls made by this tile |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;bytes_&#8203;read</span> | counter | Number of bytes read from the account database |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;read_&#8203;operation</span> | counter | Number of read operations performed on the account database |
| <span class="metrics-name">rpc_&#8203;accdb_&#8203;bytes_&#8203;copied</span> | counter | Number of bytes copied out of the account database cache on a cache hit |

</div>

## Resolh Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">resolh_&#8203;txn_&#8203;no_&#8203;bank</span> | counter | Transactions dropped because the bank was not available |
| <span class="metrics-name">resolh_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">inserted</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was added to the stash) |
| <span class="metrics-name">resolh_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">overrun</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was dropped because the stash was full) |
| <span class="metrics-name">resolh_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">published</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was published as the blockhash became known) |
| <span class="metrics-name">resolh_&#8203;stash_&#8203;operation</span><br/>{resolve_&#8203;stash_&#8203;operation="<span class="metrics-enum">removed</span>"} | counter | Operations that happened on the transaction stash (A transaction with an unknown blockhash was removed from the stash without publishing, due to a bad LUT resolved failure, or no bank. These errors are double counted with the respective metrics for those categories) |
| <span class="metrics-name">resolh_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;lookup_&#8203;index</span>"} | counter | Address lookup tables resolved (The transaction referenced an index in a LUT that didn't exist) |
| <span class="metrics-name">resolh_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;uninitialized</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT hasn't been initialized) |
| <span class="metrics-name">resolh_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT couldn't be parsed) |
| <span class="metrics-name">resolh_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT wasn't owned by the ALUT program ID) |
| <span class="metrics-name">resolh_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Address lookup tables resolved (The account referenced as a LUT couldn't be found) |
| <span class="metrics-name">resolh_&#8203;lut_&#8203;resolved</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Address lookup tables resolved (Resolved successfully) |
| <span class="metrics-name">resolh_&#8203;blockhash_&#8203;expired</span> | counter | Transactions that failed to resolve because the blockhash was expired |
| <span class="metrics-name">resolh_&#8203;txn_&#8203;bundle_&#8203;peer_&#8203;failed</span> | counter | Transactions that failed to resolve because a peer transaction in the bundle failed |

</div>

## Bank Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">bank_&#8203;txn_&#8203;sanitize_&#8203;failed</span> | counter | Transactions that failed to sanitize |
| <span class="metrics-name">bank_&#8203;txn_&#8203;not_&#8203;executed_&#8203;failed</span> | counter | Transactions that did not execute. Different from transactions that fail to execute, which make it onto the chain |
| <span class="metrics-name">bank_&#8203;txn_&#8203;load_&#8203;address_&#8203;table</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;lookup_&#8203;index</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported (The transaction referenced an index in a LUT that didn't exist) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;load_&#8203;address_&#8203;table</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;uninitialized</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported (The account referenced as a LUT hasn't been initialized) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;load_&#8203;address_&#8203;table</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;data</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported (The account referenced as a LUT couldn't be parsed) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;load_&#8203;address_&#8203;table</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">invalid_&#8203;account_&#8203;owner</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported (The account referenced as a LUT wasn't owned by the ALUT program ID) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;load_&#8203;address_&#8203;table</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported (The account referenced as a LUT couldn't be found) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;load_&#8203;address_&#8203;table</span><br/>{lut_&#8203;resolve_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Result of loading address lookup tables for a transaction. If there are multiple errors for the transaction, only the first one is reported (Resolved successfully) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">success</span>"} | counter | Result of loading and executing a transaction (Success) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;in_&#8203;use</span>"} | counter | Result of loading and executing a transaction (An account is already being processed in another transaction in a way that does not support parallelism) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;loaded_&#8203;twice</span>"} | counter | Result of loading and executing a transaction (A `Pubkey` appears twice in the transaction's `account_keys`. Instructions can reference `Pubkey`s more than once but the message must contain a list with no duplicate keys) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (Attempt to debit an account but found no record of a prior credit) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">program_&#8203;account_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (Attempt to load a program that does not exist) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (The fee payer `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;account_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (This account may not be used to pay transaction fees) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">already_&#8203;processed</span>"} | counter | Result of loading and executing a transaction (The bank has seen this transaction before. This can occur under normal operation when a UDP packet is duplicated, as a user error from a client not updating its `recent_blockhash`, or as a double-spend attack) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">blockhash_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (The bank has not seen the given `recent_blockhash` or the transaction is too old and the `recent_blockhash` has been discarded) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">instruction_&#8203;error</span>"} | counter | Result of loading and executing a transaction (An error occurred while processing an instruction) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">call_&#8203;chain_&#8203;too_&#8203;deep</span>"} | counter | Result of loading and executing a transaction (Loader call chain is too deep) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">missing_&#8203;signature_&#8203;for_&#8203;fee</span>"} | counter | Result of loading and executing a transaction (Transaction requires a fee but has no signature present) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;account_&#8203;index</span>"} | counter | Result of loading and executing a transaction (Transaction contains an invalid account reference) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">signature_&#8203;failure</span>"} | counter | Result of loading and executing a transaction (Transaction did not pass signature verification) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;program_&#8203;for_&#8203;execution</span>"} | counter | Result of loading and executing a transaction (This program may not be used for executing instructions) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">sanitize_&#8203;failure</span>"} | counter | Result of loading and executing a transaction (Transaction failed to sanitize accounts offsets correctly implies that account locks are not taken for this TX, and should not be unlocked) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">cluster_&#8203;maintenance</span>"} | counter | Result of loading and executing a transaction (Transactions are currently disabled due to cluster maintenance) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">account_&#8203;borrow_&#8203;outstanding</span>"} | counter | Result of loading and executing a transaction (Transaction processing left an account with an outstanding borrowed reference) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;max_&#8203;block_&#8203;cost_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (Transaction would exceed max Block Cost Limit) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">unsupported_&#8203;version</span>"} | counter | Result of loading and executing a transaction (Transaction version is unsupported) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;writable_&#8203;account</span>"} | counter | Result of loading and executing a transaction (Transaction loads a writable account that cannot be written) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;max_&#8203;account_&#8203;cost_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (Transaction would exceed max account limit within the block) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;block_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (Transaction would exceed account data limit within the block) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">too_&#8203;many_&#8203;account_&#8203;locks</span>"} | counter | Result of loading and executing a transaction (Transaction locked too many accounts) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">address_&#8203;lookup_&#8203;table_&#8203;not_&#8203;found</span>"} | counter | Result of loading and executing a transaction (Address lookup table not found) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;owner</span>"} | counter | Result of loading and executing a transaction (Attempted to lookup addresses from an account owned by the wrong program) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;data</span>"} | counter | Result of loading and executing a transaction (Attempted to lookup addresses from an invalid account) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;address_&#8203;lookup_&#8203;table_&#8203;index</span>"} | counter | Result of loading and executing a transaction (Address table lookup uses an invalid index) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;rent_&#8203;paying_&#8203;account</span>"} | counter | Result of loading and executing a transaction (Transaction leaves an account with a lower balance than rent-exempt minimum) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;max_&#8203;vote_&#8203;cost_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (Transaction would exceed max Vote Cost Limit) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">would_&#8203;exceed_&#8203;account_&#8203;data_&#8203;total_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (Transaction would exceed total account data limit) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">duplicate_&#8203;instruction</span>"} | counter | Result of loading and executing a transaction (Transaction contains a duplicate instruction that is not allowed) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">insufficient_&#8203;funds_&#8203;for_&#8203;rent</span>"} | counter | Result of loading and executing a transaction (Transaction results in an account with insufficient funds for rent) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">max_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;exceeded</span>"} | counter | Result of loading and executing a transaction (Transaction exceeded max loaded accounts data size cap) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">invalid_&#8203;loaded_&#8203;accounts_&#8203;data_&#8203;size_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (LoadedAccountsDataSizeLimit set for transaction must be greater than 0) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">resanitization_&#8203;needed</span>"} | counter | Result of loading and executing a transaction (Sanitized transaction differed before/after feature activation. Needs to be resanitized) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">program_&#8203;execution_&#8203;temporarily_&#8203;restricted</span>"} | counter | Result of loading and executing a transaction (Program execution is temporarily restricted on an account) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">unbalanced_&#8203;transaction</span>"} | counter | Result of loading and executing a transaction (The total balance before the transaction does not equal the total balance after the transaction) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">program_&#8203;cache_&#8203;hit_&#8203;max_&#8203;limit</span>"} | counter | Result of loading and executing a transaction (The total program cache size hit the maximum allowed limit) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">commit_&#8203;cancelled</span>"} | counter | Result of loading and executing a transaction (The process for committing the transaction was cancelled internally) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;result</span><br/>{transaction_&#8203;error="<span class="metrics-enum">bundle_&#8203;peer</span>"} | counter | Result of loading and executing a transaction (Transaction is part of a bundle and one of the peer transactions failed) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;processing_&#8203;failed</span> | counter | Transactions for which the processing stage failed and won't land on chain |
| <span class="metrics-name">bank_&#8203;txn_&#8203;fee_&#8203;only</span> | counter | Transactions that will land on chain but without executing |
| <span class="metrics-name">bank_&#8203;txn_&#8203;executed</span><br/>{txn_&#8203;execute_&#8203;result="<span class="metrics-enum">success</span>"} | counter | Transactions that execute on chain, by outcome (Executed on chain and succeeded) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;executed</span><br/>{txn_&#8203;execute_&#8203;result="<span class="metrics-enum">failed</span>"} | counter | Transactions that execute on chain, by outcome (Executed on chain but failed) |
| <span class="metrics-name">bank_&#8203;txn_&#8203;cost_&#8203;model_&#8203;undercount</span> | counter | Transactions that used more CUs than the cost model should have permitted them to |

</div>

## Pohh Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">pohh_&#8203;begin_&#8203;leader_&#8203;delay_&#8203;seconds</span> | histogram | Delay between when we become leader in a slot and when we receive the bank |
| <span class="metrics-name">pohh_&#8203;first_&#8203;microblock_&#8203;delay_&#8203;seconds</span> | histogram | Delay between when we become leader in a slot and when we receive the first microblock |
| <span class="metrics-name">pohh_&#8203;slot_&#8203;done_&#8203;delay_&#8203;seconds</span> | histogram | Delay between when we become leader in a slot and when we finish the slot |
| <span class="metrics-name">pohh_&#8203;bundle_&#8203;initialize_&#8203;delay_&#8203;seconds</span> | histogram | Delay in starting the slot caused by loading the information needed to generate the bundle crank transactions |

</div>

## Store Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">store_&#8203;txn_&#8203;inserted</span> | counter | Transactions produced while we were leader in the shreds that have been inserted so far |

</div>

## Backt Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">backt_&#8203;final_&#8203;slot</span> | gauge | Slot after which the backtest will complete |
| <span class="metrics-name">backt_&#8203;start_&#8203;slot</span> | gauge | Slot at which the backtest started |

</div>

## Benchs Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">benchs_&#8203;txn_&#8203;tx</span> | counter | Benchmark transactions sent |

</div>

## Guih Tile

<div class="metrics">

| Metric | Type | Description |
|--------|------|-------------|
| <span class="metrics-name">guih_&#8203;conn_&#8203;active</span> | gauge | Active HTTP connections to the GUI service, excluding connections that have been upgraded to a WebSocket connection |
| <span class="metrics-name">guih_&#8203;websocket_&#8203;conn_&#8203;active</span> | gauge | Active WebSocket connections to the GUI service |
| <span class="metrics-name">guih_&#8203;websocket_&#8203;frame_&#8203;tx</span> | counter | WebSocket frames sent to all connections to the GUI service |
| <span class="metrics-name">guih_&#8203;websocket_&#8203;frame_&#8203;rx</span> | counter | WebSocket frames received from all connections to the GUI service |
| <span class="metrics-name">guih_&#8203;bytes_&#8203;written</span> | counter | Bytes written to all connections to the GUI service |
| <span class="metrics-name">guih_&#8203;bytes_&#8203;read</span> | counter | Bytes read from all connections to the GUI service |

</div>
