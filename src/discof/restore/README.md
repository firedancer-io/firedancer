# Snapshot Restore

## Stream link conventions

Various snapshot components use byte streams, not packet streams.

These require custom conventions.

**Stream fragment descriptors**

Byte streams use `fd_frag_stream_meta_t` (defined in `fd_restore_base.h`).

These have the following changes:
- `chunk` is replaced by `goff` and `loff`, which are 64-bit offsets
  describing the stream offset and dcache offset respectively
- `tsorig` / `tspub` are removed (latency is less relevant)
- `sig` is removed (cannot filter without looking at stream data)
- `sz` is widened to 32 bits.

`**Dcache allocations**

Payloads in stream dcaches are unaligned.  Payloads are addressed with
uncompressed byte offsets relative to the workspace start.

(Compare this to the usual compact packet dcaches, which use 64 byte
aligned chunks with compressed addressing.)

**Stream backpressure**

Byte streams naturally require a reliable transport.

Consumers periodically publish their progress in `fseq`.
- `fseq[0]` is the lowest sequence number not yet consumed (standard)
- `fseq[1]` is the stream offset of the next byte not yet consumed
`