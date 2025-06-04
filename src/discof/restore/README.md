# Snapshot Restore

## Philosophy

Firedancer is optimized to restore snapshots as fast as possible, i.e.
at I/O and memory bandwidth limits.

Fast snapshot restore time is not only helpful for operators, but
crucial for fast recovery from failures, which may be widespread in the
worst case.

To meet these performance requirements, a multi-layer scaling approach
is used:

- **SIMD:** Cryptographic computations (hashing) are accelerated via
  AVX2 / AVX10 SIMD instructions
- **ILP:** Performance-critical logic is hand-optimized for good single-core
  throughput on AMD Zen 2 (parallel random memory accesses via prefetching,
  non-temporal memory copies, xxHash3 hashing)
- **Thread parallelism:** Certain algorithms redesigned as massively
  parallel batch computations (e.g. parallel hashmap insert via sample sort)
- **Pipelining:** Snapshot loading step run concurrently / streaming if
  possible.  Each step is pinned to a core and independently scalable
  for ideal throughput and efficient cache utilization.

## Pipeline

Phase 1: Ingest accounts into memory

```
FileRd -> UnZstd -> SnapIn -> FnkAlc -> FnkCpy
```

- FileRd: Reads a file
- UnZstd: Does Zstandard decompression
- SnapIn: Reads a snapshot
- FnkAlc: Allocates funk heap memory
- FnkCpy: Copies account data out to funk memory

Phase 2: Index accounts

```
ActIdx -> ActDup
```

- ActIdx: Indexes accounts
- ActDup: Deletes duplicate accounts

## Stream link conventions

Various snapshot components use byte streams, not packet streams.

These require custom conventions.

**Stream fragment descriptors**

Byte streams use `fd_stream_frag_meta_t` (defined in `fd_restore_base.h`).

These have the following changes:
- `chunk` is replaced by `goff` and `loff`, which are 64-bit offsets
  describing the stream offset and dcache offset respectively
- `tsorig` / `tspub` are removed (latency is less relevant)
- `sig` is removed (cannot filter without looking at stream data)
- `sz` is widened to 32 bits.

**Dcache allocations**

Payloads in stream dcaches are unaligned.  Payloads are addressed with
uncompressed byte offsets relative to the workspace start.

(Compare this to the usual compact packet dcaches, which use 64 byte
aligned chunks with compressed addressing.)

**Stream backpressure**

Byte streams naturally require a reliable transport.

Consumers periodically publish their progress in `fseq`.
- `fseq[0]` is the lowest sequence number not yet consumed (standard)
- `fseq[1]` is the stream offset of the next byte not yet consumed

**Frames in streams**

Tiles can reference stream data zero-copy style.  For example, the
`SnapIn` tile publishes fragments describing the accounts it parsed out
of a snapshot stream, where each fragment refers to a byte range in the
stream dcache.
