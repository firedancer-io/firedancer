# Frankendancer Filtering

The block diagram below illustrates the historical (ca 2023-Sep)
transaction filtering pipeline for the block production.

```
                    from external facing NICs
  (interface via mixture of AF_XDP, sockets, ENA, IO uring, DPDK,                      nic ideally near numa node as
    Verbs, Mellanox Exanic, Solarflare, Intel RDMA, PCAP, ...)                         corresponding ingress processing core
     |               |                               |
     | raw           | raw                           | raw
     | packets       | packets                       | packets
     |               |                               |
     |       +------ | ------+--------- ... -------- | ------+-----------+
     |       |       |       |                       |       |           |
     |       v       |       v                       |       v           |
     |  +- wksp --+  |  +- wksp --+                  |  +- wksp --+      |
     |  |  FSEQ   |  |  |  FSEQ   |     ...          |  |  FSEQ   |      |
     |  +---------+  |  +---------+                  |  +---------+      |
     |       |       |       |                       |       |           |
     v       v       v       v                       v       v           |
  +--- core ----+ +--- core ----+                 +--- core ----+        |             cores ideally near numa node as connected
  | NIC / QUIC  | | NIC / QUIC  |                 | NIC / QUIC  |        | flow        obj wksps, several flavors of these tiles
  | SIG VERIFY  | | SIG VERIFY  |       ...       | SIG VERIFY  |        | control     for different HPC NIC interface styles,
  |  DEDUP TAG  | |  DEDUP TAG  |                 |  DEDUP TAG  |        | info        up to 64-bit tags (per validator run
  +-------------+ +-------------+                 +-------------+        |             randomized tagging scheme for robustness)
     |       |       |       |                       |       |           |
     |       v       |       v                       |       v           |
     |  +- wksp --+  |  +- wksp --+                  |  +- wksp --+      |
     |  | MCACHE  |  |  | MCACHE  |     ...          |  | MCACHE  |      |             very deep
     |  +---------+  |  +---------+                  |  +---------+      |
     |       |       |      |                        |       |           |
     |       |       |      |                        |       |    +--- core ----+      core ideally near numa node as connected
     |       v       |      v                        |       v    | FILT RECENT |      obj wksps, performance liekly bounded by NOC
     |       +------ | -----+---------- ... -------- | ------+--->|  DUP TAGS   |      metadata handling limit (i.e. undeduped
     |               |   metadata w/tag              |            |     MUX     |      transaction rate, not raw packet bandwidth)
     |               |    for verified               |            +-------------+
     |               |    transactions               |               |       ^
     v               v                               v               v       |
+- wksp --+     +- wksp --+                     +- wksp --+     +- wksp --+  |
| DCACHE  |     | DCACHE  |             ...     | DCACHE  |     | MCACHE  |  |         very deep
+---------+     +---------+                     +---------+     +---------+  |
     |               |                               |               |       |
     v               v                               v               |  +- wksp --+
     +---------------+------------+---- ... ---------+               |  |  FSEQ   |
               verified           |                                  |  +---------+
             transactions         |                                  |       ^
                                  |         +------------------------+       |
                                  |         |     sequenced metadata         |
                                  v         v    for deduped verified        |
                               +---- core -----+     transactions            |
                               |     BLOCK     |                             |         core ideally near numa node as connected
                               |    PACKING    |-----------------------------+         obj wksps, performance likely bounded by NOC
                               |               |      flow control info                deduped transaction payload bandwidth
                               +---------------+
                                       |
                                       | blocks
                                       v
                               +---- wksp -----+                                       very deep, consider implementing as
                               |  block store  |                                       MCACHE / DCACHE pair with Rust shims for use
                               +---------------+                                       in Agave validator
                                       |
                                       v
                              to Agave validator
                             for block distribution
                                 and execution
```

- cnc / monitoring communication flows omitted for clarity

- Targets using a high core count recent x86 CPUs with one or more CPU
  sockets.  No custom hardware but see below.

- Target 1 gigantic page backed wksp for shared memory objects per each
  NUMA node used.  Ideally should keep the number of NUMA nodes touched
  by each core minimal in core / wksp placement.

- Use of named wksp allows dynamic inspection, monitoring, debugging of
  live operations / non-invasive capture of components inputs / etc
  (standard UNIX permissions model).

- Similarly, support for hotswapping individual components live (e.g.
  adding / removing ingress tiles on the fly to deal with load changes,
  failed hardware, etc) is possible long term under this model.

- This plus the above allows use of captures / replay for reproducible
  development and debugging of individual components in isolation.

- Can run the above as a single process / multi-threaded model or as a
  multi-process / multi-threaded model or any mix in between.  Current
  implementation is single process with named workspaces with support
  for quick refactoring into multi-process model if useful.

- Communications path from NIC(s) to Agave validator is reliable for
  simplicity / reproducibility.

- And, as such, these sub-components could potentially be moved (in part
  or in whole) into FPGA / ASIC / GPU accelerated (as might be useful
  long term) so long as they follow the Tango ABI.

- Assumes DEDUP needs to be done after SIG VERIFY due to encryption and
  the like.

- Uses Tango metadata signature field (and maybe other bits) to do
  transaction tagging to parallelize dedup calculations and support
  horizontal scaling (e.g. multiple high bandwidth NICs for high through
  ingress and high core count available for SIG-VERIFY parallelization).

- SIG VERIFY naturally should produce a cryptographically secure as part
  of the SHA-512 computation for use by dedup with no additional
  computation.  If for whatever reason this isn't usable, any number
  of hashing algorithms could be run in parallel.

- NIC / QUIC / SIG VERIFY / TAG core can be pipelined vertically over
  multiple cores if useful in addition to the horizontal support already
  implemented for additional compute bandwidth.
