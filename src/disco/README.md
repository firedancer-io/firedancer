# Firedancer

## Architecture

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
                               |     BLOCK     |                             |         core ideally near muma node as connected
                               |    PACKING    |-----------------------------+         obj wksps, performance likely bounded by NOC
                               |               |      flow control info                deduped transaction payload bandwidth
                               +---------------+
                                       |
                                       | blocks
                                       v
                               +---- wksp -----+                                       very deep, consider implementing as
                               |  block store  |                                       MCACHE / DCACHE pair with Rust shims for use
                               +---------------+                                       in Solana validator
                                       |
                                       v
                              to Solana validator
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

- Communications path from NIC(s) to Solana validator is reliable for
  simplicitly / reproducibility.

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

## Configuration

### Pod layout for low level configuration

```
[path to this app instance's config] {

  # There are 3 + verify_cnt tiles used by the app.  verify_cnt is implied
  # by the number of verify pods below.
  #
  # The logical tile indices for the main, pack and dedup tiles are
  # independent of the number of verifiers.
  #
  # Further, since all IPC structures below are in a named workspace,
  # monitors / debuggers with appropriate permissions can inspect the
  # data flows non-invasively real time and/or issue commands to
  # individual tiles out-of-band.
  #
  # The use of the pod and wksp allows this to be refactored into a
  # multi-process model with minimal changes and/or allow for additional
  # verify tiles to be dynamically attached / removed while running
  # longer term if desirable.

  main {

    # Run logical tile 0 and largely sleeps (reasonable to float)

    cnc [gaddr] # Location of this tile's command-and-control

    # Additional configuration information specific to this tile here
    # (all unrecognized fields will be silently ignored)

  }

  pack {

    # Runs on logical tile 1 and largely spins (ideally on a dedicated
    # core near NUMA node for IPC structures used by this tile)

    cnc  [gaddr] # Location of this tile's command-and-control

    seed [uint]  # This tile's random number generator seed
                 # Optional: tile_idx if not provided

    # Additional configuration information specific to this tile here
    # (all unrecognized fields will be silently ignored)

  }

  dedup {
  
    # Runs on logical tile 2 and largely spins (ideally on a dedicated
    # core near NUMA node for IPC structures used by this tile)

    cnc     [gaddr] # Location of this tile's command-and-control
    tcache  [gaddr] # Location of this tile's unique frag signature cache
    mcache  [gaddr] # Location of this tile's deduped verified frag metadata cache
    fseq    [gaddr] # Location where this tile receives flow control from the pack tile
    cr_max  [ulong] # Max credits for publishing to pack
                    # 0: use reasonable default
                    # Optional: 0 if not provided
    lazy    [long]  # Flow control laziness (in ns)
                    # <=0: use reasonable default
                    # Optional: 0 if not provided
    seed    [uint]  # This tile's random number generator seed
                    # Optional: tile_idx if not provided

    # Additional configuration information specific to this tile here
    # (all unrecognized fields will be silently ignored)

  }

  verify {

    # verify_cnt pods in this pod

    [verify_idx name] {
    
      # Runs on logical tile 3+verify_idx and largely spins (ideally on
      # a dedicated core near NUMA node for NIC and IPC structures).
      #
      # While users should not be exposed to it directly, the index of a
      # verify starts from 0 and is sequentially assigned based on the
      # order of the subpods in the config.

      cnc       [gaddr] # Location of this tile's command-and-control
      mcache    [gaddr] # Location of this tile's verified frag metadata cache
      dcache    [gaddr] # Location of this tile's verified frag payload cache
      fseq      [gaddr] # Location where this tile receives flow control from the dedup tile
      cr_max    [ulong] # Max credits for publishing to dedup
                        # 0: use reasonable default
                        # Optional: 0 if not provided
      cr_resume [ulong] # Credit thresh to stop polling dedup for credits
                        # 0: use reasonable default
                        # Optional: 0, if not provided
      cr_refill [ulong] # Credit thresh to start polling dedup for credits
                        # 0: use reasonable default
                        # Optional: 0, if not provided
      lazy      [long]  # Flow control laziness (in ns)
                        # <=0: use reasonable default
                        # Optional: 0 if not provided
      seed      [uint]  # This tile's random number generator seed
                        # Optional: tile_idx if not provided

      # Additional configuration information specific to this tile here
      # (all unrecognized fields will be silently ignored)

    }

    # Additional configuration information specific to all verify tiles
    # here (all unrecognized fields will be silently ignored).  Any such
    # configuration information should not be in a pod.

  }

  # Additional configuration information specific to this app instance
  # (all unrecognized fields will be silently ignored)
}

# (all other fields outside this path will be silently ignored)
```

