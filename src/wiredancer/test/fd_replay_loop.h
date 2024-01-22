#ifndef HEADER_fd_src_disco_replay_fd_replay_h
#define HEADER_fd_src_disco_replay_fd_replay_h

/* fd_replay provides services to replay data from a pcap file into a
   tango frag stream. */

#include "../../disco/fd_disco_base.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* Beyond the standard FD_CNC_SIGNAL_HALT, FD_REPLAY_CNC_SIGNAL_ACK can
   be raised by a cnc thread with an open command session while the
   replay is in the RUN state.  The replay will transition from ACK->RUN
   the next time it processes cnc signals to indicate it is running
   normally.  If a signal other than ACK, HALT, or RUN is raised, it
   will be logged as unexpected and transitioned by back to RUN. */

#define FD_REPLAY_CNC_SIGNAL_ACK (4UL)

/* A fd_replay_tile will use the fseq and cnc application regions
   to accumulate flow control diagnostics in the standard ways.  It
   additionally will accumulate to the cnc application region the
   following tile specific counters:

     CHUNK_IDX     is the chunk idx where reply tile should start publishing payloads on boot (ignored if not valid on boot)
     PCAP_DONE     is cleared before the tile starts processing the pcap and is set when the pcap processing is done
     PCAP_PUB_CNT  is the number of pcap packets published by the replay
     PCAP_PUB_SZ   is the number of pcap packet payload bytes published by the replay
     PCAP_FILT_CNT is the number of pcap packets filtered by the replay
     PCAP_FILT_SZ  is the number of pcap packet payload bytes filtered by the replay

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at
   tile startup (as such that they can be accumulated over multiple
   runs).  Clearing is up to monitoring scripts. */

#define FD_REPLAY_CNC_DIAG_CHUNK_IDX     (2UL) /* On 1st cache line of app region, updated by producer, frequently */
#define FD_REPLAY_CNC_DIAG_PCAP_DONE     (3UL) /* ", rarely */
#define FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT  (4UL) /* ", frequently */
#define FD_REPLAY_CNC_DIAG_PCAP_PUB_SZ   (5UL) /* ", frequently */
#define FD_REPLAY_CNC_DIAG_PCAP_FILT_CNT (6UL) /* ", frequently */
#define FD_REPLAY_CNC_DIAG_PCAP_FILT_SZ  (7UL) /* ", frequently */

/* FD_REPLAY_TILE_OUT_MAX are the maximum number of outputs a replay
   tile can have.  These limits are more or less arbitrary from a
   functional correctness POV.  They mostly exist to set some practical
   upper bounds for things like scratch footprint. */

#define FD_REPLAY_TILE_OUT_MAX FD_FRAG_META_ORIG_MAX

/* FD_REPLAY_TILE_SCRATCH_{ALIGN,FOOTPRINT} specify the alignment and
   footprint needed for a replay tile scratch region that can support
   out_cnt outputs.  ALIGN is an integer power of 2 of at least double
   cache line to mitigate various kinds of false sharing.  FOOTPRINT
   will be an integer multiple of ALIGN.  out_cnt is assumed to be valid
   (i.e. at most FD_REPLAY_TILE_OUT_MAX).  These are provided to
   facilitate compile time declarations. */

#define FD_REPLAY_TILE_SCRATCH_ALIGN (128UL)
#define FD_REPLAY_TILE_SCRATCH_FOOTPRINT( out_cnt )  \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,  \
    FD_FCTL_ALIGN, FD_FCTL_FOOTPRINT( (out_cnt) ) ), \
    FD_REPLAY_TILE_SCRATCH_ALIGN )

FD_PROTOTYPES_BEGIN

/* fd_replay_tile replays a packets in a pcap file as a tango fragment
   stream from origin orig into the given mcache and dcache.  The tile
   can send to out_cnt reliable consumers and an arbitrary number of
   unreliable consumers.  (While reliable consumers are simple to reason
   about, they have especially high demands on their implementation as a
   single slow reliable consumer can backpressure the replay and _all_
   other consumers using the replay.)

   When this is called, the cnc should be in the BOOT state.  Returns 0
   on a successful run of the replay tile.  That is, the tile booted
   successfully (transitioning the cnc from BOOT->RUN), ran (handling
   any application specific cnc signals while running), and (after
   receiving a HALT signal) halted successfully (transitioning the cnc
   from HALT->BOOT before return).  Returns a non-zero error code if the
   tile fails to boot up (logs details ... the cnc will not be
   transitioned from its original state and thus is likely bootable
   again if its original state was BOOT).  For maximally robust
   operation in the current implementation, all reliable consumers
   should be halted and/or caught up before this tile is halted.

   There are no theoretical restrictions on the mcache depth.
   Practically, it is recommend it be as large as possible, especially
   for bursty streams and/or a large number of reliable consumers.  This
   implementation indexes chunks relative to the workspace used by the
   mcache to facilitate easy muxing.  The dcache size should be adequate
   for compact writing.

   cr_max is the maximum number of flow control credits the replay tile
   is allowed for publishing frags.  It represents the maximum number of
   frags a reliable out can lag behind the output stream.  In the
   general case, the optimal value is usually
   min(mcache.depth,out[*].lag_max).  If cr_max is zero, mcache.depth
   will be used as a default for cr_max.  This is equivalent to
   assuming, as is typically the case, outs are allowed to lag the
   replay by up mcache.depth frags.

   lazy is the ballpark interval in ns for how often to receive credits
   from consumers.  Too small a lazy will drown the system in cache
   coherence traffic.  Too large a lazy will degrade system throughput
   because of producers stalled, waiting for credits.  lazy should be
   roughly proportional to cr_max and the constant of proportionality
   should be less than the smaller of how fast a producer can generate
   frags / how fast a consumer can process frags typically.  <=0
   indicates to pick a conservative default.

   scratch points to tile scratch memory.  fd_replay_tile_scratch_align
   and fd_replay_tile_scratch_footprint return the required alignment
   and footprint needed for this region.  This memory region is
   exclusively owned by the replay tile while the tile is running and is
   ideally near the core running the replay tile.
   fd_replay_tile_scratch_align will return the same value as
   FD_REPLAY_TILE_SCRATCH_ALIGN.  If out_cnt is not valid,
   fd_replay_tile_scratch_footprint silently returns 0 so callers can
   diagnose configuration issues.  Otherwise,
   fd_replay_tile_scratch_footprint will return the same value as
   FD_REPLAY_TILE_SCRATCH_FOOTPRINT.
   
   The lifetime of the cnc, mcache, dcache, out_fseq[*], rng and scratch
   used by this tile should be a superset of this tile's lifetime.
   While this tile is running, no other tile should use cnc for its
   command and control, publish into mcache or dcache, use the rng for
   anything (and the rng should be seeded distinctly from all other rngs
   in the system), or use scratch for anything.  This tile uses the
   fseqs passed to it in the usual producer ways (e.g. discovering the
   location of reliable consumers in the mcache's sequence space and
   updating producer oriented diagnostics).  The out_fseq array and
   pcap_path cstr will not be used the after the tile has successfully
   booted (transitioned the cnc from BOOT to RUN) or returned (e.g.
   failed to boot), whichever comes first. */

FD_FN_CONST ulong
fd_replay_tile_scratch_align( void );

FD_FN_CONST ulong
fd_replay_tile_scratch_footprint( ulong out_cnt );

int
fd_replay_tile( fd_cnc_t *       cnc,       /* Local join to the replay's command-and-control */
                char const *     pcap_path, /* Points to first byte of cstr with the path to the pcap to use */
                ulong            pkt_max,   /* Upper bound of a size of packet in the pcap */
                ulong            orig,      /* Origin for this pcap fragment stream, in [0,FD_FRAG_META_ORIG_MAX) */
                fd_frag_meta_t * mcache,    /* Local join to the replay's frag stream output mcache */
                uchar *          dcache,    /* Local join to the replay's frag stream output dcache */
                ulong            out_cnt,   /* Number of reliable consumers, reliable consumers are indexed [0,out_cnt) */
                ulong **         out_fseq,  /* out_fseq[out_idx] is the local join to reliable consumer out_idx's fseq */
                ulong            cr_max,    /* Maximum number of flow control credits, 0 means use a reasonable default */
                long             lazy,      /* Lazyiness, <=0 means use a reasonable default */
                fd_rng_t *       rng,       /* Local join to the rng this replay should use */
                void *           scratch ); /* Tile scratch memory */

int
fd_replay_tile_loop( fd_cnc_t *       cnc,       /* Local join to the replay's command-and-control */
                     char const *     pcap_path, /* Points to first byte of cstr with the path to the pcap to use */
                     ulong            pkt_max,   /* Upper bound of a size of packet in the pcap */
                     ulong            orig,      /* Origin for this pcap fragment stream, in [0,FD_FRAG_META_ORIG_MAX) */
                     fd_frag_meta_t * mcache,    /* Local join to the replay's frag stream output mcache */
                     uchar *          dcache,    /* Local join to the replay's frag stream output dcache */
                     ulong            out_cnt,   /* Number of reliable consumers, reliable consumers are indexed [0,out_cnt) */
                     ulong **         out_fseq,  /* out_fseq[out_idx] is the local join to reliable consumer out_idx's fseq */
                     ulong            cr_max,    /* Maximum number of flow control credits, 0 means use a reasonable default */
                     long             lazy,      /* Lazyiness, <=0 means use a reasonable default */
                     fd_rng_t *       rng,       /* Local join to the rng this replay should use */
                     void *           scratch ); /* Tile scratch memory */

FD_PROTOTYPES_END

#endif

#endif /* HEADER_fd_src_disco_replay_fd_replay_h */

