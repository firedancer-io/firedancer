#ifndef HEADER_fd_src_disco_stem_fd_stem_h
#define HEADER_fd_src_disco_stem_fd_stem_h

#include "../fd_disco_base.h"

#include <stddef.h> /* offsetof */

#define FD_STEM_SCRATCH_ALIGN (128UL)

struct fd_stem_context {
   fd_frag_meta_t ** mcaches;
   ulong *           seqs;
   ulong *           depths;

   ulong *           cr_avail;
   ulong *           min_cr_avail;
   ulong             cr_decrement_amount;
   int *             out_reliable;
};

typedef struct fd_stem_context fd_stem_context_t;

/* fd_stem_tile_in_t holds the state stem keeps about each input link of
   a tile.  The struct is 64-byte aligned so each entry of the in[]
   array starts on its own cache line.  Cache layout:

     - First cache line (hot polling state):
         mcache, depth, idx, seq, mline, fseq, accum[6]  -> 64 bytes.

     - Second cache line (cached dcache bounds for the centralized
       chunk/sz validation done by stem before invoking the tile's
       during_frag callback; read on every fragment arrival to perform
       the bounds check, but kept in a separate cache line so the
       tight polling state in the first line is not evicted by
       in[]-array iteration):
         chunk0, wmark, mtu                              -> 24 bytes.

   Padding to 128 bytes total is added by the (aligned(64)) attribute.
   The bounds fields live AFTER the polling state on purpose: they are
   read during per-fragment validation but do not need to share a line
   with the always-touched seq/mline pair. */

struct __attribute__((aligned(64))) fd_stem_tile_in {
  fd_frag_meta_t const * mcache;   /* local join to this in's mcache */
  uint                   depth;    /* == fd_mcache_depth( mcache ), depth of this in's cache (const) */
  uint                   idx;      /* index of this in in the list of providers, [0, in_cnt) */
  ulong                  seq;      /* sequence number of next frag expected from the upstream producer,
                                      updated when frag from this in is published */
  fd_frag_meta_t const * mline;    /* == mcache + fd_mcache_line_idx( seq, depth ), location to poll next */
  ulong *                fseq;     /* local join to the fseq used to return flow control credits to the in */
  uint                   accum[6]; /* local diagnostic accumulators.  These are drained during in housekeeping. */
                                   /* Assumes FD_FSEQ_DIAG_{PUB_CNT,PUB_SZ,FILT_CNT,FILT_SZ,OVRNP_CNT,OVRNP_FRAG_CNT} are 0:5 */

  /* Cached dcache bounds for centralized fragment validation.  See
     fd_stem.c for the check performed before each during_frag callback.
     mtu==0 is a sentinel meaning "no dcache / skip the bounds check"
     (used for control-only links and for stem instances that do not
     pass topology bounds, e.g. the QUIC trace tools). */
  ulong                  chunk0;   /* lower (inclusive) chunk bound, from fd_dcache_compact_chunk0 */
  ulong                  wmark;    /* upper (inclusive) chunk bound, from fd_dcache_compact_wmark  */
  ulong                  mtu;      /* max sz; 0 disables the bounds check for this link             */
};

typedef struct fd_stem_tile_in fd_stem_tile_in_t;

/* Lock the cache layout described above so future edits cannot
   silently break the two-cache-line split (hot polling state vs
   bounds) that this struct relies on. */
FD_STATIC_ASSERT( sizeof(fd_stem_tile_in_t)==128UL,                              fd_stem_tile_in_t_size    );
FD_STATIC_ASSERT( offsetof(fd_stem_tile_in_t, chunk0)==64UL,                     fd_stem_tile_in_t_chunk0  );
FD_STATIC_ASSERT( offsetof(fd_stem_tile_in_t, wmark )==64UL+ sizeof(ulong),      fd_stem_tile_in_t_wmark   );
FD_STATIC_ASSERT( offsetof(fd_stem_tile_in_t, mtu   )==64UL+2*sizeof(ulong),     fd_stem_tile_in_t_mtu     );

static inline void
fd_stem_publish( fd_stem_context_t * stem,
                 ulong               out_idx,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  fd_mcache_publish( stem->mcaches[ out_idx ], stem->depths[ out_idx ], seq, sig, chunk, sz, ctl, tsorig, tspub );
  if( FD_LIKELY( stem->out_reliable[ out_idx ] ) ) {
    if( FD_UNLIKELY( stem->cr_avail[ out_idx ]<stem->cr_decrement_amount ) ) { /* Ensure producer BURST is set correctly */
      FD_LOG_ERR(( "BURST underprovisioned out_idx=%lu cr_avail=%lu min_cr_avail=%lu cr_decrement_amount=%lu", out_idx, stem->cr_avail[ out_idx ], *stem->min_cr_avail, stem->cr_decrement_amount ));
    }
    stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
    *stem->min_cr_avail        = fd_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  }
  *seqp = fd_seq_inc( seq, 1UL );
}

static inline ulong
fd_stem_advance( fd_stem_context_t * stem,
                 ulong               out_idx ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  if( FD_LIKELY( stem->out_reliable[ out_idx ] ) ) {
    stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
    *stem->min_cr_avail        = fd_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  }
  *seqp = fd_seq_inc( seq, 1UL );
  return seq;
}

#endif /* HEADER_fd_src_disco_stem_fd_stem_h */
