#ifndef HEADER_fd_src_disco_stem_fd_stem_h
#define HEADER_fd_src_disco_stem_fd_stem_h

#include "../fd_disco_base.h"
#include "../sleep/fd_sleep.h"

#define FD_STEM_SCRATCH_ALIGN (128UL)

struct fd_stem_context {
   fd_frag_meta_t ** mcaches;
   ulong *           seqs;
   ulong *           depths;

   ulong *           cr_avail;
   ulong *           min_cr_avail;
   ulong             cr_decrement_amount;
   int *             out_reliable;
   ulong const *     cons_seq;
   struct fd_stem_tile_in * in;

   fd_sleep_t *            sleep;
   fd_sleep_wake_t const * wake;
   ushort const *          wake_off;
   ulong * const *         in_fseq;
   ulong const *           in_producer;
};

typedef struct fd_stem_context fd_stem_context_t;

struct fd_stem_sleep {
  fd_sleep_t *    shmem;

  ulong           tile_id;
  ulong const *   waker_fseq;  /* waker readiness word, NULL if not a client */
  ulong const *   out_link_id; /* per out: link id (seq_mirror), the tile's own array */
  ulong           in_link_id[ FD_SLEEP_IN_MAX ];               /* link id (seq_snap/sweep) */
  ulong           in_producer[ FD_SLEEP_IN_MAX ];              /* producer tile id, rung when credits return (ULONG_MAX if none) */
  fd_sleep_wake_t wake[ FD_SLEEP_OUT_MAX*FD_SLEEP_BITS_CNT ];  /* flattened (word,mask) pairs */
  ushort          wake_off[ FD_SLEEP_OUT_MAX+1UL ];            /* out_cnt+1 offsets into wake */
};

typedef struct fd_stem_sleep fd_stem_sleep_t;

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
};

typedef struct fd_stem_tile_in fd_stem_tile_in_t;

static inline ulong
fd_stem_publish( fd_stem_context_t * stem,
                 ulong               out_idx,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub ) {
  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong            depth  = stem->depths [ out_idx ];
  ulong *          seqp   = &stem->seqs  [ out_idx ];
  ulong            seq    = *seqp;
# if FD_HAS_AVX
  fd_mcache_publish_avx( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
# elif FD_HAS_ARM
  fd_mcache_publish_arm( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
# else
  fd_mcache_publish    ( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
# endif
  if( FD_LIKELY( stem->out_reliable[ out_idx ] ) ) {
    if( FD_UNLIKELY( stem->cr_avail[ out_idx ]<stem->cr_decrement_amount ) ) { /* Ensure producer BURST is set correctly */
      FD_LOG_ERR(( "BURST underprovisioned out_idx=%lu cr_avail=%lu min_cr_avail=%lu cr_decrement_amount=%lu", out_idx, stem->cr_avail[ out_idx ], *stem->min_cr_avail, stem->cr_decrement_amount ));
    }
    stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
    *stem->min_cr_avail        = fd_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  }
  *seqp = fd_seq_inc( seq, 1UL );
  if( FD_UNLIKELY( stem->sleep ) ) fd_sleep_wake_check( stem->sleep, stem->wake+stem->wake_off[ out_idx ], (ulong)(stem->wake_off[ out_idx+1UL ]-stem->wake_off[ out_idx ]) );
  return seq;
}

static inline ulong
fd_stem_advance( fd_stem_context_t * stem,
                 ulong               out_idx ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  if( FD_LIKELY( stem->out_reliable[ out_idx ] ) ) {
    if( FD_UNLIKELY( stem->cr_avail[ out_idx ]<stem->cr_decrement_amount ) ) { /* Ensure producer BURST is set correctly */
      FD_LOG_ERR(( "BURST underprovisioned out_idx=%lu cr_avail=%lu min_cr_avail=%lu cr_decrement_amount=%lu", out_idx, stem->cr_avail[ out_idx ], *stem->min_cr_avail, stem->cr_decrement_amount ));
    }
    stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
    *stem->min_cr_avail        = fd_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  }
  *seqp = fd_seq_inc( seq, 1UL );
  if( FD_UNLIKELY( stem->sleep ) ) fd_sleep_wake_check( stem->sleep, stem->wake+stem->wake_off[ out_idx ], (ulong)(stem->wake_off[ out_idx+1UL ]-stem->wake_off[ out_idx ]) );
  return seq;
}

static inline void
fd_stem_credit_return( fd_stem_context_t * stem,
                       ulong               in_idx,
                       ulong               seq ) {
  __atomic_store_n( stem->in_fseq[ in_idx ], seq, __ATOMIC_RELEASE );
  if( FD_LIKELY( !stem->sleep ) ) return;
  ulong producer = stem->in_producer[ in_idx ];
  if( FD_UNLIKELY( producer==ULONG_MAX ) ) return;
  __atomic_thread_fence( __ATOMIC_SEQ_CST );
  if( FD_UNLIKELY( FD_VOLATILE_CONST( stem->sleep->credit_bits[ producer>>6 ] ) & (1UL<<(producer&63UL)) ) ) fd_sleep_ring( stem->sleep, producer );
}

#endif /* HEADER_fd_src_disco_stem_fd_stem_h */
