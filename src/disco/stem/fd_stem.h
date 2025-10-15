#ifndef HEADER_fd_src_disco_stem_fd_stem_h
#define HEADER_fd_src_disco_stem_fd_stem_h

#include "../fd_disco_base.h"

#define FD_STEM_SCRATCH_ALIGN (128UL)

#define RELIABLE_LINK   (0)
#define UNRELIABLE_LINK (1)

struct fd_stem_context {
  fd_frag_meta_t ** mcaches;
  ulong *           seqs;
  ulong *           depths;

  ulong *           cr_avail;
  ulong *           min_cr_avail;
  ulong             cr_decrement_amount;
  int *             link_kind;
  ulong *           burst;
};

typedef struct fd_stem_context fd_stem_context_t;

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

static inline int
fd_stem_link_ready( fd_stem_context_t * stem,
                    ulong               out_idx ) {
  return stem->link_kind[ out_idx ]==RELIABLE_LINK ? stem->cr_avail[ out_idx ]>=stem->burst[ out_idx ] : 1;
}

static inline ulong
fd_stem_link_cr_avail( fd_stem_context_t * stem,
                    ulong               out_idx ) {
  return stem->link_kind[ out_idx ]==RELIABLE_LINK ? stem->cr_avail[ out_idx ] : ULONG_MAX;
}

static inline int
fd_stem_publish( fd_stem_context_t * stem,
                 ulong               out_idx,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub ) {
  if( FD_LIKELY( stem->link_kind[ out_idx ]==RELIABLE_LINK ) ) {
    if( FD_UNLIKELY( stem->cr_avail[ out_idx ]<stem->cr_decrement_amount ) ) return -1;
  }

  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  fd_mcache_publish( stem->mcaches[ out_idx ], stem->depths[ out_idx ], seq, sig, chunk, sz, ctl, tsorig, tspub );
  if( FD_LIKELY( stem->link_kind[ out_idx ]==RELIABLE_LINK ) ) {
    FD_TEST( stem->cr_avail[ out_idx ]>=stem->cr_decrement_amount );
    stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
  }
  *stem->min_cr_avail        = fd_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  *seqp = fd_seq_inc( seq, 1UL );
  return 0;
}

static inline ulong
fd_stem_advance( fd_stem_context_t * stem,
                 ulong               out_idx ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
  *stem->min_cr_avail        = fd_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  *seqp = fd_seq_inc( seq, 1UL );
  return seq;
}

#endif /* HEADER_fd_src_disco_stem_fd_stem_h */
