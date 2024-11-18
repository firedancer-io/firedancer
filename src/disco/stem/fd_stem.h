#ifndef HEADER_fd_src_disco_stem_fd_stem_h
#define HEADER_fd_src_disco_stem_fd_stem_h

#include "../fd_disco_base.h"

struct fd_stem_context {
   fd_frag_meta_t ** mcaches;
   ulong *           seqs;
   ulong *           depths;

   ulong *           cr_avail;
   ulong             cr_decrement_amount;
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

#define STEM_SCRATCH_ALIGN (128UL)

FD_FN_PURE static inline ulong
stem_scratch_align( void ) {
  return STEM_SCRATCH_ALIGN;
}

FD_FN_PURE static inline ulong
stem_scratch_footprint( ulong in_cnt,
                        ulong out_cnt,
                        ulong cons_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stem_tile_in_t), in_cnt*sizeof(fd_stem_tile_in_t)     );  /* in */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             out_cnt*sizeof(ulong)                ); /* out_depth */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             out_cnt*sizeof(ulong)                ); /* out_seq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong const *),     cons_cnt*sizeof(ulong const *)       ); /* cons_fseq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong *),           cons_cnt*sizeof(ulong *)             ); /* cons_slow */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             cons_cnt*sizeof(ulong)               ); /* cons_out */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             cons_cnt*sizeof(ulong)               ); /* cons_seq */
  l = FD_LAYOUT_APPEND( l, alignof(ushort),            (in_cnt+cons_cnt+1UL)*sizeof(ushort) ); /* event_map */
  return FD_LAYOUT_FINI( l, stem_scratch_align() );
}

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
  *stem->cr_avail -= stem->cr_decrement_amount;
  *seqp = fd_seq_inc( seq, 1UL );
}

static inline ulong
fd_stem_advance( fd_stem_context_t * stem,
                 ulong               out_idx ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  *stem->cr_avail -= stem->cr_decrement_amount;
  *seqp = fd_seq_inc( seq, 1UL );
  return seq;
}

#endif /* HEADER_fd_src_disco_stem_fd_stem_h */
