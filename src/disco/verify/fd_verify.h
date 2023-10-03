#ifndef HEADER_fd_src_disco_verify_fd_verify_h
#define HEADER_fd_src_disco_verify_fd_verify_h

#include "../fd_disco_base.h"

/* fd_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  void * wksp;
  ulong  chunk0;
  ulong  wmark;
} fd_verify_in_ctx_t;

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed. Non-matching
   transactions are filtered out of the frag stream. */

#define FD_VERIFY_TILE_SCRATCH_ALIGN (128UL)
#define FD_VERIFY_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt )                          \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,                \
    alignof(fd_verify_in_ctx_t), (in_cnt)*sizeof(fd_verify_in_ctx_t) ),              \
    FD_MUX_TILE_SCRATCH_ALIGN,   FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ), \
    FD_VERIFY_TILE_SCRATCH_ALIGN )

FD_PROTOTYPES_BEGIN

int
fd_verify_tile( fd_cnc_t *              cnc,       /* Local join to the verify's command-and-control */
                ulong                   pid,       /* Tile PID for diagnostic purposes */
                ulong                   in_cnt,    /* Number of input mcaches to multiplex, inputs are indexed [0,in_cnt) */
                const fd_frag_meta_t ** in_mcache, /* in_mcache[in_idx] is the local join to input in_idx's mcache */
                ulong **                in_fseq,   /* in_fseq  [in_idx] is the local join to input in_idx's fseq */
                uchar const **          in_dcache, /* in_dcache[in_idx] is the local join to input in_idx's dcache */
                fd_sha512_t *           sha,       /* Local join to the verify's sha verifier */
                fd_tcache_t *           tcache,    /* Local join to the verify's tcache for deduplicating signatures */
                fd_frag_meta_t *        mcache,    /* Local join to the verify's frag stream output mcache */
                uchar *                 dcache,    /* Local join to the verify's frag stream output dcache */
                ulong                   out_cnt,   /* Number of reliable consumers, reliable consumers are indexed [0,out_cnt) */
                ulong **                out_fseq,  /* out_fseq[out_idx] is the local join to reliable consumer out_idx's fseq */
                ulong                   cr_max,    /* Maximum number of flow control credits, 0 means use a reasonable default */
                long                    lazy,      /* Lazyiness, <=0 means use a reasonable default */
                fd_rng_t *              rng,       /* Local join to the rng this verify should use */
                void *                  scratch ); /* Tile scratch memory */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_verify_fd_verify_h */
