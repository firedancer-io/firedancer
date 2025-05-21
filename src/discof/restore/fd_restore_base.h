#include "../../tango/mcache/fd_mcache.h"

/* fd_frag_stream_meta_t is a variation of fd_frag_meta_t optimized for
   stream I/O. */

union fd_frag_stream_meta {

  struct {

    ulong  seq;     /* frag sequence number */
    ulong  goff;    /* global offset */

    uint   sz;
    uint   unused;
    ulong  loff;    /* dcache offset */

  };

  fd_frag_meta_t f[1];

};

typedef union fd_frag_stream_meta fd_frag_stream_meta_t;

FD_PROTOTYPES_BEGIN

#if FD_HAS_SSE

FD_FN_CONST static inline __m128i
fd_frag_stream_meta_sse0( ulong seq,
                          ulong goff ) {
  return _mm_set_epi64x( (long)goff, (long)seq );
}

FD_FN_CONST static inline __m128i
fd_frag_stream_meta_sse1( ulong sz, /* Assumed 32-bit */
                          ulong loff ) {
  return _mm_set_epi64x( (long)loff, (long)(sz) );
}

#endif /* FD_HAS_SSE */

static inline void
fd_mcache_publish_stream( fd_frag_stream_meta_t * mcache,
                          ulong                   depth,
                          ulong                   seq,
                          ulong                   goff,
                          ulong                   loff,
                          ulong                   sz ) {
  fd_frag_stream_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  FD_COMPILER_MFENCE();
  meta->seq   = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  meta->goff  = goff;
  meta->loff  = loff;
  meta->sz    = (uint)sz;
  FD_COMPILER_MFENCE();
  meta->seq   = seq;
  FD_COMPILER_MFENCE();
}

FD_PROTOTYPES_END
