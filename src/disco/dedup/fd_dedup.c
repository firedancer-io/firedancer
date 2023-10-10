#include "fd_dedup.h"

#include "../mux/fd_mux.h"

/* fd_dedup_ctx_t is the context object provided to callbacks from the
   mux tile, and contains all state needed to progress the tile. */

typedef struct {
  ulong   tcache_depth;   /* == fd_tcache_depth( tcache ), depth of this dedups's tcache (const) */
  ulong   tcache_map_cnt; /* == fd_tcache_map_cnt( tcache ), number of slots to use for tcache map (const) */
  ulong * tcache_sync;    /* == fd_tcache_oldest_laddr( tcache ), local join to the oldest key in the tcache */
  ulong * tcache_ring;
  ulong * tcache_map;

  fd_dedup_in_ctx_t * in;

  void * out_wksp;
  ulong  out_chunk0;
  ulong  out_wmark;
  ulong  out_chunk;
} fd_dedup_ctx_t;

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, flow control prevents it getting overrun, and
   downstream consumers could reuse the same chunk and workspace to
   improve performance.

   The bounds checking and copying here are defensive measures,

    * In a functioning system, the bounds checking should never fail,
      but we want to prevent an attacker with code execution on a producer
      tile from trivially being able to jump to a consumer tile with
      out of bounds chunks.

    * For security reasons, we have chosen to isolate all workspaces from
      one another, so for example, if the QUIC tile is compromised with
      RCE, it cannot wait until the sigverify tile has verified a transaction,
      and then overwrite the transaction while it's being processed by the
      banking stage. */

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)sig;
  (void)opt_filter;

  fd_dedup_ctx_t * ctx = (fd_dedup_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].wksp, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_wksp, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

/* After the transaction has been fully received, and we know we were
   not overrun while reading it, check if it's a duplicate of a prior
   transaction. */

static inline void
after_frag( void * _ctx,
            ulong * opt_sig,
            ulong * opt_chunk,
            ulong * opt_sz,
            int   * opt_filter ) {
  fd_dedup_ctx_t * ctx = (fd_dedup_ctx_t *)_ctx;

  int is_dup;
  FD_TCACHE_INSERT( is_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, *opt_sig );
  *opt_filter = is_dup;
  if( FD_LIKELY( !*opt_filter ) ) {
    *opt_chunk     = ctx->out_chunk;
    *opt_sig       = 0; /* indicate this txn is coming from dedup, and has already been parsed */
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
  }
}

int
fd_dedup_tile( fd_cnc_t *              cnc,
               ulong                   pid,
               ulong                   in_cnt,
               fd_frag_meta_t const ** in_mcache,
               ulong **                in_fseq,
               uchar const **          in_dcache,
               fd_tcache_t *           tcache,
               fd_frag_meta_t *        mcache,
               uchar *                 dcache,
               ulong                   out_cnt,
               ulong **                out_fseq,
               ulong                   cr_max,
               long                    lazy,
               fd_rng_t *              rng,
               void *                  scratch ) {
  fd_dedup_ctx_t ctx[1];

  fd_mux_callbacks_t callbacks[1] = { 0 };
  callbacks->during_frag = during_frag;
  callbacks->after_frag  = after_frag;

  ulong scratch_top = (ulong)scratch;

  do {
    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }
    if( FD_UNLIKELY( !tcache ) ) { FD_LOG_WARNING(( "NULL tcache" )); return 1; }

    ctx->tcache_depth   = fd_tcache_depth       ( tcache );
    ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
    ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
    ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
    ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

    ctx->in = (fd_dedup_in_ctx_t*)SCRATCH_ALLOC( alignof(fd_dedup_in_ctx_t), in_cnt*sizeof(fd_dedup_in_ctx_t) );
    for( ulong i=0; i<in_cnt; i++ ) {
      if( FD_UNLIKELY( !in_dcache[i] ) ) { FD_LOG_WARNING(( "NULL in_dcache[%lu]", i )); return 1; }
      if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( in_dcache[i] ), in_dcache[i], FD_TPU_DCACHE_MTU, fd_mcache_depth( in_mcache[i] ) ) ) ) {
        FD_LOG_WARNING(( "in_dcache[%lu] not compatible with wksp base and mcache depth", i ));
        return 1;
      }
      ctx->in[i].wksp   = fd_wksp_containing( in_dcache[i] );
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].wksp, in_dcache[i] );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].wksp, in_dcache[i], FD_TPU_DCACHE_MTU );
    }

    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( dcache ), dcache, FD_TPU_DCACHE_MTU, fd_mcache_depth( mcache ) ) ) ) {
      FD_LOG_WARNING(( "dcache not compatible with wksp base and mcache depth" ));
      return 1;
    }
    ctx->out_wksp   = fd_wksp_containing( dcache );
    ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_wksp, dcache );
    ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_wksp, dcache, FD_TPU_DCACHE_MTU );
    ctx->out_chunk  = ctx->out_chunk0;
  } while(0);

  return fd_mux_tile( cnc,
                      pid,
                      FD_MUX_FLAG_COPY, /* dedup copies frags, and does not run zero copy */
                      in_cnt,
                      in_mcache,
                      in_fseq,
                      mcache,
                      out_cnt,
                      out_fseq,
                      cr_max,
                      lazy,
                      rng,
                      (void*)fd_ulong_align_up( scratch_top, FD_MUX_TILE_SCRATCH_ALIGN ),
                      ctx,
                      callbacks );
}
