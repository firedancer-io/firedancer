#include "fd_dedup_tile.h"

#include "generated/fd_dedup_tile_seccomp.h"
#include <linux/unistd.h>

FD_FN_CONST ulong
fd_dedup_tile_align( void ) {
  return FD_DEDUP_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_dedup_tile_footprint( fd_dedup_tile_args_t const * args ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_dedup_tile_t ), sizeof( fd_dedup_tile_t ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(), fd_tcache_footprint( args->tcache_depth, 0 ) );
  return FD_LAYOUT_FINI( l, fd_dedup_tile_align() );
}

ulong
fd_dedup_tile_seccomp_policy( void *               shdedup,
                              struct sock_filter * out,
                              ulong                out_cnt ) {
  (void)shdedup;
  populate_sock_filter_policy_fd_dedup_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_dedup_tile_instr_cnt;
}

ulong
fd_dedup_tile_allowed_fds( void * shdedup,
                           int *  out,
                           ulong  out_cnt ) {
  (void)shdedup;

  if( FD_UNLIKELY( out_cnt<2UL ) ) FD_LOG_ERR(( "out_cnt %lu", out_cnt ));

  ulong out_idx = 0UL;
  out[ out_idx++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out[ out_idx++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_idx;
}

/* during_frag is called between pairs for sequence number checks, as we
   are reading incoming frags.  We don't actually need to copy the
   fragment here, flow control prevents it getting overrun, and
   downstream consumers could reuse the same chunk and workspace to
   improve performance.

   The bounds checking and copying here are defensive measures,

    * In a functioning system, the bounds checking should never fail,
      but we want to prevent an attacker with code execution on a
      producer tile from trivially being able to jump to a consumer tile
      with out of bounds chunks.

    * For security reasons, we have chosen to isolate all workspaces
      from one another, so for example, if the QUIC tile is compromised
      with RCE, it cannot wait until the sigverify tile has verified a
      transaction, and then overwrite the transaction while it's being
      processed by the banking stage. */

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_dedup_tile_t * ctx = (fd_dedup_tile_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

/* After the transaction has been fully received, and we know we were
   not overrun while reading it, check if it's a duplicate of a prior
   transaction. */

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int   *            opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_tsorig;
  (void)mux;

  fd_dedup_tile_t * ctx = (fd_dedup_tile_t *)_ctx;

  int is_dup;
  FD_TCACHE_INSERT( is_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, *opt_sig );
  *opt_filter = is_dup;
  if( FD_LIKELY( !*opt_filter ) ) {
    *opt_chunk     = ctx->out_chunk;
    *opt_sig       = 0; /* indicate this txn is coming from dedup, and has already been parsed */
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
  }
}

fd_dedup_tile_t *
fd_dedup_tile_join( void *                       shdedup,
                    fd_dedup_tile_args_t const * args,
                    fd_dedup_tile_topo_t const * topo ) {
  FD_SCRATCH_ALLOC_INIT( l, shdedup );
  fd_dedup_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_dedup_tile_t ), sizeof( fd_dedup_tile_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( FD_SCRATCH_ALLOC_APPEND( l, FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( args->tcache_depth, 0) ), args->tcache_depth, 0 ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_new failed" ));

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

  for( ulong i=0UL; i<topo->in_cnt; i++ ) {
    ctx->in[i].mem    = topo->in_wksp[ i ];
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, topo->in_dcache[ i ] );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, topo->in_dcache[ i ], topo->in_mtu[ i ] );
  }

  ctx->out_mem    = topo->out_wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->out_dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->out_dcache, topo->out_mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)shdedup + fd_dedup_tile_footprint( args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)shdedup - fd_dedup_tile_footprint( args ), scratch_top, (ulong)shdedup + fd_dedup_tile_footprint( args ) ));

  return ctx;
}

void
fd_dedup_tile_run( fd_dedup_tile_t *       ctx,
                   fd_cnc_t *              cnc,
                   ulong                   in_cnt,
                   fd_frag_meta_t const ** in_mcache,
                   ulong **                in_fseq,
                   fd_frag_meta_t *        mcache,
                   ulong                   out_cnt,
                   ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .during_frag         = during_frag,
    .after_frag          = after_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}
