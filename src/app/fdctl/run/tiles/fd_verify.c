#include "tiles.h"
#include "fd_verify.h"

#include "generated/verify_seccomp.h"

#include "../../../../disco/quic/fd_tpu.h"

#include <linux/unistd.h>

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_TCACHE_ALIGN;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(), fd_tcache_footprint( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  for( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_verify_ctx_t ) );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;
  (void)sig;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;
  if( FD_LIKELY( (seq % ctx->round_robin_cnt) != ctx->round_robin_idx ) ) *opt_filter = 1;
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong in_idx,
             ulong seq,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz>FD_TPU_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  /* At this point, the payload only contains the serialized txn.
     Beyond end of txn, but within bounds of msg layout, add a trailer
     describing the txn layout.

     [ payload          ] (payload_sz bytes)
     [ pad: align to 2B ] (0-1 bytes)
     [ fd_txn_t         ] (? bytes)
     [ payload_sz       ] (2B) */

  ulong payload_sz = *opt_sz;
  ulong txnt_off   = fd_ulong_align_up( payload_sz, 2UL );

  /* Ensure sufficient space to store trailer */

  long txnt_maxsz = (long)FD_TPU_DCACHE_MTU -
                    (long)txnt_off -
                    (long)sizeof(ushort);
  if( FD_UNLIKELY( txnt_maxsz<(long)FD_TXN_MAX_SZ ) ) FD_LOG_ERR(( "got malformed txn (sz %lu) does not fit in dcache", payload_sz ));

  uchar const * txn   = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_txn_t *    txn_t = (fd_txn_t *)((ulong)txn + txnt_off);

  /* Parse transaction */

  ulong txn_t_sz = fd_txn_parse( txn, payload_sz, txn_t, NULL );
  if( FD_UNLIKELY( !txn_t_sz ) ) {
    *opt_filter = 1; /* Invalid txn fails to parse. */
    return;
  }

  /* Write payload_sz */

  /* fd_txn_parse always returns a multiple of 2 so this sz is
     correctly aligned. */
  ushort * payload_sz_p = (ushort *)( (ulong)txn_t + txn_t_sz );
  *payload_sz_p = (ushort)payload_sz;

  /* End of message */

  ulong new_sz = ( (ulong)payload_sz_p + sizeof(ushort) ) - (ulong)txn;
  if( FD_UNLIKELY( new_sz>FD_TPU_DCACHE_MTU ) ) {
    FD_LOG_CRIT(( "memory corruption detected (txn_sz=%lu txn_t_sz=%lu)",
                  payload_sz, txn_t_sz ));
  }

  /* We need to access signatures and accounts, which are all before the recent_blockhash_off.
     We assert that the payload_sz includes all signatures and account pubkeys we need. */
  ushort recent_blockhash_off = txn_t->recent_blockhash_off;
  if( FD_UNLIKELY( recent_blockhash_off>=*opt_sz ) ) {
    FD_LOG_ERR( ("txn is invalid: payload_sz = %lx, recent_blockhash_off = %x", *opt_sz, recent_blockhash_off ) );
  }

  ulong txn_sig;
  int res = fd_txn_verify( ctx, txn, (ushort)payload_sz, txn_t, &txn_sig );
  if( FD_UNLIKELY( res!=FD_TXN_VERIFY_SUCCESS ) ) {
    *opt_filter = 1; /* Signature verification failed. */
    return;
  }

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mux_publish( mux, txn_sig, ctx->out_chunk, new_sz, 0UL, *opt_tsorig, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, new_sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( FD_SCRATCH_ALLOC_APPEND( l, FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) ), VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_UNLIKELY( link->is_reasm ) ) {
      fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->reasm_obj_id ].wksp_id ];
      ctx->in[i].mem = link_wksp->wksp;
      ctx->in[i].chunk0 = fd_laddr_to_chunk( ctx->in[i].mem, link->reasm );
      ctx->in[i].wmark  = ctx->in[i].chunk0 + (link->depth+link->burst-1) * FD_TPU_REASM_CHUNK_MTU;
    } else {
      fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->in[i].mem = link_wksp->wksp;
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_verify( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_verify_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_verify = {
  .name                     = "verify",
  .mux_flags                = FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
};
