#include "fd_verify_tile.h"
#include "../fd_txn_m.h"
#include "../metrics/fd_metrics.h"
#include "generated/fd_verify_tile_seccomp.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

#define IN_KIND_QUIC   (0UL)
#define IN_KIND_BUNDLE (1UL)
#define IN_KIND_GOSSIP (2UL)
#define IN_KIND_SEND   (3UL)

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_TCACHE_ALIGN;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(), fd_tcache_footprint( tile->verify.tcache_depth, 0UL ) );
  for( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_verify_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( VERIFY, TRANSACTION_RESULT, ctx->metrics.verify_tile_result );
  FD_MCNT_SET( VERIFY, GOSSIPED_VOTES_RECEIVED,  ctx->metrics.gossiped_votes_cnt );
}

static int
before_frag( fd_verify_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  /* Bundle tile can produce both "bundles" and "packets", a packet is a
     regular transaction and should be round-robined between verify
     tiles, while bundles need to go through verify:0 currently to
     prevent interleaving of bundle streams. */
  int is_bundle_packet = (ctx->in_kind[ in_idx ]==IN_KIND_BUNDLE && !sig);

  if( FD_LIKELY( is_bundle_packet || ctx->in_kind[ in_idx ]==IN_KIND_QUIC ) ) {
    return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
  } else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_BUNDLE ) ) {
    return ctx->round_robin_idx!=0UL;
  } else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
      return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx ||
             sig!=FD_GOSSIP_UPDATE_TAG_VOTE;
  }

  return 0;
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( fd_verify_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig FD_PARAM_UNUSED,
             ulong             chunk,
             ulong             sz,
             ulong             ctl FD_PARAM_UNUSED ) {

  ulong in_kind = ctx->in_kind[ in_idx ];
  if( FD_UNLIKELY( in_kind==IN_KIND_BUNDLE || in_kind==IN_KIND_QUIC || in_kind==IN_KIND_SEND ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz>FD_TPU_RAW_MTU ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark, FD_TPU_RAW_MTU ));

    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
    uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    fd_memcpy( dst, src, sz );

    fd_txn_m_t const * txnm = (fd_txn_m_t const *)dst;
    if( FD_UNLIKELY( txnm->payload_sz>FD_TPU_MTU ) ) {
      FD_LOG_ERR(( "fd_verify: txn payload size %hu exceeds max %lu", txnm->payload_sz, FD_TPU_MTU ));
    }
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz>2048UL ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

    fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );
    fd_txn_m_t * dst = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

    dst->payload_sz = (ushort)msg->vote.txn_sz;
    dst->block_engine.bundle_id = 0UL;
    dst->source_ipv4 = msg->vote.socket.addr;
    dst->source_tpu = FD_TXN_M_TPU_SOURCE_GOSSIP;
    fd_memcpy( fd_txn_m_payload( dst ), msg->vote.txn, msg->vote.txn_sz );
  }
}

static inline void
after_frag( fd_verify_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)sz;
  (void)_tspub;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP || ctx->in_kind[ in_idx ]==IN_KIND_SEND ) ) ctx->metrics.gossiped_votes_cnt++;

  fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_txn_t *  txnt = fd_txn_m_txn_t( txnm );
  txnm->txn_t_sz = (ushort)fd_txn_parse( fd_txn_m_payload( txnm ), txnm->payload_sz, txnt, NULL );

  int is_bundle = !!txnm->block_engine.bundle_id;

  if( FD_UNLIKELY( is_bundle & (txnm->block_engine.bundle_id!=ctx->bundle_id) ) ) {
    ctx->bundle_failed = 0;
    ctx->bundle_id     = txnm->block_engine.bundle_id;
  }

  if( FD_UNLIKELY( is_bundle & (!!ctx->bundle_failed) ) ) {
    ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_TILE_RESULT_V_BUNDLE_PEER_FAILURE_IDX ]++;
    return;
  }

  if( FD_UNLIKELY( !txnm->txn_t_sz ) ) {
    if( FD_UNLIKELY( is_bundle ) ) ctx->bundle_failed = 1;
    ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_TILE_RESULT_V_PARSE_FAILURE_IDX ]++;
    return;
  }

  /* Users sometimes send transactions as part of a bundle (with a tip)
     and via the normal path (without a tip).  Regardless of which
     arrives first, we want to pack the one with the tip.  Thus, we
     exempt bundles from the normal HA dedup checks.  The dedup tile
     will still do a full-bundle dedup check to make sure to drop any
     identical bundles. */
  ulong _txn_sig;
  int res = fd_txn_verify( ctx, fd_txn_m_payload( txnm ), txnm->payload_sz, txnt, !is_bundle, &_txn_sig );
  if( FD_UNLIKELY( res!=FD_TXN_VERIFY_SUCCESS ) ) {
    if( FD_UNLIKELY( is_bundle ) ) ctx->bundle_failed = 1;

    if( FD_LIKELY( res==FD_TXN_VERIFY_DEDUP ) ) ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_TILE_RESULT_V_DEDUP_FAILURE_IDX ]++;
    else                                        ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_TILE_RESULT_V_VERIFY_FAILURE_IDX ]++;

    return;
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 0 );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, realized_sz, 0UL, tsorig, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, realized_sz, ctx->out_chunk0, ctx->out_wmark );

  ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_TILE_RESULT_V_SUCCESS_IDX ]++;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  FD_TEST( fd_rng_secure( &ctx->hashmap_seed, 8U ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( FD_SCRATCH_ALLOC_APPEND( l, FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( tile->verify.tcache_depth, 0UL ) ), tile->verify.tcache_depth, 0UL ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }

  ctx->bundle_failed = 0;
  ctx->bundle_id     = 0UL;

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    ctx->in[i].mem = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );

    if(      !strcmp( link->name, "quic_verify"  ) ) ctx->in_kind[ i ] = IN_KIND_QUIC;
    else if( !strcmp( link->name, "bundle_verif" ) ) ctx->in_kind[ i ] = IN_KIND_BUNDLE;
    else if( !strcmp( link->name, "send_out"     ) ) ctx->in_kind[ i ] = IN_KIND_SEND;
    else if( !strcmp( link->name, "gossip_out"   ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else FD_LOG_ERR(( "unexpected link name %s", link->name ));
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_verify_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_verify_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_verify_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_verify_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_verify = {
  .name                     = "verify",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
