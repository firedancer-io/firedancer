#include "../../../../disco/tiles.h"

#include "generated/plugin_seccomp.h"

#include "../../../../disco/plugin/fd_plugin.h"
#include "../../../../flamenco/types/fd_types.h"

#define IN_KIND_REPLAY (0)
#define IN_KIND_GOSSIP (1)
#define IN_KIND_STAKE  (2)
#define IN_KIND_POH    (3)
#define IN_KIND_VOTE   (4)
#define IN_KIND_STARTP (5)
#define IN_KIND_VOTEL  (6)
#define IN_KIND_BUNDLE (7)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} fd_plugin_in_ctx_t;

typedef struct {
  int                in_kind[ 64UL ];
  fd_plugin_in_ctx_t in[ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_plugin_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_plugin_ctx_t ), sizeof( fd_plugin_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_frag( fd_plugin_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz ) {
  (void)seq;
  (void)sig;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
  ulong * dst = (ulong *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  /* ... todo... sigh, sz is not correct since it's too big */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) && FD_LIKELY( sig==FD_PLUGIN_MSG_GOSSIP_UPDATE || sig==FD_PLUGIN_MSG_VALIDATOR_INFO ) ) {
    ulong peer_cnt = ((ulong *)src)[ 0 ];
    FD_TEST( peer_cnt<=40200 );
    sz = 8UL + peer_cnt*FD_GOSSIP_LINK_MSG_SIZE;
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP || ctx->in_kind[ in_idx ]==IN_KIND_POH || ctx->in_kind[ in_idx ]==IN_KIND_VOTE ) && FD_LIKELY( sig==FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE ) ) {
    ulong peer_cnt = ((ulong *)src)[ 0 ];
    FD_TEST( peer_cnt<=40200 );
    sz = 8UL + peer_cnt*112UL;
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    ulong staked_cnt = ((ulong *)src)[ 1 ];
    FD_TEST( staked_cnt<=50000UL );
    sz = 40UL + staked_cnt*40UL;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( fd_plugin_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)sz;
  (void)tsorig;
  (void)stem;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPLAY: {
      FD_TEST( sig==FD_PLUGIN_MSG_SLOT_ROOTED || sig==FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED || sig==FD_PLUGIN_MSG_SLOT_COMPLETED || sig==FD_PLUGIN_MSG_SLOT_RESET || sig==FD_PLUGIN_MSG_START_PROGRESS );
      break;
    }
    case IN_KIND_GOSSIP: {
      FD_TEST( sig==FD_PLUGIN_MSG_GOSSIP_UPDATE || sig==FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE || sig==FD_PLUGIN_MSG_VALIDATOR_INFO || sig==FD_PLUGIN_MSG_BALANCE );
      break;
    }
    case IN_KIND_STAKE: {
      sig = FD_PLUGIN_MSG_LEADER_SCHEDULE;
      break;
    }
    case IN_KIND_POH: {
      FD_TEST( sig==FD_PLUGIN_MSG_SLOT_START || sig==FD_PLUGIN_MSG_SLOT_END );
      break;
    }
    case IN_KIND_VOTE: {
      FD_TEST( sig==FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE );
      break;
    }
    case IN_KIND_STARTP: {
      FD_TEST( sig==FD_PLUGIN_MSG_START_PROGRESS );
      break;
    }
    case IN_KIND_VOTEL: {
      FD_TEST( sig==FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED );
      break;
    }
    case IN_KIND_BUNDLE: {
      FD_TEST( sig==FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE );
      break;
    }
    default: FD_LOG_ERR(( "bad in_idx" ));
  }

  ulong true_size = sz;
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP || ( ctx->in_kind[ in_idx ]==IN_KIND_VOTE ) ) ) true_size = 8UL + 40200UL*(58UL+12UL*34UL);
  else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) true_size = 40UL + 40200UL*40UL; /* ... todo... sigh, sz is not correct since it's too big */

  fd_stem_publish( stem, 0UL, sig, ctx->out_chunk, sz, 0UL, 0UL, 0UL ); /* Not true_sz which might not fit */
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, true_size, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_plugin_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_plugin_ctx_t ), sizeof( fd_plugin_ctx_t ) );

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    FD_TEST( link->mtu<=topo->links[ tile->out_link_id[ 0 ] ].mtu );

    if( FD_UNLIKELY( !strcmp( link->name, "replay_plugi" ) ) )      ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_UNLIKELY( !strcmp( link->name, "gossip_plugi" ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_UNLIKELY( !strcmp( link->name, "stake_out" ) ) )    ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_UNLIKELY( !strcmp( link->name, "poh_plugin" ) ) )   ctx->in_kind[ i ] = IN_KIND_POH;
    else if( FD_UNLIKELY( !strcmp( link->name, "votes_plugin" ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTE;
    else if( FD_UNLIKELY( !strcmp( link->name, "startp_plugi" ) ) ) ctx->in_kind[ i ] = IN_KIND_STARTP;
    else if( FD_UNLIKELY( !strcmp( link->name, "votel_plugin" ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTEL;
    else if( FD_UNLIKELY( !strcmp( link->name, "bundle_plugi" ) ) ) ctx->in_kind[ i ] = IN_KIND_BUNDLE;
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

  populate_sock_filter_policy_plugin( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_plugin_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_plugin_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_plugin_ctx_t)

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_plugin = {
  .name                     = "plugin",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
