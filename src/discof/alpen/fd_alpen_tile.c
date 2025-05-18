#include "../../disco/topo/fd_topo.h"
#include "generated/fd_alpen_tile_seccomp.h"

#include "../../choreo/fd_choreo.h"

#include "../../disco/shred/fd_stake_ci.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyswitch.h"

#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/shred/fd_stake_ci.h"

#define IN_KIND_NET     (0UL)
#define IN_KIND_CONTACT (1UL)
#define IN_KIND_SIGN    (2UL)
#define IN_KIND_REPLAY  (3UL)
#define IN_KIND_STAKE   (4UL)
#define IN_KIND_APENV   (5UL)

#define NET_OUT_IDX     (0)
#define SIGN_OUT_IDX    (1)
#define ALPENV_OUT_IDX  (2)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_alpen_in_ctx_t;

typedef struct {
  fd_pubkey_t identity_key[1];
  ulong       seed;

  fd_keyswitch_t *     keyswitch;
  fd_keyguard_client_t keyguard_client[1];

  fd_stake_ci_t  * stake_ci;

  fd_alpen_in_ctx_t in[32];
  int               in_kind[ 32 ];

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * alpenv_out_mem;
  ulong       alpenv_out_chunk0;
  ulong       alpenv_out_wmark;
  ulong       alpenv_out_chunk;

} fd_alpen_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_alpen_ctx_t), sizeof(fd_alpen_ctx_t)  );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),     fd_stake_ci_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_alpen_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    /* TODO see fd_keyswitch.h, in case the pipeline needs to be flushed
       before swtiching key. */
    fd_memcpy( ctx->identity_key->uc, ctx->keyswitch->bytes, 32UL );
    fd_stake_ci_set_identity( ctx->stake_ci, ctx->identity_key );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
during_frag( fd_alpen_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl FD_PARAM_UNUSED ) {
  (void)ctx;
  (void)sig;
  FD_TEST( in_idx==0 );
  FD_TEST( chunk==0 );
  FD_TEST( sz==0 );
}

static void
after_frag( fd_alpen_ctx_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)ctx;
  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  FD_TEST( in_idx==0 );
  FD_TEST( sz==0 );

  FD_LOG_NOTICE(( "got replay sig %lu", sig ));
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_alpen_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_alpen_ctx_t), sizeof(fd_alpen_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->alpen.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[0] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->alpen.identity_key_path, /* pubkey only: */ 1 ) );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ulong) ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_alpen_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_alpen_ctx_t ), sizeof( fd_alpen_ctx_t ) );
  void *     _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );

  /* TODO add checks */

  if( FD_UNLIKELY( !tile->out_cnt ) )
    FD_LOG_ERR(( "alpen tile has no primary output link" ));

  if( FD_UNLIKELY( !tile->alpen.alpen_listen_port  ) ) FD_LOG_ERR(( "alpen_listen_port not set" ));

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  /* TODO sign tile should return signature and pubkey, this way we could avoid keyswitch */
  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  /* populate ctx */
  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_alpen", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  NONNULL( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) ) );

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, ctx->identity_key ) );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "net_alpen"    ) ) ) ctx->in_kind[ i ] = IN_KIND_NET;
    else if( FD_LIKELY( !strcmp( link->name, "crds_alpen"   ) ) ) ctx->in_kind[ i ] = IN_KIND_CONTACT;
    else if( FD_LIKELY( !strcmp( link->name, "sign_alpen"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else if( FD_LIKELY( !strcmp( link->name, "replay_alpen" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "stake_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_LIKELY( !strcmp( link->name, "alpenv_alpen" ) ) ) ctx->in_kind[ i ] = IN_KIND_APENV;
    else FD_LOG_ERR(( "alpen tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * alpenv_out = &topo->links[ tile->out_link_id[ ALPENV_OUT_IDX ] ];

  ctx->alpenv_out_mem    = topo->workspaces[ topo->objs[ alpenv_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->alpenv_out_chunk0 = fd_dcache_compact_chunk0( ctx->alpenv_out_mem, alpenv_out->dcache );
  ctx->alpenv_out_wmark  = fd_dcache_compact_wmark ( ctx->alpenv_out_mem, alpenv_out->dcache, alpenv_out->mtu );
  ctx->alpenv_out_chunk  = ctx->alpenv_out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  // if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
  //   FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );
}


static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_alpen_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_alpen_tile_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_alpen_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_alpen_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_alpen = {
    .name                     = "alpen",
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
