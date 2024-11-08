/* Repair tile runs the repair protocol for a Firedancer node. */

#define _GNU_SOURCE

#include "../../../../disco/tiles.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../util/fd_util.h"
#include "../../../../disco/fd_disco.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../flamenco/rpcserver/fd_rpc_service.h"
#include "../../../../funk/fd_funk_filemap.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "generated/rpcserv_seccomp.h"

#define REPLAY_NOTIF_IDX 0
#define STAKE_CI_IN_IDX 1

struct fd_rpcserv_tile_ctx {
  fd_rpcserver_args_t args;
  char funk_file[ PATH_MAX ];

  int activated;

  fd_rpc_ctx_t * ctx;

  fd_pubkey_t identity_key[1]; /* Just the public key */

  fd_wksp_t * replay_notif_in_mem;
  ulong       replay_notif_in_chunk0;
  ulong       replay_notif_in_wmark;
  fd_replay_notif_msg_t replay_notif_in_state;

  fd_wksp_t * stake_ci_in_mem;
  ulong       stake_ci_in_chunk0;
  ulong       stake_ci_in_wmark;
};
typedef struct fd_rpcserv_tile_ctx fd_rpcserv_tile_ctx_t;

#define FD_RPC_SCRATCH_MAX (1LU<<28)
#define FD_RPC_SCRATCH_DEPTH 64

const fd_http_server_params_t RPCSERV_HTTP_PARAMS = {
  .max_connection_cnt    = 10,
  .max_ws_connection_cnt = 10,
  .max_request_len       = 1<<16,
  .max_ws_recv_frame_len = 1<<16,
  .max_ws_send_frame_cnt = 10,
  .outgoing_buffer_sz    = 100<<20,
};

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rpcserv_tile_ctx_t), sizeof(fd_rpcserv_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_RPC_SCRATCH_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_RPC_SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static inline void
before_credit( fd_rpcserv_tile_ctx_t * ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  if( FD_UNLIKELY( !ctx->activated ) ) {
    *charge_busy = 0;
  } else {
    *charge_busy = fd_rpc_ws_poll( ctx->ctx );
  }
}

static void
during_frag( fd_rpcserv_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz ) {
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( in_idx==REPLAY_NOTIF_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->replay_notif_in_chunk0 || chunk>ctx->replay_notif_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->replay_notif_in_chunk0, ctx->replay_notif_in_wmark ));
    }
    replay_sham_link_during_frag( ctx->ctx, &ctx->replay_notif_in_state, fd_chunk_to_laddr_const( ctx->replay_notif_in_mem, chunk ), (int)sz );

  } else if( FD_UNLIKELY( in_idx==STAKE_CI_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_ci_in_chunk0 || chunk>ctx->stake_ci_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->stake_ci_in_chunk0, ctx->stake_ci_in_wmark ));
    }
    stake_sham_link_during_frag( ctx->ctx, ctx->args.stake_ci, fd_chunk_to_laddr_const( ctx->stake_ci_in_mem, chunk ), (int)sz );

  } else {
    FD_LOG_ERR(("Unknown in_idx %lu for rpc", in_idx));
  }
}

static void
after_frag( fd_rpcserv_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  chunk,
            ulong                  sz,
            ulong                  tsorig,
            fd_stem_context_t *    stem ) {
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)tsorig;
  (void)stem;

  if( FD_LIKELY( in_idx==REPLAY_NOTIF_IDX ) ) {
    if( FD_UNLIKELY( !ctx->activated ) ) {
      fd_rpcserver_args_t * args = &ctx->args;
      args->funk = fd_funk_open_file(
        ctx->funk_file, 1, 0, 0, 0, 0, FD_FUNK_READ_WRITE, NULL );
      if( args->funk == NULL ) {
        FD_LOG_ERR(( "failed to join a funky" ));
      }

      ctx->activated = 1;
      fd_rpc_start_service( args, ctx->ctx );
    }

    replay_sham_link_after_frag( ctx->ctx, &ctx->replay_notif_in_state );

  } else if( FD_UNLIKELY( in_idx==STAKE_CI_IN_IDX ) ) {
    stake_sham_link_after_frag( ctx->ctx, ctx->args.stake_ci );

  } else {
    FD_LOG_ERR(("Unknown in_idx %lu for rpc", in_idx));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_ctx_t), sizeof(fd_rpcserv_tile_ctx_t) );
  void * alloc_shmem = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  void * stake_ci_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );

  if( FD_UNLIKELY( !strcmp( tile->rpcserv.identity_key_path, "" ) ) )
    FD_LOG_ERR( ( "identity_key_path not set" ) );
  ctx->identity_key[0] = *(fd_pubkey_t const *) fd_type_pun_const( fd_keyload_load( tile->rpcserv.identity_key_path, /* pubkey only: */ 1 ) );

  fd_rpcserver_args_t * args = &ctx->args;
  fd_memset( args, 0, sizeof(args) );

  args->offline = 0;
  args->params = RPCSERV_HTTP_PARAMS;

  args->port = tile->rpcserv.rpc_port;

  args->tpu_addr.sin_family = AF_INET;
  args->tpu_addr.sin_addr.s_addr = tile->rpcserv.tpu_ip_addr;
  args->tpu_addr.sin_port = htons( (ushort)tile->rpcserv.tpu_port );

  args->stake_ci = fd_stake_ci_join( fd_stake_ci_new( stake_ci_mem, ctx->identity_key ) );

  strncpy( ctx->funk_file, tile->replay.funk_file, sizeof(ctx->funk_file) );
  /* Open funk after replay tile is booted */

  /* Blockstore setup */
  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  args->blockstore = fd_blockstore_join( fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  FD_TEST( args->blockstore!=NULL );

  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }
  args->valloc = fd_alloc_virtual( alloc );

  fd_rpc_create_ctx( args, &ctx->ctx );

  /* Wait until after replay tile boots before starting service */
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->in_cnt != 2 ||
                   strcmp( topo->links[ tile->in_link_id[ REPLAY_NOTIF_IDX ] ].name, "replay_notif") ||
                   strcmp( topo->links[ tile->in_link_id[ STAKE_CI_IN_IDX ] ].name, "stake_out" ) ) ) {
    FD_LOG_ERR(( "repair tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_cnt != 0 ) ) {
    FD_LOG_ERR(( "repair tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));
  }

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_ctx_t), sizeof(fd_rpcserv_tile_ctx_t) );
  (void)FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  (void)FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_RPC_SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_RPC_SCRATCH_DEPTH ) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, FD_RPC_SCRATCH_MAX, FD_RPC_SCRATCH_DEPTH );

  ctx->activated = 0;

  fd_topo_link_t * replay_notif_in_link   = &topo->links[ tile->in_link_id[ REPLAY_NOTIF_IDX ] ];
  ctx->replay_notif_in_mem    = topo->workspaces[ topo->objs[ replay_notif_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_notif_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_notif_in_mem, replay_notif_in_link->dcache );
  ctx->replay_notif_in_wmark  = fd_dcache_compact_wmark ( ctx->replay_notif_in_mem, replay_notif_in_link->dcache, replay_notif_in_link->mtu );

  fd_topo_link_t * stake_ci_in_link   = &topo->links[ tile->in_link_id[ STAKE_CI_IN_IDX ] ];
  ctx->stake_ci_in_mem    = topo->workspaces[ topo->objs[ stake_ci_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_ci_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_ci_in_mem, stake_ci_in_link->dcache );
  ctx->stake_ci_in_wmark  = fd_dcache_compact_wmark ( ctx->stake_ci_in_mem, stake_ci_in_link->dcache, stake_ci_in_link->mtu );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpcserv_tile_ctx_t ), sizeof( fd_rpcserv_tile_ctx_t ) );

  populate_sock_filter_policy_rpcserv( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_rpc_ws_fd( ctx->ctx ) );
  return sock_filter_policy_rpcserv_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpcserv_tile_ctx_t ), sizeof( fd_rpcserv_tile_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_rpc_ws_fd( ctx->ctx ); /* listen socket */
  return out_cnt;
}

/* TODO: This is probably not correct. */
#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rpcserv_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rpcserv_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_rpcserv = {
  .name                     = "rpcsrv",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
