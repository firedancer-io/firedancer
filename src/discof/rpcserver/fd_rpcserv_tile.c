/* Repair tile runs the repair protocol for a Firedancer node. */
#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include <sys/socket.h>
#include "generated/fd_rpcserv_tile_seccomp.h"

#include "../rpcserver/fd_rpc_service.h"

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define REPLAY_NOTIF_IDX 0
#define STAKE_IN_IDX     1

struct fd_rpcserv_tile_ctx {
  fd_rpcserver_args_t args;

  fd_rpc_ctx_t * ctx;

  fd_pubkey_t      identity_key;
  fd_keyswitch_t * keyswitch;

  fd_wksp_t * replay_notif_in_mem;
  ulong       replay_notif_in_chunk0;
  ulong       replay_notif_in_wmark;
  fd_replay_notif_msg_t replay_notif_in_state;

  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  int blockstore_fd;

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
};
typedef struct fd_rpcserv_tile_ctx fd_rpcserv_tile_ctx_t;

#define FD_RPC_SCRATCH_MAX (1LU<<30)

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
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_RPC_SCRATCH_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static inline void
during_housekeeping( fd_rpcserv_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    memcpy( &ctx->identity_key, ctx->keyswitch->bytes, sizeof(fd_pubkey_t) );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
before_credit( fd_rpcserv_tile_ctx_t * ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  *charge_busy = fd_rpc_ws_poll( ctx->ctx );
}

static void
during_frag( fd_rpcserv_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq FD_PARAM_UNUSED,
             ulong                   sig FD_PARAM_UNUSED,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( in_idx==REPLAY_NOTIF_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->replay_notif_in_chunk0 || chunk>ctx->replay_notif_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->replay_notif_in_chunk0, ctx->replay_notif_in_wmark ));
    }
    fd_rpc_replay_during_frag( ctx->ctx, &ctx->replay_notif_in_state, fd_chunk_to_laddr_const( ctx->replay_notif_in_mem, chunk ), (int)sz );

  } else if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in_chunk0 || chunk>ctx->stake_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->stake_in_chunk0, ctx->stake_in_wmark ));
    }
    fd_rpc_stake_during_frag( ctx->ctx, ctx->args.leaders, fd_chunk_to_laddr_const( ctx->stake_in_mem, chunk ), (int)sz );

  } else {
    FD_LOG_ERR(("Unknown in_idx %lu for rpc", in_idx));
  }
}

static void
after_frag( fd_rpcserv_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig,
            ulong                  tspub,
            fd_stem_context_t *    stem ) {
  (void)seq;
  (void)sig;
  (void)sz;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  if( FD_LIKELY( in_idx==REPLAY_NOTIF_IDX ) ) {
    fd_rpc_replay_after_frag( ctx->ctx, &ctx->replay_notif_in_state );
  } else if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    fd_rpc_stake_after_frag( ctx->ctx, ctx->args.leaders );
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
  void * spad_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_RPC_SCRATCH_MAX ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( !strcmp( tile->rpcserv.identity_key_path, "" ) ) )
    FD_LOG_ERR( ( "identity_key_path not set" ) );
  memcpy( &ctx->identity_key, fd_keyload_load( tile->rpcserv.identity_key_path, /* pubkey only: */ 1 ), sizeof(fd_pubkey_t) );

  fd_rpcserver_args_t * args = &ctx->args;
  fd_memset( args, 0, sizeof(fd_rpcserver_args_t) );

  args->offline = 0;
  args->params = RPCSERV_HTTP_PARAMS;

  args->port = tile->rpcserv.rpc_port;

  args->tpu_addr.sin_family = AF_INET;
  args->tpu_addr.sin_addr.s_addr = tile->rpcserv.tpu_ip_addr;
  args->tpu_addr.sin_port = htons( (ushort)tile->rpcserv.tpu_port );

  args->leaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem) );

  uchar * spad_mem_cur = spad_mem;
  args->spad = fd_spad_join( fd_spad_new( spad_mem_cur, FD_RPC_SCRATCH_MAX ) );

  /* Blockstore setup */
  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  args->blockstore = fd_blockstore_join( &args->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  FD_TEST( args->blockstore!=NULL );
  ctx->blockstore_fd = open( tile->replay.blockstore_file, O_RDONLY );
  if ( FD_UNLIKELY(ctx->blockstore_fd == -1) ){
    FD_LOG_WARNING(("%s: %s", tile->replay.blockstore_file, strerror( errno )));
  }

  args->blockstore_fd = ctx->blockstore_fd;

  args->block_index_max = tile->rpcserv.block_index_max;
  args->txn_index_max = tile->rpcserv.txn_index_max;
  args->acct_index_max = tile->rpcserv.acct_index_max;
  strncpy( args->history_file, tile->rpcserv.history_file, sizeof(args->history_file) );
  args->identity_key = &ctx->identity_key;

  fd_spad_push( args->spad ); /* We close this out when we stop the server */
  fd_rpc_create_ctx( args, &ctx->ctx );


  /* Wait until after replay tile boots before starting service */
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->in_cnt != 2 ||
                   strcmp( topo->links[ tile->in_link_id[ REPLAY_NOTIF_IDX ] ].name, "replay_notif") ||
                   strcmp( topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ].name, "stake_out" ) ) ) {
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
  FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_ulong_align_up( FD_RPC_SCRATCH_MAX, fd_spad_align() ) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_topo_link_t * replay_notif_in_link   = &topo->links[ tile->in_link_id[ REPLAY_NOTIF_IDX ] ];
  ctx->replay_notif_in_mem    = topo->workspaces[ topo->objs[ replay_notif_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_notif_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_notif_in_mem, replay_notif_in_link->dcache );
  ctx->replay_notif_in_wmark  = fd_dcache_compact_wmark ( ctx->replay_notif_in_mem, replay_notif_in_link->dcache, replay_notif_in_link->mtu );

  fd_topo_link_t * stake_in_link   = &topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ];
  ctx->stake_in_mem    = topo->workspaces[ topo->objs[ stake_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_in_mem, stake_in_link->dcache );
  ctx->stake_in_wmark  = fd_dcache_compact_wmark ( ctx->stake_in_mem, stake_in_link->dcache, stake_in_link->mtu );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  fd_rpcserver_args_t * args = &ctx->args;
  if( FD_UNLIKELY( !fd_funk_join( args->funk, fd_topo_obj_laddr( topo, tile->rpcserv.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }
  fd_rpc_start_service( args, ctx->ctx );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_ctx_t), sizeof(fd_rpcserv_tile_ctx_t) );

  populate_sock_filter_policy_fd_rpcserv_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_rpc_ws_fd( ctx->ctx ), (uint)ctx->blockstore_fd );
  return sock_filter_policy_fd_rpcserv_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_ctx_t), sizeof(fd_rpcserv_tile_ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_rpc_ws_fd( ctx->ctx ); /* listen socket */
  out_fds[ out_cnt++ ] = ctx->blockstore_fd;
  return out_cnt;
}

/* TODO: This is probably not correct. */
#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rpcserv_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rpcserv_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

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
