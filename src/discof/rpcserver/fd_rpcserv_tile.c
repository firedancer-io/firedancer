#include "../../disco/topo/fd_topo.h"
#include <sys/socket.h>
#include "generated/fd_rpcserv_tile_seccomp.h"
#include "../rpcserver/fd_rpc_service.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"

#include <fcntl.h>
#include <unistd.h>

#define IN_KIND_REPLAY_OUT    (0)
#define IN_KIND_STAKE_OUT     (1)
#define IN_KIND_REPAIR_REPLAY (2)

struct fd_rpcserv_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_rpcserv_in fd_rpcserv_in_t;

struct fd_rpcserv_tile {
  fd_rpcserver_args_t args;

  fd_rpc_ctx_t * ctx;

  fd_pubkey_t      identity_key;
  fd_keyswitch_t * keyswitch;

  int in_kind[ 16UL ];
  fd_rpcserv_in_t in[ 16UL ];
};

typedef struct fd_rpcserv_tile fd_rpcserv_tile_t;

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
  l = FD_LAYOUT_APPEND( l, alignof(fd_rpcserv_tile_t), sizeof(fd_rpcserv_tile_t) );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(),            fd_spad_footprint( FD_RPC_SCRATCH_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static inline void
during_housekeeping( fd_rpcserv_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    memcpy( &ctx->identity_key, ctx->keyswitch->bytes, sizeof(fd_pubkey_t) );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
before_credit( fd_rpcserv_tile_t * ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  *charge_busy = fd_rpc_ws_poll( ctx->ctx );
}

static inline int
returnable_frag( fd_rpcserv_tile_t * ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPLAY_OUT: {
      fd_rpc_replay_during_frag( ctx->ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sig, sz, ctl );
      fd_rpc_replay_after_frag( ctx->ctx, sig );
      break;
    }
    case IN_KIND_STAKE_OUT: {
      fd_rpc_stake_during_frag( ctx->ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sz );
      fd_rpc_stake_after_frag( ctx->ctx );
      break;
    }
    case IN_KIND_REPAIR_REPLAY: {
      fd_rpc_repair_during_frag( ctx->ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sz );
      fd_rpc_repair_after_frag( ctx->ctx );
      break;
    }
    default: FD_LOG_ERR(( "unhandled kind %d", ctx->in_kind[ in_idx ] ));
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_t), sizeof(fd_rpcserv_tile_t) );
  void * spad_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(),            fd_spad_footprint( FD_RPC_SCRATCH_MAX ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( !strcmp( tile->rpcserv.identity_key_path, "" ) ) ) FD_LOG_ERR( ( "identity_key_path not set" ) );
  memcpy( &ctx->identity_key, fd_keyload_load( tile->rpcserv.identity_key_path, /* pubkey only: */ 1 ), sizeof(fd_pubkey_t) );

  fd_rpcserver_args_t * args = &ctx->args;
  fd_memset( args, 0, sizeof(fd_rpcserver_args_t) );

  args->offline = 0;
  args->params = RPCSERV_HTTP_PARAMS;

  args->port = tile->rpcserv.rpc_port;

  args->tpu_addr.sin_family = AF_INET;
  args->tpu_addr.sin_addr.s_addr = tile->rpcserv.tpu_ip_addr;
  args->tpu_addr.sin_port = htons( (ushort)tile->rpcserv.tpu_port );

  uchar * spad_mem_cur = spad_mem;
  args->spad = fd_spad_join( fd_spad_new( spad_mem_cur, FD_RPC_SCRATCH_MAX ) );

  args->block_index_max = tile->rpcserv.block_index_max;
  args->txn_index_max = tile->rpcserv.txn_index_max;
  args->acct_index_max = tile->rpcserv.acct_index_max;
  strncpy( args->history_file, tile->rpcserv.history_file, sizeof(args->history_file) );
  args->identity_key = ctx->identity_key;

  fd_spad_push( args->spad ); /* We close this out when we stop the server */
  fd_rpc_create_ctx( args, &ctx->ctx );

  /* Wait until after replay tile boots before starting service */
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_t), sizeof(fd_rpcserv_tile_t) );
                            FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(),            fd_ulong_align_up( FD_RPC_SCRATCH_MAX, fd_spad_align() ) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  fd_rpcserver_args_t * args = &ctx->args;
  FD_TEST( fd_funk_join( args->funk, fd_topo_obj_laddr( topo, tile->rpcserv.funk_obj_id ) ) );

  args->store = fd_store_join( fd_topo_obj_laddr( topo, tile->rpcserv.store_obj_id ) );
  FD_TEST( args->store );

  fd_rpc_start_service( args, ctx->ctx );

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];

    if( FD_LIKELY( !strcmp( link->name, "replay_out"        ) ) ) ctx->in_kind[ in_idx ] = IN_KIND_REPLAY_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "replay_stake" ) ) ) ctx->in_kind[ in_idx ] = IN_KIND_STAKE_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "repair_repla" ) ) ) ctx->in_kind[ in_idx ] = IN_KIND_REPAIR_REPLAY;
    else FD_LOG_ERR(( "rpcserv tile has unexpected input link %s", link->name ));

    ctx->in[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ in_idx ].mem, link->dcache );
    ctx->in[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in[ in_idx ].mtu    = link->mtu;
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_t), sizeof(fd_rpcserv_tile_t) );

  populate_sock_filter_policy_fd_rpcserv_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_rpc_ws_fd( ctx->ctx ) );
  return sock_filter_policy_fd_rpcserv_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpcserv_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpcserv_tile_t), sizeof(fd_rpcserv_tile_t) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_rpc_ws_fd( ctx->ctx ); /* listen socket */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rpcserv_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rpcserv_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

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
