#include "fd_rpc.h"

#include "../replay/fd_replay_tile.h"
#include "../genesis/fd_genesi_tile.h"
#include "../fd_accdb_topo.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../ballet/json/cJSON_alloc.h"
#include "../../ballet/lthash/fd_lthash.h"

#include <stddef.h>
#include <sys/socket.h>

#include "generated/fd_rpc_tile_seccomp.h"

#define IN_KIND_REPLAY      (0)
#define IN_KIND_GENESI      (1)
#define IN_KIND_GOSSIP_OUT  (2)
#define IN_KIND_GENESI_FILE (3)

static fd_http_server_params_t
derive_http_params( fd_topo_tile_t const * tile ) {
  return (fd_http_server_params_t) {
    .max_connection_cnt    = tile->rpc.max_http_connections,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN,
    .max_ws_recv_frame_len = 0UL,
    .max_ws_send_frame_cnt = 0UL,
    .outgoing_buffer_sz    = tile->rpc.send_buffer_size_mb * (1UL<<20UL),
    .compress_websocket    = 0,
  };
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof( fd_rpc_tile_t );
  a = fd_ulong_max( a, fd_http_server_align() );
  a = fd_ulong_max( a, fd_alloc_align() );
  a = fd_ulong_max( a, alignof(bank_info_t) );
  a = fd_ulong_max( a, fd_rpc_cluster_node_dlist_align() );
  return a;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong http_fp = fd_http_server_footprint( derive_http_params( tile ) );
  if( FD_UNLIKELY( !http_fp ) ) FD_LOG_ERR(( "Invalid [tiles.rpc] config parameters" ));

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t )                      );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),   http_fp                                      );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),         fd_alloc_footprint()                         );
  l = FD_LAYOUT_APPEND( l, alignof(bank_info_t),     tile->rpc.max_live_slots*sizeof(bank_info_t) );
  l = FD_LAYOUT_APPEND( l, fd_rpc_cluster_node_dlist_align(), fd_rpc_cluster_node_dlist_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 256UL * (1UL<<20UL); /* 256MiB of heap space for the cJSON allocator */
}

static inline void
during_housekeeping( fd_rpc_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->identity_pubkey, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
before_credit( fd_rpc_tile_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  long now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->next_poll_deadline ) ) {
    *charge_busy = fd_http_server_poll( ctx->http, 0 );
    ctx->next_poll_deadline = fd_tickcount() + (long)(fd_tempo_tick_per_ns( NULL )*128L*1000L);
  }
}

static int
before_frag( fd_rpc_tile_t *   ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig ) {
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP_OUT ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }

  return 0;
}

static inline int
returnable_frag( fd_rpc_tile_t *     ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz FD_PARAM_UNUSED,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {

  if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) {
    switch( sig ) {
      case REPLAY_SIG_SLOT_COMPLETED: {
        fd_replay_slot_completed_t const * slot_completed = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

        bank_info_t * bank = &ctx->banks[ slot_completed->bank_idx ];
        bank->slot = slot_completed->slot;
        bank->transaction_count = slot_completed->transaction_count;
        bank->block_height = slot_completed->block_height;
        fd_memcpy( bank->block_hash, slot_completed->block_hash.uc, 32 );

        bank->inflation.initial         = slot_completed->inflation.initial;
        bank->inflation.terminal        = slot_completed->inflation.terminal;
        bank->inflation.taper           = slot_completed->inflation.taper;
        bank->inflation.foundation      = slot_completed->inflation.foundation;
        bank->inflation.foundation_term = slot_completed->inflation.foundation_term;

        bank->rent.lamports_per_uint8_year = slot_completed->rent.lamports_per_uint8_year;
        bank->rent.exemption_threshold     = slot_completed->rent.exemption_threshold;
        bank->rent.burn_percent            = slot_completed->rent.burn_percent;

        /* In Agave, "processed" confirmation is the bank we've just
           voted for (handle_votable_bank), which is also guaranteed to
           have been replayed.

           Right now tower is not really built out to replicate this
           exactly, so we use the latest replayed slot, which is
           slightly more eager than Agave but shouldn't really affect
           end-users, since any use-cases that assume "processed" means
           "voted-for" would fail in Agave in cases where a cast vote
           does not land.

           tldr: This isn't strictly conformant with Agave, but doesn't
           need to be since Agave doesn't provide any guarantees anyways. */
        if( FD_LIKELY( ctx->processed_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->processed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->processed_idx = slot_completed->bank_idx;
        break;
      }
      case REPLAY_SIG_OC_ADVANCED: {
        fd_replay_oc_advanced_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        if( FD_LIKELY( ctx->confirmed_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->confirmed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->confirmed_idx = msg->bank_idx;
        ctx->cluster_confirmed_slot = msg->slot;
        break;
      }
      case REPLAY_SIG_ROOT_ADVANCED: {
        fd_replay_root_advanced_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        if( FD_LIKELY( ctx->finalized_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->finalized_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->finalized_idx = msg->bank_idx;
        break;
      }
      default: {
        break;
      }
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP_OUT ) {
    fd_gossip_update_message_t const * update = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    switch( update->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
        if( FD_UNLIKELY( update->contact_info->idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected contact_info_idx %lu >= %lu", update->contact_info->idx, FD_CONTACT_INFO_TABLE_SIZE ));
        fd_rpc_cluster_node_t * node = &ctx->cluster_nodes[ update->contact_info->idx ];
        if( FD_LIKELY( node->valid ) ) fd_rpc_cluster_node_dlist_idx_remove( ctx->cluster_nodes_dlist, update->contact_info->idx, ctx->cluster_nodes );

        node->valid = 1;
        node->identity = *(fd_pubkey_t *)update->origin;
        fd_memcpy( node->ci, update->contact_info->value, sizeof(fd_gossip_contact_info_t) );

        fd_rpc_cluster_node_dlist_idx_push_tail( ctx->cluster_nodes_dlist, update->contact_info->idx, ctx->cluster_nodes );
        break;
      }
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
        if( FD_UNLIKELY( update->contact_info_remove->idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected remove_contact_info_idx %lu >= %lu", update->contact_info_remove->idx, FD_CONTACT_INFO_TABLE_SIZE ));
        fd_rpc_cluster_node_t * node = &ctx->cluster_nodes[ update->contact_info->idx ];
        FD_TEST( node->valid );
        node->valid = 0;
        fd_rpc_cluster_node_dlist_idx_remove( ctx->cluster_nodes_dlist, update->contact_info->idx, ctx->cluster_nodes );
        break;
      }
      default: break;
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_GENESI ) {
    ctx->has_genesis_hash = 1;
    uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) {
      fd_memcpy( ctx->genesis_hash, src+sizeof(fd_lthash_value_t), 32UL );
    } else {
      fd_memcpy( ctx->genesis_hash, src, 32UL );
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_GENESI_FILE ) {
    uchar * src = (uchar *)fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

    ctx->genesis_tar_bz_sz = fd_rpc_file_as_tarball(
      ctx,
      "genesis.bin",
      src, sz,
      ctx->genesis_tar, sizeof(ctx->genesis_tar),
      ctx->genesis_tar_bz, sizeof(ctx->genesis_tar_bz) );
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_params = derive_http_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );
  fd_http_server_t * _http = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( http_params ) );

  if( FD_UNLIKELY( !strcmp( tile->rpc.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->rpc.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity_key, 32UL );

  fd_http_server_callbacks_t callbacks = {
    .request = rpc_http_request,
  };
  ctx->http = fd_http_server_join( fd_http_server_new( _http, http_params, callbacks, ctx ) );
  fd_http_server_listen( ctx->http, tile->rpc.listen_addr, tile->rpc.listen_port );

  FD_LOG_NOTICE(( "rpc server listening at http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->rpc.listen_addr ), tile->rpc.listen_port ));
}

extern char const fdctl_version_string[];

static inline fd_rpc_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_rpc_out_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0 };


  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_rpc_out_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX };

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_rpc_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t )                                );
                        FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( derive_http_params( tile ) ) );
  void * _alloc       = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),         fd_alloc_footprint()                                   );
  void * _banks       = FD_SCRATCH_ALLOC_APPEND( l, alignof(bank_info_t),     tile->rpc.max_live_slots*sizeof(bank_info_t)           );
  void * _nodes_dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_rpc_cluster_node_dlist_align(), fd_rpc_cluster_node_dlist_footprint() );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  for( ulong i=0UL; i<FD_CONTACT_INFO_TABLE_SIZE; i++ ) ctx->cluster_nodes[ i ].valid = 0;

  ctx->bz2_alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( ctx->bz2_alloc );

  ctx->next_poll_deadline = fd_tickcount();

  ctx->cluster_confirmed_slot = ULONG_MAX;
  ctx->genesis_tar_bz_sz = ULONG_MAX;

  ctx->processed_idx = ULONG_MAX;
  ctx->confirmed_idx = ULONG_MAX;
  ctx->finalized_idx = ULONG_MAX;

  ctx->cluster_nodes_dlist = fd_rpc_cluster_node_dlist_join( fd_rpc_cluster_node_dlist_new( _nodes_dlist ) );
  ctx->banks = _banks;
  ctx->max_live_slots = tile->rpc.max_live_slots;
  for( ulong i=0UL; i<ctx->max_live_slots; i++ ) ctx->banks[ i ].slot = ULONG_MAX;

  FD_TEST( fd_cstr_printf_check( ctx->version_string, sizeof( ctx->version_string ), NULL, "%s", fdctl_version_string ) );

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if     ( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_rpc" ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI_FILE;
    else FD_LOG_ERR(( "unexpected link name %s", link->name ));
  }

  *ctx->replay_out = out1( topo, tile, "rpc_replay" ); FD_TEST( ctx->replay_out->idx!=ULONG_MAX );

  fd_accdb_init_from_topo( ctx->accdb, topo, tile );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
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
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );

  populate_sock_filter_policy_fd_rpc_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->http ) );
  return sock_filter_policy_fd_rpc_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->http ); /* rpc listen socket */
  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  ulong base = 5UL;
  return base+tile->rpc.max_http_connections;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rpc_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rpc_tile_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_rpc = {
  .name                     = "rpc",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
