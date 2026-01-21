/* The frontend assets are pre-built and statically compiled into the
   binary here.  To regenerate them, run

    $ git clone https://github.com/firedancer-io/firedancer-frontend.git frontend
    $ make frontend

   from the repository root. */

#include "../../disco/gui/generated/http_import_dist.h"

/* The list of files used to serve the frontend is set here.  This is a
   global variable since is is populated at boot based on the
   `development.gui.frontend_release_channel` option and is accessed in
   the gui_http_request callback. */
static fd_http_static_file_t * STATIC_FILES;

#include <sys/socket.h> /* SOCK_CLOEXEC, SOCK_NONBLOCK needed for seccomp filter */
#include <stdlib.h>

#include "generated/fd_gui_tile_seccomp.h"

#include "../../disco/tiles.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/gui/fd_gui.h"
#include "../../disco/plugin/fd_plugin.h"
#include "../../discof/replay/fd_exec.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/net/fd_net_checks.h"
#include "../../discof/genesis/fd_genesi_tile.h" // TODO: Layering violation
#include "../../waltz/http/fd_http_server.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../ballet/json/cJSON_alloc.h"
#include "../../util/clock/fd_clock.h"
#include "../../discof/repair/fd_repair.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../util/pod/fd_pod_format.h"

#include "../../flamenco/gossip/fd_gossip_private.h"
#include "../../flamenco/runtime/fd_bank.h"

#define IN_KIND_PLUGIN       ( 0UL)
#define IN_KIND_POH_PACK     ( 1UL)
#define IN_KIND_PACK_BANK    ( 2UL)
#define IN_KIND_PACK_POH     ( 3UL)
#define IN_KIND_BANK_POH     ( 4UL)
#define IN_KIND_SHRED_OUT    ( 5UL) /* firedancer only */
#define IN_KIND_NET_GOSSVF   ( 6UL) /* firedancer only */
#define IN_KIND_GOSSIP_NET   ( 7UL) /* firedancer only */
#define IN_KIND_GOSSIP_OUT   ( 8UL) /* firedancer only */
#define IN_KIND_SNAPCT       ( 9UL) /* firedancer only */
#define IN_KIND_REPAIR_NET   (10UL) /* firedancer only */
#define IN_KIND_TOWER_OUT    (11UL) /* firedancer only */
#define IN_KIND_REPLAY_OUT   (12UL) /* firedancer only */
#define IN_KIND_REPLAY_STAKE (13UL) /* firedancer only */
#define IN_KIND_GENESI_OUT   (14UL) /* firedancer only */
#define IN_KIND_SNAPIN       (15UL) /* firedancer only */
#define IN_KIND_EXEC_REPLAY  (16UL) /* firedancer only */

FD_IMPORT_BINARY( firedancer_svg, "book/public/fire.svg" );

#define FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN       8192
#define FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN 8192
#define FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT 8192

static fd_http_server_params_t
derive_http_params( fd_topo_tile_t const * tile ) {
  return (fd_http_server_params_t) {
    .max_connection_cnt    = tile->gui.max_http_connections,
    .max_ws_connection_cnt = tile->gui.max_websocket_connections,
    .max_request_len       = FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN,
    .max_ws_recv_frame_len = FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN,
    .max_ws_send_frame_cnt = FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT,
    .outgoing_buffer_sz    = tile->gui.send_buffer_size_mb * (1UL<<20UL),
    .compress_websocket    = tile->gui.websocket_compression,
  };
}

struct fd_gui_in_ctx {
  fd_wksp_t * mem;
  ulong       mtu;
  ulong       chunk0;
  ulong       wmark;
};

typedef struct fd_gui_in_ctx fd_gui_in_ctx_t;

struct fd_gui_out_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_gui_out_ctx fd_gui_out_ctx_t;

typedef struct {
  fd_topo_t * topo;
  fd_banks_t  banks[1];

  int is_full_client;
  int snapshots_enabled;

  fd_gui_t * gui;
  fd_gui_peers_ctx_t * peers;

  ulong in_cnt;
  ulong idle_cnt;

  /* Most of the gui tile uses fd_clock for timing, but some stem
     timestamps still used tickcounts, so we keep separate timestamps
     here to handle those cases until fd_clock is more widely adopted. */
  long ref_wallclock;
  long ref_tickcount;
  const double tick_per_ns;

  fd_clock_t clock[1];
  long       recal_next; /* next recalibration time (ns) */

  uchar __attribute__((aligned(FD_CLOCK_ALIGN))) clock_mem[ FD_CLOCK_FOOTPRINT ];

  ulong chunk;
  union {
    struct {
      ulong slot;
      ulong shred_idx;
    } repair_net;

    uchar net_gossvf[ FD_NET_MTU ];
    uchar gossip_net[ FD_NET_MTU ];
  } parsed;

  fd_http_server_t * gui_server;

  long next_poll_deadline;

  char version_string[ 16UL ];

  fd_keyswitch_t * keyswitch;
  uchar const *    identity_key;

  int               has_vote_key;
  fd_pubkey_t const vote_key[ 1UL ];

  ulong           in_kind[ 64UL ];
  ulong           in_bank_idx[ 64UL ];
  fd_gui_in_ctx_t in[ 64UL ];

  fd_net_rx_bounds_t net_in_bounds[ 64UL ];

  fd_gui_out_ctx_t replay_out[ 1 ];
} fd_gui_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_http_server_params_t http_param = derive_http_params( tile );
  ulong http_fp = fd_http_server_footprint( http_param );
  if( FD_UNLIKELY( !http_fp ) ) FD_LOG_ERR(( "Invalid [tiles.gui] config parameters" ));

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),  http_fp );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_align(),    fd_gui_peers_footprint( http_param.max_ws_connection_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_align(),          fd_gui_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),        fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 256UL * (1UL<<20UL); /* 256MiB of heap space for the cJSON allocator */
}

static inline void
during_housekeeping( fd_gui_ctx_t * ctx ) {
  ctx->ref_wallclock = fd_log_wallclock();
  ctx->ref_tickcount = fd_tickcount();

  if( FD_UNLIKELY( fd_clock_now( ctx->clock ) >= ctx->recal_next ) ) {
    ctx->recal_next = fd_clock_default_recal( ctx->clock );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_gui_set_identity( ctx->gui, ctx->keyswitch->bytes );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_gui_ctx_t * ctx ) {
  FD_MGAUGE_SET( GUI, CONNECTION_COUNT, ctx->gui_server->metrics.connection_cnt );
  FD_MGAUGE_SET( GUI, WEBSOCKET_CONNECTION_COUNT, ctx->gui_server->metrics.ws_connection_cnt );

  FD_MCNT_SET( GUI, WEBSOCKET_FRAMES_SENT,     ctx->gui_server->metrics.frames_written );
  FD_MCNT_SET( GUI, WEBSOCKET_FRAMES_RECEIVED, ctx->gui_server->metrics.frames_read );

  FD_MCNT_SET( GUI, BYTES_WRITTEN, ctx->gui_server->metrics.bytes_written );
  FD_MCNT_SET( GUI, BYTES_READ,    ctx->gui_server->metrics.bytes_read );
}

static void
before_credit( fd_gui_ctx_t *      ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt<2UL*ctx->in_cnt ) ) return;
  ctx->idle_cnt = 0UL;

  int charge_busy_server = 0;
  long now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->next_poll_deadline ) ) {
    charge_busy_server = fd_http_server_poll( ctx->gui_server, 0 );
    ctx->next_poll_deadline = fd_tickcount() + (long)(ctx->tick_per_ns * 128L * 1000L);
  }

  int charge_poll = 0;
  charge_poll |= fd_gui_poll( ctx->gui, fd_clock_now( ctx->clock ) );
  if( FD_UNLIKELY( ctx->is_full_client ) ) charge_poll |= fd_gui_peers_poll( ctx->peers, fd_clock_now( ctx->clock ) );

  *charge_busy = charge_busy_server | charge_poll;
}

static int
before_frag( fd_gui_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig ) {
  (void)seq;

  /* Ignore "done draining banks" signal from pack->poh */
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PACK_POH && sig==ULONG_MAX ) ) return 1;
  return 0;
}

static inline void
during_frag( fd_gui_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq    FD_PARAM_UNUSED,
             ulong          sig,
             ulong          chunk,
             ulong          sz,
             ulong          ctl ) {

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PLUGIN ) ) {
    /* ... todo... sigh, sz is not correct since it's too big */
    if( FD_LIKELY( sig==FD_PLUGIN_MSG_GOSSIP_UPDATE ) ) {
      ulong peer_cnt = ((ulong *)src)[ 0 ];
      FD_TEST( peer_cnt<=FD_GUI_MAX_PEER_CNT );
      sz = 8UL + peer_cnt*FD_GOSSIP_LINK_MSG_SIZE;
    } else if( FD_LIKELY( sig==FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE ) ) {
      ulong peer_cnt = ((ulong *)src)[ 0 ];
      FD_TEST( peer_cnt<=FD_GUI_MAX_PEER_CNT );
      sz = 8UL + peer_cnt*112UL;
    } else if( FD_UNLIKELY( sig==FD_PLUGIN_MSG_LEADER_SCHEDULE ) ) {
      ulong staked_cnt = ((ulong *)src)[ 1 ];
      FD_TEST( staked_cnt<=MAX_STAKED_LEADERS );
      sz = fd_stake_weight_msg_sz( staked_cnt );
    }
  }

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_STAKE ) ) {
    fd_stake_weight_msg_t * leader_schedule = (fd_stake_weight_msg_t *)src;
    FD_TEST( sz==(ushort)(sizeof(fd_stake_weight_msg_t)+(leader_schedule->staked_cnt*sizeof(fd_vote_stake_weight_t))) );
    sz = fd_stake_weight_msg_sz( leader_schedule->staked_cnt );
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GENESI_OUT ) ) {
    if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) sz = sizeof(fd_lthash_value_t)+sizeof(fd_hash_t);
  }

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_OUT ) ) {
    if( FD_LIKELY( sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_BECAME_LEADER  ) ) return;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "in_kind %lu chunk %lu %lu corrupt, not in range [%lu,%lu] or too large (%lu)", ctx->in_kind[ in_idx ], chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, ctx->in[ in_idx ].mtu ));

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPAIR_NET: {
      FD_TEST( ctx->is_full_client );
      ctx->parsed.repair_net.slot = ULONG_MAX;
      uchar * payload;
      ulong payload_sz;
      if( FD_LIKELY( fd_ip4_udp_hdr_strip( src, sz, &payload, &payload_sz, NULL, NULL, NULL ) ) ) {
        fd_repair_msg_t const * msg = (fd_repair_msg_t const *)payload;
        if( FD_LIKELY( msg->kind==FD_REPAIR_KIND_SHRED ) ) {
          if( FD_UNLIKELY( msg->shred.slot==0 ) ) break;
          ctx->parsed.repair_net.slot = msg->shred.slot;
          ctx->parsed.repair_net.shred_idx = msg->shred.shred_idx;
        }
      }
      break;
    }
    case IN_KIND_NET_GOSSVF: {
      FD_TEST( ctx->is_full_client );
      FD_TEST( sz<=sizeof(ctx->parsed.net_gossvf) );
      uchar const * net_src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );
      fd_memcpy( ctx->parsed.net_gossvf, net_src, sz );
      break;
    }
    case IN_KIND_GOSSIP_NET: {
      FD_TEST( ctx->is_full_client );
      FD_TEST( sz<=sizeof(ctx->parsed.gossip_net) );
      fd_memcpy( ctx->parsed.gossip_net, src, sz );
      break;
    }
  }

  ctx->chunk = chunk;
}

static inline void
after_frag( fd_gui_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)stem;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );

  switch ( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_PLUGIN: {
      FD_TEST( !ctx->is_full_client );
      fd_gui_plugin_message( ctx->gui, sig, src, fd_clock_now( ctx->clock ) );
      break;
    }
    case IN_KIND_EXEC_REPLAY: {
      FD_TEST( ctx->is_full_client );
      if( FD_LIKELY( sig>>32==FD_EXEC_TT_TXN_EXEC ) ) {
        fd_exec_task_done_msg_t * msg = (fd_exec_task_done_msg_t *)src;

        long tickcount = fd_tickcount();
        long tsorig_ns = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tsorig, tickcount ) - ctx->ref_tickcount) / ctx->tick_per_ns);
        long tspub_ns = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, tickcount ) - ctx->ref_tickcount) / ctx->tick_per_ns);
        fd_gui_handle_exec_txn_done( ctx->gui, msg->txn_exec->slot, msg->txn_exec->start_shred_idx, msg->txn_exec->end_shred_idx, tsorig_ns, tspub_ns );
      }

      break;
    }
    case IN_KIND_REPLAY_OUT: {
      FD_TEST( ctx->is_full_client );
      if( FD_UNLIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
        fd_replay_slot_completed_t const * replay =  (fd_replay_slot_completed_t const *)src;


        /* bank should already have positive refcnt */
        fd_bank_t bank[1];
        FD_TEST( fd_banks_bank_query( bank, ctx->banks, replay->bank_idx ) );
        FD_TEST( bank->data->refcnt!=0 );

        fd_vote_states_t const * vote_states = fd_bank_vote_states_locking_query( bank );
        FD_TEST( fd_vote_states_cnt( vote_states )<FD_RUNTIME_MAX_VOTE_ACCOUNTS );

        fd_vote_states_iter_t iter_[1];
        ulong vote_count = 0UL;
        for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
            !fd_vote_states_iter_done( iter );
            fd_vote_states_iter_next( iter ) ) {
          fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );

          ctx->peers->votes[ vote_count ].vote_account        = vote_state->vote_account;
          ctx->peers->votes[ vote_count ].node_account        = vote_state->node_account;
          ctx->peers->votes[ vote_count ].stake               = vote_state->stake;
          ctx->peers->votes[ vote_count ].last_vote_slot      = vote_state->last_vote_slot;
          ctx->peers->votes[ vote_count ].last_vote_timestamp = vote_state->last_vote_timestamp;
          ctx->peers->votes[ vote_count ].commission          = vote_state->commission;
          // ctx->peers->votes[ vote_count ].epoch               = fd_ulong_if( !vote_state->credits_cnt, ULONG_MAX, vote_state->epoch[ 0 ]   );
          // ctx->peers->votes[ vote_count ].epoch_credits       = fd_ulong_if( !vote_state->credits_cnt, ULONG_MAX, vote_state->credits[ 0 ] );

          vote_count++;
        }
        fd_bank_vote_states_end_locking_query( bank );

        fd_gui_slot_completed_t slot_completed;
        if( FD_LIKELY( replay->parent_bank_idx!=ULONG_MAX ) ) {
          fd_bank_t parent_bank[1];
          FD_TEST( fd_banks_bank_query( parent_bank, ctx->banks, replay->parent_bank_idx ) );

          slot_completed.total_txn_cnt          = (uint)(fd_bank_txn_count_get( bank )                 - fd_bank_txn_count_get( parent_bank ));
          slot_completed.vote_txn_cnt           = slot_completed.total_txn_cnt - (uint)(fd_bank_nonvote_txn_count_get( bank ) - fd_bank_nonvote_txn_count_get( parent_bank ));
          slot_completed.failed_txn_cnt         = (uint)(fd_bank_failed_txn_count_get( bank )          - fd_bank_failed_txn_count_get( parent_bank ));
          slot_completed.nonvote_failed_txn_cnt = (uint)(fd_bank_nonvote_failed_txn_count_get( bank )  - fd_bank_nonvote_failed_txn_count_get( parent_bank ));

          fd_stem_publish( stem, ctx->replay_out->idx, replay->parent_bank_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        } else {
          slot_completed.total_txn_cnt          = (uint)fd_bank_txn_count_get( bank );
          slot_completed.vote_txn_cnt           = slot_completed.total_txn_cnt - (uint)fd_bank_nonvote_txn_count_get( bank );
          slot_completed.failed_txn_cnt         = (uint)fd_bank_failed_txn_count_get( bank );
          slot_completed.nonvote_failed_txn_cnt = (uint)fd_bank_nonvote_failed_txn_count_get( bank );
        }

        slot_completed.slot              = fd_bank_slot_get( bank );
        slot_completed.completed_time    = replay->completion_time_nanos;
        slot_completed.parent_slot       = fd_bank_parent_slot_get( bank );
        slot_completed.max_compute_units = fd_uint_if( replay->cost_tracker.block_cost_limit==0UL, UINT_MAX, (uint)replay->cost_tracker.block_cost_limit );
        slot_completed.transaction_fee   = fd_bank_execution_fees_get( bank );
        slot_completed.transaction_fee   = slot_completed.transaction_fee - (slot_completed.transaction_fee>>1); /* burn */
        slot_completed.priority_fee      = fd_bank_priority_fees_get( bank );
        slot_completed.tips              = fd_bank_tips_get( bank );
        slot_completed.compute_units     = fd_uint_if( replay->cost_tracker.block_cost==0UL, UINT_MAX, (uint)replay->cost_tracker.block_cost );
        slot_completed.shred_cnt         = (uint)fd_bank_shred_cnt_get( bank );

        /* release shared ownership of bank and parent_bank */
        fd_stem_publish( stem, ctx->replay_out->idx, replay->bank_idx, 0UL, 0UL, 0UL, 0UL, 0UL );

        /* update vote info */
        fd_gui_peers_handle_vote_update( ctx->peers, ctx->peers->votes, vote_count, fd_clock_now( ctx->clock ), ctx->gui->summary.identity_key );

        /* update slot data */
        fd_gui_handle_replay_update( ctx->gui, &slot_completed, &replay->block_hash, ctx->peers->slot_voted, replay->storage_slot, replay->root_slot, replay->identity_balance, fd_clock_now( ctx->clock ) );

      } else if( FD_UNLIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) {
        fd_became_leader_t * became_leader = (fd_became_leader_t *)src;
        fd_gui_became_leader( ctx->gui, became_leader->slot, became_leader->slot_start_ns, became_leader->slot_end_ns, became_leader->limits.slot_max_cost, became_leader->max_microblocks_in_slot );
      } else {
        return;
      }
      break;
    }
    case IN_KIND_REPLAY_STAKE: {
      FD_TEST( ctx->is_full_client );

      fd_stake_weight_msg_t * leader_schedule = (fd_stake_weight_msg_t *)src;
      fd_gui_handle_leader_schedule( ctx->gui, leader_schedule, fd_clock_now( ctx->clock ) );
      break;
    }
    case IN_KIND_SNAPIN: {
      FD_TEST( ctx->is_full_client );
      fd_gui_peers_handle_config_account( ctx->peers, src, sz );
      break;
    }
    case IN_KIND_GENESI_OUT: {
      FD_TEST( ctx->is_full_client );

      if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) {
        fd_gui_handle_genesis_hash( ctx->gui, src+sizeof(fd_lthash_value_t) );
      } else {
        fd_gui_handle_genesis_hash( ctx->gui, src );
      }
      break;
    }
    case IN_KIND_TOWER_OUT: {
      FD_TEST( ctx->is_full_client );
      if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_DONE )) {
        fd_tower_slot_done_t const * tower = (fd_tower_slot_done_t const *)src;
        fd_gui_handle_tower_update( ctx->gui, tower, fd_clock_now( ctx->clock ) );
      }
      if( FD_UNLIKELY( sig==FD_TOWER_SIG_SLOT_CONFIRMED ) ) {
        fd_gui_handle_notarization_update( ctx->gui, (fd_tower_slot_confirmed_t const *)src );
      }
      break;
    }
    case IN_KIND_SHRED_OUT: {
      FD_TEST( ctx->is_full_client );
      long tsorig_nanos = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tsorig, fd_tickcount() ) - ctx->ref_tickcount) / ctx->tick_per_ns);
      if( FD_LIKELY( sz!=0 && sz!=FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ * 2 + sizeof(int) ) ) {
        ulong slot = fd_disco_shred_out_shred_sig_slot( sig );
        int is_turbine = fd_disco_shred_out_shred_sig_is_turbine( sig );
        ulong shred_idx  = fd_disco_shred_out_shred_sig_shred_idx( sig );
        /* tsorig is the timestamp when the shred was received by the shred tile */
        fd_gui_handle_shred( ctx->gui, slot, shred_idx, is_turbine, tsorig_nanos );
      }
      if( FD_UNLIKELY( sz==FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ * 2 + sizeof(int) && FD_LOAD( int, src + FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ * 2 ) ) ) {
        fd_gui_handle_leader_fec( ctx->gui, fd_disco_shred_out_fec_sig_slot( sig ), fd_disco_shred_out_fec_sig_data_cnt( sig ), fd_disco_shred_out_fec_sig_is_slot_complete( sig ), tsorig_nanos );
      }
      break;
    }
    case IN_KIND_SNAPCT: {
      FD_TEST( ctx->is_full_client );
      fd_gui_handle_snapshot_update( ctx->gui, (fd_snapct_update_t *)src );
      break;
    }
    case IN_KIND_REPAIR_NET: {
      if( FD_UNLIKELY( ctx->parsed.repair_net.slot==ULONG_MAX ) ) break;
      long tsorig_ns = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tsorig, fd_tickcount() ) - ctx->ref_tickcount) / ctx->tick_per_ns);
      fd_gui_handle_repair_request( ctx->gui, ctx->parsed.repair_net.slot, ctx->parsed.repair_net.shred_idx, tsorig_ns );
      break;
    }
    case IN_KIND_NET_GOSSVF: {
      FD_TEST( ctx->is_full_client );
      uchar * payload;
      ulong payload_sz;
      fd_ip4_hdr_t * ip4_hdr;
      fd_udp_hdr_t * udp_hdr;
      if( FD_LIKELY( fd_ip4_udp_hdr_strip( ctx->parsed.net_gossvf, sz, &payload, &payload_sz, NULL, &ip4_hdr, &udp_hdr ) ) ) {
        fd_gui_peers_handle_gossip_message( ctx->peers, payload, payload_sz, &(fd_ip4_port_t){ .addr = ip4_hdr->saddr, .port = udp_hdr->net_sport }, 1 );
      }
      break;
    }
    case IN_KIND_GOSSIP_NET: {
      FD_TEST( ctx->is_full_client );
      uchar * payload;
      ulong payload_sz;
      fd_ip4_hdr_t * ip4_hdr;
      fd_udp_hdr_t * udp_hdr;
      FD_TEST( fd_ip4_udp_hdr_strip( ctx->parsed.gossip_net, sz, &payload, &payload_sz, NULL, &ip4_hdr, &udp_hdr ) );
      fd_gui_peers_handle_gossip_message( ctx->peers, payload, payload_sz, &(fd_ip4_port_t){ .addr = ip4_hdr->daddr, .port = udp_hdr->net_dport }, 0 );
      break;
    }
    case IN_KIND_GOSSIP_OUT: {
      FD_TEST( ctx->is_full_client );
      fd_gossip_update_message_t * update = (fd_gossip_update_message_t *)src;
      switch( update->tag ) {
        case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: FD_TEST( sz == FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE ); break;
        case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: FD_TEST( sz == FD_GOSSIP_UPDATE_SZ_CONTACT_INFO ); break;
        default: break;
      }
      fd_gui_peers_handle_gossip_update( ctx->peers, update, fd_clock_now( ctx-> clock ) );
      break;
    }
    case IN_KIND_POH_PACK: {
      FD_TEST( !ctx->is_full_client );
      FD_TEST( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_BECAME_LEADER );
      fd_became_leader_t * became_leader = (fd_became_leader_t *)src;
      fd_gui_became_leader( ctx->gui, fd_disco_poh_sig_slot( sig ), became_leader->slot_start_ns, became_leader->slot_end_ns, became_leader->limits.slot_max_cost, became_leader->max_microblocks_in_slot );
      break;
    }
    case IN_KIND_PACK_POH: {
      fd_gui_unbecame_leader( ctx->gui, fd_disco_bank_sig_slot( sig ), (fd_done_packing_t const *)src, fd_clock_now( ctx->clock ) );
      break;
    }
    case IN_KIND_PACK_BANK: {
      if( FD_LIKELY( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK ) ) {
        fd_microblock_bank_trailer_t * trailer = (fd_microblock_bank_trailer_t *)( src+sz-sizeof(fd_microblock_bank_trailer_t) );
        long now = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, fd_tickcount() ) - ctx->ref_tickcount) / ctx->tick_per_ns);
        fd_gui_microblock_execution_begin( ctx->gui,
                                          now,
                                          fd_disco_poh_sig_slot( sig ),
                                          (fd_txn_p_t *)src,
                                          (sz-sizeof( fd_microblock_bank_trailer_t ))/sizeof( fd_txn_p_t ),
                                          (uint)trailer->microblock_idx,
                                          trailer->pack_txn_idx );
      } else {
        FD_LOG_ERR(( "unexpected poh packet type %lu", fd_disco_poh_sig_pkt_type( sig ) ));
      }
      break;
    }
    case IN_KIND_BANK_POH: {
      fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( src+sz-sizeof( fd_microblock_trailer_t ) );
      long now = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, fd_tickcount() ) - ctx->ref_tickcount) / ctx->tick_per_ns);
      fd_gui_microblock_execution_end( ctx->gui,
                                      now,
                                      ctx->in_bank_idx[ in_idx ],
                                      fd_disco_bank_sig_slot( sig ),
                                      (sz-sizeof( fd_microblock_trailer_t ))/sizeof( fd_txn_p_t ),
                                      (fd_txn_p_t *)src,
                                      trailer->pack_txn_idx,
                                      trailer->txn_start_pct,
                                      trailer->txn_load_end_pct,
                                      trailer->txn_end_pct,
                                      trailer->txn_preload_end_pct,
                                      trailer->tips );
      break;
    }
    default: FD_LOG_ERR(( "unexpected in_kind %lu", ctx->in_kind[ in_idx ] ));
  }
}

static fd_http_server_response_t
gui_http_request( fd_http_server_request_t const * request ) {
  if( FD_UNLIKELY( request->method!=FD_HTTP_SERVER_METHOD_GET ) ) {
    return (fd_http_server_response_t){
      .status = 405,
    };
  }

  if( FD_LIKELY( !strcmp( request->path, "/websocket" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .upgrade_websocket = 1,
#ifdef FD_HAS_ZSTD
      .compress_websocket = request->headers.compress_websocket,
#else
      .compress_websocket = 0,
#endif
    };
  } else if( FD_LIKELY( !strcmp( request->path, "/favicon.svg" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .static_body       = firedancer_svg,
      .static_body_len   = firedancer_svg_sz,
      .content_type      = "image/svg+xml",
      .upgrade_websocket = 0,
    };
  }

  int is_vite_page = !strcmp( request->path, "/" ) ||
                     !strcmp( request->path, "/slotDetails" ) ||
                     !strcmp( request->path, "/leaderSchedule" ) ||
                     !strcmp( request->path, "/gossip") ||
                     !strncmp( request->path, "/?", strlen("/?") ) ||
                     !strncmp( request->path, "/slotDetails?", strlen("/slotDetails?") ) ||
                     !strncmp( request->path, "/leaderSchedule?", strlen("/leaderSchedule?") ) ||
                     !strncmp( request->path, "/gossip?", strlen("/gossip?") );

  FD_TEST( STATIC_FILES );
  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++ ) {
    if( !strcmp( request->path, f->name ) ||
        (!strcmp( f->name, "/index.html" ) && is_vite_page) ) {
      char const * content_type = NULL;

      char const * ext = strrchr( f->name, '.' );
      if( FD_LIKELY( ext ) ) {
        if( !strcmp( ext, ".html" ) ) content_type = "text/html; charset=utf-8";
        else if( !strcmp( ext, ".css" ) ) content_type = "text/css";
        else if( !strcmp( ext, ".js" ) ) content_type = "application/javascript";
        else if( !strcmp( ext, ".svg" ) ) content_type = "image/svg+xml";
        else if( !strcmp( ext, ".woff" ) ) content_type = "font/woff";
        else if( !strcmp( ext, ".woff2" ) ) content_type = "font/woff2";
      }

      char const * cache_control = NULL;
      if( FD_LIKELY( !strncmp( request->path, "/assets", 7 ) ) ) cache_control = "public, max-age=31536000, immutable";
      else if( FD_LIKELY( !strcmp( f->name, "/index.html" ) ) )  cache_control = "no-cache";

      const uchar * data = f->data;
      ulong data_len = *(f->data_len);

      int accepts_zstd = 0;
      if( FD_LIKELY( request->headers.accept_encoding ) ) {
        accepts_zstd = !!strstr( request->headers.accept_encoding, "zstd" );
      }

      int accepts_gzip = 0;
      if( FD_LIKELY( request->headers.accept_encoding ) ) {
        accepts_gzip = !!strstr( request->headers.accept_encoding, "gzip" );
      }

      char const * content_encoding = NULL;
      if( FD_LIKELY( accepts_zstd && f->zstd_data ) ) {
        content_encoding = "zstd";
        data = f->zstd_data;
        data_len = *(f->zstd_data_len);
      } else if( FD_LIKELY( accepts_gzip && f->gzip_data ) ) {
        content_encoding = "gzip";
        data = f->gzip_data;
        data_len = *(f->gzip_data_len);
      }

      return (fd_http_server_response_t){
        .status            = 200,
        .static_body       = data,
        .static_body_len   = data_len,
        .content_type      = content_type,
        .cache_control     = cache_control,
        .content_encoding  = content_encoding,
        .upgrade_websocket = 0,
      };
    }
  }

  return (fd_http_server_response_t){
    .status            = 404,
  };
}

static void
gui_ws_open( ulong  conn_id,
             void * _ctx ) {
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;

  fd_gui_ws_open( ctx->gui, conn_id, fd_clock_now( ctx->clock ) );
  if( FD_UNLIKELY( ctx->is_full_client ) ) fd_gui_peers_ws_open( ctx->peers, conn_id, fd_clock_now( ctx->clock ) );
}

static void
gui_ws_close( ulong  conn_id,
              int    reason,
              void * _ctx ) {
  (void) reason;
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;
  if( FD_UNLIKELY( ctx->is_full_client ) ) fd_gui_peers_ws_close( ctx->peers, conn_id );
}

static void
gui_ws_message( ulong         ws_conn_id,
                uchar const * data,
                ulong         data_len,
                void *        _ctx ) {
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;

  int reason = fd_gui_ws_message( ctx->gui, ws_conn_id, data, data_len );
  if( FD_UNLIKELY( ctx->is_full_client && reason==FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD ) ) reason = fd_gui_peers_ws_message( ctx->peers, ws_conn_id, data, data_len );

  if( FD_UNLIKELY( reason<0 ) ) fd_http_server_ws_close( ctx->gui_server, ws_conn_id, reason );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  fd_http_server_params_t http_param = derive_http_params( tile );
  fd_http_server_t * _gui = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( http_param ) );

  fd_http_server_callbacks_t gui_callbacks = {
    .request    = gui_http_request,
    .ws_open    = gui_ws_open,
    .ws_close   = gui_ws_close,
    .ws_message = gui_ws_message,
  };
  ctx->gui_server = fd_http_server_join( fd_http_server_new( _gui, http_param, gui_callbacks, ctx ) );
  fd_http_server_listen( ctx->gui_server, tile->gui.listen_addr, tile->gui.listen_port );

  FD_LOG_NOTICE(( "gui server listening at http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->gui.listen_addr ), tile->gui.listen_port ));

  if( FD_UNLIKELY( !strcmp( tile->gui.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key = fd_keyload_load( tile->gui.identity_key_path, /* pubkey only: */ 1 );

  if( FD_UNLIKELY( !strcmp( tile->gui.vote_key_path, "" ) ) ) {
    ctx->has_vote_key = 0;
  } else {
    ctx->has_vote_key = 1;
    if( FD_UNLIKELY( !fd_base58_decode_32( tile->gui.vote_key_path, (uchar *)ctx->vote_key->uc ) ) ) {
      const uchar * vote_key = fd_keyload_load( tile->gui.vote_key_path, /* pubkey only: */ 1 );
      fd_memcpy( (uchar *)ctx->vote_key->uc, vote_key, 32UL );
    }
  }
}

extern char const fdctl_version_string[];

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_topo_tile_t * gui_tile = &topo->tiles[ fd_topo_find_tile( topo, "gui", 0UL ) ];
  switch( gui_tile->gui.frontend_release_channel ) {
    case 0: STATIC_FILES = STATIC_FILES_STABLE; break;
    case 1: STATIC_FILES = STATIC_FILES_ALPHA;  break;
    case 2: STATIC_FILES = STATIC_FILES_DEV;    break;
    default: __builtin_unreachable();
  }

  fd_http_server_params_t http_param = derive_http_params( tile );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t )                                    );
                       FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),  fd_http_server_footprint( http_param )                    );
  void * _peers      = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_align(),    fd_gui_peers_footprint( http_param.max_ws_connection_cnt) );
  void * _gui        = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),          fd_gui_footprint()                                        );
  void * _alloc      = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),        fd_alloc_footprint()                                      );

  ctx->is_full_client = ULONG_MAX!=fd_topo_find_tile( topo, "repair", 0UL );
  ctx->snapshots_enabled = ULONG_MAX!=fd_topo_find_tile( topo, "snapct", 0UL );

  fd_clock_default_init( ctx->clock, ctx->clock_mem );
  ctx->recal_next = fd_clock_recal_next( ctx->clock );

  ctx->ref_wallclock = fd_log_wallclock();
  ctx->ref_tickcount = fd_tickcount();
  *(double *)&ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );

  FD_TEST( fd_cstr_printf_check( ctx->version_string, sizeof( ctx->version_string ), NULL, "%s", fdctl_version_string ) );

  ctx->topo = topo;
  ctx->peers = fd_gui_peers_join( fd_gui_peers_new( _peers, ctx->gui_server, ctx->topo, http_param.max_ws_connection_cnt, fd_clock_now( ctx->clock) ) );
  ctx->gui  = fd_gui_join(  fd_gui_new( _gui, ctx->gui_server, ctx->version_string, tile->gui.cluster, ctx->identity_key, ctx->has_vote_key, ctx->vote_key->uc, ctx->is_full_client, ctx->snapshots_enabled, tile->gui.is_voting, tile->gui.schedule_strategy, ctx->topo, fd_clock_now( ctx->clock ) ) );
  FD_TEST( ctx->gui );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );

  ctx->next_poll_deadline = fd_tickcount();

  ctx->idle_cnt = 0UL;
  ctx->in_cnt = tile->in_cnt;

  ulong banks_obj_id       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  ulong banks_locks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks_locks" );

  if( FD_UNLIKELY( ctx->is_full_client ) ) {
    FD_TEST( banks_obj_id!=ULONG_MAX );
    FD_TEST( banks_locks_obj_id!=ULONG_MAX );
    FD_TEST( fd_banks_join( ctx->banks, fd_topo_obj_laddr( topo, banks_obj_id ), fd_topo_obj_laddr( topo, banks_locks_obj_id ) ) );
    FD_TEST( ctx->banks );
  }

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "plugin_out"        ) ) ) ctx->in_kind[ i ] = IN_KIND_PLUGIN;
    else if( FD_LIKELY( !strcmp( link->name, "poh_pack"     ) ) ) ctx->in_kind[ i ] = IN_KIND_POH_PACK;
    else if( FD_LIKELY( !strcmp( link->name, "pack_bank"    ) ) ) ctx->in_kind[ i ] = IN_KIND_PACK_BANK;
    else if( FD_LIKELY( !strcmp( link->name, "pack_poh"     ) ) ) ctx->in_kind[ i ] = IN_KIND_PACK_POH;
    else if( FD_LIKELY( !strcmp( link->name, "bank_poh"     ) ) ) ctx->in_kind[ i ] = IN_KIND_BANK_POH;
    else if( FD_LIKELY( !strcmp( link->name, "shred_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED_OUT;    /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "net_gossvf"   ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET_GOSSVF;
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
    }
    else if( FD_LIKELY( !strcmp( link->name, "gossip_net"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_NET;   /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_OUT;   /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "snapct_gui"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPCT;       /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "repair_net"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPAIR_NET;   /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "tower_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_TOWER_OUT;    /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY_OUT;   /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "replay_stake" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY_STAKE; /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI_OUT; /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "snapin_gui"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPIN; /* full client only */
    else if( FD_LIKELY( !strcmp( link->name, "exec_replay"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EXEC_REPLAY;  /* full client only */
    else FD_LOG_ERR(( "gui tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( !strcmp( link->name, "bank_poh" ) ) ) {
      ulong producer = fd_topo_find_link_producer( topo, &topo->links[ tile->in_link_id[ i ] ] );
      ctx->in_bank_idx[ i ] = topo->tiles[ producer ].kind_id;
    }

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  if( FD_UNLIKELY( ctx->is_full_client ) ) {
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "gui_replay", 0UL );
    FD_TEST( idx!=ULONG_MAX );
    fd_gui_out_ctx_t * replay_out = ctx->replay_out;
    replay_out->idx    = idx;
  }

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
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  populate_sock_filter_policy_fd_gui_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->gui_server ) );
  return sock_filter_policy_fd_gui_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->gui_server ); /* gui listen socket */
  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  ulong base = 5UL;
  return base + tile->gui.max_http_connections + tile->gui.max_websocket_connections;
}

#define STEM_BURST (1UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gui_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gui_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gui = {
  .name                     = "gui",
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
