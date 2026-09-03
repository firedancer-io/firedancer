/* The frontend assets are pre-built and statically compiled into the
   binary here.  To regenerate them, run

    $ git clone https://github.com/firedancer-io/firedancer-frontend.git frontend
    $ make frontend

   from the repository root. */

#include "../../disco/gui/generated/http_import_dist.h"

/* STATIC_FILES is the null-terminated list of frontend assets baked into
   the binary.  It is defined in generated/http_import_dist.c and accessed
   in the gui_http_request callback. */

#include <sys/socket.h> /* SOCK_CLOEXEC, SOCK_NONBLOCK needed for seccomp filter */

#include <linux/futex.h>
#include "generated/fd_gui_tile_seccomp.h"

#include "../../disco/tiles.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/gui/fd_gui.h"
#include "../../disco/gui/fd_gui_store.h"
#include "../../disco/gui/fd_gui_hist.h"
#include "../../discof/replay/fd_execrp.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/waker/fd_waker.h"
#include "../../disco/fd_clock_tile.h"
#include "../../discof/genesis/fd_genesi_tile.h" // TODO: Layering violation
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/base64/fd_base64.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../third_party/cjson/cJSON_alloc.h"
#include "../../discof/repair/fd_repair.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../discof/votor/fd_votor_tile.h"
#include "../../disco/shred/fd_shred_tile.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"

#define IN_KIND_PACK_EXECLE   ( 2UL)
#define IN_KIND_PACK_POH      ( 3UL)
#define IN_KIND_EXECLE_POH    ( 4UL)
#define IN_KIND_SHRED_OUT     ( 5UL) /* firedancer only */
#define IN_KIND_NET_GOSSVF    ( 6UL) /* firedancer only */
#define IN_KIND_GOSSIP_NET    ( 7UL) /* firedancer only */
#define IN_KIND_GOSSIP_OUT    ( 8UL) /* firedancer only */
#define IN_KIND_SNAPCT        ( 9UL) /* firedancer only */
#define IN_KIND_REPAIR_NET    (10UL) /* firedancer only */
#define IN_KIND_TOWER_OUT     (11UL) /* firedancer only */
#define IN_KIND_REPLAY_OUT    (12UL) /* firedancer only */
#define IN_KIND_EPOCH         (13UL) /* firedancer only */
#define IN_KIND_GENESI_OUT    (14UL) /* firedancer only */
#define IN_KIND_SNAPIN        (15UL) /* firedancer only */
#define IN_KIND_EXECRP_REPLAY (16UL) /* firedancer only */
#define IN_KIND_BUNDLE        (17UL)
#define IN_KIND_SNAPIN_MANIF  (18UL) /* firedancer only */
#define IN_KIND_SNAPSV_OUT    (19UL) /* firedancer only */
#define IN_KIND_DIAG          (20UL) /* firedancer only */
#define IN_KIND_VOTOR_OUT     (21UL) /* firedancer only */

FD_IMPORT_BINARY( firedancer_svg, "book/public/fire.svg" );

#define FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN       65536
#define FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN 65536
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
    .send_buffer_sz        = 4UL<<20UL,
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
  fd_topo_t const * topo;
  ulong             seed;

  int is_full_client;
  int snapshots_enabled;

  fd_gui_t * gui;
  fd_gui_store_t * db;
  fd_gui_peers_ctx_t * peers;

  ulong in_cnt;
  ulong idle_cnt;

  fd_clock_tile_t clock[1];

  ulong chunk;
  union {
    struct {
      ulong slot;
      ulong shred_idx;
    } repair_net;

    uchar net_gossvf[ FD_NET_MTU ];
    uchar gossip_net[ FD_NET_MTU ];

    struct {
      fd_snapsv_msg_t snapsv_out;
      int             snapsv_eom;
    };

    fd_votor_msg_t votor_out;
  } parsed;

  fd_http_server_t * gui_server;

  char index_html_etag[ 3 ][ 24 ]; /* plain, zstd, gzip */
  char index_html_link[ 1024 ];


  /* The tile is a waker client: the server runs in epoll mode on the
     inherited inner epoll fd and fd servicing is gated on the waker
     readiness fseq.  See fd_waker.h. */
  ulong   waker_client_idx;
  ulong * waker_fseq;

  fd_keyswitch_t * keyswitch;
  uchar const *    identity_key;

  int               has_vote_key;
  fd_pubkey_t const vote_key[ 1UL ];

  ulong           in_kind[ FD_TOPO_MAX_TILE_IN_LINKS ];
  int             in_reliable[ FD_TOPO_MAX_TILE_IN_LINKS ];
  ulong           in_bank_idx[ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_gui_in_ctx_t in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  fd_net_rx_bounds_t net_in_bounds[ FD_TOPO_MAX_TILE_IN_LINKS ];
} fd_gui_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof( fd_gui_ctx_t );
  a = fd_ulong_max( a, fd_http_server_align() );
  a = fd_ulong_max( a, fd_gui_peers_align() );
  a = fd_ulong_max( a, fd_gui_align() );
  a = fd_ulong_max( a, fd_alloc_align() );
  return a;
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
  l = FD_LAYOUT_APPEND( l, fd_gui_align(),          fd_gui_footprint( tile->gui.tile_cnt, tile->gui.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_store_align(),    fd_gui_store_footprint( tile->gui.db_size_gib<<30, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( tile->gui.db_size_gib<<30 ) ) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),        fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 128UL * (1UL<<20UL); /* 128MiB of heap space for the cJSON allocator */
}

static inline void
during_housekeeping( fd_gui_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) {
    fd_clock_tile_recal( ctx->clock );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_gui_set_identity( ctx->gui, ctx->keyswitch->bytes );
    if( FD_LIKELY( !ctx->gui->summary.is_alpenglow ) ) fd_gui_peers_handle_identity_change( ctx->peers );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_gui_ctx_t * ctx ) {
  FD_MGAUGE_SET( GUI, CONN_ACTIVE, ctx->gui_server->metrics.connection_cnt );
  FD_MGAUGE_SET( GUI, WEBSOCKET_CONN_ACTIVE, ctx->gui_server->metrics.ws_connection_cnt );

  FD_MCNT_SET( GUI, WEBSOCKET_FRAME_TX,     ctx->gui_server->metrics.frames_written );
  FD_MCNT_SET( GUI, WEBSOCKET_FRAME_RX, ctx->gui_server->metrics.frames_read );

  FD_MCNT_SET( GUI, BYTES_WRITTEN, ctx->gui_server->metrics.bytes_written );
  FD_MCNT_SET( GUI, BYTES_READ,    ctx->gui_server->metrics.bytes_read );

  FD_MGAUGE_SET( GUI, DISK_ALLOCATED_BYTES, fd_gui_store_file_sz( ctx->db ) );

  ulong db_cnt = fd_gui_store_cnt( ctx->db );

  ulong used_bytes  [ FD_GUI_HIST_CNT ];
  ulong cap_bytes   [ FD_GUI_HIST_CNT ]; ulong free_bytes  [ FD_GUI_HIST_CNT ];
  ulong used_slots  [ FD_GUI_HIST_CNT ];
  ulong cap_slots   [ FD_GUI_HIST_CNT ]; ulong free_slots  [ FD_GUI_HIST_CNT ];
  memset( used_bytes, 0, sizeof(used_bytes) );
  memset( cap_bytes,  0, sizeof(cap_bytes)  ); memset( free_bytes, 0, sizeof(free_bytes) );
  memset( used_slots, 0, sizeof(used_slots) );
  memset( cap_slots,  0, sizeof(cap_slots)  ); memset( free_slots, 0, sizeof(free_slots) );

  for( ulong i=0UL; i<db_cnt; i++ ) {
    fd_gui_store_ring_stats( ctx->db, i,
                             &used_bytes[ i ],
                             &cap_bytes[ i ],  &free_bytes[ i ],
                             &used_slots[ i ],
                             &cap_slots[ i ],  &free_slots[ i ] );
  }

  FD_MGAUGE_ENUM_COPY( GUI, DB_USED_BYTES,       used_bytes );
  FD_MGAUGE_ENUM_COPY( GUI, DB_CAPACITY_BYTES,   cap_bytes  );
  FD_MGAUGE_ENUM_COPY( GUI, DB_FREE_BYTES,       free_bytes );
  FD_MGAUGE_ENUM_COPY( GUI, DB_RECORD_USED,      used_slots );
  FD_MGAUGE_ENUM_COPY( GUI, DB_RECORD_CAPACITY,  cap_slots  );
  FD_MGAUGE_ENUM_COPY( GUI, DB_RECORD_FREE,      free_slots );

  fd_gui_store_metrics_t const * dm = fd_gui_store_metrics( ctx->db );
  FD_MCNT_ENUM_COPY( GUI, DB_KV_QUERIED,         dm->kv_lookups      );
  FD_MCNT_ENUM_COPY( GUI, DB_TS_RECORD_APPENDED, dm->ts_appends      );
  FD_MCNT_ENUM_COPY( GUI, DB_TS_SCANNED,         dm->ts_reads        );
  FD_MCNT_ENUM_COPY( GUI, DB_TS_RECORD_READ,     dm->ts_read_records );
  FD_MCNT_ENUM_COPY( GUI, DB_RECORD_EVICTED,     dm->evict_records   );
  FD_MCNT_ENUM_COPY( GUI, DB_EVICTION,           dm->evicts          );
  FD_MCNT_ENUM_COPY( GUI, DB_REGION_CLAIMED,     dm->region_grows    );
  fd_gui_hist_metrics_t const * hist = fd_gui_hist_metrics( ctx->gui );
  static ulong const zero_hist_metrics[ FD_GUI_HIST_CNT ] = { 0UL };
  ulong const * hist_map_full = hist ? hist->map_full : zero_hist_metrics;
  ulong const * hist_reserves = hist ? hist->reserves  : zero_hist_metrics;
  FD_MCNT_ENUM_COPY( GUI, DB_REGION_RECLAIMED,   dm->region_reclaims );
  FD_MCNT_ENUM_COPY( GUI, DB_MAP_FULL,           hist_map_full );
  FD_MCNT_ENUM_COPY( GUI, DB_FORCED_EVICTION,    hist_reserves );
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
  long now = fd_clock_tile_now( ctx->clock );
  /* Wake protocol (fd_waker.h): only service fds when the waker
     raised our readiness word.  Clear FIRST, service a bounded
     amount, rearm LAST.  The drain is deliberately bounded (gui is
     a reliable consumer of hot links; unbounded fd work here would
     backpressure replay): EPOLL_CTL_MOD re-polls the inner set
     immediately, so leftover or raced readiness re-fires the outer
     set and servicing resumes next iteration. */
  if( FD_UNLIKELY( fd_fseq_query( ctx->waker_fseq )==1UL ) ) {
    fd_fseq_update( ctx->waker_fseq, 0UL );
    /* 8 matches a browser's per-host parallel connection budget */
    charge_busy_server = fd_http_server_epoll_poll( ctx->gui_server, 8UL );
    fd_waker_client_rearm( ctx->waker_client_idx );
  }

  int charge_poll = 0;
  charge_poll |= fd_gui_poll( ctx->gui, now );
  charge_poll |= fd_gui_peers_poll( ctx->peers, now );

  *charge_busy = charge_busy_server | charge_poll;
}

static int
before_frag( fd_gui_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig ) {
  (void)seq;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PACK_POH && sig==FD_PACK_MSG_REDUCE_MB_BOUND ) ) return 1;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP_OUT &&
                 (sig==FD_GOSSIP_UPDATE_TAG_WFS_DONE || sig==FD_GOSSIP_UPDATE_TAG_PEER_SATURATED) ) ) return 1;
  return 0;
}

static inline void
during_frag( fd_gui_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq FD_PARAM_UNUSED,
             ulong          sig,
             ulong          chunk,
             ulong          sz,
             ulong          ctl ) {
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_TOWER_OUT ) ) return; /* process in returnable_frag */

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) ) {
    fd_epoch_info_msg_t * epoch_info = (fd_epoch_info_msg_t *)src;
    FD_TEST( epoch_info->staked_vote_cnt<=MAX_STAKE_WEIGHTS );
    FD_TEST( epoch_info->staked_id_cnt<=MAX_STAKE_WEIGHTS );
    sz = fd_epoch_info_msg_sz( epoch_info->staked_vote_cnt, epoch_info->staked_id_cnt );
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GENESI_OUT ) ) {
    sz = sig;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_DIAG ) ) {
    sz = sig;
  }

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_OUT ) ) {
    if( FD_LIKELY( sig!=REPLAY_SIG_SLOT_COMPLETED &&
                   sig!=REPLAY_SIG_BECAME_LEADER  &&
                   sig!=REPLAY_SIG_ROOT_ADVANCED  &&
                   sig!=REPLAY_SIG_OC_ADVANCED ) ) return;
  }

  if( FD_UNLIKELY( (sz>0UL && (chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark)) || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "in_kind %lu chunk %lu %lu corrupt, not in range [%lu,%lu] or too large (%lu)", ctx->in_kind[ in_idx ], chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, ctx->in[ in_idx ].mtu ));

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPAIR_NET: {
      ctx->parsed.repair_net.slot = ULONG_MAX;
      uchar * payload;
      ulong payload_sz;
      if( FD_LIKELY( fd_ip4_udp_hdr_strip( src, sz, &payload, &payload_sz, NULL, NULL, NULL ) ) ) {
        fd_repair_msg_t const * msg = (fd_repair_msg_t const *)fd_type_pun_const( payload );
        if( FD_LIKELY( msg->kind==FD_REPAIR_KIND_SHRED ) ) {
          if( FD_UNLIKELY( msg->shred.slot==0 ) ) break;
          ctx->parsed.repair_net.slot = msg->shred.slot;
          ctx->parsed.repair_net.shred_idx = msg->shred.shred_idx;
        }
      }
      break;
    }
    case IN_KIND_NET_GOSSVF: {
      FD_TEST( sz<=sizeof(ctx->parsed.net_gossvf) );
      uchar const * net_src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );
      fd_memcpy( ctx->parsed.net_gossvf, net_src, sz );
      break;
    }
    case IN_KIND_GOSSIP_NET: {
      FD_TEST( sz<=sizeof(ctx->parsed.gossip_net) );
      fd_memcpy( ctx->parsed.gossip_net, src, sz );
      break;
    }
    case IN_KIND_SNAPSV_OUT: {
      FD_TEST( sz<=sizeof(ctx->parsed.snapsv_out) );
      fd_memcpy( &ctx->parsed.snapsv_out, src, sz );
      ctx->parsed.snapsv_eom = fd_frag_meta_ctl_eom( ctl );
      break;
    }
    case IN_KIND_VOTOR_OUT: {
      if( FD_UNLIKELY( sz!=sizeof(fd_votor_msg_t) ) ) break;
      fd_memcpy( &ctx->parsed.votor_out, src, sz );
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

  if( FD_LIKELY( ctx->in_reliable[ in_idx ] ) ) ctx->idle_cnt = 0UL;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_TOWER_OUT ) ) return; /* process in returnable_frag */

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_EXECRP_REPLAY: {
      if( FD_LIKELY( sig>>32==FD_EXECRP_TT_TXN_EXEC ) ) {
        fd_execrp_task_done_msg_t * msg = (fd_execrp_task_done_msg_t *)src;

        long tsorig_ns = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tsorig );
        long tspub_ns  = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tspub  );
        fd_gui_handle_exec_txn_done( ctx->gui, msg->txn_exec->slot, msg->txn_exec->start_shred_idx, msg->txn_exec->end_shred_idx, tsorig_ns, tspub_ns, fd_clock_tile_now( ctx->clock ) );

        int txn_succeeded = msg->txn_exec->is_committable && !msg->txn_exec->is_fees_only && !msg->txn_exec->txn_err;
        if( FD_UNLIKELY( msg->txn_exec->vote.slot!=ULONG_MAX && txn_succeeded ) ) {
          int vote_acct_is_us = !ctx->gui->summary.has_vote_key || !memcmp( ctx->gui->summary.vote_key->uc, msg->txn_exec->vote.vote_acct->uc, sizeof(fd_pubkey_t) );
          int is_us = !ctx->gui->summary.is_alpenglow && vote_acct_is_us && !memcmp( ctx->gui->summary.identity_key->uc, msg->txn_exec->vote.identity->uc, sizeof(fd_pubkey_t) );
          fd_gui_peers_handle_vote( ctx->peers,
                                    msg->txn_exec->vote.vote_acct,
                                    msg->txn_exec->vote.slot,
                                    is_us );
          if( FD_UNLIKELY( is_us ) ) {
            for( ulong i=0UL; i<msg->txn_exec->vote.vote_slot_cnt; i++ ) {
              fd_gui_stage_landed_vote( ctx->gui, msg->txn_exec->slot, msg->txn_exec->bank_seq, msg->txn_exec->vote.vote_slots[ i ] );
            }
          }
        }
      }

      break;
    }
    case IN_KIND_VOTOR_OUT: {
      if( FD_UNLIKELY( sz!=sizeof(fd_votor_msg_t) ) ) return;

      fd_votor_msg_t const * msg = &ctx->parsed.votor_out;

      switch( sig ) {
        case FD_VOTOR_SIG_NOTAR:          fd_gui_handle_ag_notarized( ctx->gui, msg->notar.slot,          &msg->notar.block_id,          FD_GUI_AG_NOTAR_REGULAR  ); break;
        case FD_VOTOR_SIG_NOTAR_FALLBACK: fd_gui_handle_ag_notarized( ctx->gui, msg->notar_fallback.slot, &msg->notar_fallback.block_id, FD_GUI_AG_NOTAR_FALLBACK ); break;
        case FD_VOTOR_SIG_SKIP:           fd_gui_handle_ag_skip_cert( ctx->gui, msg->skip.slot );                                     break;
        case FD_VOTOR_SIG_FAST_FINAL:     fd_gui_handle_ag_finalized( ctx->gui, msg->fast_final.slot,     &msg->fast_final.block_id,     FD_GUI_AG_FINAL_FAST     ); break;
        case FD_VOTOR_SIG_FINAL:          fd_gui_handle_ag_finalized( ctx->gui, msg->final.slot,          &msg->final.block_id,          FD_GUI_AG_FINAL_SLOW     ); break;
        case FD_VOTOR_SIG_LEADER:         fd_gui_handle_ag_leader( ctx->gui, msg->leader.parent_slot );                                break;
        default:                                                                                                                      break;
      }
      break;
    }
    case IN_KIND_REPLAY_OUT: {
      if( FD_UNLIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
        fd_replay_slot_completed_t const * slot_completed =  (fd_replay_slot_completed_t const *)src;

        if( FD_LIKELY( !ctx->gui->summary.is_alpenglow ) ) fd_gui_peers_update_delinquency( ctx->peers, fd_clock_tile_now( ctx->clock ) );

        fd_gui_handle_replay_update( ctx->gui, slot_completed, ctx->peers->slot_voted, fd_clock_tile_now( ctx->clock ) );
      } else if( FD_UNLIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) {
        fd_became_leader_t * became_leader = (fd_became_leader_t *)src;
        fd_gui_became_leader( ctx->gui, became_leader->slot, became_leader->slot_start_ns, became_leader->slot_end_ns, became_leader->limits.slot_max_cost, became_leader->max_microblocks_in_slot, became_leader->bank_seq );
      } else if( FD_UNLIKELY( sig==REPLAY_SIG_ROOT_ADVANCED ) ) {
        fd_replay_root_advanced_t const * ra = (fd_replay_root_advanced_t const *)src;
        fd_gui_handle_root_advanced( ctx->gui, ra->slot, ra->bank_seq, fd_clock_tile_now( ctx->clock ) );
      } else if( FD_UNLIKELY( sig==REPLAY_SIG_OC_ADVANCED ) ) {
        fd_replay_oc_advanced_t const * oc = (fd_replay_oc_advanced_t const *)src;
        fd_gui_handle_oc_advanced( ctx->gui, oc->slot, oc->bank_seq, fd_clock_tile_now( ctx->clock ) );
      } else {
        return;
      }
      break;
    }
    case IN_KIND_EPOCH: {
      fd_epoch_info_msg_t * epoch_info = (fd_epoch_info_msg_t *)src;
      fd_gui_handle_epoch_info( ctx->gui, epoch_info, fd_clock_tile_now( ctx->clock ) );
      fd_gui_peers_handle_epoch_info( ctx->peers, epoch_info, fd_clock_tile_now( ctx->clock ) );
      break;
    }
    case IN_KIND_SNAPIN: {
      fd_gui_peers_handle_config_account( ctx->peers, src, sz );
      break;
    }
    case IN_KIND_SNAPIN_MANIF: {
      if( fd_ssmsg_sig_message( sig )==FD_SSMSG_DONE ) {
        fd_gui_peers_commit_snapshot_manifest( ctx->peers );
      } else {
        fd_gui_stage_snapshot_manifest( ctx->gui, (fd_snapshot_manifest_t const *)src );
        fd_gui_peers_stage_snapshot_manifest( ctx->peers, (fd_snapshot_manifest_t const *)src, fd_clock_tile_now( ctx->clock ) );
      }
      break;
    }
    case IN_KIND_GENESI_OUT: {
      fd_genesis_meta_t const * meta = (fd_genesis_meta_t const *)src;
      fd_gui_handle_genesis_hash( ctx->gui, &meta->genesis_hash );
      break;
    }
    case IN_KIND_SHRED_OUT: {
      long tsorig_nanos = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tsorig );
      uint sig_src      = fd_shred_sig_src( sig );
      if( FD_LIKELY( sig_src==SHRED_SIG_SRC_TURBINE || sig_src==SHRED_SIG_SRC_REPAIR || sig_src==SHRED_SIG_SRC_BAD_REPAIR ) ) {
        fd_shred_base_t const * msg = (fd_shred_base_t const *)fd_type_pun_const( src );
        ulong slot      = msg->shred.slot;
        ulong shred_idx = msg->shred.idx;
        int is_turbine  = sig_src==SHRED_SIG_SRC_TURBINE;
        /* tsorig is the timestamp when the shred was received by the shred tile */
        fd_gui_handle_shred( ctx->gui, slot, shred_idx, is_turbine, tsorig_nanos, fd_clock_tile_now( ctx->clock ) );
      }
      if( FD_UNLIKELY( sig==SHRED_SIG_FEC_COMPLETE_LEADER ) ) {
        fd_fec_complete_t const * complete_msg = (fd_fec_complete_t const *)fd_type_pun_const( src );
        fd_gui_handle_leader_fec( ctx->gui, complete_msg->last_shred_hdr.slot, FD_FEC_SHRED_CNT, complete_msg->last_shred_hdr.data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE, tsorig_nanos, fd_clock_tile_now( ctx->clock ) );
      }
      break;
    }
    case IN_KIND_SNAPCT: {
      fd_gui_handle_snapshot_update( ctx->gui, (fd_snapct_update_t *)src );
      break;
    }
    case IN_KIND_SNAPSV_OUT: {
      long sample_time_nanos = fd_frag_meta_ts_decomp( tspub, fd_clock_tile_now( ctx->clock ) );
      fd_gui_handle_snapsv_update( ctx->gui, sig, &ctx->parsed.snapsv_out, sz, ctx->parsed.snapsv_eom, sample_time_nanos );
      break;
    }
    case IN_KIND_REPAIR_NET: {
      if( FD_UNLIKELY( ctx->parsed.repair_net.slot==ULONG_MAX ) ) break;
      long tsorig_ns = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tsorig );
      fd_gui_handle_repair_request( ctx->gui, ctx->parsed.repair_net.slot, ctx->parsed.repair_net.shred_idx, tsorig_ns );
      break;
    }
    case IN_KIND_NET_GOSSVF: {
      uchar * payload;
      ulong payload_sz;
      fd_ip4_hdr_t * ip4_hdr;
      fd_udp_hdr_t * udp_hdr;
      if( FD_LIKELY( fd_ip4_udp_hdr_strip( ctx->parsed.net_gossvf, sz, &payload, &payload_sz, NULL, &ip4_hdr, &udp_hdr ) ) ) {
        fd_gossip_socket_t socket = {
          .is_ipv6 = 0,
          .ip4 = ip4_hdr->saddr,
          .port = udp_hdr->net_sport,
        };
        fd_gui_peers_handle_gossip_message( ctx->peers, payload, payload_sz, &socket, 1 );
      }
      break;
    }
    case IN_KIND_GOSSIP_NET: {
      uchar * payload;
      ulong payload_sz;
      fd_ip4_hdr_t * ip4_hdr;
      fd_udp_hdr_t * udp_hdr;
      FD_TEST( fd_ip4_udp_hdr_strip( ctx->parsed.gossip_net, sz, &payload, &payload_sz, NULL, &ip4_hdr, &udp_hdr ) );
      fd_gossip_socket_t socket = {
        .is_ipv6 = 0,
        .ip4 = ip4_hdr->daddr,
        .port = udp_hdr->net_dport,
      };
      fd_gui_peers_handle_gossip_message( ctx->peers, payload, payload_sz, &socket, 0 );
      break;
    }
    case IN_KIND_GOSSIP_OUT: {
      fd_gui_peers_handle_gossip_update( ctx->peers, (fd_gossip_update_message_t *)src, fd_clock_tile_now( ctx->clock ) );
      break;
    }
    case IN_KIND_PACK_POH: {
      if( FD_UNLIKELY( sig==FD_PACK_MSG_DONE_DRAINING ) ) fd_gui_done_draining( ctx->gui, fd_clock_tile_now( ctx->clock ) );
      else                                                fd_gui_unbecame_leader( ctx->gui, fd_disco_execle_sig_slot( sig ), (fd_done_packing_t const *)src );
      break;
    }
    case IN_KIND_PACK_EXECLE: {
      FD_TEST( sz>=sizeof(fd_microblock_execle_trailer_t) );
      FD_TEST( (sz-sizeof(fd_microblock_execle_trailer_t))%sizeof(fd_txn_e_t)==0UL );

      if( FD_LIKELY( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK ) ) {
        fd_microblock_execle_trailer_t trailer[1];
        fd_memcpy( trailer, src+sz-sizeof(fd_microblock_execle_trailer_t), sizeof(fd_microblock_execle_trailer_t) );
        long tspub_ns = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tspub );
        fd_gui_microblock_execution_begin( ctx->gui,
                                          tspub_ns,
                                          fd_disco_poh_sig_slot( sig ),
                                          (fd_txn_e_t *)src,
                                          (sz-sizeof( fd_microblock_execle_trailer_t ))/sizeof( fd_txn_e_t ),
                                          (uint)trailer->microblock_idx,
                                          trailer->pack_txn_idx,
                                          trailer->bank_seq,
                                          fd_clock_tile_now( ctx->clock ) );
      } else {
        FD_LOG_ERR(( "unexpected poh packet type %lu", fd_disco_poh_sig_pkt_type( sig ) ));
      }
      break;
    }
    case IN_KIND_EXECLE_POH: {
      FD_TEST( sz>=sizeof(fd_microblock_trailer_t) );
      FD_TEST( (sz-sizeof(fd_microblock_trailer_t))%sizeof(fd_txn_p_t)==0UL );

      fd_microblock_trailer_t trailer[1];
      fd_memcpy( trailer, src+sz-sizeof(fd_microblock_trailer_t), sizeof(fd_microblock_trailer_t) );
      long tspub_ns = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tspub );
      ulong txn_cnt = (sz-sizeof( fd_microblock_trailer_t ))/sizeof(fd_txn_p_t);
      fd_gui_microblock_execution_end( ctx->gui,
                                      tspub_ns,
                                      ctx->in_bank_idx[ in_idx ],
                                      fd_disco_execle_sig_slot( sig ),
                                      txn_cnt,
                                      (fd_txn_p_t *)src,
                                      trailer->pack_txn_idx,
                                      trailer->txn_ns_dt,
                                      trailer->tips,
                                      trailer->bank_seq,
                                      fd_clock_tile_now( ctx->clock ) );
      break;
    }
    case IN_KIND_BUNDLE: {
      fd_gui_handle_block_engine_update( ctx->gui, (fd_bundle_block_engine_update_t *)src );
      break;
    }
    case IN_KIND_DIAG: {
      fd_gui_handle_diag_snapshot( ctx->gui, src, sig );
      break;
    }
    default: FD_LOG_ERR(( "unexpected in_kind %lu", ctx->in_kind[ in_idx ] ));
  }
}

static int
returnable_frag( fd_gui_ctx_t *      ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem   FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_OUT && !ctx->gui->epoch.has_epoch_schedule ) ) return 1; /* epoch info not received yet: defer polling */

  if( FD_LIKELY( ctx->in_kind[ in_idx ]!=IN_KIND_TOWER_OUT ) ) return 0; /* process in {before|during|after}_frag */

  if( FD_UNLIKELY( (sz>0UL && (chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark)) || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "in_kind %lu chunk %lu %lu corrupt, not in range [%lu,%lu] or too large (%lu)", ctx->in_kind[ in_idx ], chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, ctx->in[ in_idx ].mtu ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );

  if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_DONE ) ) {
    FD_TEST( sz>=sizeof(fd_tower_slot_done_t) );
    fd_tower_slot_done_t const * tower = (fd_tower_slot_done_t const *)src;
    if( FD_UNLIKELY( !fd_gui_slot_get( ctx->gui, tower->replay_slot, tower->replay_bank_seq ) ) ) return 1; /* block not replayed yet: defer polling */
    fd_gui_handle_tower_update( ctx->gui, tower, fd_clock_tile_now( ctx->clock ) );
  }

  return 0;
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
      .cache_control     = "public, max-age=86400",
      .upgrade_websocket = 0,
    };
  }

  int is_vite_page = !strcmp( request->path, "/" ) ||
                     !strcmp( request->path, "/slotDetails" ) ||
                     !strcmp( request->path, "/leaderSchedule" ) ||
                     !strcmp( request->path, "/gossip") ||
                     !strcmp( request->path, "/accounts") ||
                     !strncmp( request->path, "/?", strlen("/?") ) ||
                     !strncmp( request->path, "/slotDetails?", strlen("/slotDetails?") ) ||
                     !strncmp( request->path, "/leaderSchedule?", strlen("/leaderSchedule?") ) ||
                     !strncmp( request->path, "/gossip?", strlen("/gossip?") ) ||
                     !strncmp( request->path, "/accounts?", strlen("/accounts?") );

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
        else if( !strcmp( ext, ".wasm" ) ) content_type = "application/wasm";
      }

      char const * cache_control = NULL;
      if( FD_LIKELY( !strncmp( request->path, "/assets", 7 ) ) ) cache_control = "public, max-age=31536000, immutable";
      else if( FD_LIKELY( !strcmp( f->name, "/index.html" ) ) )  cache_control = "no-cache";
      else if( FD_UNLIKELY( !strcmp( f->name, "/version" ) ) )   cache_control = "no-cache";

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
      ulong enc_idx = 0UL;
      if( FD_LIKELY( accepts_zstd && f->zstd_data ) ) {
        content_encoding = "zstd";
        data = f->zstd_data;
        data_len = *(f->zstd_data_len);
        enc_idx = 1UL;
      } else if( FD_LIKELY( accepts_gzip && f->gzip_data ) ) {
        content_encoding = "gzip";
        data = f->gzip_data;
        data_len = *(f->gzip_data_len);
        enc_idx = 2UL;
      }

      char const * etag = NULL;
      char const * link = NULL;
      if( FD_LIKELY( !strcmp( f->name, "/index.html" ) ) ) {
        fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)request->ctx;
        etag = ctx->index_html_etag[ enc_idx ];
        link = ctx->index_html_link[ 0 ] ? ctx->index_html_link : NULL;
        if( FD_UNLIKELY( fd_http_server_etag_matches( request->headers.if_none_match, etag ) ) ) {
          return (fd_http_server_response_t){
            .status        = 304,
            .cache_control = cache_control,
            .etag          = etag,
            .link          = link,
          };
        }
      }

      return (fd_http_server_response_t){
        .status            = 200,
        .static_body       = data,
        .static_body_len   = data_len,
        .content_type      = content_type,
        .cache_control     = cache_control,
        .content_encoding  = content_encoding,
        .etag              = etag,
        .link              = link,
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

  fd_gui_ws_open( ctx->gui, conn_id, fd_clock_tile_now( ctx->clock ) );
  fd_gui_peers_ws_open( ctx->peers, conn_id, fd_clock_tile_now( ctx->clock ) );
}

static void
gui_ws_close( ulong  conn_id,
              int    reason,
              void * _ctx ) {
  (void) reason;
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;
  fd_gui_peers_ws_close( ctx->peers, conn_id );
}

static void
gui_ws_message( ulong         ws_conn_id,
                uchar const * data,
                ulong         data_len,
                void *        _ctx ) {
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;

  int reason = fd_gui_ws_message( ctx->gui, ws_conn_id, data, data_len );
  if( FD_UNLIKELY( reason==FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD ) ) reason = fd_gui_peers_ws_message( ctx->peers, ws_conn_id, data, data_len );

  if( FD_UNLIKELY( reason<0 ) ) fd_http_server_ws_close( ctx->gui_server, ws_conn_id, reason );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_param = derive_http_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );
  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );
  http_param.treap_seed = ctx->seed;
  fd_http_server_t * _gui = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( http_param ) );
                     FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_align(),    fd_gui_peers_footprint( http_param.max_ws_connection_cnt ) );
                     FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),          fd_gui_footprint( tile->gui.tile_cnt, tile->gui.max_live_slots ) );
  void * _db       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_store_align(),       fd_gui_store_footprint( tile->gui.db_size_gib<<30, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( tile->gui.db_size_gib<<30 ) ) );

  fd_http_server_callbacks_t gui_callbacks = {
    .request    = gui_http_request,
    .ws_open    = gui_ws_open,
    .ws_close   = gui_ws_close,
    .ws_message = gui_ws_message,
  };
  ctx->gui_server = fd_http_server_join( fd_http_server_new( _gui, http_param, gui_callbacks, ctx ) );

  ctx->waker_client_idx = tile->waker_client_idx;
  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
  fd_http_server_listen( ctx->gui_server, FD_WAKER_INNER_FD( ctx->waker_client_idx ), tile->gui.listen_addr, tile->gui.listen_port );

  FD_LOG_NOTICE(( "gui server listening at %shttp://" FD_IP4_ADDR_FMT ":%u%s", fd_log_style_bold(), FD_IP4_ADDR_FMT_ARGS( tile->gui.listen_addr ), tile->gui.listen_port, fd_log_style_normal() ));

  ctx->db = fd_gui_store_join( fd_gui_store_new( _db, tile->gui.gui_database_path, tile->gui.db_size_gib<<30, fd_gui_hist_db_cnt(), ctx->seed, fd_gui_hist_db_descs( tile->gui.db_size_gib<<30 ) ) );
  if( FD_UNLIKELY( !ctx->db ) ) FD_LOG_ERR(( "fd_gui_store_new(%s) failed; gui tile cannot start", tile->gui.gui_database_path ));

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

static int
index_html_refs( fd_http_static_file_t const * html,
                 char const *                  name ) {
  ulong name_len = strlen( name );
  if( FD_UNLIKELY( name_len>*(html->data_len) ) ) return 0;
  for( ulong i=0UL; i<=*(html->data_len)-name_len; i++ ) if( FD_UNLIKELY( !memcmp( html->data+i, name, name_len ) ) ) return 1;
  return 0;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_param = derive_http_params( tile );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t )                                    );
                       FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),  fd_http_server_footprint( http_param )                    );
  void * _peers      = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_align(),    fd_gui_peers_footprint( http_param.max_ws_connection_cnt) );
  void * _gui        = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),          fd_gui_footprint( tile->gui.tile_cnt, tile->gui.max_live_slots ) );
                       FD_SCRATCH_ALLOC_APPEND( l, fd_gui_store_align(),       fd_gui_store_footprint( tile->gui.db_size_gib<<30, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( tile->gui.db_size_gib<<30 ) ) );
  void * _alloc      = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),        fd_alloc_footprint()                                      );

  fd_http_static_file_t const * index_html = NULL;
  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++ ) {
    if( FD_UNLIKELY( !strcmp( f->name, "/index.html" ) ) ) index_html = f;
  }
  FD_TEST( index_html );

  {
    fd_http_static_file_t const * f = index_html;
    uchar hash[ 32 ];
    uchar const * rep_data[ 3 ]     = { f->data,     f->zstd_data,     f->gzip_data     };
    ulong const * rep_data_len[ 3 ] = { f->data_len, f->zstd_data_len, f->gzip_data_len };
    for( ulong e=0UL; e<3UL; e++ ) {
      ctx->index_html_etag[ e ][ 0 ] = '\0';
      if( FD_UNLIKELY( !rep_data[ e ] ) ) continue;
      fd_sha256_hash( rep_data[ e ], *(rep_data_len[ e ]), hash );
      char b64[ FD_BASE64_ENC_SZ( 9UL )+1UL ];
      b64[ fd_base64_encode( b64, hash, 9UL ) ] = '\0';
      FD_TEST( fd_cstr_printf_check( ctx->index_html_etag[ e ], sizeof(ctx->index_html_etag[ e ]), NULL, "\"%s\"", b64 ) );
    }
  }

  char const * preload_js     = NULL;
  char const * preload_css    = NULL;
  char const * preload_worker = NULL;
  char const * preload_wasm   = NULL;
  char const * split_js[ 16 ];
  ulong        split_js_cnt   = 0UL;
  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++ ) {
    char const * ext = strrchr( f->name, '.' );
    if( FD_UNLIKELY( !ext ) ) continue;
    if( FD_UNLIKELY( !strncmp( f->name, "/assets/index-", 14UL ) ) ) {
      if( !strcmp( ext, ".js" ) ) {
        if( FD_UNLIKELY( index_html_refs( index_html, f->name ) ) )                              preload_js = f->name;
        else if( FD_LIKELY( split_js_cnt<sizeof(split_js)/sizeof(split_js[ 0 ]) ) )              split_js[ split_js_cnt++ ] = f->name;
      }
      else if( !strcmp( ext, ".css" ) && index_html_refs( index_html, f->name ) )                preload_css = f->name;
    }
    else if( FD_UNLIKELY( !strncmp( f->name, "/assets/wsWorker-", 17UL ) && !strcmp( ext, ".js"   ) ) ) preload_worker = f->name;
    else if( FD_UNLIKELY( !strncmp( f->name, "/assets/zstd-dec-", 17UL ) && !strcmp( ext, ".wasm" ) ) ) preload_wasm   = f->name;
    else if( FD_UNLIKELY( !strncmp( f->name, "/assets/UplotReact-", 19UL ) && !strcmp( ext, ".js" ) &&
                          split_js_cnt<sizeof(split_js)/sizeof(split_js[ 0 ]) ) )                split_js[ split_js_cnt++ ] = f->name;
  }

  ctx->index_html_link[ 0 ] = '\0';
  ulong off = 0UL, sz;
  if( FD_LIKELY( preload_js ) ) {
    FD_TEST( fd_cstr_printf_check( ctx->index_html_link+off, sizeof(ctx->index_html_link)-off, &sz, "%s<%s>; rel=modulepreload", off ? ", " : "", preload_js ) );
    off += sz;
  }
  if( FD_LIKELY( preload_css ) ) {
    FD_TEST( fd_cstr_printf_check( ctx->index_html_link+off, sizeof(ctx->index_html_link)-off, &sz, "%s<%s>; rel=preload; as=style; crossorigin", off ? ", " : "", preload_css ) );
    off += sz;
  }
  if( FD_LIKELY( preload_worker ) ) {
    FD_TEST( fd_cstr_printf_check( ctx->index_html_link+off, sizeof(ctx->index_html_link)-off, &sz, "%s<%s>; rel=preload; as=worker", off ? ", " : "", preload_worker ) );
    off += sz;
  }
  if( FD_LIKELY( preload_wasm ) ) {
    FD_TEST( fd_cstr_printf_check( ctx->index_html_link+off, sizeof(ctx->index_html_link)-off, &sz, "%s<%s>; rel=preload; as=fetch; crossorigin", off ? ", " : "", preload_wasm ) );
    off += sz;
  }
  for( ulong i=0UL; i<split_js_cnt; i++ ) {
    FD_TEST( fd_cstr_printf_check( ctx->index_html_link+off, sizeof(ctx->index_html_link)-off, &sz, "%s<%s>; rel=modulepreload", off ? ", " : "", split_js[ i ] ) );
    off += sz;
  }

  ctx->is_full_client = ULONG_MAX!=fd_topo_find_tile( topo, "replay", 0UL );
  ctx->snapshots_enabled = ULONG_MAX!=fd_topo_find_tile( topo, "snapct", 0UL );

  fd_clock_tile_init( ctx->clock );

  ctx->topo = topo;
  ctx->peers = fd_gui_peers_join( fd_gui_peers_new( _peers, ctx->gui_server, ctx->topo, http_param.max_ws_connection_cnt, tile->gui.wfs_bank_hash, ctx->seed, fd_clock_tile_now( ctx->clock ) ) );
  /* The accounts database is a full-client (Firedancer) feature only.
     Frankendancer has no accdb, so its topology leaves accdb_obj_id
     unset (ULONG_MAX) and the gui tile joins no accdb shmem.  The gui
     only reads partition stats from the shmem; it never reads account
     data from disk, so it does not join the accdb fd. */
  fd_accdb_shmem_t * accdb_shmem = NULL;
  if( FD_LIKELY( tile->gui.accdb_obj_id!=ULONG_MAX ) ) {
    void * accdb_shmem_raw = fd_topo_obj_laddr( topo, tile->gui.accdb_obj_id );
    FD_TEST( accdb_shmem_raw );
    accdb_shmem = fd_accdb_shmem_join( accdb_shmem_raw );
    FD_TEST( accdb_shmem );
  }
  ctx->gui   = fd_gui_join( fd_gui_new( _gui, ctx->gui_server, fd_version_cstr, tile->gui.cluster, ctx->identity_key, ctx->has_vote_key, ctx->vote_key->uc, ctx->is_full_client, tile->gui.is_alpenglow, tile->gui.max_live_slots, ctx->snapshots_enabled, tile->gui.is_voting, tile->gui.schedule_strategy, tile->gui.wfs_bank_hash, tile->gui.expected_shred_version, tile->gui.accounts_database_path, tile->gui.gui_database_path, ctx->db, ctx->topo, accdb_shmem, fd_clock_tile_now( ctx->clock ) ) );
  FD_TEST( ctx->gui );
  FD_TEST( ctx->db );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
  ctx->waker_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->waker_fseq_obj_id ) );
  FD_TEST( ctx->waker_fseq );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );


  ctx->idle_cnt = 0UL;
  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  ctx->in_cnt = tile->in_cnt;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "pack_execle"  ) ) ) ctx->in_kind[ i ] = IN_KIND_PACK_EXECLE;
    else if( FD_LIKELY( !strcmp( link->name, "pack_poh"     ) ) ) ctx->in_kind[ i ] = IN_KIND_PACK_POH;
    else if( FD_LIKELY( !strcmp( link->name, "execle_poh"   ) ) ) ctx->in_kind[ i ] = IN_KIND_EXECLE_POH;
    else if( FD_LIKELY( !strcmp( link->name, "shred_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "net_gossvf"   ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET_GOSSVF;
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
    }
    else if( FD_LIKELY( !strcmp( link->name, "gossip_net"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_NET;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "snapct_gui"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPCT;
    else if( FD_LIKELY( !strcmp( link->name, "repair_net"    ) ) ) ctx->in_kind[ i ] = IN_KIND_REPAIR_NET;
    else if( FD_LIKELY( !strcmp( link->name, "tower_out"     ) ) ) ctx->in_kind[ i ] = IN_KIND_TOWER_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "snapin_gui"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPIN;
    else if( FD_LIKELY( !strcmp( link->name, "snapin_manif"  ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPIN_MANIF;
    else if( FD_LIKELY( !strcmp( link->name, "snapsv_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPSV_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "execrp_replay" ) ) ) ctx->in_kind[ i ] = IN_KIND_EXECRP_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "bundle_status"  ) ) ) ctx->in_kind[ i ] = IN_KIND_BUNDLE;
    else if( FD_LIKELY( !strcmp( link->name, "diag_gui"       ) ) ) ctx->in_kind[ i ] = IN_KIND_DIAG;
    else if( FD_LIKELY( !strcmp( link->name, "votor_out"      ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR_OUT;
    else FD_LOG_ERR(( "gui tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( !strcmp( link->name, "execle_poh" ) ) ) {
      ulong producer = fd_topo_find_link_producer( topo, &topo->links[ tile->in_link_id[ i ] ] );
      ctx->in_bank_idx[ i ] = topo->tiles[ producer ].kind_id;
    }

    ctx->in_reliable[ i ] = tile->in_link_reliable[ i ];
    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
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
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  uint epoll_inner_fd = (uint)FD_WAKER_INNER_FD( tile->waker_client_idx );
  uint epoll_outer_fd = (uint)FD_WAKER_OUTER_FD;

  populate_sock_filter_policy_fd_gui_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->gui_server ), (uint)fd_gui_store_fd( ctx->db ), epoll_inner_fd, epoll_outer_fd );
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

  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->gui_server ); /* gui listen socket */
  out_fds[ out_cnt++ ] = fd_gui_store_fd( ctx->db ); /* historical store data file */
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD;                             /* waker outer epoll fd (rearm) */
  out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( tile->waker_client_idx );   /* waker inner epoll fd */
  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, socket, stderr, logfile, guidb, and one spare for new accept() connections */
  ulong base = 6UL;
  return base + tile->gui.max_http_connections + tile->gui.max_websocket_connections;
}

#define STEM_BURST (2UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gui_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gui_ctx_t)


#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag
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
