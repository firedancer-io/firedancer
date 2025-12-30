#include "fd_gui.h"
#include "fd_gui_peers.h"
#include "fd_gui_printf.h"
#include "fd_gui_metrics.h"

#include "../metrics/fd_metrics.h"
#include "../plugin/fd_plugin.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/json/cJSON.h"
#include "../../disco/genesis/fd_genesis_cluster.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

#include <stdio.h>

FD_FN_CONST ulong
fd_gui_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_gui_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_gui_align(), sizeof( fd_gui_t ) );
  return FD_LAYOUT_FINI( l, fd_gui_align() );
}

void *
fd_gui_new( void *                shmem,
            fd_http_server_t *    http,
            char const *          version,
            char const *          cluster,
            uchar const *         identity_key,
            int                   has_vote_key,
            uchar const *         vote_key,
            int                   is_full_client,
            int                   snapshots_enabled,
            int                   is_voting,
            int                   schedule_strategy,
            fd_topo_t *           topo,
            long                  now ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( topo->tile_cnt>FD_GUI_TILE_TIMER_TILE_CNT ) ) {
    FD_LOG_WARNING(( "too many tiles" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gui_t * gui                = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),                sizeof(fd_gui_t) );

  gui->http = http;
  gui->topo = topo;

  gui->leader_slot = ULONG_MAX;
  gui->summary.schedule_strategy = schedule_strategy;


  gui->next_sample_400millis  = now;
  gui->next_sample_100millis  = now;
  gui->next_sample_50millis   = now;
  gui->next_sample_12_5millis = now;
  gui->next_sample_10millis   = now;

  memcpy( gui->summary.identity_key->uc, identity_key, 32UL );
  fd_base58_encode_32( identity_key, NULL, gui->summary.identity_key_base58 );
  gui->summary.identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  if( FD_LIKELY( has_vote_key ) ) {
    gui->summary.has_vote_key = 1;
    memcpy( gui->summary.vote_key->uc, vote_key, 32UL );
    fd_base58_encode_32( vote_key, NULL, gui->summary.vote_key_base58 );
    gui->summary.vote_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';
  } else {
    gui->summary.has_vote_key = 0;
    memset( gui->summary.vote_key_base58, 0, sizeof(gui->summary.vote_key_base58) );
  }

  gui->summary.is_full_client                = is_full_client;
  gui->summary.version                       = version;
  gui->summary.cluster                       = cluster;
  gui->summary.startup_time_nanos            = gui->next_sample_400millis;

  if( FD_UNLIKELY( is_full_client ) ) {
    if( FD_UNLIKELY( snapshots_enabled ) ) {
      gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_JOINING_GOSSIP;
      gui->summary.boot_progress.joining_gossip_time_nanos = gui->next_sample_400millis;
      for( ulong i=0UL; i<FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT; i++ ) {
        gui->summary.boot_progress.loading_snapshot[ i ].reset_cnt = ULONG_MAX; /* ensures other fields are reset initially */
        gui->summary.boot_progress.loading_snapshot[ i ].read_path[ 0 ] = '\0';
        gui->summary.boot_progress.loading_snapshot[ i ].insert_path[ 0 ] = '\0';
      }
      gui->summary.boot_progress.catching_up_time_nanos        = 0L;
      gui->summary.boot_progress.catching_up_first_replay_slot = ULONG_MAX;
    } else {
      fd_memset( &gui->summary.boot_progress, 0, sizeof(gui->summary.boot_progress) );
      gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_RUNNING;
    }
  } else {
    gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_INITIALIZING;
    gui->summary.startup_progress.startup_got_full_snapshot              = 0;
    gui->summary.startup_progress.startup_full_snapshot_slot             = 0;
    gui->summary.startup_progress.startup_incremental_snapshot_slot      = 0;
    gui->summary.startup_progress.startup_waiting_for_supermajority_slot = ULONG_MAX;
    gui->summary.startup_progress.startup_ledger_max_slot                = ULONG_MAX;
  }

  gui->summary.identity_account_balance      = 0UL;
  gui->summary.vote_account_balance          = 0UL;
  gui->summary.estimated_slot_duration_nanos = 0UL;

  gui->summary.vote_distance = 0UL;
  gui->summary.vote_state = is_voting ? FD_GUI_VOTE_STATE_VOTING : FD_GUI_VOTE_STATE_NON_VOTING;

  gui->summary.sock_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "sock"   );
  gui->summary.net_tile_cnt    = fd_topo_tile_name_cnt( gui->topo, "net"    );
  gui->summary.quic_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "quic"   );
  gui->summary.verify_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "verify" );
  gui->summary.resolv_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "resolv" );
  gui->summary.bank_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "bank"   );
  gui->summary.shred_tile_cnt  = fd_topo_tile_name_cnt( gui->topo, "shred"  );

  gui->summary.slot_rooted                   = ULONG_MAX;
  gui->summary.slot_optimistically_confirmed = ULONG_MAX;
  gui->summary.slot_completed                = ULONG_MAX;
  gui->summary.slot_estimated                = ULONG_MAX;
  gui->summary.slot_caught_up                = ULONG_MAX;
  gui->summary.slot_repair                   = ULONG_MAX;
  gui->summary.slot_turbine                  = ULONG_MAX;
  gui->summary.slot_reset                    = ULONG_MAX;
  gui->summary.slot_storage                  = ULONG_MAX;
  gui->summary.active_fork_cnt               = 1UL;

  for( ulong i=0UL; i < (FD_GUI_REPAIR_SLOT_HISTORY_SZ+1UL); i++ )  gui->summary.slots_max_repair[ i ].slot  = ULONG_MAX;
  for( ulong i=0UL; i < (FD_GUI_TURBINE_SLOT_HISTORY_SZ+1UL); i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;

  for( ulong i=0UL; i < FD_GUI_TURBINE_RECV_TIMESTAMPS; i++ ) gui->turbine_slots[ i ].slot = ULONG_MAX;

  gui->summary.estimated_tps_history_idx = 0UL;
  memset( gui->summary.estimated_tps_history, 0, sizeof(gui->summary.estimated_tps_history) );

  memset( gui->summary.txn_waterfall_reference, 0, sizeof(gui->summary.txn_waterfall_reference) );
  memset( gui->summary.txn_waterfall_current,   0, sizeof(gui->summary.txn_waterfall_current) );

  memset( gui->summary.tile_stats_reference, 0, sizeof(gui->summary.tile_stats_reference) );
  memset( gui->summary.tile_stats_current, 0, sizeof(gui->summary.tile_stats_current) );

  memset( gui->summary.tile_timers_snap[ 0 ], 0, sizeof(gui->summary.tile_timers_snap[ 0 ]) );
  memset( gui->summary.tile_timers_snap[ 1 ], 0, sizeof(gui->summary.tile_timers_snap[ 1 ]) );
  gui->summary.tile_timers_snap_idx    = 2UL;

  memset( gui->summary.scheduler_counts_snap[ 0 ], 0, sizeof(gui->summary.scheduler_counts_snap[ 0 ]) );
  memset( gui->summary.scheduler_counts_snap[ 1 ], 0, sizeof(gui->summary.scheduler_counts_snap[ 1 ]) );
  gui->summary.scheduler_counts_snap_idx    = 2UL;

  for( ulong i=0UL; i<FD_GUI_SLOTS_CNT;  i++ ) gui->slots[ i ]->slot             = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_LEADER_CNT; i++ ) gui->leader_slots[ i ]->slot      = ULONG_MAX;
  gui->leader_slots_cnt      = 0UL;

  gui->block_engine.has_block_engine = 0;

  gui->epoch.has_epoch[ 0 ] = 0;
  gui->epoch.has_epoch[ 1 ] = 0;

  gui->gossip.peer_cnt               = 0UL;
  gui->vote_account.vote_account_cnt = 0UL;
  gui->validator_info.info_cnt       = 0UL;

  gui->pack_txn_idx = 0UL;

  gui->shreds.leader_shred_cnt      = 0UL;
  gui->shreds.staged_next_broadcast = 0UL;
  gui->shreds.staged_head           = 0UL;
  gui->shreds.staged_tail           = 0UL;
  gui->shreds.history_tail          = 0UL;
  gui->shreds.history_slot          = ULONG_MAX;
  gui->summary.catch_up_repair_sz  = 0UL;
  gui->summary.catch_up_turbine_sz = 0UL;

  return gui;
}

fd_gui_t *
fd_gui_join( void * shmem ) {
  return (fd_gui_t *)shmem;
}

void
fd_gui_set_identity( fd_gui_t *    gui,
                     uchar const * identity_pubkey ) {
  memcpy( gui->summary.identity_key->uc, identity_pubkey, 32UL );
  fd_base58_encode_32( identity_pubkey, NULL, gui->summary.identity_key_base58 );
  gui->summary.identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  fd_gui_printf_identity_key( gui );
  fd_http_server_ws_broadcast( gui->http );

  fd_gui_printf_identity_balance( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_ws_open( fd_gui_t * gui,
                ulong      ws_conn_id ) {
  void (* printers[] )( fd_gui_t * gui ) = {
    gui->summary.is_full_client ? fd_gui_printf_boot_progress : fd_gui_printf_startup_progress,
    fd_gui_printf_version,
    fd_gui_printf_cluster,
    fd_gui_printf_commit_hash,
    fd_gui_printf_identity_key,
    fd_gui_printf_vote_key,
    fd_gui_printf_startup_time_nanos,
    fd_gui_printf_vote_state,
    fd_gui_printf_vote_distance,
    fd_gui_printf_turbine_slot,
    fd_gui_printf_repair_slot,
    fd_gui_printf_slot_caught_up,
    fd_gui_printf_skipped_history,
    fd_gui_printf_skipped_history_cluster,
    fd_gui_printf_tps_history,
    fd_gui_printf_tiles,
    fd_gui_printf_schedule_strategy,
    fd_gui_printf_identity_balance,
    fd_gui_printf_vote_balance,
    fd_gui_printf_estimated_slot_duration_nanos,
    fd_gui_printf_root_slot,
    fd_gui_printf_storage_slot,
    fd_gui_printf_reset_slot,
    fd_gui_printf_active_fork_cnt,
    fd_gui_printf_optimistically_confirmed_slot,
    fd_gui_printf_completed_slot,
    fd_gui_printf_estimated_slot,
    fd_gui_printf_live_tile_timers,
    fd_gui_printf_live_tile_metrics,
    fd_gui_printf_catch_up_history,
  };

  ulong printers_len = sizeof(printers) / sizeof(printers[0]);
  for( ulong i=0UL; i<printers_len; i++ ) {
    printers[ i ]( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  if( FD_LIKELY( gui->block_engine.has_block_engine ) ) {
    fd_gui_printf_block_engine( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( gui->epoch.has_epoch[ i ] ) ) {
      fd_gui_printf_skip_rate( gui, i );
      FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
      fd_gui_printf_epoch( gui, i );
      FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    }
  }

  /* Print peers last because it's the largest message and would
     block other information. */
  fd_gui_printf_peers_all( gui );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
}

static void
fd_gui_tile_timers_snap( fd_gui_t * gui ) {
  fd_gui_tile_timers_t * cur = gui->summary.tile_timers_snap[ gui->summary.tile_timers_snap_idx ];
  gui->summary.tile_timers_snap_idx = (gui->summary.tile_timers_snap_idx+1UL)%FD_GUI_TILE_TIMER_SNAP_CNT;
  for( ulong i=0UL; i<gui->topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &gui->topo->tiles[ i ];
    if ( FD_UNLIKELY( !tile->metrics ) ) {
      /* bench tiles might not have been booted initially.
         This check shouldn't be necessary if all tiles barrier after boot. */
      // TODO(FIXME) this probably isn't the right fix but it makes fddev bench work for now
      return;
    }
    volatile ulong const * tile_metrics = fd_metrics_tile( tile->metrics );

    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_HOUSEKEEPING_IDX    ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING )    ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_HOUSEKEEPING_IDX   ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING )   ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_HOUSEKEEPING_IDX ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING ) ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_PREFRAG_IDX         ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG )         ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_PREFRAG_IDX        ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_PREFRAG )        ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_PREFRAG_IDX      ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG )      ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_POSTFRAG_IDX        ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG )        ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_POSTFRAG_IDX       ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_POSTFRAG )       ];

    cur[ i ].in_backp  = (int)tile_metrics[ MIDX(GAUGE, TILE, IN_BACKPRESSURE) ];
    cur[ i ].status    = (uint)tile_metrics[ MIDX( GAUGE, TILE, STATUS ) ];
    cur[ i ].heartbeat = tile_metrics[ MIDX( GAUGE, TILE, HEARTBEAT ) ];
    cur[ i ].backp_cnt = tile_metrics[ MIDX( COUNTER, TILE, BACKPRESSURE_COUNT ) ];
    cur[ i ].nvcsw     = tile_metrics[ MIDX( COUNTER, TILE, CONTEXT_SWITCH_VOLUNTARY_COUNT ) ];
    cur[ i ].nivcsw    = tile_metrics[ MIDX( COUNTER, TILE, CONTEXT_SWITCH_INVOLUNTARY_COUNT ) ];
  }
}

static void
fd_gui_scheduler_counts_snap( fd_gui_t * gui, long now ) {
  fd_gui_scheduler_counts_t * cur = gui->summary.scheduler_counts_snap[ gui->summary.scheduler_counts_snap_idx ];
  gui->summary.scheduler_counts_snap_idx = (gui->summary.scheduler_counts_snap_idx+1UL)%FD_GUI_SCHEDULER_COUNT_SNAP_CNT;

  fd_topo_tile_t const * pack = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "pack", 0UL ) ];
  volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );

  cur->sample_time_ns = now;

  cur->regular     = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS_REGULAR ) ];
  cur->votes       = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS_VOTES ) ];
  cur->conflicting = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS_CONFLICTING ) ];
  cur->bundles     = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS_BUNDLES ) ];
}

static void
fd_gui_estimated_tps_snap( fd_gui_t * gui ) {
  ulong total_txn_cnt          = 0UL;
  ulong vote_txn_cnt           = 0UL;
  ulong nonvote_failed_txn_cnt = 0UL;

  if( FD_LIKELY( gui->summary.slot_completed==ULONG_MAX ) ) return;
  for( ulong i=0UL; i<fd_ulong_min( gui->summary.slot_completed+1UL, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong _slot = gui->summary.slot_completed-i;
    fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, _slot );
    if( FD_UNLIKELY( !slot ) ) break; /* Slot no longer exists, no TPS. */
    if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) continue; /* Slot is on this fork but was never completed, must have been in root path on boot. */
    if( FD_UNLIKELY( slot->completed_time+FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS*1000L*1000L*1000L<gui->next_sample_400millis ) ) break; /* Slot too old. */
    if( FD_UNLIKELY( slot->skipped ) ) continue; /* Skipped slots don't count to TPS. */

    total_txn_cnt          += slot->total_txn_cnt;
    vote_txn_cnt           += slot->vote_txn_cnt;
    nonvote_failed_txn_cnt += slot->nonvote_failed_txn_cnt;
  }

  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ][ 0 ] = total_txn_cnt;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ][ 1 ] = vote_txn_cnt;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ][ 2 ] = nonvote_failed_txn_cnt;
  gui->summary.estimated_tps_history_idx = (gui->summary.estimated_tps_history_idx+1UL) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;
}

static void
fd_gui_network_stats_snap( fd_gui_t *               gui,
                           fd_gui_network_stats_t * cur ) {
  fd_topo_t * topo = gui->topo;
  ulong gossvf_tile_cnt = fd_topo_tile_name_cnt( topo, "gossvf" );
  ulong gossip_tile_cnt = fd_topo_tile_name_cnt( topo, "gossip" );
  ulong shred_tile_cnt  = fd_topo_tile_name_cnt( topo, "shred" );
  ulong net_tile_cnt    = fd_topo_tile_name_cnt( topo, "net" );
  ulong quic_tile_cnt   = fd_topo_tile_name_cnt( topo, "quic" );

  cur->in.gossip   = fd_gui_metrics_gossip_total_ingress_bytes( topo, gossvf_tile_cnt );
  cur->out.gossip  = fd_gui_metrics_gosip_total_egress_bytes( topo, gossip_tile_cnt );
  cur->in.turbine  = fd_gui_metrics_sum_tiles_counter( topo, "shred", shred_tile_cnt, MIDX( COUNTER, SHRED, SHRED_TURBINE_RCV_BYTES ) );

  cur->out.turbine = 0UL;
  cur->out.repair  = 0UL;
  cur->out.tpu     = 0UL;
  for( ulong i=0UL; i<net_tile_cnt; i++ ) {
    ulong net_tile_idx = fd_topo_find_tile( topo, "net", i );
    if( FD_UNLIKELY( net_tile_idx==ULONG_MAX ) ) continue;
    fd_topo_tile_t const * net = &topo->tiles[ net_tile_idx ];
    for( ulong j=0UL; j<net->in_cnt; j++ ) {
      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "shred_net" ) ) ) {
          cur->out.turbine += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
      }

      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "repair_net" ) ) ) {
          cur->out.repair += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
      }

      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "send_net" ) ) ) {
          cur->out.tpu += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
      }
    }
  }

  cur->in.repair = fd_gui_metrics_sum_tiles_counter( topo, "shred", shred_tile_cnt, MIDX( COUNTER, SHRED, SHRED_REPAIR_RCV_BYTES ) );
  ulong repair_tile_idx = fd_topo_find_tile( topo, "repair", 0UL );
  if( FD_LIKELY( repair_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * repair = &topo->tiles[ repair_tile_idx ];

    for( ulong i=0UL; i<repair->in_cnt; i++ ) {
      if( FD_UNLIKELY( !strcmp( topo->links[ repair->in_link_id[ i ] ].name, "net_repair" ) ) ) {
          cur->in.repair += fd_metrics_link_in( repair->metrics, i )[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
      }
    }
  }

  cur->in.tpu = 0UL;
  for( ulong i=0UL; i<quic_tile_cnt; i++ ) {
    ulong quic_tile_idx = fd_topo_find_tile( topo, "quic", i );
    if( FD_UNLIKELY( quic_tile_idx==ULONG_MAX ) ) continue;
    fd_topo_tile_t const * quic = &topo->tiles[ quic_tile_idx ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    cur->in.tpu += quic_metrics[ MIDX( COUNTER, QUIC, RECEIVED_BYTES ) ];
  }

  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong * bundle_metrics = fd_metrics_tile( bundle->metrics );
    cur->in.tpu += bundle_metrics[ MIDX( COUNTER, BUNDLE, PROTO_RECEIVED_BYTES ) ];
  }

  ulong metric_tile_idx = fd_topo_find_tile( topo, "metric", 0UL );
  if( FD_LIKELY( metric_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * metric = &topo->tiles[ metric_tile_idx ];
    volatile ulong * metric_metrics = fd_metrics_tile( metric->metrics );
    cur->in.metric  = metric_metrics[ MIDX( COUNTER, METRIC, BYTES_READ ) ];
    cur->out.metric = metric_metrics[ MIDX( COUNTER, METRIC, BYTES_WRITTEN ) ];
  } else {
    cur->in.metric  = 0UL;
    cur->out.metric = 0UL;
  }
}

/* Snapshot all of the data from metrics to construct a view of the
   transaction waterfall.

   Tiles are sampled in reverse pipeline order: this helps prevent data
   discrepancies where a later tile has "seen" more transactions than an
   earlier tile, which shouldn't typically happen. */

static void
fd_gui_txn_waterfall_snap( fd_gui_t *               gui,
                           fd_gui_txn_waterfall_t * cur ) {
  fd_topo_t * topo = gui->topo;

  cur->out.block_success = 0UL;
  cur->out.block_fail    = 0UL;

  cur->out.bank_invalid = 0UL;
  for( ulong i=0UL; i<gui->summary.bank_tile_cnt; i++ ) {
    fd_topo_tile_t const * bank = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];

    volatile ulong const * bank_metrics = fd_metrics_tile( bank->metrics );
    if( FD_LIKELY( !gui->summary.is_full_client ) ) {
      cur->out.block_success += bank_metrics[ MIDX( COUNTER, BANK, SUCCESSFUL_TRANSACTIONS ) ];

      cur->out.block_fail +=
          bank_metrics[ MIDX( COUNTER, BANK, EXECUTED_FAILED_TRANSACTIONS ) ]
        + bank_metrics[ MIDX( COUNTER, BANK, FEE_ONLY_TRANSACTIONS        ) ];

      cur->out.bank_invalid +=
          bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_ACCOUNT_UNINITIALIZED ) ]
        + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_ACCOUNT_NOT_FOUND ) ]
        + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_ACCOUNT_OWNER ) ]
        + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_ACCOUNT_DATA ) ]
        + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_LOOKUP_INDEX  ) ];

      cur->out.bank_invalid +=
          bank_metrics[ MIDX( COUNTER, BANK, PROCESSING_FAILED ) ];

      /* These branches are unused in Frankendancer */
      cur->out.bank_nonce_already_advanced = 0UL;
      cur->out.bank_nonce_advance_failed   = 0UL;
      cur->out.bank_nonce_wrong_blockhash  = 0UL;
    } else {
      cur->out.block_success += bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_LANDED_LANDED_SUCCESS ) ];
      cur->out.block_fail    +=
          bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_LANDED_LANDED_FEES_ONLY ) ]
        + bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_LANDED_LANDED_FAILED ) ];
      cur->out.bank_invalid  += bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_LANDED_UNLANDED ) ];

      cur->out.bank_nonce_already_advanced = bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_RESULT_NONCE_ALREADY_ADVANCED ) ];
      cur->out.bank_nonce_advance_failed   = bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_RESULT_NONCE_ADVANCE_FAILED ) ];
      cur->out.bank_nonce_wrong_blockhash  = bank_metrics[ MIDX( COUNTER, BANKF, TRANSACTION_RESULT_NONCE_WRONG_BLOCKHASH ) ];
    }
  }


  fd_topo_tile_t const * pack = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );

  cur->out.pack_invalid_bundle =
      pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_PARTIAL_BUNDLE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_INSERTION_FAILED ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_CREATION_FAILED ) ];

  cur->out.pack_invalid =
      pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_NONCE_CONFLICT ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_BUNDLE_BLACKLIST ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_INVALID_NONCE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_WRITE_SYSVAR ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ESTIMATION_FAIL ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE_ACCOUNT ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_MANY_ACCOUNTS ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_LARGE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ADDR_LUT ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_UNAFFORDABLE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE ) ]
    - pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_INSERTION_FAILED ) ]; /* so we don't double count this, since its already accounted for in invalid_bundle */

  cur->out.pack_expired = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_EXPIRED ) ] +
                          pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_EXPIRED ) ] +
                          pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DELETED ) ] +
                          pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_NONCE_PRIORITY ) ];

  cur->out.pack_already_executed = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_ALREADY_EXECUTED ) ];

  cur->out.pack_leader_slow = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_PRIORITY ) ];

  cur->out.pack_wait_full =
      pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_FROM_EXTRA ) ];

  cur->out.pack_retained = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS ) ];

  ulong inserted_to_extra = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TO_EXTRA ) ];
  ulong inserted_from_extra = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_FROM_EXTRA ) ]
                              + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_FROM_EXTRA ) ];
  cur->out.pack_retained += fd_ulong_if( inserted_to_extra>=inserted_from_extra, inserted_to_extra-inserted_from_extra, 0UL );

  cur->out.resolv_lut_failed = 0UL;
  cur->out.resolv_expired    = 0UL;
  cur->out.resolv_ancient    = 0UL;
  cur->out.resolv_no_ledger  = 0UL;
  cur->out.resolv_retained   = 0UL;
  for( ulong i=0UL; i<gui->summary.resolv_tile_cnt; i++ ) {
    fd_topo_tile_t const * resolv = &topo->tiles[ fd_topo_find_tile( topo, "resolv", i ) ];
    volatile ulong const * resolv_metrics = fd_metrics_tile( resolv->metrics );

    if( FD_LIKELY( !gui->summary.is_full_client ) ) {
      cur->out.resolv_no_ledger += resolv_metrics[ MIDX( COUNTER, RESOLV, NO_BANK_DROP ) ];
      cur->out.resolv_expired += resolv_metrics[ MIDX( COUNTER, RESOLV, BLOCKHASH_EXPIRED ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLV, TRANSACTION_BUNDLE_PEER_FAILURE  ) ];
      cur->out.resolv_lut_failed += resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_ACCOUNT_NOT_FOUND ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_INVALID_ACCOUNT_OWNER ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_INVALID_ACCOUNT_DATA ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_ACCOUNT_UNINITIALIZED ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_INVALID_LOOKUP_INDEX ) ];
      cur->out.resolv_ancient += resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_OVERRUN ) ];

      ulong inserted_to_resolv = resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_INSERTED ) ];
      ulong removed_from_resolv = resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_OVERRUN ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_PUBLISHED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_REMOVED ) ];
      cur->out.resolv_retained += fd_ulong_if( inserted_to_resolv>=removed_from_resolv, inserted_to_resolv-removed_from_resolv, 0UL );
    } else {
      cur->out.resolv_no_ledger += resolv_metrics[ MIDX( COUNTER, RESOLF, NO_BANK_DROP ) ];
      cur->out.resolv_expired += resolv_metrics[ MIDX( COUNTER, RESOLF, BLOCKHASH_EXPIRED ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLF, TRANSACTION_BUNDLE_PEER_FAILURE  ) ];
      cur->out.resolv_lut_failed += resolv_metrics[ MIDX( COUNTER, RESOLF, LUT_RESOLVED_ACCOUNT_NOT_FOUND ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLF, LUT_RESOLVED_INVALID_ACCOUNT_OWNER ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLF, LUT_RESOLVED_INVALID_ACCOUNT_DATA ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLF, LUT_RESOLVED_ACCOUNT_UNINITIALIZED ) ]
                                  + resolv_metrics[ MIDX( COUNTER, RESOLF, LUT_RESOLVED_INVALID_LOOKUP_INDEX ) ];
      cur->out.resolv_ancient += resolv_metrics[ MIDX( COUNTER, RESOLF, STASH_OPERATION_OVERRUN ) ];

      ulong inserted_to_resolv = resolv_metrics[ MIDX( COUNTER, RESOLF, STASH_OPERATION_INSERTED ) ];
      ulong removed_from_resolv = resolv_metrics[ MIDX( COUNTER, RESOLF, STASH_OPERATION_OVERRUN ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLF, STASH_OPERATION_PUBLISHED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLF, STASH_OPERATION_REMOVED ) ];
      cur->out.resolv_retained += fd_ulong_if( inserted_to_resolv>=removed_from_resolv, inserted_to_resolv-removed_from_resolv, 0UL );
    }
  }


  fd_topo_tile_t const * dedup = &topo->tiles[ fd_topo_find_tile( topo, "dedup", 0UL ) ];
  volatile ulong const * dedup_metrics = fd_metrics_tile( dedup->metrics );

  cur->out.dedup_duplicate = dedup_metrics[ MIDX( COUNTER, DEDUP, TRANSACTION_DEDUP_FAILURE ) ]
                           + dedup_metrics[ MIDX( COUNTER, DEDUP, TRANSACTION_BUNDLE_PEER_FAILURE ) ];


  cur->out.verify_overrun   = 0UL;
  cur->out.verify_duplicate = 0UL;
  cur->out.verify_parse     = 0UL;
  cur->out.verify_failed    = 0UL;

  for( ulong i=0UL; i<gui->summary.verify_tile_cnt; i++ ) {
    fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
    volatile ulong const * verify_metrics = fd_metrics_tile( verify->metrics );

    for( ulong j=0UL; j<gui->summary.quic_tile_cnt; j++ ) {
      /* TODO: Not precise... even if 1 frag gets skipped, it could have been for this verify tile. */
      cur->out.verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / gui->summary.verify_tile_cnt;
      cur->out.verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ];
    }

    cur->out.verify_failed    += verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_VERIFY_FAILURE ) ] +
                                 verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_BUNDLE_PEER_FAILURE ) ];
    cur->out.verify_parse     += verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_PARSE_FAILURE ) ];
    cur->out.verify_duplicate += verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_DEDUP_FAILURE ) ];
  }


  cur->out.quic_overrun      = 0UL;
  cur->out.quic_frag_drop    = 0UL;
  cur->out.quic_abandoned    = 0UL;
  cur->out.tpu_quic_invalid  = 0UL;
  cur->out.tpu_udp_invalid   = 0UL;
  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    cur->out.tpu_udp_invalid  += quic_metrics[ MIDX( COUNTER, QUIC, LEGACY_TXN_UNDERSZ      ) ];
    cur->out.tpu_udp_invalid  += quic_metrics[ MIDX( COUNTER, QUIC, LEGACY_TXN_OVERSZ       ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_UNDERSZ             ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_OVERSZ              ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, TXN_OVERSZ              ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_CRYPTO_FAILED       ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_NO_CONN             ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_NET_HEADER_INVALID  ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_QUIC_HEADER_INVALID ) ];
    cur->out.quic_abandoned   += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_ABANDONED          ) ];
    cur->out.quic_frag_drop   += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_OVERRUN            ) ];

    for( ulong j=0UL; j<gui->summary.net_tile_cnt; j++ ) {
      /* TODO: Not precise... net frags that were skipped might not have been destined for QUIC tile */
      /* TODO: Not precise... even if 1 frag gets skipped, it could have been for this QUIC tile */
      cur->out.quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / gui->summary.quic_tile_cnt;
      cur->out.quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ];
    }
  }

  cur->out.net_overrun = 0UL;
  for( ulong i=0UL; i<gui->summary.net_tile_cnt; i++ ) {
    fd_topo_tile_t const * net = &topo->tiles[ fd_topo_find_tile( topo, "net", i ) ];
    volatile ulong * net_metrics = fd_metrics_tile( net->metrics );

    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_RING_FULL ) ];
    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_DROPPED_OTHER ) ];
    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_FILL_RING_EMPTY_DESCS ) ];
  }

  ulong bundle_txns_received = 0UL;
  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong const * bundle_metrics = fd_metrics_tile( bundle->metrics );

    bundle_txns_received = bundle_metrics[ MIDX( COUNTER, BUNDLE, TRANSACTION_RECEIVED ) ];
  }

  cur->in.pack_cranked =
      pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_INSERTED ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_INSERTION_FAILED ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_CREATION_FAILED ) ];

  if( FD_UNLIKELY( gui->summary.is_full_client ) ) {
    cur->in.gossip = 0UL;
    for( ulong i=0UL; i<gui->summary.verify_tile_cnt; i++ ) {
      fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
      volatile ulong const * verify_metrics = fd_metrics_tile( verify->metrics );
      cur->in.gossip += verify_metrics[ MIDX( COUNTER, VERIFY, GOSSIPED_VOTES_RECEIVED ) ];
    }
  } else {
    cur->in.gossip = dedup_metrics[ MIDX( COUNTER, DEDUP, GOSSIPED_VOTES_RECEIVED ) ];
  }

  cur->in.quic     = cur->out.tpu_quic_invalid +
                     cur->out.quic_overrun +
                     cur->out.quic_frag_drop +
                     cur->out.quic_abandoned +
                     cur->out.net_overrun;
  cur->in.udp      = cur->out.tpu_udp_invalid;
  cur->in.block_engine = bundle_txns_received;
  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    cur->in.quic += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_RECEIVED_QUIC_FAST ) ];
    cur->in.quic += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_RECEIVED_QUIC_FRAG ) ];
    cur->in.udp  += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_RECEIVED_UDP       ) ];
  }
}

static void
fd_gui_tile_stats_snap( fd_gui_t *                     gui,
                        fd_gui_txn_waterfall_t const * waterfall,
                        fd_gui_tile_stats_t *          stats,
                        long                           now ) {
  fd_topo_t const * topo = gui->topo;

  stats->sample_time_nanos = now;

  stats->net_in_rx_bytes  = 0UL;
  stats->net_out_tx_bytes = 0UL;
  for( ulong i=0UL; i<gui->summary.net_tile_cnt; i++ ) {
    fd_topo_tile_t const * net = &topo->tiles[ fd_topo_find_tile( topo, "net", i ) ];
    volatile ulong * net_metrics = fd_metrics_tile( net->metrics );

    stats->net_in_rx_bytes  += net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL ) ];
    stats->net_out_tx_bytes += net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL ) ];
  }

  for( ulong i=0UL; i<gui->summary.sock_tile_cnt; i++ ) {
    fd_topo_tile_t const * sock = &topo->tiles[ fd_topo_find_tile( topo, "sock", i ) ];
    volatile ulong * sock_metrics = fd_metrics_tile( sock->metrics );

    stats->net_in_rx_bytes  += sock_metrics[ MIDX( COUNTER, SOCK, RX_BYTES_TOTAL ) ];
    stats->net_out_tx_bytes += sock_metrics[ MIDX( COUNTER, SOCK, TX_BYTES_TOTAL ) ];
  }

  stats->quic_conn_cnt = 0UL;
  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    stats->quic_conn_cnt += quic_metrics[ MIDX( GAUGE, QUIC, CONNECTIONS_ALLOC ) ];
  }

  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong * bundle_metrics = fd_metrics_tile( bundle->metrics );
    stats->bundle_rtt_smoothed_nanos = bundle_metrics[ MIDX( GAUGE, BUNDLE, RTT_SMOOTHED ) ];

    fd_histf_new( &stats->bundle_rx_delay_hist, FD_MHIST_MIN( BUNDLE, MESSAGE_RX_DELAY_NANOS ), FD_MHIST_MAX( BUNDLE, MESSAGE_RX_DELAY_NANOS ) );
    stats->bundle_rx_delay_hist.sum = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + FD_HISTF_BUCKET_CNT ];
    for( ulong b=0; b<FD_HISTF_BUCKET_CNT; b++ ) stats->bundle_rx_delay_hist.counts[ b ] = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + b ];
  }

  stats->verify_drop_cnt = waterfall->out.verify_duplicate +
                           waterfall->out.verify_parse +
                           waterfall->out.verify_failed;
  stats->verify_total_cnt = waterfall->in.gossip +
                            waterfall->in.quic +
                            waterfall->in.udp -
                            waterfall->out.net_overrun -
                            waterfall->out.tpu_quic_invalid -
                            waterfall->out.tpu_udp_invalid -
                            waterfall->out.quic_abandoned -
                            waterfall->out.quic_frag_drop -
                            waterfall->out.quic_overrun -
                            waterfall->out.verify_overrun;
  stats->dedup_drop_cnt = waterfall->out.dedup_duplicate;
  stats->dedup_total_cnt = stats->verify_total_cnt -
                           waterfall->out.verify_duplicate -
                            waterfall->out.verify_parse -
                            waterfall->out.verify_failed;

  fd_topo_tile_t const * pack  = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );
  stats->pack_buffer_cnt      = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS ) ];
  stats->pack_buffer_capacity = pack->pack.max_pending_transactions;

  stats->bank_txn_exec_cnt = waterfall->out.block_fail + waterfall->out.block_success;
}

static void
fd_gui_run_boot_progress( fd_gui_t * gui, long now ) {
  fd_topo_tile_t const * snapct = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapct", 0UL ) ];
  volatile ulong * snapct_metrics = fd_metrics_tile( snapct->metrics );

  fd_topo_tile_t const * snapdc = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapdc", 0UL ) ];
  volatile ulong * snapdc_metrics = fd_metrics_tile( snapdc->metrics );

  fd_topo_tile_t const * snapin = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapin", 0UL ) ];
  volatile ulong * snapin_metrics = fd_metrics_tile( snapin->metrics );

  ulong snapshot_phase = snapct_metrics[ MIDX( GAUGE, SNAPCT, STATE ) ];

  /* state transitions */
  if( FD_UNLIKELY( gui->summary.slot_caught_up!=ULONG_MAX ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_RUNNING;
  } else if( FD_LIKELY( snapshot_phase == FD_SNAPCT_STATE_SHUTDOWN && gui->summary.slots_max_turbine[ 0 ].slot!=ULONG_MAX && gui->summary.slot_completed!=ULONG_MAX ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP;
  } else if( FD_LIKELY( snapshot_phase==FD_SNAPCT_STATE_READING_FULL_FILE
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_FULL_FILE
                     || snapshot_phase==FD_SNAPCT_STATE_READING_FULL_HTTP
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT;
  } else if( FD_LIKELY( snapshot_phase==FD_SNAPCT_STATE_READING_INCREMENTAL_FILE
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE
                     || snapshot_phase==FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_LOADING_INCREMENTAL_SNAPSHOT;
  }

  /* It's possible for the incremental snapshot phase to be skipped, or
     complete before we can sample it.  This ensures we always get at
     least one pass of the metrics. */
  if( FD_UNLIKELY( gui->summary.boot_progress.phase==FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP
                && gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].reset_cnt==ULONG_MAX ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_LOADING_INCREMENTAL_SNAPSHOT;
  }

  switch ( gui->summary.boot_progress.phase ) {
    case FD_GUI_BOOT_PROGRESS_TYPE_JOINING_GOSSIP: {
      gui->summary.boot_progress.joining_gossip_time_nanos = now;
      break;
    }
    case FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT:
    case FD_GUI_BOOT_PROGRESS_TYPE_LOADING_INCREMENTAL_SNAPSHOT: {
      ulong snapshot_idx = fd_ulong_if( gui->summary.boot_progress.phase==FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT, FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX );
      ulong _retry_cnt = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_DOWNLOAD_RETRIES ) ], snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_DOWNLOAD_RETRIES ) ]);

      /* reset boot state if necessary */
      if( FD_UNLIKELY( gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_cnt!=_retry_cnt ) ) {
        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_time_nanos = now;
        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_cnt = _retry_cnt;
      }

      ulong _total_bytes                   = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_TOTAL ) ],                snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_TOTAL ) ]                );
      ulong _read_bytes                    = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ],                 snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) ]                 );
      ulong _decompress_decompressed_bytes = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN ) ], snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN ) ] );
      ulong _decompress_compressed_bytes   = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_COMPRESSED_BYTES_READ ) ],      snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ ) ]      );
      ulong _insert_bytes                  = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapin_metrics[ MIDX( GAUGE, SNAPIN, FULL_BYTES_READ ) ],                 snapin_metrics[ MIDX( GAUGE, SNAPIN, INCREMENTAL_BYTES_READ ) ]                 );
      ulong _insert_accounts               = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED ) ];

      /* metadata */
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].total_bytes_compressed = _total_bytes;
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].sample_time_nanos = now;

      /* read stage */
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].read_bytes_compressed = _read_bytes;

      /* decompress stage */
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].decompress_bytes_compressed   = _decompress_compressed_bytes;
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].decompress_bytes_decompressed = _decompress_decompressed_bytes;

      /* insert stage */
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].insert_bytes_decompressed = _insert_bytes;

      /* Use the latest compression ratio to estimate decompressed size */
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].insert_accounts_current = _insert_accounts;

      break;
    }
    case FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP: {
      gui->summary.boot_progress.catching_up_time_nanos = now;
      break;
    }
    case FD_GUI_BOOT_PROGRESS_TYPE_RUNNING: break;
    default: FD_LOG_ERR(( "unknown boot progress phase: %d", gui->summary.boot_progress.phase ));
  }
}

static inline int
fd_gui_ephemeral_slots_contains( fd_gui_ephemeral_slot_t * slots, ulong slots_sz, ulong slot ) {
  for( ulong i=0UL; i<slots_sz; i++ ) {
    if( FD_UNLIKELY( slots[ i ].slot==ULONG_MAX ) ) break;
    if( FD_UNLIKELY( slots[ i ].slot==slot ) ) return 1;
  }
  return 0;
}

#define SORT_NAME fd_gui_ephemeral_slot_sort
#define SORT_KEY_T fd_gui_ephemeral_slot_t
#define SORT_BEFORE(a,b) fd_int_if( (a).slot==ULONG_MAX, 0, fd_int_if( (b).slot==ULONG_MAX, 1, fd_int_if( (a).slot==(b).slot, (a).timestamp_arrival_nanos>(b).timestamp_arrival_nanos, (a).slot>(b).slot ) ) )
#include "../../util/tmpl/fd_sort.c"

static inline void
fd_gui_try_insert_ephemeral_slot( fd_gui_ephemeral_slot_t * slots, ulong slots_sz, ulong slot, long now ) {
  int already_present = 0;
  for( ulong i=0UL; i<slots_sz; i++ ) {
    /* evict any slots older than 4.8 seconds */
    if( FD_UNLIKELY( slots[ i ].slot!=ULONG_MAX && now-slots[ i ].timestamp_arrival_nanos>4800000000L ) ) {
      slots[ i ].slot = ULONG_MAX;
      continue;
    }

    /* if we've already seen this slot, just update the timestamp */
    if( FD_UNLIKELY( slots[ i ].slot==slot ) ) {
      slots[ i ].timestamp_arrival_nanos = now;
      already_present = 1;
    }
  }
  if( FD_LIKELY( already_present ) ) return;

  /* Insert the new slot number, evicting a smaller slot if necessary */
  slots[ slots_sz ].timestamp_arrival_nanos = now;
  slots[ slots_sz ].slot = slot;
  fd_gui_ephemeral_slot_sort_insert( slots, slots_sz+1UL );
}

static inline void
fd_gui_try_insert_catch_up_slot( ulong * slots, ulong capacity, ulong * slots_sz, ulong slot ) {
  /* catch up history is run-length encoded */
  int inserted = 0;
  for( ulong i=0UL; i<*slots_sz; i++ ) {
    if( FD_UNLIKELY( i%2UL==1UL && slots[ i ]==slot-1UL ) ) {
      slots[ i ]++;
      inserted = 1;
      break;
    } else if( FD_UNLIKELY( i%2UL==0UL && slots[ i ]==slot+1UL ) ) {
      slots[ i ]--;
      inserted = 1;
      break;
    }
  }
  if( FD_LIKELY( !inserted ) ) {
    slots[ (*slots_sz)++ ] = slot;
    slots[ (*slots_sz)++ ] = slot;
  }

  /* colesce intervals that touch */
  ulong removed = 0UL;
  for( ulong i=1UL; i<(*slots_sz)-1UL; i+=2 ) {
    if( FD_UNLIKELY( slots[ i ]==slots[ i+1UL ] ) ) {
      slots[ i ]     = ULONG_MAX;
      slots[ i+1UL ] = ULONG_MAX;
      removed += 2;
    }
  }

  if( FD_UNLIKELY( (*slots_sz)>removed+capacity-2UL ) ) {
    /* We are at capacity, start coalescing earlier intervals. */
    slots[ 1 ] = ULONG_MAX;
    slots[ 2 ] = ULONG_MAX;
  }

  fd_sort_up_ulong_insert( slots, (*slots_sz) );
  (*slots_sz) -= removed;
}

void
fd_gui_handle_repair_slot( fd_gui_t * gui, ulong slot, long now ) {
  int was_sent = fd_gui_ephemeral_slots_contains( gui->summary.slots_max_repair, FD_GUI_REPAIR_SLOT_HISTORY_SZ, slot );
  fd_gui_try_insert_ephemeral_slot( gui->summary.slots_max_repair, FD_GUI_REPAIR_SLOT_HISTORY_SZ, slot, now );

  if( FD_UNLIKELY( !was_sent && slot!=gui->summary.slot_repair ) ) {
    gui->summary.slot_repair = slot;

    fd_gui_printf_repair_slot( gui );
    fd_http_server_ws_broadcast( gui->http );

    if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX ) ) fd_gui_try_insert_catch_up_slot( gui->summary.catch_up_repair, FD_GUI_REPAIR_CATCH_UP_HISTORY_SZ, &gui->summary.catch_up_repair_sz, slot );
  }
}

void
fd_gui_handle_repair_request( fd_gui_t * gui, ulong slot, ulong shred_idx, long now ) {
  fd_gui_slot_staged_shred_event_t * recv_event = &gui->shreds.staged[ gui->shreds.staged_tail % FD_GUI_SHREDS_STAGING_SZ ];
  gui->shreds.staged_tail++;
  recv_event->timestamp = now;
  recv_event->shred_idx = (ushort)shred_idx;
  recv_event->slot      = slot;
  recv_event->event     = FD_GUI_SLOT_SHRED_REPAIR_REQUEST;
}

int
fd_gui_poll( fd_gui_t * gui, long now ) {
  if( FD_LIKELY( now>gui->next_sample_400millis ) ) {
    fd_gui_estimated_tps_snap( gui );
    fd_gui_printf_estimated_tps( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_400millis += 400L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_100millis ) ) {
    fd_gui_txn_waterfall_snap( gui, gui->summary.txn_waterfall_current );
    fd_gui_printf_live_txn_waterfall( gui, gui->summary.txn_waterfall_reference, gui->summary.txn_waterfall_current, 0UL /* TODO: REAL NEXT LEADER SLOT */ );
    fd_http_server_ws_broadcast( gui->http );

    fd_gui_network_stats_snap( gui, gui->summary.network_stats_current );
    fd_gui_printf_live_network_metrics( gui, gui->summary.network_stats_current );
    fd_http_server_ws_broadcast( gui->http );

    *gui->summary.tile_stats_reference = *gui->summary.tile_stats_current;
    fd_gui_tile_stats_snap( gui, gui->summary.txn_waterfall_current, gui->summary.tile_stats_current, now );
    fd_gui_printf_live_tile_stats( gui, gui->summary.tile_stats_reference, gui->summary.tile_stats_current );
    fd_http_server_ws_broadcast( gui->http );

    if( FD_UNLIKELY( gui->summary.is_full_client && gui->summary.boot_progress.phase!=FD_GUI_BOOT_PROGRESS_TYPE_RUNNING ) ) {
      fd_gui_run_boot_progress( gui, now );
      fd_gui_printf_boot_progress( gui );
      fd_http_server_ws_broadcast( gui->http );
    }

    gui->next_sample_100millis += 100L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_50millis ) ) {
    if( FD_LIKELY( gui->summary.is_full_client && gui->shreds.staged_next_broadcast<gui->shreds.staged_tail ) ) {
      fd_gui_printf_shred_updates( gui );
      fd_http_server_ws_broadcast( gui->http );
      gui->shreds.staged_next_broadcast = gui->shreds.staged_tail;
    }

    /* We get the repair slot from the sampled metric after catching up
       and from incoming shred data before catchup. This makes the
       catchup progress bar look complete while also keeping the
       overview slots vis correct.  TODO: do this properly using frags
       sent over a link */
    if( FD_LIKELY( gui->summary.slot_caught_up!=ULONG_MAX ) ) {
      fd_topo_tile_t * repair = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "repair", 0UL ) ];
      volatile ulong const * repair_metrics = fd_metrics_tile( repair->metrics );
      ulong slot = repair_metrics[ MIDX( COUNTER, REPAIR, REPAIRED_SLOTS ) ];
      fd_gui_handle_repair_slot( gui, slot, now );
    }

    gui->next_sample_50millis += 50L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_12_5millis ) ) {
    fd_gui_printf_server_time_nanos( gui, now );
    fd_http_server_ws_broadcast( gui->http );

    fd_gui_tile_timers_snap( gui );

    /* every 25ms */
    if( (gui->next_sample_12_5millis % (25L*1000L*1000L)) >= (long)(12.5*1000L*1000L) ) {
      fd_gui_printf_live_tile_timers( gui );
      fd_http_server_ws_broadcast( gui->http );

      fd_gui_printf_live_tile_metrics( gui );
      fd_http_server_ws_broadcast( gui->http );
    }

    gui->next_sample_12_5millis += (long)(12.5*1000L*1000L);
    return 1;
  }


  if( FD_LIKELY( now>gui->next_sample_10millis ) ) {
    fd_gui_scheduler_counts_snap( gui, now );

    gui->next_sample_10millis += 10L*1000L*1000L;
    return 1;
  }

  return 0;
}

static void
fd_gui_handle_gossip_update( fd_gui_t *    gui,
                             uchar const * msg ) {
  /* `gui->gossip.peer_cnt` is guaranteed to be in [0, FD_GUI_MAX_PEER_CNT], because
  `peer_cnt` is FD_TEST-ed to be less than or equal FD_GUI_MAX_PEER_CNT.
  For every new peer that is added an existing peer will be removed or was still free.
  And adding a new peer is done at most `peer_cnt` times. */
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  FD_TEST( peer_cnt<=FD_GUI_MAX_PEER_CNT );

  ulong added_cnt = 0UL;
  ulong added[ FD_GUI_MAX_PEER_CNT ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ FD_GUI_MAX_PEER_CNT ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ FD_GUI_MAX_PEER_CNT ] = {0};

  uchar const * data = (uchar const *)(header+1UL);
  for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ i ].pubkey, data+j*(58UL+12UL*6UL), 32UL ) ) ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( removed[ removed_cnt++ ].uc, gui->gossip.peers[ i ].pubkey->uc, 32UL );
      if( FD_LIKELY( i+1UL!=gui->gossip.peer_cnt ) ) {
        gui->gossip.peers[ i ] = gui->gossip.peers[ gui->gossip.peer_cnt-1UL ];
        i--;
      }
      gui->gossip.peer_cnt--;
    }
  }

  ulong before_peer_cnt = gui->gossip.peer_cnt;
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int found = 0;
    ulong found_idx = 0;
    for( ulong j=0UL; j<gui->gossip.peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ j ].pubkey, data+i*(58UL+12UL*6UL), 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( gui->gossip.peers[ gui->gossip.peer_cnt ].pubkey->uc, data+i*(58UL+12UL*6UL), 32UL );
      gui->gossip.peers[ gui->gossip.peer_cnt ].wallclock = *(ulong const *)(data+i*(58UL+12UL*6UL)+32UL);
      gui->gossip.peers[ gui->gossip.peer_cnt ].shred_version = *(ushort const *)(data+i*(58UL+12UL*6UL)+40UL);
      gui->gossip.peers[ gui->gossip.peer_cnt ].has_version = *(data+i*(58UL+12UL*6UL)+42UL);
      if( FD_LIKELY( gui->gossip.peers[ gui->gossip.peer_cnt ].has_version ) ) {
        gui->gossip.peers[ gui->gossip.peer_cnt ].version.major = *(ushort const *)(data+i*(58UL+12UL*6UL)+43UL);
        gui->gossip.peers[ gui->gossip.peer_cnt ].version.minor = *(ushort const *)(data+i*(58UL+12UL*6UL)+45UL);
        gui->gossip.peers[ gui->gossip.peer_cnt ].version.patch = *(ushort const *)(data+i*(58UL+12UL*6UL)+47UL);
        gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit = *(data+i*(58UL+12UL*6UL)+49UL);
        if( FD_LIKELY( gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit ) ) {
          gui->gossip.peers[ gui->gossip.peer_cnt ].version.commit = *(uint const *)(data+i*(58UL+12UL*6UL)+50UL);
        }
        gui->gossip.peers[ gui->gossip.peer_cnt ].version.feature_set = *(uint const *)(data+i*(58UL+12UL*6UL)+54UL);
      }

      for( ulong j=0UL; j<12UL; j++ ) {
        gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL);
        gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
      }

      gui->gossip.peer_cnt++;
    } else {
      int peer_updated = gui->gossip.peers[ found_idx ].shred_version!=*(ushort const *)(data+i*(58UL+12UL*6UL)+40UL) ||
                         // gui->gossip.peers[ found_idx ].wallclock!=*(ulong const *)(data+i*(58UL+12UL*6UL)+32UL) ||
                         gui->gossip.peers[ found_idx ].has_version!=*(data+i*(58UL+12UL*6UL)+42UL);

      if( FD_LIKELY( !peer_updated && gui->gossip.peers[ found_idx ].has_version ) ) {
        peer_updated = gui->gossip.peers[ found_idx ].version.major!=*(ushort const *)(data+i*(58UL+12UL*6UL)+43UL) ||
                        gui->gossip.peers[ found_idx ].version.minor!=*(ushort const *)(data+i*(58UL+12UL*6UL)+45UL) ||
                        gui->gossip.peers[ found_idx ].version.patch!=*(ushort const *)(data+i*(58UL+12UL*6UL)+47UL) ||
                        gui->gossip.peers[ found_idx ].version.has_commit!=*(data+i*(58UL+12UL*6UL)+49UL) ||
                        (gui->gossip.peers[ found_idx ].version.has_commit && gui->gossip.peers[ found_idx ].version.commit!=*(uint const *)(data+i*(58UL+12UL*6UL)+50UL)) ||
                        gui->gossip.peers[ found_idx ].version.feature_set!=*(uint const *)(data+i*(58UL+12UL*6UL)+54UL);
      }

      if( FD_LIKELY( !peer_updated ) ) {
        for( ulong j=0UL; j<12UL; j++ ) {
          peer_updated = gui->gossip.peers[ found_idx ].sockets[ j ].ipv4!=*(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL) ||
                          gui->gossip.peers[ found_idx ].sockets[ j ].port!=*(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
          if( FD_LIKELY( peer_updated ) ) break;
        }
      }

      if( FD_UNLIKELY( peer_updated ) ) {
        updated[ update_cnt++ ] = found_idx;
        gui->gossip.peers[ found_idx ].shred_version = *(ushort const *)(data+i*(58UL+12UL*6UL)+40UL);
        gui->gossip.peers[ found_idx ].wallclock = *(ulong const *)(data+i*(58UL+12UL*6UL)+32UL);
        gui->gossip.peers[ found_idx ].has_version = *(data+i*(58UL+12UL*6UL)+42UL);
        if( FD_LIKELY( gui->gossip.peers[ found_idx ].has_version ) ) {
          gui->gossip.peers[ found_idx ].version.major = *(ushort const *)(data+i*(58UL+12UL*6UL)+43UL);
          gui->gossip.peers[ found_idx ].version.minor = *(ushort const *)(data+i*(58UL+12UL*6UL)+45UL);
          gui->gossip.peers[ found_idx ].version.patch = *(ushort const *)(data+i*(58UL+12UL*6UL)+47UL);
          gui->gossip.peers[ found_idx ].version.has_commit = *(data+i*(58UL+12UL*6UL)+49UL);
          if( FD_LIKELY( gui->gossip.peers[ found_idx ].version.has_commit ) ) {
            gui->gossip.peers[ found_idx ].version.commit = *(uint const *)(data+i*(58UL+12UL*6UL)+50UL);
          }
          gui->gossip.peers[ found_idx ].version.feature_set = *(uint const *)(data+i*(58UL+12UL*6UL)+54UL);
        }

        for( ulong j=0UL; j<12UL; j++ ) {
          gui->gossip.peers[ found_idx ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL);
          gui->gossip.peers[ found_idx ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
        }
      }
    }
  }

  added_cnt = gui->gossip.peer_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->gossip.peer_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_printf_peers_gossip_update( gui, updated, update_cnt, removed, removed_cnt, added, added_cnt );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_vote_account_update( fd_gui_t *    gui,
                                   uchar const * msg ) {
  /* See fd_gui_handle_gossip_update for why `gui->vote_account.vote_account_cnt`
  is guaranteed to be in [0, FD_GUI_MAX_PEER_CNT]. */
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  FD_TEST( peer_cnt<=FD_GUI_MAX_PEER_CNT );

  ulong added_cnt = 0UL;
  ulong added[ FD_GUI_MAX_PEER_CNT ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ FD_GUI_MAX_PEER_CNT ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ FD_GUI_MAX_PEER_CNT ] = {0};

  uchar const * data = (uchar const *)(header+1UL);
  for( ulong i=0UL; i<gui->vote_account.vote_account_cnt; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ i ].vote_account, data+j*112UL, 32UL ) ) ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( removed[ removed_cnt++ ].uc, gui->vote_account.vote_accounts[ i ].vote_account->uc, 32UL );
      if( FD_LIKELY( i+1UL!=gui->vote_account.vote_account_cnt ) ) {
        gui->vote_account.vote_accounts[ i ] = gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt-1UL ];
        i--;
      }
      gui->vote_account.vote_account_cnt--;
    }
  }

  ulong before_peer_cnt = gui->vote_account.vote_account_cnt;
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int found = 0;
    ulong found_idx;
    for( ulong j=0UL; j<gui->vote_account.vote_account_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ j ].vote_account, data+i*112UL, 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].vote_account->uc, data+i*112UL, 32UL );
      fd_memcpy( gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].pubkey->uc, data+i*112UL+32UL, 32UL );

      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].activated_stake = *(ulong const *)(data+i*112UL+64UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].last_vote = *(ulong const *)(data+i*112UL+72UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].root_slot = *(ulong const *)(data+i*112UL+80UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].epoch_credits = *(ulong const *)(data+i*112UL+88UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].commission = *(data+i*112UL+96UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].delinquent = *(data+i*112UL+97UL);

      gui->vote_account.vote_account_cnt++;
    } else {
      int peer_updated =
        memcmp( gui->vote_account.vote_accounts[ found_idx ].pubkey->uc, data+i*112UL+32UL, 32UL ) ||
        gui->vote_account.vote_accounts[ found_idx ].activated_stake != *(ulong const *)(data+i*112UL+64UL) ||
        // gui->vote_account.vote_accounts[ found_idx ].last_vote       != *(ulong const *)(data+i*112UL+72UL) ||
        // gui->vote_account.vote_accounts[ found_idx ].root_slot       != *(ulong const *)(data+i*112UL+80UL) ||
        // gui->vote_account.vote_accounts[ found_idx ].epoch_credits   != *(ulong const *)(data+i*112UL+88UL) ||
        gui->vote_account.vote_accounts[ found_idx ].commission      != *(data+i*112UL+96UL) ||
        gui->vote_account.vote_accounts[ found_idx ].delinquent      != *(data+i*112UL+97UL);

      if( FD_UNLIKELY( peer_updated ) ) {
        updated[ update_cnt++ ] = found_idx;

        fd_memcpy( gui->vote_account.vote_accounts[ found_idx ].pubkey->uc, data+i*112UL+32UL, 32UL );
        gui->vote_account.vote_accounts[ found_idx ].activated_stake = *(ulong const *)(data+i*112UL+64UL);
        gui->vote_account.vote_accounts[ found_idx ].last_vote = *(ulong const *)(data+i*112UL+72UL);
        gui->vote_account.vote_accounts[ found_idx ].root_slot = *(ulong const *)(data+i*112UL+80UL);
        gui->vote_account.vote_accounts[ found_idx ].epoch_credits = *(ulong const *)(data+i*112UL+88UL);
        gui->vote_account.vote_accounts[ found_idx ].commission = *(data+i*112UL+96UL);
        gui->vote_account.vote_accounts[ found_idx ].delinquent = *(data+i*112UL+97UL);
      }
    }
  }

  added_cnt = gui->vote_account.vote_account_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->vote_account.vote_account_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_printf_peers_vote_account_update( gui, updated, update_cnt, removed, removed_cnt, added, added_cnt );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_validator_info_update( fd_gui_t *    gui,
                                     uchar const * msg ) {
  if( FD_UNLIKELY( gui->validator_info.info_cnt == FD_GUI_MAX_PEER_CNT ) ) {
    FD_LOG_DEBUG(("validator info cnt exceeds 40200 %lu, ignoring additional entries", gui->validator_info.info_cnt ));
    return;
  }
  uchar const * data = (uchar const *)fd_type_pun_const( msg );

  ulong added_cnt = 0UL;
  ulong added[ 1 ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ 1 ] = {0};

  ulong removed_cnt = 0UL;
  /* Unlike gossip or vote account updates, validator info messages come
     in as info is discovered, and may contain as little as 1 validator
     per message.  Therefore, it doesn't make sense to use the remove
     mechanism.  */

  ulong before_peer_cnt = gui->validator_info.info_cnt;
  int found = 0;
  ulong found_idx;
  for( ulong j=0UL; j<gui->validator_info.info_cnt; j++ ) {
    if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ j ].pubkey, data, 32UL ) ) ) {
      found_idx = j;
      found = 1;
      break;
    }
  }

  if( FD_UNLIKELY( !found ) ) {
    fd_memcpy( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data, 32UL );

    strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+32UL), 64 );
    gui->validator_info.info[ gui->validator_info.info_cnt ].name[ 63 ] = '\0';

    strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+96UL), 128 );
    gui->validator_info.info[ gui->validator_info.info_cnt ].website[ 127 ] = '\0';

    strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+224UL), 256 );
    gui->validator_info.info[ gui->validator_info.info_cnt ].details[ 255 ] = '\0';

    strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+480UL), 128 );
    gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri[ 127 ] = '\0';

    gui->validator_info.info_cnt++;
  } else {
    int peer_updated =
      memcmp( gui->validator_info.info[ found_idx ].pubkey->uc, data, 32UL ) ||
      strncmp( gui->validator_info.info[ found_idx ].name, (char const *)(data+32UL), 64 ) ||
      strncmp( gui->validator_info.info[ found_idx ].website, (char const *)(data+96UL), 128 ) ||
      strncmp( gui->validator_info.info[ found_idx ].details, (char const *)(data+224UL), 256 ) ||
      strncmp( gui->validator_info.info[ found_idx ].icon_uri, (char const *)(data+480UL), 128 );

    if( FD_UNLIKELY( peer_updated ) ) {
      updated[ update_cnt++ ] = found_idx;

      fd_memcpy( gui->validator_info.info[ found_idx ].pubkey->uc, data, 32UL );

      strncpy( gui->validator_info.info[ found_idx ].name, (char const *)(data+32UL), 64 );
      gui->validator_info.info[ found_idx ].name[ 63 ] = '\0';

      strncpy( gui->validator_info.info[ found_idx ].website, (char const *)(data+96UL), 128 );
      gui->validator_info.info[ found_idx ].website[ 127 ] = '\0';

      strncpy( gui->validator_info.info[ found_idx ].details, (char const *)(data+224UL), 256 );
      gui->validator_info.info[ found_idx ].details[ 255 ] = '\0';

      strncpy( gui->validator_info.info[ found_idx ].icon_uri, (char const *)(data+480UL), 128 );
      gui->validator_info.info[ found_idx ].icon_uri[ 127 ] = '\0';
    }
  }

  added_cnt = gui->validator_info.info_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->validator_info.info_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_printf_peers_validator_info_update( gui, updated, update_cnt, NULL, removed_cnt, added, added_cnt );
  fd_http_server_ws_broadcast( gui->http );
}

int
fd_gui_request_slot( fd_gui_t *    gui,
                     ulong         ws_conn_id,
                     ulong         request_id,
                     cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;
  fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request( gui, _slot, request_id );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_request_slot_transactions( fd_gui_t *    gui,
                                  ulong         ws_conn_id,
                                  ulong         request_id,
                                  cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;
  fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_transactions_request( gui, _slot, request_id );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_request_slot_detailed( fd_gui_t *    gui,
                              ulong         ws_conn_id,
                              ulong         request_id,
                              cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;
  fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request_detailed( gui, _slot, request_id );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

static inline ulong
fd_gui_slot_duration( fd_gui_t const * gui, fd_gui_slot_t const * cur ) {
  fd_gui_slot_t const * prev = fd_gui_get_slot_const( gui, cur->slot-1UL );
  if( FD_UNLIKELY( !prev ||
                   prev->skipped ||
                   prev->completed_time == LONG_MAX ||
                   prev->slot != (cur->slot - 1UL) ||
                   cur->skipped ||
                   cur->completed_time == LONG_MAX ) ) return ULONG_MAX;

  return (ulong)(cur->completed_time - prev->completed_time);
}

/* All rankings are initialized / reset to ULONG_MAX.  These sentinels
   sort AFTER non-sentinel ranking entries.  Equal slots are sorted by
   oldest slot AFTER.  Otherwise sort by value according to ranking
   type. */
#define SORT_NAME fd_gui_slot_ranking_sort
#define SORT_KEY_T fd_gui_slot_ranking_t
#define SORT_BEFORE(a,b) fd_int_if( (a).slot==ULONG_MAX, 0, fd_int_if( (b).slot==ULONG_MAX, 1, fd_int_if( (a).value==(b).value, (a).slot>(b).slot, fd_int_if( (a).type==FD_GUI_SLOT_RANKING_TYPE_DESC, (a).value>(b).value, (a).value<(b).value ) ) ) )
#include "../../util/tmpl/fd_sort.c"

static inline void
fd_gui_try_insert_ranking( fd_gui_t               * gui,
                           fd_gui_slot_rankings_t * rankings,
                           fd_gui_slot_t const    * slot ) {
  /* Rankings are inserted into an extra slot at the end of the ranking
     array, then the array is sorted. */
#define TRY_INSERT_SLOT( ranking_name, ranking_slot, ranking_value ) \
  do { \
    rankings->FD_CONCAT2(largest_, ranking_name) [ FD_GUI_SLOT_RANKINGS_SZ ] = (fd_gui_slot_ranking_t){ .slot = (ranking_slot), .value = (ranking_value), .type = FD_GUI_SLOT_RANKING_TYPE_DESC }; \
    fd_gui_slot_ranking_sort_insert( rankings->FD_CONCAT2(largest_, ranking_name), FD_GUI_SLOT_RANKINGS_SZ+1UL ); \
    rankings->FD_CONCAT2(smallest_, ranking_name)[ FD_GUI_SLOT_RANKINGS_SZ ] = (fd_gui_slot_ranking_t){ .slot = (ranking_slot), .value = (ranking_value), .type = FD_GUI_SLOT_RANKING_TYPE_ASC  }; \
    fd_gui_slot_ranking_sort_insert( rankings->FD_CONCAT2(smallest_, ranking_name), FD_GUI_SLOT_RANKINGS_SZ+1UL ); \
  } while (0)

    if( slot->skipped ) {
      TRY_INSERT_SLOT( skipped, slot->slot, slot->slot );
      return;
    }

    ulong dur = fd_gui_slot_duration( gui, slot );
    if( FD_LIKELY( dur!=ULONG_MAX ) ) TRY_INSERT_SLOT( duration, slot->slot, dur                         );
    TRY_INSERT_SLOT( tips,           slot->slot, slot->tips                                              );
    TRY_INSERT_SLOT( fees,           slot->slot, slot->priority_fee + slot->transaction_fee              );
    TRY_INSERT_SLOT( rewards,        slot->slot, slot->tips + slot->priority_fee + slot->transaction_fee );
    TRY_INSERT_SLOT( rewards_per_cu, slot->slot, slot->compute_units==0UL ? 0UL : (slot->tips + slot->priority_fee + slot->transaction_fee) / slot->compute_units );
    TRY_INSERT_SLOT( compute_units,  slot->slot, slot->compute_units                                     );
#undef TRY_INSERT_SLOT
}

static void
fd_gui_update_slot_rankings( fd_gui_t * gui ) {
  ulong first_replay_slot = ULONG_MAX;
  if( FD_LIKELY( gui->summary.is_full_client ) ) {
    ulong slot_caught_up   = gui->summary.slot_caught_up;
    ulong slot_incremental = gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].slot;
    ulong slot_full        = gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].slot;
    first_replay_slot = fd_ulong_if( slot_caught_up!=ULONG_MAX, fd_ulong_if( slot_incremental!=ULONG_MAX, slot_incremental+1UL, fd_ulong_if( slot_full!=ULONG_MAX, slot_full+1UL, ULONG_MAX ) ), ULONG_MAX );
  } else {
    first_replay_slot = gui->summary.startup_progress.startup_ledger_max_slot;
  }
  if( FD_UNLIKELY( first_replay_slot==ULONG_MAX ) ) return;
  if( FD_UNLIKELY( gui->summary.slot_rooted ==ULONG_MAX ) ) return;

  ulong epoch_start_slot = ULONG_MAX;
  ulong epoch            = ULONG_MAX;
  for( ulong i = 0UL; i<2UL; i++ ) {
    if( FD_LIKELY( gui->epoch.has_epoch[ i ] ) ) {
      /* the "current" epoch is the smallest */
      epoch_start_slot = fd_ulong_min( epoch_start_slot, gui->epoch.epochs[ i ].start_slot );
      epoch            = fd_ulong_min( epoch,            gui->epoch.epochs[ i ].epoch      );
    }
  }

  if( FD_UNLIKELY( epoch==ULONG_MAX ) ) return;
  ulong epoch_idx = epoch % 2UL;

  /* No new slots since the last update */
  if( FD_UNLIKELY( gui->epoch.epochs[ epoch_idx ].rankings_slot>gui->summary.slot_rooted ) ) return;

  /* Slots before first_replay_slot are unavailable. */
  gui->epoch.epochs[ epoch_idx ].rankings_slot = fd_ulong_max( gui->epoch.epochs[ epoch_idx ].rankings_slot, first_replay_slot );

  /* Update the rankings. Only look through slots we haven't already. */
  for( ulong s = gui->summary.slot_rooted; s>=gui->epoch.epochs[ epoch_idx ].rankings_slot; s--) {
    fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, s );
    if( FD_UNLIKELY( !slot ) ) break;

    fd_gui_try_insert_ranking( gui, gui->epoch.epochs[ epoch_idx ].rankings, slot );
    if( FD_UNLIKELY( slot->mine ) ) fd_gui_try_insert_ranking( gui, gui->epoch.epochs[ epoch_idx ].my_rankings, slot );
  }

  gui->epoch.epochs[ epoch_idx ].rankings_slot = gui->summary.slot_rooted + 1UL;
}

int
fd_gui_request_slot_rankings( fd_gui_t *    gui,
                              ulong         ws_conn_id,
                              ulong         request_id,
                              cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "mine" );
  if( FD_UNLIKELY( !cJSON_IsBool( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  int mine = !!(slot_param->type & cJSON_True);
  fd_gui_update_slot_rankings( gui );
  fd_gui_printf_slot_rankings_request( gui, request_id, mine );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_request_slot_shreds( fd_gui_t *    gui,
                            ulong         ws_conn_id,
                            ulong         request_id,
                            cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;

  fd_gui_slot_t const * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot || gui->shreds.history_tail > slot->shreds.end_offset + FD_GUI_SHREDS_HISTORY_SZ ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query_shreds", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_shred_updates( gui, _slot, request_id );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len ) {
  /* TODO: cJSON allocates, might fail SIGSYS due to brk(2)...
     switch off this (or use wksp allocator) */
  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)data, data_len, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) {
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "id" );
  if( FD_UNLIKELY( !cJSON_IsNumber( node ) ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }
  ulong id = node->valueulong;

  const cJSON * topic = cJSON_GetObjectItemCaseSensitive( json, "topic" );
  if( FD_UNLIKELY( !cJSON_IsString( topic ) || topic->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * key = cJSON_GetObjectItemCaseSensitive( json, "key" );
  if( FD_UNLIKELY( !cJSON_IsString( key ) || key->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query_detailed" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot_detailed( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query_transactions" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot_transactions( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query_rankings" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot_rankings( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query_shreds" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot_shreds( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "summary" ) && !strcmp( key->valuestring, "ping" ) ) ) {
    fd_gui_printf_summary_ping( gui, id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );

    cJSON_Delete( json );
    return 0;
  }

  cJSON_Delete( json );
  return FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD;
}

static fd_gui_slot_t *
fd_gui_clear_slot( fd_gui_t *      gui,
                   ulong           _slot,
                   ulong           _parent_slot ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  int mine = 0;
  ulong epoch_idx = 0UL;
  for( ulong i=0UL; i<2UL; i++) {
    if( FD_UNLIKELY( !gui->epoch.has_epoch[ i ] ) ) continue;
    if( FD_LIKELY( _slot>=gui->epoch.epochs[ i ].start_slot && _slot<=gui->epoch.epochs[ i ].end_slot ) ) {
      fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( gui->epoch.epochs[ i ].lsched, _slot );
      mine = !memcmp( slot_leader->uc, gui->summary.identity_key->uc, 32UL );
      epoch_idx = i;
      break;
    }
  }

  slot->slot                   = _slot;
  slot->parent_slot            = _parent_slot;
  slot->vote_slot              = ULONG_MAX;
  slot->reset_slot             = ULONG_MAX;
  slot->max_compute_units      = UINT_MAX;
  slot->completed_time         = LONG_MAX;
  slot->mine                   = mine;
  slot->skipped                = 0;
  slot->must_republish         = 1;
  slot->level                  = FD_GUI_SLOT_LEVEL_INCOMPLETE;
  slot->total_txn_cnt          = UINT_MAX;
  slot->vote_txn_cnt           = UINT_MAX;
  slot->failed_txn_cnt         = UINT_MAX;
  slot->nonvote_failed_txn_cnt = UINT_MAX;
  slot->compute_units          = UINT_MAX;
  slot->transaction_fee        = ULONG_MAX;
  slot->priority_fee           = ULONG_MAX;
  slot->tips                   = ULONG_MAX;
  slot->shred_cnt              = UINT_MAX;
  slot->shreds.start_offset    = ULONG_MAX;
  slot->shreds.end_offset      = ULONG_MAX;

  if( FD_LIKELY( slot->mine ) ) {
    /* All slots start off not skipped, until we see it get off the reset
       chain. */
    gui->epoch.epochs[ epoch_idx ].my_total_slots++;

    slot->leader_history_idx = gui->leader_slots_cnt++;
    fd_gui_leader_slot_t * lslot = gui->leader_slots[ slot->leader_history_idx % FD_GUI_LEADER_CNT ];

    lslot->slot                        = _slot;
    memset( lslot->block_hash.uc, 0, sizeof(fd_hash_t) );
    lslot->leader_start_time           = LONG_MAX;
    lslot->leader_end_time             = LONG_MAX;
    lslot->tile_timers_sample_cnt      = 0UL;
    lslot->scheduler_counts_sample_cnt = 0UL;
    lslot->txs.microblocks_upper_bound = USHORT_MAX;
    lslot->txs.begin_microblocks       = 0U;
    lslot->txs.end_microblocks         = 0U;
    lslot->txs.start_offset            = ULONG_MAX;
    lslot->txs.end_offset              = ULONG_MAX;
    lslot->unbecame_leader             = 0;
  }

  if( FD_UNLIKELY( !_slot ) ) {
    /* Slot 0 is always rooted */
    slot->level   = FD_GUI_SLOT_LEVEL_ROOTED;
  }

  return slot;
}

void
fd_gui_handle_leader_schedule( fd_gui_t *                    gui,
                               fd_stake_weight_msg_t const * leader_schedule,
                               long                          now ) {
  FD_TEST( leader_schedule->staked_cnt<=MAX_STAKED_LEADERS );
  FD_TEST( leader_schedule->slot_cnt<=MAX_SLOTS_PER_EPOCH );

  ulong idx = leader_schedule->epoch % 2UL;
  gui->epoch.has_epoch[ idx ] = 1;

  gui->epoch.epochs[ idx ].epoch            = leader_schedule->epoch;
  gui->epoch.epochs[ idx ].start_slot       = leader_schedule->start_slot;
  gui->epoch.epochs[ idx ].end_slot         = leader_schedule->start_slot + leader_schedule->slot_cnt - 1; // end_slot is inclusive.
  gui->epoch.epochs[ idx ].excluded_stake   = leader_schedule->excluded_stake;
  gui->epoch.epochs[ idx ].my_total_slots   = 0UL;
  gui->epoch.epochs[ idx ].my_skipped_slots = 0UL;

  memset( gui->epoch.epochs[ idx ].rankings,    (int)(UINT_MAX), sizeof(gui->epoch.epochs[ idx ].rankings)    );
  memset( gui->epoch.epochs[ idx ].my_rankings, (int)(UINT_MAX), sizeof(gui->epoch.epochs[ idx ].my_rankings) );

  gui->epoch.epochs[ idx ].rankings_slot = leader_schedule->start_slot;

  fd_vote_stake_weight_t const * stake_weights = leader_schedule->weights;
  fd_memcpy( gui->epoch.epochs[ idx ].stakes, stake_weights, leader_schedule->staked_cnt*sizeof(fd_vote_stake_weight_t) );

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( gui->epoch.epochs[ idx ].lsched ) );
  gui->epoch.epochs[idx].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[ idx ]._lsched,
                                                                               leader_schedule->epoch,
                                                                               gui->epoch.epochs[ idx ].start_slot,
                                                                               leader_schedule->slot_cnt,
                                                                               leader_schedule->staked_cnt,
                                                                               gui->epoch.epochs[ idx ].stakes,
                                                                               leader_schedule->excluded_stake,
                                                                               leader_schedule->vote_keyed_lsched ) );

  if( FD_UNLIKELY( leader_schedule->start_slot==0UL ) ) {
    gui->epoch.epochs[ 0 ].start_time = now;
  } else {
    gui->epoch.epochs[ idx ].start_time = LONG_MAX;

    for( ulong i=0UL; i<fd_ulong_min( leader_schedule->start_slot-1UL, FD_GUI_SLOTS_CNT ); i++ ) {
      fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, leader_schedule->start_slot-i );
      if( FD_UNLIKELY( !slot ) ) break;
      else if( FD_UNLIKELY( slot->skipped ) ) continue;

      gui->epoch.epochs[ idx ].start_time = slot->completed_time;
      break;
    }
  }

  fd_gui_printf_epoch( gui, idx );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_slot_start( fd_gui_t * gui,
                          ulong      _slot,
                          ulong      parent_slot,
                          long       now ) {
  FD_TEST( gui->leader_slot==ULONG_MAX );
  gui->leader_slot = _slot;

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, _slot, parent_slot );

  fd_gui_tile_timers_snap( gui );
  gui->summary.tile_timers_snap_idx_slot_start = (gui->summary.tile_timers_snap_idx+(FD_GUI_TILE_TIMER_SNAP_CNT-1UL))%FD_GUI_TILE_TIMER_SNAP_CNT;

  fd_gui_scheduler_counts_snap( gui, now );
  gui->summary.scheduler_counts_snap_idx_slot_start = (gui->summary.scheduler_counts_snap_idx+(FD_GUI_SCHEDULER_COUNT_SNAP_CNT-1UL))%FD_GUI_SCHEDULER_COUNT_SNAP_CNT;

  fd_gui_txn_waterfall_t waterfall[ 1 ];
  fd_gui_txn_waterfall_snap( gui, waterfall );
  fd_gui_tile_stats_snap( gui, waterfall, slot->tile_stats_begin, now );
}

static void
fd_gui_handle_slot_end( fd_gui_t * gui,
                        ulong      _slot,
                        ulong      _cus_used,
                        long       now ) {
  if( FD_UNLIKELY( !gui->summary.is_full_client && gui->leader_slot!=_slot ) ) {
    FD_LOG_ERR(( "gui->leader_slot %lu _slot %lu", gui->leader_slot, _slot ));
  }
  gui->leader_slot = ULONG_MAX;

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) return;

  if( FD_UNLIKELY( !gui->summary.is_full_client ) ) slot->compute_units = (uint)_cus_used;

  fd_gui_tile_timers_snap( gui );

  fd_gui_scheduler_counts_snap( gui, now );

  fd_gui_leader_slot_t * lslot = fd_gui_get_leader_slot( gui, _slot );
  if( FD_LIKELY( lslot ) ) {
    fd_rng_t rng[ 1 ];
    fd_rng_new( rng, 0UL, 0UL);

#define DOWNSAMPLE( a, a_start, a_end, a_capacity, b, b_sz ) (__extension__({  \
  ulong __cnt = 0UL; \
  ulong __a_sz = (fd_ulong_if( a_end<a_start, a_end+a_capacity, a_end )-a_start); \
  if( FD_UNLIKELY( __a_sz && b_sz ) ) { \
    for( ulong a_idx=0UL; a_idx<__a_sz && __cnt<b_sz; a_idx++ ) { \
      if( FD_UNLIKELY( fd_rng_float_robust( rng ) > (float)(b_sz-__cnt) / (float)(__a_sz-__cnt) ) ) continue; \
      fd_memcpy( b[ __cnt ], a[ ((a_start+a_idx)%a_capacity) ], sizeof(b[ __cnt ]) ); \
      __cnt++; \
    } \
  } \
  __cnt; }))

    lslot->tile_timers_sample_cnt = DOWNSAMPLE(
      gui->summary.tile_timers_snap,
      gui->summary.tile_timers_snap_idx_slot_start,
      gui->summary.tile_timers_snap_idx,
      FD_GUI_TILE_TIMER_SNAP_CNT,
      lslot->tile_timers,
      FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT );

    lslot->scheduler_counts_sample_cnt = DOWNSAMPLE(
      gui->summary.scheduler_counts_snap,
      gui->summary.scheduler_counts_snap_idx_slot_start,
      gui->summary.scheduler_counts_snap_idx,
      FD_GUI_SCHEDULER_COUNT_SNAP_CNT,
      lslot->scheduler_counts,
      FD_GUI_SCHEDULER_COUNT_LEADER_DOWNSAMPLE_CNT );
#undef DOWNSAMPLE
  }

  /* When a slot ends, snap the state of the waterfall and save it into
     that slot, and also reset the reference counters to the end of the
     slot. */

  fd_gui_txn_waterfall_snap( gui, slot->waterfall_end );
  memcpy( slot->waterfall_begin, gui->summary.txn_waterfall_reference, sizeof(slot->waterfall_begin) );
  memcpy( gui->summary.txn_waterfall_reference, slot->waterfall_end, sizeof(gui->summary.txn_waterfall_reference) );

  fd_gui_tile_stats_snap( gui, slot->waterfall_end, slot->tile_stats_end, now );
}

void
fd_gui_handle_shred( fd_gui_t * gui,
                     ulong      slot,
                     ulong      shred_idx,
                     int        is_turbine,
                     long       tsorig ) {
  int was_sent = fd_gui_ephemeral_slots_contains( gui->summary.slots_max_turbine, FD_GUI_TURBINE_SLOT_HISTORY_SZ, slot );
  if( FD_LIKELY( is_turbine ) ) fd_gui_try_insert_ephemeral_slot( gui->summary.slots_max_turbine, FD_GUI_TURBINE_SLOT_HISTORY_SZ, slot, tsorig );

  /* If we haven't caught up yet, update repair slot using received
     shreds. This is not technically correct, but close enough and will
     make the progress bar look correct. */
  if( FD_UNLIKELY( !is_turbine && gui->summary.slot_caught_up==ULONG_MAX ) ) fd_gui_handle_repair_slot( gui, slot, tsorig );

  if( FD_UNLIKELY( !was_sent && is_turbine && slot!=gui->summary.slot_turbine ) ) {
    gui->summary.slot_turbine = slot;

    fd_gui_printf_turbine_slot( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->turbine_slots[ slot % FD_GUI_TURBINE_RECV_TIMESTAMPS ].slot = slot;
    gui->turbine_slots[ slot % FD_GUI_TURBINE_RECV_TIMESTAMPS ].timestamp = tsorig;

    ulong duration_sum = 0UL;
    ulong slot_cnt = 0UL;

    for( ulong i=0UL; i<FD_GUI_TURBINE_RECV_TIMESTAMPS; i++ ) {
      fd_gui_turbine_slot_t * cur = &gui->turbine_slots[ i ];
      fd_gui_turbine_slot_t * prev = &gui->turbine_slots[ (i+FD_GUI_TURBINE_RECV_TIMESTAMPS-1UL) % FD_GUI_TURBINE_RECV_TIMESTAMPS ];
      if( FD_UNLIKELY( cur->slot==ULONG_MAX || prev->slot==ULONG_MAX || cur->slot!=prev->slot+1UL ) ) continue;

      long slot_duration = cur->timestamp - prev->timestamp;
      duration_sum += (ulong)fd_long_max( slot_duration, 0UL );
      slot_cnt++;
    }

    if( FD_LIKELY( slot_cnt>0 ) ) {
      gui->summary.estimated_slot_duration_nanos = (ulong)(duration_sum / slot_cnt);
      fd_gui_printf_estimated_slot_duration_nanos( gui );
      fd_http_server_ws_broadcast( gui->http );
    }

    if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX ) ) fd_gui_try_insert_catch_up_slot( gui->summary.catch_up_turbine, FD_GUI_TURBINE_CATCH_UP_HISTORY_SZ, &gui->summary.catch_up_turbine_sz, slot );
  }

  fd_gui_slot_staged_shred_event_t * recv_event = &gui->shreds.staged[ gui->shreds.staged_tail % FD_GUI_SHREDS_STAGING_SZ ];
  gui->shreds.staged_tail++;
  recv_event->timestamp = tsorig;
  recv_event->shred_idx = (ushort)shred_idx;
  recv_event->slot      = slot;
  recv_event->event     = fd_uchar_if( is_turbine, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR );
}

void
fd_gui_handle_leader_fec( fd_gui_t * gui,
                          ulong      slot,
                          ulong      fec_shred_cnt,
                          int        is_end_of_slot,
                          long       tsorig ) {
  for( ulong i=gui->shreds.leader_shred_cnt; i<gui->shreds.leader_shred_cnt+fec_shred_cnt; i++ ) {
    fd_gui_slot_staged_shred_event_t * exec_end_event = &gui->shreds.staged[ gui->shreds.staged_tail % FD_GUI_SHREDS_STAGING_SZ ];
    gui->shreds.staged_tail++;
    exec_end_event->timestamp = tsorig;
    exec_end_event->shred_idx = (ushort)i;
    exec_end_event->slot      = slot;
    exec_end_event->event     = FD_GUI_SLOT_SHRED_SHRED_PUBLISHED;
  }
  gui->shreds.leader_shred_cnt += fec_shred_cnt;
  if( FD_UNLIKELY( is_end_of_slot ) ) gui->shreds.leader_shred_cnt = 0UL;
}

void
fd_gui_handle_exec_txn_done( fd_gui_t * gui,
                             ulong      slot,
                             ulong      start_shred_idx,
                             ulong      end_shred_idx,
                             long       tsorig_ns FD_PARAM_UNUSED,
                             long       tspub_ns ) {
  for( ulong i = start_shred_idx; i<end_shred_idx; i++ ) {
    /*
      We're leaving this state transition out due to its proximity to
      FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, but if we ever wanted
      to send this data to the frontend we could.

      fd_gui_slot_staged_shred_event_t * exec_start_event = &gui->shreds.staged[ gui->shreds.staged_tail % FD_GUI_SHREDS_STAGING_SZ ];
      gui->shreds.staged_tail++;
      exec_start_event->timestamp = tsorig_ns;
      exec_start_event->shred_idx = (ushort)i;
      exec_start_event->slot      = slot;
      exec_start_event->event     = FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_START;
    */

    fd_gui_slot_staged_shred_event_t * exec_end_event = &gui->shreds.staged[ gui->shreds.staged_tail % FD_GUI_SHREDS_STAGING_SZ ];
    gui->shreds.staged_tail++;
    exec_end_event->timestamp = tspub_ns;
    exec_end_event->shred_idx = (ushort)i;
    exec_end_event->slot      = slot;
    exec_end_event->event     = FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE;
  }
}

static void
fd_gui_handle_reset_slot_legacy( fd_gui_t * gui,
                                 ulong *    msg,
                                 long       now ) {
  ulong last_landed_vote = msg[ 0 ];

  ulong parent_cnt = msg[ 1 ];
  FD_TEST( parent_cnt<4096UL );

  ulong _slot = msg[ 2 ];

  for( ulong i=0UL; i<parent_cnt; i++ ) {
    ulong parent_slot = msg[2UL+i];
    fd_gui_slot_t * slot = fd_gui_get_slot( gui, parent_slot );
    if( FD_UNLIKELY( !slot ) ) {
      ulong parent_parent_slot = ULONG_MAX;
      if( FD_UNLIKELY( i!=parent_cnt-1UL) ) parent_parent_slot = msg[ 3UL+i ];
      fd_gui_clear_slot( gui, parent_slot, parent_parent_slot );
    }
  }

  if( FD_UNLIKELY( gui->summary.vote_distance!=_slot-last_landed_vote ) ) {
    gui->summary.vote_distance = _slot-last_landed_vote;
    fd_gui_printf_vote_distance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_LIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_NON_VOTING ) ) {
    if( FD_UNLIKELY( last_landed_vote==ULONG_MAX || (last_landed_vote+150UL)<_slot ) ) {
      if( FD_UNLIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_DELINQUENT ) ) {
        gui->summary.vote_state = FD_GUI_VOTE_STATE_DELINQUENT;
        fd_gui_printf_vote_state( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    } else {
      if( FD_UNLIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_VOTING ) ) {
        gui->summary.vote_state = FD_GUI_VOTE_STATE_VOTING;
        fd_gui_printf_vote_state( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    }
  }

  ulong parent_slot_idx = 0UL;

  int republish_skip_rate[ 2 ] = {0};

  for( ulong i=0UL; i<fd_ulong_min( _slot+1, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;

    fd_gui_slot_t * slot = fd_gui_get_slot( gui, parent_slot );
    if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, parent_slot, ULONG_MAX );

    /* The chain of parents may stretch into already rooted slots if
       they haven't been squashed yet, if we reach one of them we can
       just exit, all the information prior to the root is already
       correct. */

    if( FD_LIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    int should_republish = slot->must_republish;
    slot->must_republish = 0;

    if( FD_UNLIKELY( parent_slot!=msg[2UL+parent_slot_idx] ) ) {
      /* We are between two parents in the rooted chain, which means
         we were skipped. */
      if( FD_UNLIKELY( !slot->skipped ) ) {
        slot->skipped = 1;
        should_republish = 1;
        if( FD_LIKELY( slot->mine ) ) {
          for( ulong i=0UL; i<2UL; i++ ) {
            if( FD_LIKELY( parent_slot>=gui->epoch.epochs[ i ].start_slot && parent_slot<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots++;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }
    } else {
      /* Reached the next parent... */
      if( FD_UNLIKELY( slot->skipped ) ) {
        slot->skipped = 0;
        should_republish = 1;
        if( FD_LIKELY( slot->mine ) ) {
          for( ulong i=0UL; i<2UL; i++ ) {
            if( FD_LIKELY( parent_slot>=gui->epoch.epochs[ i ].start_slot && parent_slot<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots--;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }
      parent_slot_idx++;
    }

    if( FD_LIKELY( should_republish ) ) {
      fd_gui_printf_slot( gui, parent_slot );
      fd_http_server_ws_broadcast( gui->http );
    }

    /* We reached the last parent in the chain, everything above this
       must have already been rooted, so we can exit. */

    if( FD_UNLIKELY( parent_slot_idx>=parent_cnt ) ) break;
  }

  ulong duration_sum = 0UL;
  ulong slot_cnt = 0UL;

  /* If we've just caught up we should truncate our slot history to avoid including catch-up slots */
  int just_caught_up = gui->summary.slot_caught_up!=ULONG_MAX && _slot>gui->summary.slot_caught_up && _slot<gui->summary.slot_caught_up+750UL;
  ulong slot_duration_history_sz = fd_ulong_if( just_caught_up, _slot-gui->summary.slot_caught_up, 750UL );
  for( ulong i=0UL; i<fd_ulong_min( _slot+1, slot_duration_history_sz ); i++ ) {
    ulong parent_slot = _slot - i;

    fd_gui_slot_t const * slot = fd_gui_get_slot_const( gui, parent_slot );
    if( FD_UNLIKELY( !slot) ) break;
    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect _slot-i %lu got slot->slot %lu", _slot, i, _slot-i, slot->slot ));
    }

    ulong slot_duration = fd_gui_slot_duration( gui, slot );
    if( FD_LIKELY( slot_duration!=ULONG_MAX ) ) {
      duration_sum += slot_duration;
      slot_cnt++;
    }
  }

  if( FD_LIKELY( slot_cnt>0 ) ) {
    gui->summary.estimated_slot_duration_nanos = (ulong)(duration_sum / slot_cnt);
    fd_gui_printf_estimated_slot_duration_nanos( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_LIKELY( gui->summary.slot_completed==ULONG_MAX || _slot!=gui->summary.slot_completed ) ) {
    gui->summary.slot_completed = _slot;
    fd_gui_printf_completed_slot( gui );
    fd_http_server_ws_broadcast( gui->http );

    /* Also update slot_turbine which could be larger than the max
       turbine slot if we are leader */
    if( FD_UNLIKELY( gui->summary.slots_max_turbine[ 0 ].slot!=ULONG_MAX && gui->summary.slot_completed!=ULONG_MAX && gui->summary.slot_completed>gui->summary.slots_max_turbine[ 0 ].slot ) ) {
      fd_gui_try_insert_ephemeral_slot( gui->summary.slots_max_turbine, FD_GUI_TURBINE_SLOT_HISTORY_SZ, gui->summary.slot_completed, now );
    }

    int slot_turbine_hist_full = gui->summary.slots_max_turbine[ FD_GUI_TURBINE_SLOT_HISTORY_SZ-1UL ].slot!=ULONG_MAX;
    if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX && slot_turbine_hist_full && gui->summary.slots_max_turbine[ 0 ].slot < (gui->summary.slot_completed + 3UL) ) ) {
      gui->summary.slot_caught_up = gui->summary.slot_completed + 4UL;

      fd_gui_printf_slot_caught_up( gui );
      fd_http_server_ws_broadcast( gui->http );
    }
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( republish_skip_rate[ i ] ) ) {
      fd_gui_printf_skip_rate( gui, i );
      fd_http_server_ws_broadcast( gui->http );
    }
  }
}

static void
fd_gui_handle_completed_slot( fd_gui_t * gui,
                              ulong *    msg,
                              long       now ) {

  /* This is the slot used by frontend clients as the "startup slot". In
     certain boot conditions, we don't recieve this slot from Agave, so
     we include a bit of a hacky assignment here to make sure it is
     always present. */
  if( FD_UNLIKELY( gui->summary.startup_progress.startup_ledger_max_slot==ULONG_MAX ) ) {
    gui->summary.startup_progress.startup_ledger_max_slot = msg[ 0 ];
  }

  ulong _slot                    = msg[ 0 ];
  uint  total_txn_count          = (uint)msg[ 1 ];
  uint  nonvote_txn_count        = (uint)msg[ 2 ];
  uint  failed_txn_count         = (uint)msg[ 3 ];
  uint  nonvote_failed_txn_count = (uint)msg[ 4 ];
  uint  compute_units            = (uint)msg[ 5 ];
  ulong transaction_fee          = msg[ 6 ];
  ulong priority_fee             = msg[ 7 ];
  ulong tips                     = msg[ 8 ];
  ulong _parent_slot             = msg[ 9 ];
  ulong max_compute_units        = msg[ 10 ];

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, _slot, _parent_slot );

  slot->completed_time = now;
  slot->parent_slot = _parent_slot;
  slot->max_compute_units = (uint)max_compute_units;
  if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_COMPLETED ) ) {
    /* Typically a slot goes from INCOMPLETE to COMPLETED but it can
       happen that it starts higher.  One such case is when we
       optimistically confirm a higher slot that skips this one, but
       then later we replay this one anyway to track the bank fork. */

    if( FD_LIKELY( gui->summary.slot_optimistically_confirmed!=ULONG_MAX && _slot<gui->summary.slot_optimistically_confirmed ) ) {
      /* Cluster might have already optimistically confirmed by the time
         we finish replaying it. */
      slot->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
    } else {
      slot->level = FD_GUI_SLOT_LEVEL_COMPLETED;
    }
  }
  slot->total_txn_cnt          = total_txn_count;
  slot->vote_txn_cnt           = total_txn_count - nonvote_txn_count;
  slot->failed_txn_cnt         = failed_txn_count;
  slot->nonvote_failed_txn_cnt = nonvote_failed_txn_count;
  slot->transaction_fee        = transaction_fee;
  slot->priority_fee           = priority_fee;
  slot->tips                   = tips;

  /* In Frankendancer, CUs come from our own leader pipeline (the field
     sent from the Agave codepath is zero'd out) */
  slot->compute_units          = fd_uint_if( !gui->summary.is_full_client && slot->mine, slot->compute_units, compute_units );

  if( FD_UNLIKELY( gui->epoch.has_epoch[ 0 ] && _slot==gui->epoch.epochs[ 0 ].end_slot ) ) {
    gui->epoch.epochs[ 0 ].end_time = slot->completed_time;
  } else if( FD_UNLIKELY( gui->epoch.has_epoch[ 1 ] && _slot==gui->epoch.epochs[ 1 ].end_slot ) ) {
    gui->epoch.epochs[ 1 ].end_time = slot->completed_time;
  }

  /* Broadcast new skip rate if one of our slots got completed. */
  if( FD_LIKELY( slot->mine ) ) {
    for( ulong i=0UL; i<2UL; i++ ) {
      if( FD_LIKELY( _slot>=gui->epoch.epochs[ i ].start_slot && _slot<=gui->epoch.epochs[ i ].end_slot ) ) {
        fd_gui_printf_skip_rate( gui, i );
        fd_http_server_ws_broadcast( gui->http );
        break;
      }
    }
  }
}

static void
fd_gui_handle_rooted_slot_legacy( fd_gui_t * gui,
                                  ulong *    msg ) {
  ulong _slot = msg[ 0 ];

  // FD_LOG_WARNING(( "Got rooted slot %lu", _slot ));

  /* Slot 0 is always rooted.  No need to iterate all the way back to
     i==_slot */
  for( ulong i=0UL; i<fd_ulong_min( _slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;

    fd_gui_slot_t * slot = fd_gui_get_slot( gui, parent_slot );
    if( FD_UNLIKELY( !slot ) ) break;

    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect parent_slot %lu got slot->slot %lu", _slot, i, parent_slot, slot->slot ));
    }
    if( FD_UNLIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    slot->level = FD_GUI_SLOT_LEVEL_ROOTED;
    fd_gui_printf_slot( gui, parent_slot );
    fd_http_server_ws_broadcast( gui->http );
  }

  gui->summary.slot_rooted = _slot;
  fd_gui_printf_root_slot( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_optimistically_confirmed_slot( fd_gui_t * gui,
                                             ulong      _slot ) {
  /* Slot 0 is always rooted.  No need to iterate all the way back to
     i==_slot */
  for( ulong i=0UL; i<fd_ulong_min( _slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;

    fd_gui_slot_t * slot = fd_gui_get_slot( gui, parent_slot );
    if( FD_UNLIKELY( !slot) ) break;

    if( FD_UNLIKELY( slot->slot>parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect parent_slot %lu got slot->slot %lu", _slot, i, parent_slot, slot->slot ));
    } else if( FD_UNLIKELY( slot->slot<parent_slot ) ) {
      /* Slot not even replayed yet ... will come out as optimistically confirmed */
      continue;
    }
    if( FD_UNLIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED ) ) {
      slot->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
      fd_gui_printf_slot( gui, parent_slot );
      fd_http_server_ws_broadcast( gui->http );
    }
  }

  if( FD_UNLIKELY( gui->summary.slot_optimistically_confirmed!=ULONG_MAX && _slot<gui->summary.slot_optimistically_confirmed ) ) {
    /* Optimistically confirmed slot went backwards ... mark some slots as no
       longer optimistically confirmed. */
    for( ulong i=gui->summary.slot_optimistically_confirmed; i>=_slot; i-- ) {
      fd_gui_slot_t * slot = fd_gui_get_slot( gui, i );
      if( FD_UNLIKELY( !slot ) ) break;
      if( FD_LIKELY( slot->slot==i ) ) {
        /* It's possible for the optimistically confirmed slot to skip
           backwards between two slots that we haven't yet replayed.  In
           that case we don't need to change anything, since they will
           get marked properly when they get completed. */
        slot->level = FD_GUI_SLOT_LEVEL_COMPLETED;
        fd_gui_printf_slot( gui, i );
        fd_http_server_ws_broadcast( gui->http );
      }
    }
  }

  gui->summary.slot_optimistically_confirmed = _slot;
  fd_gui_printf_optimistically_confirmed_slot( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_balance_update( fd_gui_t *    gui,
                              ulong const * msg ) {
  switch( msg[ 0 ] ) {
    case 0UL:
      gui->summary.identity_account_balance = msg[ 1 ];
      fd_gui_printf_identity_balance( gui );
      fd_http_server_ws_broadcast( gui->http );
      break;
    case 1UL:
      gui->summary.vote_account_balance = msg[ 1 ];
      fd_gui_printf_vote_balance( gui );
      fd_http_server_ws_broadcast( gui->http );
      break;
    default:
      FD_LOG_ERR(( "balance: unknown account type: %lu", msg[ 0 ] ));
  }
}

static void
fd_gui_handle_start_progress( fd_gui_t *    gui,
                              uchar const * msg ) {
  uchar type = msg[ 0 ];

  switch (type) {
    case 0:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_INITIALIZING;
      FD_LOG_INFO(( "progress: initializing" ));
      break;
    case 1: {
      char const * snapshot_type;
      if( FD_UNLIKELY( gui->summary.startup_progress.startup_got_full_snapshot ) ) {
        gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_INCREMENTAL_SNAPSHOT;
        snapshot_type = "incremental";
      } else {
        gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_FULL_SNAPSHOT;
        snapshot_type = "full";
      }
      FD_LOG_INFO(( "progress: searching for %s snapshot", snapshot_type ));
      break;
    }
    case 2: {
      uchar is_full_snapshot = msg[ 1 ];
      if( FD_LIKELY( is_full_snapshot ) ) {
          gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_FULL_SNAPSHOT;
          gui->summary.startup_progress.startup_full_snapshot_slot = *((ulong *)(msg + 2));
          gui->summary.startup_progress.startup_full_snapshot_peer_ip_addr = *((uint *)(msg + 10));
          gui->summary.startup_progress.startup_full_snapshot_peer_port = *((ushort *)(msg + 14));
          gui->summary.startup_progress.startup_full_snapshot_total_bytes = *((ulong *)(msg + 16));
          gui->summary.startup_progress.startup_full_snapshot_current_bytes = *((ulong *)(msg + 24));
          gui->summary.startup_progress.startup_full_snapshot_elapsed_secs = *((double *)(msg + 32));
          gui->summary.startup_progress.startup_full_snapshot_remaining_secs = *((double *)(msg + 40));
          gui->summary.startup_progress.startup_full_snapshot_throughput = *((double *)(msg + 48));
          FD_LOG_INFO(( "progress: downloading full snapshot: slot=%lu", gui->summary.startup_progress.startup_full_snapshot_slot ));
      } else {
          gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_INCREMENTAL_SNAPSHOT;
          gui->summary.startup_progress.startup_incremental_snapshot_slot = *((ulong *)(msg + 2));
          gui->summary.startup_progress.startup_incremental_snapshot_peer_ip_addr = *((uint *)(msg + 10));
          gui->summary.startup_progress.startup_incremental_snapshot_peer_port = *((ushort *)(msg + 14));
          gui->summary.startup_progress.startup_incremental_snapshot_total_bytes = *((ulong *)(msg + 16));
          gui->summary.startup_progress.startup_incremental_snapshot_current_bytes = *((ulong *)(msg + 24));
          gui->summary.startup_progress.startup_incremental_snapshot_elapsed_secs = *((double *)(msg + 32));
          gui->summary.startup_progress.startup_incremental_snapshot_remaining_secs = *((double *)(msg + 40));
          gui->summary.startup_progress.startup_incremental_snapshot_throughput = *((double *)(msg + 48));
          FD_LOG_INFO(( "progress: downloading incremental snapshot: slot=%lu", gui->summary.startup_progress.startup_incremental_snapshot_slot ));
      }
      break;
    }
    case 3: {
      gui->summary.startup_progress.startup_got_full_snapshot = 1;
      break;
    }
    case 4:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_CLEANING_BLOCK_STORE;
      FD_LOG_INFO(( "progress: cleaning block store" ));
      break;
    case 5:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_CLEANING_ACCOUNTS;
      FD_LOG_INFO(( "progress: cleaning accounts" ));
      break;
    case 6:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_LOADING_LEDGER;
      FD_LOG_INFO(( "progress: loading ledger" ));
      break;
    case 7: {
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_PROCESSING_LEDGER;
      gui->summary.startup_progress.startup_ledger_slot = fd_ulong_load_8( msg + 1 );
      gui->summary.startup_progress.startup_ledger_max_slot = fd_ulong_load_8( msg + 9 );
      FD_LOG_INFO(( "progress: processing ledger: slot=%lu, max_slot=%lu", gui->summary.startup_progress.startup_ledger_slot, gui->summary.startup_progress.startup_ledger_max_slot ));
      break;
    }
    case 8:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_STARTING_SERVICES;
      FD_LOG_INFO(( "progress: starting services" ));
      break;
    case 9:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_HALTED;
      FD_LOG_INFO(( "progress: halted" ));
      break;
    case 10: {
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY;
      gui->summary.startup_progress.startup_waiting_for_supermajority_slot = fd_ulong_load_8( msg + 1 );
      gui->summary.startup_progress.startup_waiting_for_supermajority_stake_pct = fd_ulong_load_8( msg + 9 );
      FD_LOG_INFO(( "progress: waiting for supermajority: slot=%lu, gossip_stake_percent=%lu", gui->summary.startup_progress.startup_waiting_for_supermajority_slot, gui->summary.startup_progress.startup_waiting_for_supermajority_stake_pct ));
      break;
    }
    case 11:
      gui->summary.startup_progress.phase = FD_GUI_START_PROGRESS_TYPE_RUNNING;
      FD_LOG_INFO(( "progress: running" ));
      break;
    default:
      FD_LOG_ERR(( "progress: unknown type: %u", type ));
  }

  fd_gui_printf_startup_progress( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_handle_genesis_hash( fd_gui_t *    gui,
                            uchar const * msg ) {
  FD_BASE58_ENCODE_32_BYTES(msg, hash_cstr);
  ulong cluster = fd_genesis_cluster_identify(hash_cstr);
  char const * cluster_name = fd_genesis_cluster_name(cluster);

  if( FD_LIKELY( strcmp( gui->summary.cluster, cluster_name ) ) ) {
    gui->summary.cluster = fd_genesis_cluster_name(cluster);
    fd_gui_printf_cluster( gui );
    fd_http_server_ws_broadcast( gui->http );
  }
}

static void
fd_gui_handle_block_engine_update( fd_gui_t *    gui,
                                   uchar const * msg ) {
  fd_plugin_msg_block_engine_update_t const * update = (fd_plugin_msg_block_engine_update_t const *)msg;

  gui->block_engine.has_block_engine = 1;

  /* copy strings and ensure null termination within bounds */
  FD_TEST( fd_cstr_nlen( update->name,    sizeof(gui->block_engine.name   ) ) < sizeof(gui->block_engine.name   ) );
  FD_TEST( fd_cstr_nlen( update->url,     sizeof(gui->block_engine.url    ) ) < sizeof(gui->block_engine.url    ) );
  FD_TEST( fd_cstr_nlen( update->ip_cstr, sizeof(gui->block_engine.ip_cstr) ) < sizeof(gui->block_engine.ip_cstr) );
  ulong name_len    = fd_cstr_nlen( update->name,    sizeof(gui->block_engine.name   ) );
  ulong url_len     = fd_cstr_nlen( update->url,     sizeof(gui->block_engine.url    ) );
  ulong ip_cstr_len = fd_cstr_nlen( update->ip_cstr, sizeof(gui->block_engine.ip_cstr) );
  fd_memcpy( gui->block_engine.name,    update->name,    name_len+1UL );
  fd_memcpy( gui->block_engine.url,     update->url,     url_len+1UL );
  fd_memcpy( gui->block_engine.ip_cstr, update->ip_cstr, ip_cstr_len+1UL );

  gui->block_engine.status = update->status;

  fd_gui_printf_block_engine( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_handle_snapshot_update( fd_gui_t *                 gui,
                               fd_snapct_update_t const * msg ) {
  FD_TEST( msg && fd_cstr_nlen( msg->read_path, 1 ) );

  ulong snapshot_idx = fd_ulong_if( msg->type==FD_SNAPCT_SNAPSHOT_TYPE_FULL, FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX );

  char const * filename = strrchr(msg->read_path, '/');

  /* Skip the '/'  */
  if( FD_UNLIKELY( filename ) ) filename++;

  if (msg->type == FD_SNAPCT_SNAPSHOT_TYPE_INCREMENTAL) {
      ulong slot1, slot2;
      if ( FD_LIKELY( sscanf( filename, "incremental-snapshot-%lu-%lu-", &slot1, &slot2 )==2 ) )
        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].slot = slot2;
      else FD_LOG_ERR(("failed to scan filename: %s parsed from %s", filename, msg->read_path ));
  } else if (msg->type == FD_SNAPCT_SNAPSHOT_TYPE_FULL) {
      ulong slot1;
      if ( FD_LIKELY( sscanf( filename, "snapshot-%lu-", &slot1 )==1 ) )
        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].slot = slot1;
      else FD_LOG_ERR(("failed to scan filename: %s parsed from %s", filename, msg->read_path ));
  }
  fd_cstr_printf_check( gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].read_path, sizeof(gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].read_path), NULL, "%s", msg->read_path );
}

static void
fd_gui_handle_reset_slot( fd_gui_t * gui, ulong reset_slot, long now ) {
  FD_TEST( reset_slot!=ULONG_MAX );

  /* reset_slot has not changed */
  if( FD_UNLIKELY( gui->summary.slot_completed!=ULONG_MAX && reset_slot==gui->summary.slot_completed ) ) return;

  ulong prev_slot_completed = gui->summary.slot_completed;
  gui->summary.slot_completed = reset_slot;

  if( FD_LIKELY( fd_gui_get_slot( gui, gui->summary.slot_completed ) ) ) {
    fd_gui_printf_slot( gui, gui->summary.slot_completed );
    fd_http_server_ws_broadcast( gui->http );
  }

  fd_gui_printf_completed_slot( gui );
  fd_http_server_ws_broadcast( gui->http );

  /* Also update slot_turbine which could be larger than the max
  turbine slot if we are leader */
  if( FD_UNLIKELY( gui->summary.slots_max_turbine[ 0 ].slot!=ULONG_MAX && gui->summary.slot_completed > gui->summary.slots_max_turbine[ 0 ].slot ) ) {
    fd_gui_try_insert_ephemeral_slot( gui->summary.slots_max_turbine, FD_GUI_TURBINE_SLOT_HISTORY_SZ, gui->summary.slot_completed, now );
  }

  int slot_turbine_hist_full = gui->summary.slots_max_turbine[ FD_GUI_TURBINE_SLOT_HISTORY_SZ-1UL ].slot!=ULONG_MAX;
  if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX && slot_turbine_hist_full && gui->summary.slots_max_turbine[ 0 ].slot < (gui->summary.slot_completed + 3UL) ) ) {
    gui->summary.slot_caught_up = gui->summary.slot_completed + 4UL;

    fd_gui_printf_slot_caught_up( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  /* ensure a history exists */
  if( FD_UNLIKELY( prev_slot_completed==ULONG_MAX || gui->summary.slot_rooted==ULONG_MAX ) ) return;

  /* slot complete recieved out of order on the same fork? */
  FD_TEST( fd_gui_slot_is_ancestor( gui, prev_slot_completed, gui->summary.slot_completed ) || !fd_gui_slot_is_ancestor( gui, gui->summary.slot_completed, prev_slot_completed ) );

  /* fork switch: we need to "undo" the previous fork */
  int republish_skip_rate[ 2 ] = {0};
  if( FD_UNLIKELY( !fd_gui_slot_is_ancestor( gui, prev_slot_completed, gui->summary.slot_completed ) ) ) {
    /* The handling for skipped slot on a fork switch is tricky.  We
        want to rebate back any slots that were skipped but are no
        longer.  We also need to make sure we count skipped slots
        towards the correct epoch. */
    for( ulong i=fd_ulong_max( gui->summary.slot_completed, prev_slot_completed); i>gui->summary.slot_rooted; i-- ) {

      int is_skipped_on_old_fork = i<=prev_slot_completed         && fd_gui_is_skipped_on_fork( gui, gui->summary.slot_rooted, prev_slot_completed,         i );
      int is_skipped_on_new_fork = i<=gui->summary.slot_completed && fd_gui_is_skipped_on_fork( gui, gui->summary.slot_rooted, gui->summary.slot_completed, i );

      if( FD_LIKELY( is_skipped_on_old_fork && !is_skipped_on_new_fork ) ) {
        fd_gui_slot_t * skipped = fd_gui_get_slot( gui, i );
        if( FD_LIKELY( !skipped ) ) {
          fd_gui_slot_t * p = fd_gui_get_parent_slot_on_fork( gui, prev_slot_completed, i );
          skipped = fd_gui_clear_slot( gui, i, p ? p->slot : ULONG_MAX );
        }

        skipped->skipped = 0;
        fd_gui_printf_slot( gui, skipped->slot );
        fd_http_server_ws_broadcast( gui->http );
        skipped->must_republish = 0;

        if( FD_LIKELY( skipped->mine ) ) {
          for( ulong i=0UL; i<2UL; i++ ) {
            if( FD_LIKELY( i>=gui->epoch.epochs[ i ].start_slot && i<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots--;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }

      if( FD_LIKELY( !is_skipped_on_old_fork && is_skipped_on_new_fork ) ) {
        fd_gui_slot_t * skipped = fd_gui_get_slot( gui, i );
        if( FD_LIKELY( !skipped ) ) {
          fd_gui_slot_t * p = fd_gui_get_parent_slot_on_fork( gui, prev_slot_completed, i );
          skipped = fd_gui_clear_slot( gui, i, p ? p->slot : ULONG_MAX );
        }

        skipped->skipped = 1;
        fd_gui_printf_slot( gui, skipped->slot );
        fd_http_server_ws_broadcast( gui->http );
        skipped->must_republish = 0;

        if( FD_LIKELY( skipped->mine ) ) {
          for( ulong i=0UL; i<2UL; i++ ) {
            if( FD_LIKELY( i>=gui->epoch.epochs[ i ].start_slot && i<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots++;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }
    }
  } else {
    /* publish new skipped slots  */
    fd_gui_slot_t * s = fd_gui_get_slot( gui, gui->summary.slot_completed );
    while( s && s->slot>=prev_slot_completed ) {
      fd_gui_slot_t * p = fd_gui_get_slot( gui, s->parent_slot );
      if( FD_UNLIKELY( !p ) ) break;
      for( ulong i=p->slot+1; i<s->slot; i++ ) {
        fd_gui_slot_t * skipped = fd_gui_get_slot( gui, i );
        if( FD_LIKELY( !skipped ) ) {
          fd_gui_slot_t * p = fd_gui_get_parent_slot_on_fork( gui, gui->summary.slot_completed, i );
          skipped = fd_gui_clear_slot( gui, i, p ? p->slot : ULONG_MAX );
        }
        skipped->skipped = 1;
        fd_gui_printf_slot( gui, skipped->slot );
        fd_http_server_ws_broadcast( gui->http );
        skipped->must_republish = 0;
        if( FD_LIKELY( skipped->mine ) ) {
          for( ulong i=0UL; i<2UL; i++ ) {
            if( FD_LIKELY( i>=gui->epoch.epochs[ i ].start_slot && i<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots++;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }
      s = p;
    }
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( republish_skip_rate[ i ] ) ) {
      fd_gui_printf_skip_rate( gui, i );
      fd_http_server_ws_broadcast( gui->http );
    }
  }
}

#define SORT_NAME fd_gui_slot_staged_shred_event_evict_sort
#define SORT_KEY_T fd_gui_slot_staged_shred_event_t
#define SORT_BEFORE(a,b) (__extension__({ (void)(b); (a).slot==ULONG_MAX; }))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME fd_gui_slot_staged_shred_event_slot_sort
#define SORT_KEY_T fd_gui_slot_staged_shred_event_t
#define SORT_BEFORE(a,b) ((a).slot<(b).slot)
#include "../../util/tmpl/fd_sort.c"

static void
fd_gui_handle_rooted_slot( fd_gui_t * gui, ulong root_slot ) {
  /* start at the new root and move backwards towards the old root,
     rooting everything in-between */
  for( ulong i=0UL; i<fd_ulong_min( root_slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = root_slot - i;

    fd_gui_slot_t * slot = fd_gui_get_slot( gui, parent_slot );
    if( FD_UNLIKELY( !slot ) ) break;

    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect parent_slot %lu got slot->slot %lu", root_slot, i, parent_slot, slot->slot ));
    }
    if( FD_UNLIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    /* change notarization levels and rebroadcast */
    slot->level = FD_GUI_SLOT_LEVEL_ROOTED;
    fd_gui_printf_slot( gui, parent_slot );
    fd_http_server_ws_broadcast( gui->http );
  }

  /* archive root shred events.  We want to avoid n^2 iteration here
     since it can significantly slow things down.  Instead, we copy
     over all rooted shreds to a scratch space, stable sort by slot,
     copy the sorted arrays to the shred history. */
  ulong archive_cnt          = 0UL;
  ulong kept_cnt             = 0UL;
  ulong kept_before_next_cnt = 0UL;

  for( ulong i=gui->shreds.staged_head; i<gui->shreds.staged_tail; i++ ) {
    fd_gui_slot_staged_shred_event_t const * src = &gui->shreds.staged[ i % FD_GUI_SHREDS_STAGING_SZ ];

    if( FD_UNLIKELY( gui->shreds.history_slot!=ULONG_MAX && src->slot<=gui->shreds.history_slot ) ) continue;

    if( FD_UNLIKELY( src->slot<=root_slot ) ) {
      gui->shreds._staged_scratch[ archive_cnt++ ] = *src;
      continue;
    }

    /* The entries from the staging area are evicted by setting their
    slot field to ULONG MAX, then sorting the staging area.

    IMPORTANT: this sort needs to be stable since we always keep
    valid un-broadcast events at the end of the ring buffer */
    if( FD_UNLIKELY( i<gui->shreds.staged_next_broadcast ) ) kept_before_next_cnt++;
    gui->shreds._staged_scratch2[ kept_cnt++ ] = *src;
  }

  /* copy shred events to archive */
  for( ulong j=0UL; j<kept_cnt; j++ ) gui->shreds.staged[ (gui->shreds.staged_head + j) % FD_GUI_SHREDS_STAGING_SZ ] = gui->shreds._staged_scratch2[ j ];
  gui->shreds.staged_tail = gui->shreds.staged_head + kept_cnt;
  /* Remap next_broadcast to preserve continuity after compaction */
  gui->shreds.staged_next_broadcast = gui->shreds.staged_head + kept_before_next_cnt;

  /* sort scratch by slot increasing */
  if( FD_LIKELY( archive_cnt ) ) {
    fd_gui_slot_staged_shred_event_slot_sort_stable( gui->shreds._staged_scratch, archive_cnt, gui->shreds._staged_scratch2 );

    for( ulong i=0UL; i<archive_cnt; i++ ) {
      if( FD_UNLIKELY( gui->shreds._staged_scratch[ i ].slot!=gui->shreds.history_slot ) ) {
        fd_gui_slot_t * prev_slot = fd_gui_get_slot( gui, gui->shreds.history_slot );
        if( FD_LIKELY( prev_slot ) ) prev_slot->shreds.end_offset = gui->shreds.history_tail;

        gui->shreds.history_slot = gui->shreds._staged_scratch[ i ].slot;

        fd_gui_slot_t * next_slot = fd_gui_get_slot( gui, gui->shreds.history_slot );
        if( FD_LIKELY( next_slot ) ) next_slot->shreds.start_offset = gui->shreds.history_tail;
      }

      gui->shreds.history[ gui->shreds.history_tail % FD_GUI_SHREDS_HISTORY_SZ ].timestamp = gui->shreds._staged_scratch[ i ].timestamp;
      gui->shreds.history[ gui->shreds.history_tail % FD_GUI_SHREDS_HISTORY_SZ ].shred_idx = gui->shreds._staged_scratch[ i ].shred_idx;
      gui->shreds.history[ gui->shreds.history_tail % FD_GUI_SHREDS_HISTORY_SZ ].event     = gui->shreds._staged_scratch[ i ].event;

      gui->shreds.history_tail++;
    }
  }

  gui->summary.slot_rooted = root_slot;
  fd_gui_printf_root_slot( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_handle_notarization_update( fd_gui_t *                        gui,
                                   fd_tower_slot_confirmed_t const * notar ) {
  if( FD_UNLIKELY( notar->slot!=ULONG_MAX && gui->summary.slot_optimistically_confirmed!=notar->slot && notar->kind==FD_TOWER_SLOT_CONFIRMED_CLUSTER ) ) {
    fd_gui_handle_optimistically_confirmed_slot( gui, notar->slot );
  }
}

static inline void
try_publish_vote_status( fd_gui_t * gui, ulong _slot ) {
  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );

  /* For unstaked nodes, slot->vote_slot will always be ULONG_MAX */
  if( FD_UNLIKELY( !slot || slot->vote_slot==ULONG_MAX || slot->reset_slot==ULONG_MAX ) ) return;

  ulong vote_distance = slot->reset_slot-slot->vote_slot;
  if( FD_LIKELY( vote_distance<FD_GUI_SLOTS_CNT ) ) {
    for( ulong s=slot->vote_slot; s<slot->reset_slot; s++ ) {
      fd_gui_slot_t * cur = fd_gui_get_slot( gui, s );
      if( FD_UNLIKELY( cur && cur->skipped ) ) vote_distance--;
    }
  }

  if( FD_UNLIKELY( gui->summary.vote_distance!=vote_distance ) ) {
    gui->summary.vote_distance = vote_distance;
    fd_gui_printf_vote_distance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_LIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_NON_VOTING ) ) {
    if( FD_UNLIKELY( slot->vote_slot==ULONG_MAX || vote_distance>150UL ) ) {
      if( FD_UNLIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_DELINQUENT ) ) {
        gui->summary.vote_state = FD_GUI_VOTE_STATE_DELINQUENT;
        fd_gui_printf_vote_state( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    } else {
      if( FD_UNLIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_VOTING ) ) {
        gui->summary.vote_state = FD_GUI_VOTE_STATE_VOTING;
        fd_gui_printf_vote_state( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    }
  }
}

/* fd_gui_handle_tower_update handles updates from the tower tile, which
   manages consensus related fork switching, rooting, slot confirmation. */
void
fd_gui_handle_tower_update( fd_gui_t *                   gui,
                            fd_tower_slot_done_t const * tower,
                            long                         now ) {
  (void)now;

  if( FD_UNLIKELY( tower->active_fork_cnt!=gui->summary.active_fork_cnt ) ) {
    gui->summary.active_fork_cnt = tower->active_fork_cnt;
    fd_gui_printf_active_fork_cnt( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, tower->replay_slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, tower->replay_slot, ULONG_MAX );
  slot->reset_slot = tower->reset_slot;

  try_publish_vote_status( gui, tower->replay_slot );

  if( FD_LIKELY( gui->summary.slot_reset!=tower->reset_slot ) ) {
    gui->summary.slot_reset = tower->reset_slot;
    fd_gui_printf_reset_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
  }
}

void
fd_gui_handle_replay_update( fd_gui_t *                gui,
                             fd_gui_slot_completed_t * slot_completed,
                             fd_hash_t const *         block_hash,
                             ulong                     vote_slot,
                             ulong                     storage_slot,
                             ulong                     rooted_slot,
                             ulong                     identity_balance,
                             long                      now ) {
  (void)now;

  if( FD_LIKELY( rooted_slot!=ULONG_MAX && gui->summary.slot_rooted!=rooted_slot ) ) {
    fd_gui_handle_rooted_slot( gui, rooted_slot );
  }

  if( FD_LIKELY( gui->summary.slot_storage!=storage_slot ) ) {
    gui->summary.slot_storage = storage_slot;
    fd_gui_printf_storage_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( identity_balance!=ULONG_MAX && gui->summary.identity_account_balance!=identity_balance ) ) {
    gui->summary.identity_account_balance = identity_balance;

    fd_gui_printf_identity_balance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( gui->summary.boot_progress.catching_up_first_replay_slot==ULONG_MAX ) ) {
    gui->summary.boot_progress.catching_up_first_replay_slot = slot_completed->slot;
  }

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, slot_completed->slot );
  if( FD_UNLIKELY( slot ) ) {
    /* Its possible that this slot was labeled as skipped by another
       consensus fork at some point in the past. In this case no need to
       clear it, but we should update parent_slot */
       slot->parent_slot = slot_completed->parent_slot;
  } else {
    slot = fd_gui_clear_slot( gui, slot_completed->slot, slot_completed->parent_slot );
  }

  if( FD_UNLIKELY( slot->mine ) ) {
    fd_gui_leader_slot_t * lslot = fd_gui_get_leader_slot( gui, slot->slot );
    if( FD_LIKELY( lslot ) ) fd_memcpy( lslot->block_hash.uc, block_hash->uc, sizeof(fd_hash_t) );
  }

  slot->completed_time    = slot_completed->completed_time;
  slot->parent_slot       = slot_completed->parent_slot;
  slot->max_compute_units = fd_uint_if( slot_completed->max_compute_units==UINT_MAX, slot->max_compute_units, slot_completed->max_compute_units );
  if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_COMPLETED ) ) {
    /* Typically a slot goes from INCOMPLETE to COMPLETED but it can
       happen that it starts higher.  One such case is when we
       optimistically confirm a higher slot that skips this one, but
       then later we replay this one anyway to track the bank fork. */

    if( FD_LIKELY( gui->summary.slot_optimistically_confirmed!=ULONG_MAX && slot->slot<gui->summary.slot_optimistically_confirmed ) ) {
      /* Cluster might have already optimistically confirmed by the time
         we finish replaying it. */
      slot->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
    } else {
      slot->level = FD_GUI_SLOT_LEVEL_COMPLETED;
    }
  }
  slot->total_txn_cnt          = slot_completed->total_txn_cnt;
  slot->vote_txn_cnt           = slot_completed->vote_txn_cnt;
  slot->failed_txn_cnt         = slot_completed->failed_txn_cnt;
  slot->nonvote_failed_txn_cnt = slot_completed->nonvote_failed_txn_cnt;
  slot->transaction_fee        = slot_completed->transaction_fee;
  slot->priority_fee           = slot_completed->priority_fee;
  slot->tips                   = slot_completed->tips;
  slot->compute_units          = slot_completed->compute_units;
  slot->shred_cnt              = slot_completed->shred_cnt;
  slot->vote_slot              = vote_slot;

  try_publish_vote_status( gui, slot_completed->slot );

  if( FD_UNLIKELY( gui->epoch.has_epoch[ 0 ] && slot->slot==gui->epoch.epochs[ 0 ].end_slot ) ) {
    gui->epoch.epochs[ 0 ].end_time = slot->completed_time;
  } else if( FD_UNLIKELY( gui->epoch.has_epoch[ 1 ] && slot->slot==gui->epoch.epochs[ 1 ].end_slot ) ) {
    gui->epoch.epochs[ 1 ].end_time = slot->completed_time;
  }

  /* Broadcast new skip rate if one of our slots got completed. */
  if( FD_LIKELY( slot->mine ) ) {
    for( ulong i=0UL; i<2UL; i++ ) {
      if( FD_LIKELY( slot->slot>=gui->epoch.epochs[ i ].start_slot && slot->slot<=gui->epoch.epochs[ i ].end_slot ) ) {
        fd_gui_printf_skip_rate( gui, i );
        fd_http_server_ws_broadcast( gui->http );
        break;
      }
    }
  }

  /* We'll treat the latest slot_complete from replay as the reset slot.
     We get an explicit reset_slot from tower, but that message may come
     in before we get the slot_complete from replay. */
  if( FD_UNLIKELY( gui->summary.slot_completed!=slot->slot ) ) {
    fd_gui_handle_reset_slot( gui, slot->slot, now );
  }

  /* Add a "slot complete" event for all of the shreds in this slot */
  if( FD_UNLIKELY( slot->shred_cnt > FD_GUI_MAX_SHREDS_PER_BLOCK ) ) FD_LOG_ERR(( "unexpected shred_cnt=%lu", (ulong)slot->shred_cnt ));
  fd_gui_slot_staged_shred_event_t * slot_complete_event = &gui->shreds.staged[ gui->shreds.staged_tail % FD_GUI_SHREDS_STAGING_SZ ];
  gui->shreds.staged_tail++;
  slot_complete_event->event     = FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE;
  slot_complete_event->timestamp = slot_completed->completed_time;
  slot_complete_event->shred_idx = USHORT_MAX;
  slot_complete_event->slot      = slot->slot;

  /* addresses racey behavior if we just sample at 400ms */
  if( FD_LIKELY( gui->summary.slot_caught_up!=ULONG_MAX ) ) {
    fd_topo_tile_t * repair = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "repair", 0UL ) ];
    volatile ulong const * repair_metrics = fd_metrics_tile( repair->metrics );
    ulong slot = repair_metrics[ MIDX( COUNTER, REPAIR, REPAIRED_SLOTS ) ];
    fd_gui_handle_repair_slot( gui, slot, now );
  }
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       long          now ) {

  switch( plugin_msg ) {
    case FD_PLUGIN_MSG_SLOT_ROOTED:
      fd_gui_handle_rooted_slot_legacy( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED:
      fd_gui_handle_optimistically_confirmed_slot( gui, ((ulong *)msg)[0] );
      break;
    case FD_PLUGIN_MSG_SLOT_COMPLETED: {
      fd_gui_handle_completed_slot( gui, (ulong *)msg, now );
      break;
    }
    case FD_PLUGIN_MSG_LEADER_SCHEDULE: {
      FD_STATIC_ASSERT( sizeof(fd_stake_weight_msg_t)==6*sizeof(ulong), "new fields breaks things" );
      fd_gui_handle_leader_schedule( gui, (fd_stake_weight_msg_t *)msg, now );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_START: {
      ulong slot = ((ulong *)msg)[ 0 ];
      ulong parent_slot = ((ulong *)msg)[ 1 ];
      fd_gui_handle_slot_start( gui, slot, parent_slot, now );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_END: {
      ulong slot = ((ulong *)msg)[ 0 ];
      ulong cus_used = ((ulong *)msg)[ 1 ];
      fd_gui_handle_slot_end( gui, slot, cus_used, now );
      break;
    }
    case FD_PLUGIN_MSG_GOSSIP_UPDATE: {
      fd_gui_handle_gossip_update( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE: {
      fd_gui_handle_vote_account_update( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_VALIDATOR_INFO: {
      fd_gui_handle_validator_info_update( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_RESET: {
      fd_gui_handle_reset_slot_legacy( gui, (ulong *)msg, now );
      break;
    }
    case FD_PLUGIN_MSG_BALANCE: {
      fd_gui_handle_balance_update( gui, (ulong *)msg );
      break;
    }
    case FD_PLUGIN_MSG_START_PROGRESS: {
      fd_gui_handle_start_progress( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_GENESIS_HASH_KNOWN: {
      fd_gui_handle_genesis_hash( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE: {
      fd_gui_handle_block_engine_update( gui, msg );
      break;
    }
    default:
      FD_LOG_ERR(( "Unhandled plugin msg: 0x%lx", plugin_msg ));
      break;
  }
}

void
fd_gui_became_leader( fd_gui_t * gui,
                      ulong      _slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks ) {
  if( FD_LIKELY( gui->summary.is_full_client && gui->leader_slot!=ULONG_MAX ) ) {
    /* stop sampling for other leader slot in progress */
    fd_gui_handle_slot_end( gui, gui->leader_slot, ULONG_MAX, start_time_nanos );
  }

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, _slot, ULONG_MAX );
  fd_gui_leader_slot_t * lslot = fd_gui_get_leader_slot( gui, _slot );
  if( FD_UNLIKELY( !lslot ) ) return;

  slot->max_compute_units = (uint)max_compute_units;
  lslot->leader_start_time = fd_long_if( lslot->leader_start_time==LONG_MAX, start_time_nanos, lslot->leader_start_time );
  lslot->leader_end_time   = end_time_nanos;
  if( FD_LIKELY( lslot->txs.microblocks_upper_bound==USHORT_MAX ) ) lslot->txs.microblocks_upper_bound = (ushort)max_microblocks;

  if( FD_UNLIKELY( gui->summary.is_full_client ) ) fd_gui_handle_slot_start( gui, slot->slot, slot->parent_slot, start_time_nanos );
}

void
fd_gui_unbecame_leader( fd_gui_t *                gui,
                        ulong                     _slot,
                        fd_done_packing_t const * done_packing,
                        long                      now ) {
  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, _slot, ULONG_MAX );
  fd_gui_leader_slot_t * lslot = fd_gui_get_leader_slot( gui, _slot );
  if( FD_LIKELY( !lslot ) ) return;
  lslot->txs.microblocks_upper_bound = (uint)done_packing->microblocks_in_slot;
  fd_memcpy( lslot->scheduler_stats, done_packing, sizeof(fd_done_packing_t) );

  /* fd_gui_handle_slot_end may have already been called in response to
     a "became_leader" message for a subseqeunt slot. */
  if( FD_UNLIKELY( gui->summary.is_full_client && gui->leader_slot==_slot ) ) fd_gui_handle_slot_end( gui, slot->slot, ULONG_MAX, now );

  lslot->unbecame_leader = 1;
}

void
fd_gui_microblock_execution_begin( fd_gui_t *   gui,
                                   long         now,
                                   ulong        _slot,
                                   fd_txn_p_t * txns,
                                   ulong        txn_cnt,
                                   uint         microblock_idx,
                                   ulong        pack_txn_idx ) {
  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  fd_gui_leader_slot_t * lslot = fd_gui_get_leader_slot( gui, _slot );
  if( FD_UNLIKELY( !lslot ) ) return;

  lslot->leader_start_time = fd_long_if( lslot->leader_start_time==LONG_MAX, now, lslot->leader_start_time );

  if( FD_UNLIKELY( lslot->txs.start_offset==ULONG_MAX ) ) lslot->txs.start_offset = pack_txn_idx;
  else                                                    lslot->txs.start_offset = fd_ulong_min( lslot->txs.start_offset, pack_txn_idx );

  gui->pack_txn_idx = fd_ulong_max( gui->pack_txn_idx, pack_txn_idx+txn_cnt-1UL );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn_payload = &txns[ i ];
    fd_txn_t * txn = TXN( txn_payload );

    ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * txn->signature_cnt;
    ulong priority_rewards                    = ULONG_MAX;
    ulong requested_execution_cus             = ULONG_MAX;
    ulong precompile_sigs                     = ULONG_MAX;
    ulong requested_loaded_accounts_data_cost = ULONG_MAX;
    uint _flags;
    ulong cost_estimate = fd_pack_compute_cost( txn, txn_payload->payload, &_flags, &requested_execution_cus, &priority_rewards, &precompile_sigs, &requested_loaded_accounts_data_cost );
    sig_rewards += FD_PACK_FEE_PER_SIGNATURE * precompile_sigs;
    sig_rewards = sig_rewards * FD_PACK_TXN_FEE_BURN_PCT / 100UL;

    fd_gui_txn_t * txn_entry = gui->txs[ (pack_txn_idx + i)%FD_GUI_TXN_HISTORY_SZ ];
    fd_memcpy(txn_entry->signature, txn_payload->payload + txn->signature_off, FD_SHA512_HASH_SZ);
    txn_entry->timestamp_arrival_nanos     = txn_payload->scheduler_arrival_time_nanos;
    txn_entry->compute_units_requested     = cost_estimate & 0x1FFFFFU;
    txn_entry->priority_fee                = priority_rewards;
    txn_entry->transaction_fee             = sig_rewards;
    txn_entry->timestamp_delta_start_nanos = (int)(now - lslot->leader_start_time);
    txn_entry->source_ipv4                 = txn_payload->source_ipv4;
    txn_entry->source_tpu                  = txn_payload->source_tpu;
    txn_entry->microblock_idx              = microblock_idx;
    txn_entry->flags                      |= (uchar)FD_GUI_TXN_FLAGS_STARTED;
    txn_entry->flags                      &= (uchar)(~(uchar)(FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE | FD_GUI_TXN_FLAGS_FROM_BUNDLE));
    txn_entry->flags                      |= (uchar)fd_uint_if(txn_payload->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE, FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE, 0U);
    txn_entry->flags                      |= (uchar)fd_uint_if((txn_payload->flags & FD_TXN_P_FLAGS_BUNDLE) || (txn_payload->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE), FD_GUI_TXN_FLAGS_FROM_BUNDLE, 0U);
  }

  /* At the moment, bank publishes at most 1 transaction per microblock,
     even if it received microblocks with multiple transactions
     (i.e. a bundle). This means that we need to calculate microblock
     count here based on the transaction count. */
  lslot->txs.begin_microblocks += (uint)txn_cnt;
}

void
fd_gui_microblock_execution_end( fd_gui_t *   gui,
                                 long         now,
                                 ulong        bank_idx,
                                 ulong        _slot,
                                 ulong        txn_cnt,
                                 fd_txn_p_t * txns,
                                 ulong        pack_txn_idx,
                                 uchar        txn_start_pct,
                                 uchar        txn_load_end_pct,
                                 uchar        txn_end_pct,
                                 uchar        txn_preload_end_pct,
                                 ulong        tips ) {
  if( FD_UNLIKELY( 1UL!=txn_cnt ) ) FD_LOG_ERR(( "gui expects 1 txn per microblock from bank, found %lu", txn_cnt ));

  fd_gui_slot_t * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot ) ) slot = fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  fd_gui_leader_slot_t * lslot = fd_gui_get_leader_slot( gui, _slot );
  if( FD_UNLIKELY( !lslot ) ) return;

  lslot->leader_start_time = fd_long_if( lslot->leader_start_time==LONG_MAX, now, lslot->leader_start_time );

  if( FD_UNLIKELY( lslot->txs.end_offset==ULONG_MAX ) ) lslot->txs.end_offset = pack_txn_idx + txn_cnt;
  else                                                  lslot->txs.end_offset = fd_ulong_max( lslot->txs.end_offset, pack_txn_idx+txn_cnt );

  gui->pack_txn_idx = fd_ulong_max( gui->pack_txn_idx, pack_txn_idx+txn_cnt-1UL );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn_p = &txns[ i ];

    fd_gui_txn_t * txn_entry = gui->txs[ (pack_txn_idx + i)%FD_GUI_TXN_HISTORY_SZ ];
    txn_entry->bank_idx                  = bank_idx                           & 0x3FU;
    txn_entry->compute_units_consumed    = txn_p->bank_cu.actual_consumed_cus & 0x1FFFFFU;
    txn_entry->error_code                = (txn_p->flags >> 24)               & 0x3FU;
    txn_entry->timestamp_delta_end_nanos = (int)(now - lslot->leader_start_time);
    txn_entry->txn_start_pct             = txn_start_pct;
    txn_entry->txn_load_end_pct          = txn_load_end_pct;
    txn_entry->txn_end_pct               = txn_end_pct;
    txn_entry->txn_preload_end_pct       = txn_preload_end_pct;
    txn_entry->tips                      = tips;
    txn_entry->flags                    |= (uchar)FD_GUI_TXN_FLAGS_ENDED;
    txn_entry->flags                    &= (uchar)(~(uchar)FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK);
    txn_entry->flags                    |= (uchar)fd_uint_if(txn_p->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS, FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK, 0U);
  }

  lslot->txs.end_microblocks = lslot->txs.end_microblocks + (uint)txn_cnt;
}
