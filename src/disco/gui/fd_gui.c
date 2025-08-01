#include "fd_gui.h"
#include "fd_gui_printf.h"

#include "../metrics/fd_metrics.h"
#include "../plugin/fd_plugin.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/json/cJSON.h"
#include "../../disco/genesis/fd_genesis_cluster.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../disco/shred/fd_stake_ci.h"

FD_FN_CONST ulong
fd_gui_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_gui_footprint( void ) {
  return sizeof(fd_gui_t);
}

void *
fd_gui_new( void *             shmem,
            fd_http_server_t * http,
            char const *       version,
            char const *       cluster,
            uchar const *      identity_key,
            int                has_vote_key,
            uchar const *      vote_key,
            int                is_voting,
            int                schedule_strategy,
            fd_topo_t *        topo ) {

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

  fd_gui_t * gui = (fd_gui_t *)shmem;

  gui->http = http;
  gui->topo = topo;

  gui->debug_in_leader_slot = ULONG_MAX;
  gui->summary.schedule_strategy = schedule_strategy;


  gui->next_sample_400millis = fd_log_wallclock();
  gui->next_sample_100millis = gui->next_sample_400millis;
  gui->next_sample_10millis  = gui->next_sample_400millis;

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

  gui->summary.version                       = version;
  gui->summary.cluster                       = cluster;
  gui->summary.startup_time_nanos            = gui->next_sample_400millis;

  gui->summary.startup_progress                       = FD_GUI_START_PROGRESS_TYPE_INITIALIZING;
  gui->summary.startup_got_full_snapshot              = 0;
  gui->summary.startup_full_snapshot_slot             = 0;
  gui->summary.startup_incremental_snapshot_slot      = 0;
  gui->summary.startup_waiting_for_supermajority_slot = ULONG_MAX;

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

  gui->summary.slot_rooted                   = 0UL;
  gui->summary.slot_optimistically_confirmed = 0UL;
  gui->summary.slot_completed                = 0UL;
  gui->summary.slot_estimated                = 0UL;

  gui->summary.estimated_tps_history_idx = 0UL;
  memset( gui->summary.estimated_tps_history, 0, sizeof(gui->summary.estimated_tps_history) );

  memset( gui->summary.txn_waterfall_reference, 0, sizeof(gui->summary.txn_waterfall_reference) );
  memset( gui->summary.txn_waterfall_current,   0, sizeof(gui->summary.txn_waterfall_current) );

  memset( gui->summary.tile_stats_reference, 0, sizeof(gui->summary.tile_stats_reference) );
  memset( gui->summary.tile_stats_current, 0, sizeof(gui->summary.tile_stats_current) );

  memset( gui->summary.tile_timers_snap[ 0 ], 0, sizeof(gui->summary.tile_timers_snap[ 0 ]) );
  memset( gui->summary.tile_timers_snap[ 1 ], 0, sizeof(gui->summary.tile_timers_snap[ 1 ]) );
  gui->summary.tile_timers_snap_idx    = 2UL;
  gui->summary.tile_timers_history_idx = 0UL;
  for( ulong i=0UL; i<FD_GUI_TILE_TIMER_LEADER_CNT; i++ ) gui->summary.tile_timers_leader_history_slot[ i ] = ULONG_MAX;

  gui->block_engine.has_block_engine = 0;

  gui->epoch.has_epoch[ 0 ] = 0;
  gui->epoch.has_epoch[ 1 ] = 0;

  gui->gossip.peer_cnt               = 0UL;
  gui->vote_account.vote_account_cnt = 0UL;
  gui->validator_info.info_cnt       = 0UL;

  for( ulong i=0UL; i<FD_GUI_SLOTS_CNT; i++ ) gui->slots[ i ]->slot = ULONG_MAX;
  gui->pack_txn_idx = 0UL;

  fd_histf_new( gui->bundle_rx_delay_hist_current,   FD_MHIST_MIN( BUNDLE, MESSAGE_RX_DELAY_NANOS ), FD_MHIST_MAX( BUNDLE, MESSAGE_RX_DELAY_NANOS ) );
  fd_histf_new( gui->bundle_rx_delay_hist_reference, FD_MHIST_MIN( BUNDLE, MESSAGE_RX_DELAY_NANOS ), FD_MHIST_MAX( BUNDLE, MESSAGE_RX_DELAY_NANOS ) );

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
    fd_gui_printf_startup_progress,
    fd_gui_printf_version,
    fd_gui_printf_cluster,
    fd_gui_printf_commit_hash,
    fd_gui_printf_identity_key,
    fd_gui_printf_vote_key,
    fd_gui_printf_startup_time_nanos,
    fd_gui_printf_vote_state,
    fd_gui_printf_vote_distance,
    fd_gui_printf_skipped_history,
    fd_gui_printf_tps_history,
    fd_gui_printf_tiles,
    fd_gui_printf_schedule_strategy,
    fd_gui_printf_identity_balance,
    fd_gui_printf_vote_balance,
    fd_gui_printf_estimated_slot_duration_nanos,
    fd_gui_printf_root_slot,
    fd_gui_printf_optimistically_confirmed_slot,
    fd_gui_printf_completed_slot,
    fd_gui_printf_estimated_slot,
    fd_gui_printf_live_tile_timers,
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

    cur[ i ].caughtup_housekeeping_ticks     = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING ) ];
    cur[ i ].processing_housekeeping_ticks   = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING ) ];
    cur[ i ].backpressure_housekeeping_ticks = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING ) ];
    cur[ i ].caughtup_prefrag_ticks          = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG ) ];
    cur[ i ].processing_prefrag_ticks        = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_PREFRAG ) ];
    cur[ i ].backpressure_prefrag_ticks      = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    cur[ i ].caughtup_postfrag_ticks         = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ];
    cur[ i ].processing_postfrag_ticks       = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_POSTFRAG ) ];
  }
}

static void
fd_gui_estimated_tps_snap( fd_gui_t * gui ) {
  ulong total_txn_cnt          = 0UL;
  ulong vote_txn_cnt           = 0UL;
  ulong nonvote_failed_txn_cnt = 0UL;

  for( ulong i=0UL; i<fd_ulong_min( gui->summary.slot_completed+1UL, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong _slot = gui->summary.slot_completed-i;
    fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX || slot->slot!=_slot ) ) break; /* Slot no longer exists, no TPS. */
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

    cur->out.block_success += bank_metrics[ MIDX( COUNTER, BANK, SUCCESSFUL_TRANSACTIONS ) ];

    cur->out.block_fail +=
        bank_metrics[ MIDX( COUNTER, BANK, EXECUTED_FAILED_TRANSACTIONS ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, FEE_ONLY_TRANSACTIONS        ) ];

    cur->out.bank_invalid +=
        bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_SLOT_HASHES_SYSVAR_NOT_FOUND ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_ACCOUNT_NOT_FOUND ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_ACCOUNT_OWNER ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_ACCOUNT_DATA ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_INDEX ) ];

    cur->out.bank_invalid +=
        bank_metrics[ MIDX( COUNTER, BANK, PROCESSING_FAILED ) ];
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

  cur->in.gossip   = dedup_metrics[ MIDX( COUNTER, DEDUP, GOSSIPED_VOTES_RECEIVED ) ];
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
                        fd_gui_tile_stats_t *          stats ) {
  fd_topo_t const * topo = gui->topo;

  stats->sample_time_nanos = fd_log_wallclock();

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

    gui->bundle_rx_delay_hist_current->sum = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + FD_HISTF_BUCKET_CNT ];
    for( ulong b=0; b<FD_HISTF_BUCKET_CNT; b++ ) gui->bundle_rx_delay_hist_current->counts[ b ] = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + b ];
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

int
fd_gui_poll( fd_gui_t * gui ) {
  long now = fd_log_wallclock();

  int did_work = 0;

  if( FD_LIKELY( now>gui->next_sample_400millis ) ) {
    fd_gui_estimated_tps_snap( gui );
    fd_gui_printf_estimated_tps( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_400millis += 400L*1000L*1000L;
    did_work = 1;
  }

  if( FD_LIKELY( now>gui->next_sample_100millis ) ) {
    fd_gui_txn_waterfall_snap( gui, gui->summary.txn_waterfall_current );
    fd_gui_printf_live_txn_waterfall( gui, gui->summary.txn_waterfall_reference, gui->summary.txn_waterfall_current, 0UL /* TODO: REAL NEXT LEADER SLOT */ );
    fd_http_server_ws_broadcast( gui->http );

    *gui->summary.tile_stats_reference = *gui->summary.tile_stats_current;
    fd_gui_tile_stats_snap( gui, gui->summary.txn_waterfall_current, gui->summary.tile_stats_current );
    fd_gui_printf_live_tile_stats( gui, gui->summary.tile_stats_reference, gui->summary.tile_stats_current );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_100millis += 100L*1000L*1000L;
    did_work = 1;
  }

  if( FD_LIKELY( now>gui->next_sample_10millis ) ) {
    fd_gui_tile_timers_snap( gui );

    fd_gui_printf_live_tile_timers( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_10millis += 10L*1000L*1000L;
    did_work = 1;
  }

  return did_work;
}

static void
fd_gui_handle_gossip_update( fd_gui_t *    gui,
                             uchar const * msg ) {
  if( FD_UNLIKELY( gui->gossip.peer_cnt == FD_GUI_MAX_PEER_CNT ) ) {
    FD_LOG_DEBUG(("gossip peer cnt exceeds 40200 %lu, ignoring additional entries", gui->gossip.peer_cnt ));
    return;
  }
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
        gui->gossip.peer_cnt--;
        i--;
      }
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
  if( FD_UNLIKELY( gui->vote_account.vote_account_cnt==FD_GUI_MAX_PEER_CNT ) ) {
    FD_LOG_DEBUG(("vote account cnt exceeds 40200 %lu, ignoring additional entries", gui->vote_account.vote_account_cnt ));
    return;
  }
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
        gui->vote_account.vote_account_cnt--;
        i--;
      }
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
  fd_gui_slot_t const * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot || slot->slot==ULONG_MAX ) ) {
    fd_gui_printf_null_query_response( gui, "slot", "query", request_id );
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
  fd_gui_slot_t const * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot || slot->slot==ULONG_MAX ) ) {
    fd_gui_printf_null_query_response( gui, "slot", "query", request_id );
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
  fd_gui_slot_t const * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot || slot->slot==ULONG_MAX ) ) {
    fd_gui_printf_null_query_response( gui, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request_detailed( gui, _slot, request_id );
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
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "summary" ) && !strcmp( key->valuestring, "ping" ) ) ) {
    fd_gui_printf_summary_ping( gui, id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );

    cJSON_Delete( json );
    return 0;
  }

  cJSON_Delete( json );
  return FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD;
}

static void
fd_gui_clear_slot( fd_gui_t * gui,
                   ulong      _slot,
                   ulong      _parent_slot ) {
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
  slot->max_compute_units      = UINT_MAX;
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
  slot->leader_state           = FD_GUI_SLOT_LEADER_UNSTARTED;
  slot->completed_time         = LONG_MAX;

  slot->txs.leader_start_time  = LONG_MAX;
  slot->txs.leader_end_time    = LONG_MAX;
  slot->txs.microblocks_upper_bound = USHORT_MAX;
  slot->txs.begin_microblocks  = 0U;
  slot->txs.end_microblocks    = 0U;
  slot->txs.reference_ticks    = LONG_MAX;
  slot->txs.reference_nanos    = LONG_MAX;
  slot->txs.start_offset       = ULONG_MAX;
  slot->txs.end_offset         = ULONG_MAX;

  if( FD_LIKELY( slot->mine ) ) {
    /* All slots start off not skipped, until we see it get off the reset
       chain. */
    gui->epoch.epochs[ epoch_idx ].my_total_slots++;
  }

  if( FD_UNLIKELY( !_slot ) ) {
    /* Slot 0 is always rooted */
    slot->level   = FD_GUI_SLOT_LEVEL_ROOTED;
  }
}

static void
fd_gui_handle_leader_schedule( fd_gui_t *    gui,
                               ulong const * msg ) {
  ulong epoch               = msg[ 0 ];
  ulong staked_cnt          = msg[ 1 ];
  ulong start_slot          = msg[ 2 ];
  ulong slot_cnt            = msg[ 3 ];
  ulong excluded_stake      = msg[ 4 ];
  ulong vote_keyed_lsched   = msg[ 5 ];

  FD_TEST( staked_cnt<=MAX_STAKED_LEADERS );
  FD_TEST( slot_cnt<=MAX_SLOTS_PER_EPOCH );

  ulong idx = epoch % 2UL;
  gui->epoch.has_epoch[ idx ] = 1;

  gui->epoch.epochs[ idx ].epoch            = epoch;
  gui->epoch.epochs[ idx ].start_slot       = start_slot;
  gui->epoch.epochs[ idx ].end_slot         = start_slot + slot_cnt - 1; // end_slot is inclusive.
  gui->epoch.epochs[ idx ].excluded_stake   = excluded_stake;
  gui->epoch.epochs[ idx ].my_total_slots   = 0UL;
  gui->epoch.epochs[ idx ].my_skipped_slots = 0UL;

  fd_vote_stake_weight_t const * stake_weights = fd_type_pun_const( msg+6UL );
  memcpy( gui->epoch.epochs[ idx ].stakes, stake_weights, staked_cnt*sizeof(fd_vote_stake_weight_t) );

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( gui->epoch.epochs[ idx ].lsched ) );
  gui->epoch.epochs[idx].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[ idx ]._lsched,
                                                                               epoch,
                                                                               gui->epoch.epochs[ idx ].start_slot,
                                                                               slot_cnt,
                                                                               staked_cnt,
                                                                               gui->epoch.epochs[ idx ].stakes,
                                                                               excluded_stake,
                                                                               vote_keyed_lsched ) );

  if( FD_UNLIKELY( start_slot==0UL ) ) {
    gui->epoch.epochs[ 0 ].start_time = fd_log_wallclock();
  } else {
    gui->epoch.epochs[ idx ].start_time = LONG_MAX;

    for( ulong i=0UL; i<fd_ulong_min( start_slot-1UL, FD_GUI_SLOTS_CNT ); i++ ) {
      fd_gui_slot_t * slot = gui->slots[ (start_slot-i) % FD_GUI_SLOTS_CNT ];
      if( FD_UNLIKELY( slot->slot!=(start_slot-i) ) ) break;
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
                          ulong *    msg ) {
  ulong _slot = msg[ 0 ];
  ulong _parent_slot = msg[ 1 ];
  // FD_LOG_WARNING(( "Got start slot %lu parent_slot %lu", _slot, _parent_slot ));
  FD_TEST( gui->debug_in_leader_slot==ULONG_MAX );
  gui->debug_in_leader_slot = _slot;

  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, _parent_slot );
  slot->leader_state = FD_GUI_SLOT_LEADER_STARTED;

  fd_gui_tile_timers_snap( gui );
  gui->summary.tile_timers_snap_idx_slot_start = (gui->summary.tile_timers_snap_idx+(FD_GUI_TILE_TIMER_SNAP_CNT-1UL))%FD_GUI_TILE_TIMER_SNAP_CNT;

  fd_gui_txn_waterfall_t waterfall[ 1 ];
  fd_gui_txn_waterfall_snap( gui, waterfall );
  fd_gui_tile_stats_snap( gui, waterfall, slot->tile_stats_begin );
}

static void
fd_gui_handle_slot_end( fd_gui_t * gui,
                        ulong *    msg ) {
  ulong _slot     = msg[ 0 ];
  ulong _cus_used = msg[ 1 ];
  if( FD_UNLIKELY( gui->debug_in_leader_slot!=_slot ) ) {
    FD_LOG_ERR(( "gui->debug_in_leader_slot %lu _slot %lu", gui->debug_in_leader_slot, _slot ));
  }
  gui->debug_in_leader_slot = ULONG_MAX;

  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  FD_TEST( slot->slot==_slot );

  slot->leader_state  = FD_GUI_SLOT_LEADER_ENDED;
  slot->compute_units = (uint)_cus_used;

  fd_gui_tile_timers_snap( gui );
  /* Record slot number so we can detect overwrite. */
  gui->summary.tile_timers_leader_history_slot[ gui->summary.tile_timers_history_idx ] = _slot;
  /* Point into per-leader-slot storage. */
  slot->tile_timers_history_idx = gui->summary.tile_timers_history_idx;
  /* Downsample tile timers into per-leader-slot storage. */
  ulong end = gui->summary.tile_timers_snap_idx;
  end = fd_ulong_if( end<gui->summary.tile_timers_snap_idx_slot_start, end+FD_GUI_TILE_TIMER_SNAP_CNT, end );
  gui->summary.tile_timers_leader_history_slot_sample_cnt[ gui->summary.tile_timers_history_idx ] = end-gui->summary.tile_timers_snap_idx_slot_start;
  ulong stride = fd_ulong_max( 1UL, (end-gui->summary.tile_timers_snap_idx_slot_start) / FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT );
  for( ulong sample_snap_idx=gui->summary.tile_timers_snap_idx_slot_start, i=0UL; sample_snap_idx<end; sample_snap_idx+=stride, i++ ) {
    memcpy( gui->summary.tile_timers_leader_history[ gui->summary.tile_timers_history_idx ][ i ], gui->summary.tile_timers_snap[ sample_snap_idx%FD_GUI_TILE_TIMER_SNAP_CNT ], sizeof(gui->summary.tile_timers_leader_history[ gui->summary.tile_timers_history_idx ][ i ]) );
  }
  gui->summary.tile_timers_history_idx = (gui->summary.tile_timers_history_idx+1UL)%FD_GUI_TILE_TIMER_LEADER_CNT;

  /* When a slot ends, snap the state of the waterfall and save it into
     that slot, and also reset the reference counters to the end of the
     slot. */

  fd_gui_txn_waterfall_snap( gui, slot->waterfall_end );
  memcpy( slot->waterfall_begin, gui->summary.txn_waterfall_reference, sizeof(slot->waterfall_begin) );
  memcpy( gui->summary.txn_waterfall_reference, slot->waterfall_end, sizeof(gui->summary.txn_waterfall_reference) );

  fd_gui_tile_stats_snap( gui, slot->waterfall_end, slot->tile_stats_end );
}

static void
fd_gui_handle_reset_slot( fd_gui_t * gui,
                          ulong *    msg ) {
  ulong last_landed_vote = msg[ 0 ];

  ulong parent_cnt = msg[ 1 ];
  FD_TEST( parent_cnt<4096UL );

  ulong _slot = msg[ 2 ];

  for( ulong i=0UL; i<parent_cnt; i++ ) {
    ulong parent_slot = msg[2UL+i];
    fd_gui_slot_t * slot = gui->slots[ parent_slot % FD_GUI_SLOTS_CNT ];
    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
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
    ulong parent_idx = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX || slot->slot!=parent_slot ) ) fd_gui_clear_slot( gui, parent_slot, ULONG_MAX );

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

  ulong last_slot = _slot;
  long last_published = gui->slots[ _slot % FD_GUI_SLOTS_CNT ]->completed_time;

  for( ulong i=0UL; i<fd_ulong_min( _slot+1, 750UL ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx  = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;
    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect _slot-i %lu got slot->slot %lu", _slot, i, _slot-i, slot->slot ));
    }

    if( FD_LIKELY( !slot->skipped ) ) {
      last_slot = parent_slot;
      last_published = slot->completed_time;
    }
  }

  if( FD_LIKELY( _slot!=last_slot )) {
    gui->summary.estimated_slot_duration_nanos = (ulong)(fd_log_wallclock()-last_published)/(_slot-last_slot);
    fd_gui_printf_estimated_slot_duration_nanos( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_LIKELY( _slot!=gui->summary.slot_completed ) ) {
    gui->summary.slot_completed = _slot;
    fd_gui_printf_completed_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
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
                              ulong *    msg ) {
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

  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, _parent_slot );

  slot->completed_time = fd_log_wallclock();
  slot->parent_slot = _parent_slot;
  slot->max_compute_units = (uint)max_compute_units;
  if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_COMPLETED ) ) {
    /* Typically a slot goes from INCOMPLETE to COMPLETED but it can
       happen that it starts higher.  One such case is when we
       optimistically confirm a higher slot that skips this one, but
       then later we replay this one anyway to track the bank fork. */

    if( FD_LIKELY( _slot<gui->summary.slot_optimistically_confirmed ) ) {
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
  if( FD_LIKELY( slot->leader_state==FD_GUI_SLOT_LEADER_UNSTARTED ) ) {
    /* If we were already leader for this slot, then the poh component
       calculated the CUs used and sent them there, rather than the
       replay component which is sending this completed slot. */
    slot->compute_units   = compute_units;
  }

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
fd_gui_handle_rooted_slot( fd_gui_t * gui,
                           ulong *    msg ) {
  ulong _slot = msg[ 0 ];

  // FD_LOG_WARNING(( "Got rooted slot %lu", _slot ));

  /* Slot 0 is always rooted.  No need to iterate all the way back to
     i==_slot */
  for( ulong i=0UL; i<fd_ulong_min( _slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;

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
                                             ulong *    msg ) {
  ulong _slot = msg[ 0 ];

  /* Slot 0 is always rooted.  No need to iterate all the way back to
     i==_slot */
  for( ulong i=0UL; i<fd_ulong_min( _slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;

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

  if( FD_UNLIKELY( _slot<gui->summary.slot_optimistically_confirmed ) ) {
    /* Optimistically confirmed slot went backwards ... mark some slots as no
       longer optimistically confirmed. */
    for( ulong i=gui->summary.slot_optimistically_confirmed; i>=_slot; i-- ) {
      fd_gui_slot_t * slot = gui->slots[ i % FD_GUI_SLOTS_CNT ];
      if( FD_UNLIKELY( slot->slot==ULONG_MAX ) ) break;
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
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_INITIALIZING;
      FD_LOG_INFO(( "progress: initializing" ));
      break;
    case 1: {
      char const * snapshot_type;
      if( FD_UNLIKELY( gui->summary.startup_got_full_snapshot ) ) {
        gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_INCREMENTAL_SNAPSHOT;
        snapshot_type = "incremental";
      } else {
        gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_FULL_SNAPSHOT;
        snapshot_type = "full";
      }
      FD_LOG_INFO(( "progress: searching for %s snapshot", snapshot_type ));
      break;
    }
    case 2: {
      uchar is_full_snapshot = msg[ 1 ];
      if( FD_LIKELY( is_full_snapshot ) ) {
          gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_FULL_SNAPSHOT;
          gui->summary.startup_full_snapshot_slot = *((ulong *)(msg + 2));
          gui->summary.startup_full_snapshot_peer_ip_addr = *((uint *)(msg + 10));
          gui->summary.startup_full_snapshot_peer_port = *((ushort *)(msg + 14));
          gui->summary.startup_full_snapshot_total_bytes = *((ulong *)(msg + 16));
          gui->summary.startup_full_snapshot_current_bytes = *((ulong *)(msg + 24));
          gui->summary.startup_full_snapshot_elapsed_secs = *((double *)(msg + 32));
          gui->summary.startup_full_snapshot_remaining_secs = *((double *)(msg + 40));
          gui->summary.startup_full_snapshot_throughput = *((double *)(msg + 48));
          FD_LOG_INFO(( "progress: downloading full snapshot: slot=%lu", gui->summary.startup_full_snapshot_slot ));
      } else {
          gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_INCREMENTAL_SNAPSHOT;
          gui->summary.startup_incremental_snapshot_slot = *((ulong *)(msg + 2));
          gui->summary.startup_incremental_snapshot_peer_ip_addr = *((uint *)(msg + 10));
          gui->summary.startup_incremental_snapshot_peer_port = *((ushort *)(msg + 14));
          gui->summary.startup_incremental_snapshot_total_bytes = *((ulong *)(msg + 16));
          gui->summary.startup_incremental_snapshot_current_bytes = *((ulong *)(msg + 24));
          gui->summary.startup_incremental_snapshot_elapsed_secs = *((double *)(msg + 32));
          gui->summary.startup_incremental_snapshot_remaining_secs = *((double *)(msg + 40));
          gui->summary.startup_incremental_snapshot_throughput = *((double *)(msg + 48));
          FD_LOG_INFO(( "progress: downloading incremental snapshot: slot=%lu", gui->summary.startup_incremental_snapshot_slot ));
      }
      break;
    }
    case 3: {
      gui->summary.startup_got_full_snapshot = 1;
      break;
    }
    case 4:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_CLEANING_BLOCK_STORE;
      FD_LOG_INFO(( "progress: cleaning block store" ));
      break;
    case 5:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_CLEANING_ACCOUNTS;
      FD_LOG_INFO(( "progress: cleaning accounts" ));
      break;
    case 6:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_LOADING_LEDGER;
      FD_LOG_INFO(( "progress: loading ledger" ));
      break;
    case 7: {
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_PROCESSING_LEDGER;
      gui->summary.startup_ledger_slot = fd_ulong_load_8( msg + 1 );
      gui->summary.startup_ledger_max_slot = fd_ulong_load_8( msg + 9 );
      FD_LOG_INFO(( "progress: processing ledger: slot=%lu, max_slot=%lu", gui->summary.startup_ledger_slot, gui->summary.startup_ledger_max_slot ));
      break;
    }
    case 8:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_STARTING_SERVICES;
      FD_LOG_INFO(( "progress: starting services" ));
      break;
    case 9:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_HALTED;
      FD_LOG_INFO(( "progress: halted" ));
      break;
    case 10: {
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY;
      gui->summary.startup_waiting_for_supermajority_slot = fd_ulong_load_8( msg + 1 );
      gui->summary.startup_waiting_for_supermajority_stake_pct = fd_ulong_load_8( msg + 9 );
      FD_LOG_INFO(( "progress: waiting for supermajority: slot=%lu, gossip_stake_percent=%lu", gui->summary.startup_waiting_for_supermajority_slot, gui->summary.startup_waiting_for_supermajority_stake_pct ));
      break;
    }
    case 11:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_RUNNING;
      FD_LOG_INFO(( "progress: running" ));
      break;
    default:
      FD_LOG_ERR(( "progress: unknown type: %u", type ));
  }

  fd_gui_printf_startup_progress( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
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
  memcpy( gui->block_engine.name,    update->name,    sizeof(gui->block_engine.name   )-1 );
  memcpy( gui->block_engine.url,     update->url,     sizeof(gui->block_engine.url    )-1 );
  memcpy( gui->block_engine.ip_cstr, update->ip_cstr, sizeof(gui->block_engine.ip_cstr)-1 );
  gui->block_engine.status = update->status;

  fd_gui_printf_block_engine( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg ) {

  switch( plugin_msg ) {
    case FD_PLUGIN_MSG_SLOT_ROOTED:
      fd_gui_handle_rooted_slot( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED:
      fd_gui_handle_optimistically_confirmed_slot( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_COMPLETED:
      fd_gui_handle_completed_slot( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_ESTIMATED:
      gui->summary.slot_estimated = *(ulong const *)msg;
      fd_gui_printf_estimated_slot( gui );
      fd_http_server_ws_broadcast( gui->http );
      break;
    case FD_PLUGIN_MSG_LEADER_SCHEDULE: {
      fd_gui_handle_leader_schedule( gui, (ulong const *)msg );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_START: {
      fd_gui_handle_slot_start( gui, (ulong *)msg );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_END: {
      fd_gui_handle_slot_end( gui, (ulong *)msg );
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
      fd_gui_handle_reset_slot( gui, (ulong *)msg );
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

static void
fd_gui_init_slot_txns( fd_gui_t * gui,
                       long       tickcount,
                       ulong      _slot ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  /* initialize reference timestamp */
  if ( FD_UNLIKELY( LONG_MAX==slot->txs.reference_ticks ) ) {
    slot->txs.reference_ticks = tickcount;
    slot->txs.reference_nanos = fd_log_wallclock() - (long)((double)(fd_tickcount() - slot->txs.reference_ticks) / fd_tempo_tick_per_ns( NULL ));
  }
}

void
fd_gui_became_leader( fd_gui_t * gui,
                      long       tickcount,
                      ulong      _slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks ) {
  fd_gui_init_slot_txns( gui, tickcount, _slot );
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  slot->max_compute_units = (uint)max_compute_units;

  slot->txs.leader_start_time = start_time_nanos;
  slot->txs.leader_end_time   = end_time_nanos;
  if( FD_LIKELY( slot->txs.microblocks_upper_bound==USHORT_MAX ) ) slot->txs.microblocks_upper_bound = (ushort)max_microblocks;

  // snapshot of bundle rx histogram at leader rotation start
  ulong bundle_tile_idx = fd_topo_find_tile( gui->topo, "bundle", 0UL );
  if( FD_UNLIKELY( bundle_tile_idx!=ULONG_MAX && _slot % 4 == 0 ) ) {
    fd_topo_tile_t const * bundle = &gui->topo->tiles[ bundle_tile_idx ];
    volatile ulong * bundle_metrics = fd_metrics_tile( bundle->metrics );
    (void)bundle_metrics;

    gui->bundle_rx_delay_hist_current->sum = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + FD_HISTF_BUCKET_CNT ];
    for( ulong b=0; b<FD_HISTF_BUCKET_CNT; b++ ) gui->bundle_rx_delay_hist_current->counts[ b ] = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + b ];

    gui->bundle_rx_delay_hist_reference->sum = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + FD_HISTF_BUCKET_CNT ];
    for( ulong b=0; b<FD_HISTF_BUCKET_CNT; b++ ) gui->bundle_rx_delay_hist_reference->counts[ b ] = bundle_metrics[ MIDX( HISTOGRAM, BUNDLE, MESSAGE_RX_DELAY_NANOS ) + b ];
  }
}

void
fd_gui_unbecame_leader( fd_gui_t * gui,
                        long       tickcount,
                        ulong      _slot,
                        ulong      microblocks_in_slot ) {
  fd_gui_init_slot_txns( gui, tickcount, _slot );
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  slot->txs.microblocks_upper_bound = (ushort)microblocks_in_slot;
}

void
fd_gui_microblock_execution_begin( fd_gui_t *   gui,
                                   long         tickcount,
                                   ulong        _slot,
                                   fd_txn_p_t * txns,
                                   ulong        txn_cnt,
                                   uint         microblock_idx,
                                   ulong        pack_txn_idx ) {
  fd_gui_init_slot_txns( gui, tickcount, _slot );
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  if( FD_UNLIKELY( slot->txs.start_offset==ULONG_MAX ) ) slot->txs.start_offset = pack_txn_idx;
  else                                                   slot->txs.start_offset = fd_ulong_min( slot->txs.start_offset, pack_txn_idx );

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
    txn_entry->timestamp_delta_start_nanos = (int)((double)(tickcount - slot->txs.reference_ticks) / fd_tempo_tick_per_ns( NULL ));
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
  slot->txs.begin_microblocks = (ushort)(slot->txs.begin_microblocks + txn_cnt);
}

void
fd_gui_microblock_execution_end( fd_gui_t *   gui,
                                 long         tickcount,
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

  fd_gui_init_slot_txns( gui, tickcount, _slot );
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  if( FD_UNLIKELY( slot->txs.end_offset==ULONG_MAX ) ) slot->txs.end_offset = pack_txn_idx + txn_cnt;
  else                                                 slot->txs.end_offset = fd_ulong_max( slot->txs.end_offset, pack_txn_idx+txn_cnt );

  gui->pack_txn_idx = fd_ulong_max( gui->pack_txn_idx, pack_txn_idx+txn_cnt-1UL );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn_p = &txns[ i ];

    fd_gui_txn_t * txn_entry = gui->txs[ (pack_txn_idx + i)%FD_GUI_TXN_HISTORY_SZ ];
    txn_entry->bank_idx                  = bank_idx                           & 0x3FU;
    txn_entry->compute_units_consumed    = txn_p->bank_cu.actual_consumed_cus & 0x1FFFFFU;
    txn_entry->error_code                = (txn_p->flags >> 24)               & 0x3FU;
    txn_entry->timestamp_delta_end_nanos = (int)((double)(tickcount - slot->txs.reference_ticks) / fd_tempo_tick_per_ns( NULL ));
    txn_entry->txn_start_pct             = txn_start_pct;
    txn_entry->txn_load_end_pct          = txn_load_end_pct;
    txn_entry->txn_end_pct               = txn_end_pct;
    txn_entry->txn_preload_end_pct       = txn_preload_end_pct;
    txn_entry->tips                      = tips;
    txn_entry->flags                    |= (uchar)FD_GUI_TXN_FLAGS_ENDED;
    txn_entry->flags                    &= (uchar)(~(uchar)FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK);
    txn_entry->flags                    |= (uchar)fd_uint_if(txn_p->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS, FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK, 0U);
  }

  slot->txs.end_microblocks = slot->txs.end_microblocks + (uint)txn_cnt;
}
