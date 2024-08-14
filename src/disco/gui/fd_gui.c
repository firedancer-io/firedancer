#include "fd_gui.h"
#include "fd_gui_printf.h"

#include "../fd_disco.h"
#include "../plugin/fd_plugin.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/json/cJSON.h"

#include "../../app/fdctl/config.h"

FD_FN_CONST ulong
fd_gui_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_gui_footprint( void ) {
  return sizeof(fd_gui_t);
}

void *
fd_gui_new( void *        shmem,
            fd_hcache_t * hcache,
            char const *  version,
            char const *  cluster,
            char const *  identity_key_base58,
            fd_topo_t *   topo ) {
  fd_gui_t * gui = (fd_gui_t *)shmem;

  gui->hcache = hcache;
  gui->topo   = topo;

  gui->summary.version             = version;
  gui->summary.cluster             = cluster;
  gui->summary.identity_key_base58 = identity_key_base58;

  gui->summary.slot_rooted                   = 0UL;
  gui->summary.slot_optimistically_confirmed = 0UL;
  gui->summary.slot_completed                = 0UL;
  gui->summary.slot_estimated                = 0UL;

  fd_memset( gui->summary.txn_info_prev, 0, sizeof(gui->summary.txn_info_prev[ 0 ]) );
  fd_memset( gui->summary.txn_info_this, 0, sizeof(gui->summary.txn_info_this[ 0 ]) );
  fd_memset( gui->summary.txn_info_json, 0, sizeof(gui->summary.txn_info_json[ 0 ]) );
  fd_memset( gui->summary.txn_info_slot, 0, sizeof(gui->summary.txn_info_slot) );
  gui->summary.became_leader_high_slot = 0;

  gui->next_sample_100millis = fd_log_wallclock();
  gui->next_sample_10millis  = fd_log_wallclock();

  gui->summary.net_tile_count    = fd_topo_tile_name_cnt( gui->topo, "net" );
  gui->summary.quic_tile_count   = fd_topo_tile_name_cnt( gui->topo, "quic" );
  gui->summary.verify_tile_count = fd_topo_tile_name_cnt( gui->topo, "verify" );
  gui->summary.bank_tile_count   = fd_topo_tile_name_cnt( gui->topo, "bank" );
  gui->summary.shred_tile_count  = fd_topo_tile_name_cnt( gui->topo, "shred" );

  fd_memset( gui->summary.tile_info, 0, sizeof(gui->summary.tile_info) );
  gui->summary.tile_info_sample_cnt = 0;
  gui->summary.last_tile_info_ts = fd_log_wallclock();

  gui->epoch.max_known_epoch = 1UL;
  fd_stake_weight_t dummy_stakes[1] = {{ .key = {{0}}, .stake = 1UL }};
  for( ulong i=0UL; i<FD_GUI_NUM_EPOCHS; i++ ) {
    gui->epoch.epochs[ i ].epoch          = i;
    gui->epoch.epochs[ i ].start_slot     = 0UL;
    gui->epoch.epochs[ i ].end_slot       = 0UL; // end_slot is inclusive.
    gui->epoch.epochs[ i ].excluded_stake = 0UL;
    gui->epoch.epochs[ i ].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[ i ]._lsched, 0UL, 0UL, 1UL, 1UL, dummy_stakes, 0UL ) );
    fd_memcpy( gui->epoch.epochs[ i ].stakes, dummy_stakes, sizeof(dummy_stakes[ 0 ]) );
  }

  gui->gossip.peer_cnt               = 0UL;
  gui->vote_account.vote_account_cnt = 0UL;
  gui->validator_info.info_cnt       = 0UL;

  return gui;
}

fd_gui_t *
fd_gui_join( void * shmem ) {
  return (fd_gui_t *)shmem;
}

void
fd_gui_ws_open( fd_gui_t * gui,
                ulong      ws_conn_id ) {
  void (* printers[] )( fd_gui_t * gui ) = {
    fd_gui_printf_version,
    fd_gui_printf_cluster,
    fd_gui_printf_identity_key,
    fd_gui_printf_root_slot,
    fd_gui_printf_optimistically_confirmed_slot,
    fd_gui_printf_completed_slot,
    fd_gui_printf_estimated_slot,
    fd_gui_printf_topology,
    fd_gui_printf_epoch1,
    fd_gui_printf_epoch2,
    fd_gui_printf_txn_info_summary,
    fd_gui_printf_peers_all,
  };

  ulong printers_len = sizeof(printers) / sizeof(printers[0]);
  for( ulong i=0UL; i<printers_len; i++ ) {
    printers[ i ]( gui );
    FD_TEST( !fd_hcache_snap_ws_send( gui->hcache, ws_conn_id ) );
  }
}

static void
fd_gui_sample_counters( fd_gui_t * gui ) {
  fd_topo_t * topo      = gui->topo;
  fd_gui_txn_info_t * txn_info = gui->summary.txn_info_this;
  ulong net_tile_cnt    = gui->summary.net_tile_count;
  ulong quic_tile_cnt   = gui->summary.quic_tile_count;
  ulong verify_tile_cnt = gui->summary.verify_tile_count;
  ulong bank_tile_cnt   = gui->summary.bank_tile_count;

  ulong bank_exec = 0UL;
  ulong bank_exec_success = 0UL;
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_tile_t const * bank = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];
    ulong * bank_metrics = fd_metrics_tile( bank->metrics );
    bank_exec_success += bank_metrics[ MIDX( COUNTER, BANK_TILE, TRANSACTION_EXECUTED_SUCCESS ) ];
    bank_exec += bank_metrics[ MIDX( COUNTER, BANK_TILE, TRANSACTION_EXECUTING_SUCCESS ) ];
  }
  ulong bank_exec_failure = bank_exec - bank_exec_success;

  fd_topo_tile_t const * pack = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  ulong * pack_metrics = fd_metrics_tile( pack->metrics );
  ulong pack_invalid = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_WRITE_SYSVAR ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ESTIMATION_FAIL ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE_ACCOUNT ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_MANY_ACCOUNTS ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_LARGE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_EXPIRED ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ADDR_LUT ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_UNAFFORDABLE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_EXPIRED ) ];
  ulong pack_nonleader = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_FROM_EXTRA ) ];
  ulong pack_priority = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_PRIORITY ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_NONVOTE_REPLACE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_VOTE_REPLACE ) ];
  ulong pack_sent = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_SCHEDULE_TAKEN ) ];
  ulong pack_buffered = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TO_EXTRA ) ]-
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_FROM_EXTRA ) ];

  /* We read bank_exec first, and then pack_sent.  Otherwise, bank_exec
     might be larger than pack_sent by the time we read it, leading to
     an underflow for the subtraction.
     In general, we read values downstream before we read values
     further upstream the TPU pipeline, so subtractions don't
     underflow. */
  ulong bank_invalid = pack_sent - bank_exec;

  fd_topo_tile_t const * dedup = &topo->tiles[ fd_topo_find_tile( topo, "dedup", 0UL ) ];
  ulong * dedup_metrics = fd_metrics_tile( dedup->metrics );
  ulong gossip_recv = dedup_metrics[ MIDX( COUNTER, DEDUP, GOSSIPED_VOTES_RECEIVED ) ];
  ulong dedup_drop = 0UL;
  for( ulong i=0UL; i<verify_tile_cnt; i++ ) {
    dedup_drop += fd_metrics_link_in( dedup->metrics, i )[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
  }

  ulong verify_drop    = 0UL;
  ulong verify_sent    = 0UL;
  ulong verify_overrun = 0UL;
  for( ulong i=0UL; i<verify_tile_cnt; i++ ) {
    fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
    for( ulong j=0UL; i<quic_tile_cnt; i++ ) {
      verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / verify_tile_cnt;
      verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ] / verify_tile_cnt;
      verify_drop += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
      verify_sent += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_PUBLISHED_COUNT_OFF ];
    }
  }

  ulong quic_recv = 0UL;
  ulong quic_sent = 0UL;
  ulong quic_overrun = 0UL;
  for( ulong i=0UL; i<quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    quic_sent += quic_metrics[ MIDX( COUNTER, QUIC_TILE, REASSEMBLY_NOTIFY_OKAY ) ];
    quic_recv += quic_metrics[ MIDX( COUNTER, QUIC_TILE, REASSEMBLY_NOTIFY_ATTEMPTED ) ];
    for( ulong j=0UL; i<net_tile_cnt; i++ ) {
      quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / quic_tile_cnt;
      quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ] / quic_tile_cnt;
    }
  }
  ulong quic_reasm = quic_recv - quic_sent;

  ulong nonquic_recv = 0UL;
  ulong nonquic_sent = 0UL;
  ulong net_overrun = 0UL; // TODO
  ulong net_invalid = 0UL;
  for( ulong i=0UL; i<quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    net_invalid += quic_metrics[ MIDX( COUNTER, QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL ) ];
    net_invalid += quic_metrics[ MIDX( COUNTER, QUIC_TILE, NON_QUIC_PACKET_TOO_LARGE ) ];
    nonquic_sent += quic_metrics[ MIDX( COUNTER, QUIC_TILE, LEGACY_NOTIFY_OKAY ) ];
    nonquic_recv += quic_metrics[ MIDX( COUNTER, QUIC_TILE, LEGACY_NOTIFY_ATTEMPTED ) ];
    net_invalid += nonquic_recv - nonquic_sent;
  }

  txn_info->acquired_txns_quic = quic_recv + quic_overrun;
  txn_info->acquired_txns_nonquic = nonquic_sent + net_overrun + net_invalid;
  txn_info->acquired_txns_gossip = gossip_recv;
  txn_info->dropped_txns_net_overrun = net_overrun;
  txn_info->dropped_txns_net_invalid = net_invalid;
  txn_info->dropped_txns_quic_overrun = quic_overrun;
  txn_info->dropped_txns_quic_reasm = quic_reasm;
  txn_info->dropped_txns_verify_overrun = verify_overrun;
  txn_info->dropped_txns_verify_drop = verify_drop;
  txn_info->dropped_txns_dedup_drop = dedup_drop;
  txn_info->dropped_txns_pack_nonleader = pack_nonleader;
  txn_info->dropped_txns_pack_invalid = pack_invalid;
  txn_info->dropped_txns_pack_priority = pack_priority;
  txn_info->dropped_txns_bank_invalid = bank_invalid;
  txn_info->executed_txns_failure = bank_exec_failure;
  txn_info->executed_txns_success = bank_exec_success;
  txn_info->dropped_txns = txn_info->dropped_txns_net_overrun +
                          txn_info->dropped_txns_net_invalid +
                          txn_info->dropped_txns_quic_overrun +
                          txn_info->dropped_txns_quic_reasm +
                          txn_info->dropped_txns_verify_overrun +
                          txn_info->dropped_txns_verify_drop +
                          txn_info->dropped_txns_dedup_drop +
                          txn_info->dropped_txns_pack_nonleader +
                          txn_info->dropped_txns_pack_invalid +
                          txn_info->dropped_txns_pack_priority +
                          txn_info->dropped_txns_bank_invalid;
  txn_info->buffered_txns = pack_buffered;

  fd_gui_txn_info_t * txn_info_prev = gui->summary.txn_info_prev;
  fd_gui_txn_info_t * txn_info_json = gui->summary.txn_info_json;
  txn_info_json->acquired_txns_quic = txn_info->acquired_txns_quic - txn_info_prev->acquired_txns_quic;
  txn_info_json->acquired_txns_nonquic = txn_info->acquired_txns_nonquic - txn_info_prev->acquired_txns_nonquic;
  txn_info_json->acquired_txns_gossip = txn_info->acquired_txns_gossip - txn_info_prev->acquired_txns_gossip;
  txn_info_json->dropped_txns = txn_info->dropped_txns - txn_info_prev->dropped_txns;
  txn_info_json->dropped_txns_net_overrun = txn_info->dropped_txns_net_overrun - txn_info_prev->dropped_txns_net_overrun;
  txn_info_json->dropped_txns_net_invalid = txn_info->dropped_txns_net_invalid - txn_info_prev->dropped_txns_net_invalid;
  txn_info_json->dropped_txns_quic_overrun = txn_info->dropped_txns_quic_overrun - txn_info_prev->dropped_txns_quic_overrun;
  txn_info_json->dropped_txns_quic_reasm = txn_info->dropped_txns_quic_reasm - txn_info_prev->dropped_txns_quic_reasm;
  txn_info_json->dropped_txns_verify_overrun = txn_info->dropped_txns_verify_overrun - txn_info_prev->dropped_txns_verify_overrun;
  txn_info_json->dropped_txns_verify_drop = txn_info->dropped_txns_verify_drop - txn_info_prev->dropped_txns_verify_drop;
  txn_info_json->dropped_txns_dedup_drop = txn_info->dropped_txns_dedup_drop - txn_info_prev->dropped_txns_dedup_drop;
  txn_info_json->dropped_txns_pack_nonleader = txn_info->dropped_txns_pack_nonleader - txn_info_prev->dropped_txns_pack_nonleader;
  txn_info_json->dropped_txns_pack_invalid = txn_info->dropped_txns_pack_invalid - txn_info_prev->dropped_txns_pack_invalid;
  txn_info_json->dropped_txns_pack_priority = txn_info->dropped_txns_pack_priority - txn_info_prev->dropped_txns_pack_priority;
  txn_info_json->dropped_txns_bank_invalid = txn_info->dropped_txns_bank_invalid - txn_info_prev->dropped_txns_bank_invalid;
  txn_info_json->executed_txns_failure = txn_info->executed_txns_failure - txn_info_prev->executed_txns_failure;
  txn_info_json->executed_txns_success = txn_info->executed_txns_success - txn_info_prev->executed_txns_success;
  txn_info_json->buffered_txns = txn_info->buffered_txns;
  txn_info_json->acquired_txns = txn_info->acquired_txns_leftover +
                                txn_info->acquired_txns_quic +
                                txn_info->acquired_txns_nonquic +
                                txn_info->acquired_txns_gossip -
                                txn_info_prev->acquired_txns_quic -
                                txn_info_prev->acquired_txns_nonquic -
                                txn_info_prev->acquired_txns_gossip;
  /* Clear numbers that are just underflows due to jitter. */
  ulong * val = fd_type_pun( txn_info_json );
  for( ulong i = 0; i < sizeof(*txn_info_json) / sizeof(*val); i++ ) {
    if( val[i] > ULONG_MAX / 2 ) {
      val[i] = 0;
    }
  }
}

static void
fd_gui_sample_tiles( fd_gui_t * gui ) {
  for( ulong i=0UL; i<gui->topo->tile_cnt; i++ ) {
    fd_gui_tile_info_t * tile_info = gui->summary.tile_info + ( 2 * i + ( gui->summary.tile_info_sample_cnt % 2 ) );
    fd_topo_tile_t * tile = &gui->topo->tiles[ i ];

    if ( FD_UNLIKELY( !tile->metrics ) ) {
      /* bench tiles might not have been booted initially.
         This check shouldn't be necessary if all tiles barrier after boot. */
      continue;
    }
    fd_metrics_register( tile->metrics );

    tile_info->housekeeping_ticks       = FD_MHIST_SUM( STEM, LOOP_HOUSEKEEPING_DURATION_SECONDS );
    tile_info->backpressure_ticks       = FD_MHIST_SUM( STEM, LOOP_BACKPRESSURE_DURATION_SECONDS );
    tile_info->caught_up_ticks          = FD_MHIST_SUM( STEM, LOOP_CAUGHT_UP_DURATION_SECONDS );
    tile_info->overrun_polling_ticks    = FD_MHIST_SUM( STEM, LOOP_OVERRUN_POLLING_DURATION_SECONDS );
    tile_info->overrun_reading_ticks    = FD_MHIST_SUM( STEM, LOOP_OVERRUN_READING_DURATION_SECONDS );
    tile_info->filter_before_frag_ticks = FD_MHIST_SUM( STEM, LOOP_FILTER_BEFORE_FRAGMENT_DURATION_SECONDS );
    tile_info->filter_after_frag_ticks  = FD_MHIST_SUM( STEM, LOOP_FILTER_AFTER_FRAGMENT_DURATION_SECONDS );
    tile_info->finish_ticks             = FD_MHIST_SUM( STEM, LOOP_FINISH_DURATION_SECONDS );
  }

  gui->summary.tile_info_sample_cnt++;
}

void
fd_gui_poll( fd_gui_t * gui ) {
  long current = fd_log_wallclock();

  if( FD_LIKELY( current>gui->next_sample_100millis ) ) {
    fd_gui_sample_counters( gui );

    fd_gui_printf_txn_info_summary( gui );
    fd_hcache_snap_ws_broadcast( gui->hcache );

    gui->next_sample_100millis += 100L*1000L*1000L;
  }
  if( FD_LIKELY( current>gui->next_sample_10millis ) ) {
    fd_gui_sample_tiles( gui );

    fd_gui_printf_tile_info( gui );
    fd_hcache_snap_ws_broadcast( gui->hcache );

    gui->next_sample_10millis += 10L*1000L*1000L;
  }
}

static void
fd_gui_handle_gossip_update( fd_gui_t *    gui,
                             uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  ulong added_cnt = 0UL;
  ulong added[ 40200 ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ 40200 ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ 40200 ] = {0};

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
        fd_memcpy( &gui->gossip.peers[ i ], &gui->gossip.peers[ gui->gossip.peer_cnt-1UL ], sizeof(struct fd_gui_gossip_peer) );
        gui->gossip.peer_cnt--;
        i--;
      }
    }
  }

  ulong before_peer_cnt = gui->gossip.peer_cnt;
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int found = 0;
    ulong found_idx;
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
      int peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].shred_version!=*(ushort const *)(data+i*(58UL+12UL*6UL)+40UL) ||
                          gui->gossip.peers[ gui->gossip.peer_cnt ].wallclock!=*(ulong const *)(data+i*(58UL+12UL*6UL)+32UL) ||
                          gui->gossip.peers[ gui->gossip.peer_cnt ].has_version!=*(data+i*(58UL+12UL*6UL)+42UL);
      if( FD_LIKELY( !peer_updated && gui->gossip.peers[ gui->gossip.peer_cnt ].has_version ) ) {
        peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].version.major!=*(ushort const *)(data+i*(58UL+12UL*6UL)+43UL) ||
                        gui->gossip.peers[ gui->gossip.peer_cnt ].version.minor!=*(ushort const *)(data+i*(58UL+12UL*6UL)+45UL) ||
                        gui->gossip.peers[ gui->gossip.peer_cnt ].version.patch!=*(ushort const *)(data+i*(58UL+12UL*6UL)+47UL) ||
                        gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit!=*(data+i*(58UL+12UL*6UL)+49UL) ||
                        (gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit && gui->gossip.peers[ gui->gossip.peer_cnt ].version.commit!=*(uint const *)(data+i*(58UL+12UL*6UL)+50UL)) ||
                        gui->gossip.peers[ gui->gossip.peer_cnt ].version.feature_set!=*(uint const *)(data+i*(58UL+12UL*6UL)+54UL);

        if( FD_LIKELY( !peer_updated ) ) {
          for( ulong j=0UL; j<12UL; j++ ) {
            peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].ipv4!=*(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL) ||
                            gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].port!=*(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
            if( FD_LIKELY( peer_updated ) ) break;
          }
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
          gui->gossip.peers[ gui->gossip.peer_cnt ].version.feature_set = *(uint const *)(data+i*(58UL+12UL*6UL)+54UL);
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
  fd_hcache_snap_ws_broadcast( gui->hcache );
}

static void
fd_gui_handle_vote_account_update( fd_gui_t *    gui,
                                   uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  ulong added_cnt = 0UL;
  ulong added[ 40200 ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ 40200 ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ 40200 ] = {0};

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
        fd_memcpy( &gui->vote_account.vote_accounts[ i ], &gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt-1UL ], sizeof(struct fd_gui_vote_account) );
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
        memcmp( gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].pubkey->uc, data+i*112UL+32UL, 32UL ) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].activated_stake != *(ulong const *)(data+i*112UL+64UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].last_vote       != *(ulong const *)(data+i*112UL+72UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].root_slot       != *(ulong const *)(data+i*112UL+80UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].epoch_credits   != *(ulong const *)(data+i*112UL+88UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].commission      != *(data+i*112UL+96UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].delinquent      != *(data+i*112UL+97UL);

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
  fd_hcache_snap_ws_broadcast( gui->hcache );
}

static void
fd_gui_handle_validator_info_update( fd_gui_t *    gui,
                                     uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  ulong added_cnt = 0UL;
  ulong added[ 40200 ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ 40200 ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ 40200 ] = {0};

  uchar const * data = (uchar const *)(header+1UL);
  for( ulong i=0UL; i<gui->validator_info.info_cnt; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ i ].pubkey, data+j*608UL, 32UL ) ) ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( removed[ removed_cnt++ ].uc, gui->validator_info.info[ i ].pubkey->uc, 32UL );
      if( FD_LIKELY( i+1UL!=gui->validator_info.info_cnt ) ) {
        fd_memcpy( &gui->validator_info.info[ i ], &gui->validator_info.info[ gui->validator_info.info_cnt-1UL ], sizeof(struct fd_gui_validator_info) );
        gui->validator_info.info_cnt--;
        i--;
      }
    }
  }

  ulong before_peer_cnt = gui->validator_info.info_cnt;
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int found = 0;
    ulong found_idx;
    for( ulong j=0UL; j<gui->validator_info.info_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ j ].pubkey, data+i*608UL, 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data+i*608UL, 32UL );

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+i*608UL+32UL), 64 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].name[ 63 ] = '\0';

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+i*608UL+96UL), 128 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].website[ 127 ] = '\0';

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+i*608UL+224UL), 256 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].details[ 255 ] = '\0';

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+i*608UL+480UL), 128 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri[ 127 ] = '\0';

      gui->validator_info.info_cnt++;
    } else {
      int peer_updated =
        memcmp( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data+i*608UL, 32UL ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+i*608UL+32UL), 64 ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+i*608UL+96UL), 128 ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+i*608UL+224UL), 256 ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+i*608UL+480UL), 128 );

      if( FD_UNLIKELY( peer_updated ) ) {
        updated[ update_cnt++ ] = found_idx;

        fd_memcpy( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data+i*608UL, 32UL );

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+i*608UL+32UL), 64 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].name[ 63 ] = '\0';

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+i*608UL+96UL), 128 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].website[ 127 ] = '\0';

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+i*608UL+224UL), 256 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].details[ 255 ] = '\0';

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+i*608UL+480UL), 128 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri[ 127 ] = '\0';
      }
    }
  }

  added_cnt = gui->validator_info.info_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->validator_info.info_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_printf_peers_validator_info_update( gui, updated, update_cnt, removed, removed_cnt, added, added_cnt );
  fd_hcache_snap_ws_broadcast( gui->hcache );
}

FD_FN_UNUSED static fd_gui_txn_info_t *
fd_gui_get_txn_info_for_slot( fd_gui_t * gui,
                              ulong      slot ) {
  fd_gui_txn_info_t * dst_txn_info = NULL;
  for( ulong idx=0UL; idx<FD_GUI_NUM_EPOCHS; idx++ ) {
    if( FD_LIKELY( slot>=gui->epoch.epochs[ idx ].start_slot && slot<=gui->epoch.epochs[ idx ].end_slot ) ) {
      if( slot==gui->summary.txn_info_slot[ idx ][ slot - gui->epoch.epochs[ idx ].start_slot ] ) {
        dst_txn_info = &(gui->summary.txn_info_hist[ idx ][ slot - gui->epoch.epochs[ idx ].start_slot ]);
      }
    }
  }
  return dst_txn_info;
}

static void
fd_gui_set_txn_info_for_slot( fd_gui_t *                gui,
                              ulong const               slot,
                              fd_gui_txn_info_t const * txn_info ) {
  fd_gui_txn_info_t * dst_txn_info = NULL;
  ulong *             dst_slot     = NULL;
  for( ulong idx=0UL; idx<FD_GUI_NUM_EPOCHS; idx++ ) {
    if( slot>=gui->epoch.epochs[ idx ].start_slot && slot<=gui->epoch.epochs[ idx ].end_slot ) {
      dst_txn_info = &(gui->summary.txn_info_hist[ idx ][ slot - gui->epoch.epochs[ idx ].start_slot ]);
      dst_slot = &(gui->summary.txn_info_slot[ idx ][ slot - gui->epoch.epochs[ idx ].start_slot ]);
      break;
    }
  }
  if( FD_LIKELY( dst_txn_info ) ) {
    fd_memcpy( dst_txn_info, txn_info, sizeof(*dst_txn_info) );
    *dst_slot = slot;
  }
}

void
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len ) {
  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)data, data_len, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) {
    return;
  }

  const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "seq" );
  if( FD_UNLIKELY( !cJSON_IsNumber( node ) ) ) {
    goto GUI_WS_MESSAGE_CLEANUP;
  }
  ulong seq = node->valueulong;
  (void)seq;
  node = cJSON_GetObjectItemCaseSensitive( json, "query" );
  if( FD_UNLIKELY( !cJSON_IsString( node ) || node->valuestring==NULL ) ) {
    goto GUI_WS_MESSAGE_CLEANUP;
  }

  if( !strncmp( node->valuestring, "txn_info", strlen( "txn_info" ) ) ) {
    node = cJSON_GetObjectItemCaseSensitive( json, "args" );
    if( FD_UNLIKELY( !cJSON_IsArray( node ) || cJSON_GetArraySize( node )!=1 ) ) {
      goto GUI_WS_MESSAGE_CLEANUP;
    }
    node = cJSON_GetArrayItem( node, 0 );
    if( FD_UNLIKELY( !cJSON_IsNumber( node ) ) ) {
      goto GUI_WS_MESSAGE_CLEANUP;
    }
    ulong slot = node->valueulong;
    fd_gui_txn_info_t * txn_info = fd_gui_get_txn_info_for_slot( gui, slot );
    if( txn_info ) {
      fd_gui_printf_txn_info_summary_this( gui, txn_info, slot );
      FD_TEST( !fd_hcache_snap_ws_send( gui->hcache, ws_conn_id ) );
      // FD_LOG_NOTICE(( "txn_info slot=%lu queried and replied", slot ));
      goto GUI_WS_MESSAGE_CLEANUP;
    }
  }

GUI_WS_MESSAGE_CLEANUP:
  cJSON_Delete( json );
  return;
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len ) {
  (void)msg_len;

  FD_LOG_NOTICE(( "Start handling" ));
  long current = fd_log_wallclock();

  ulong msg_type = fd_plugin_sig_msg_type( plugin_msg );
  ulong slot     = fd_plugin_sig_slot( plugin_msg );
  switch( msg_type ) {
    case FD_PLUGIN_MSG_SLOT_ROOTED:
      gui->summary.slot_rooted = *(ulong const *)msg;
      fd_gui_printf_root_slot( gui );
      fd_hcache_snap_ws_broadcast( gui->hcache );
      break;
    case FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED:
      gui->summary.slot_optimistically_confirmed = *(ulong const *)msg;
      fd_gui_printf_optimistically_confirmed_slot( gui );
      fd_hcache_snap_ws_broadcast( gui->hcache );
      break;
    case FD_PLUGIN_MSG_SLOT_COMPLETED:
      gui->summary.slot_completed = *(ulong const *)msg;
      fd_gui_printf_completed_slot( gui );
      fd_hcache_snap_ws_broadcast( gui->hcache );
      FD_LOG_NOTICE(( "broadcast slot %lu", gui->summary.slot_completed ));
      break;
    case FD_PLUGIN_MSG_SLOT_ESTIMATED:
      gui->summary.slot_estimated = *(ulong const *)msg;
      fd_gui_printf_estimated_slot( gui );
      fd_hcache_snap_ws_broadcast( gui->hcache );
      break;
    case FD_PLUGIN_MSG_LEADER_SCHEDULE: {
      ulong const * hdr         = fd_type_pun_const( msg );
      ulong epoch               = hdr[ 0 ];
      ulong staked_cnt          = hdr[ 1 ];
      ulong start_slot          = hdr[ 2 ];
      ulong slot_cnt            = hdr[ 3 ];
      ulong excluded_stake      = hdr[ 4 ];

      if( FD_UNLIKELY( staked_cnt>MAX_PUB_CNT ) ) FD_LOG_ERR(( "staked_cnt %lu too large", staked_cnt ));

      if( FD_LIKELY( epoch>gui->epoch.max_known_epoch ) ) gui->epoch.max_known_epoch = epoch;
      ulong idx = epoch % FD_GUI_NUM_EPOCHS;
      gui->epoch.epochs[ idx ].epoch          = epoch;
      gui->epoch.epochs[ idx ].start_slot     = start_slot;
      gui->epoch.epochs[ idx ].end_slot       = start_slot + slot_cnt - 1; // end_slot is inclusive.
      gui->epoch.epochs[ idx ].excluded_stake = excluded_stake;
      fd_epoch_leaders_delete( fd_epoch_leaders_leave( gui->epoch.epochs[ idx ].lsched ) );
      gui->epoch.epochs[idx].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[ idx ]._lsched,
                                                                                   epoch,
                                                                                   gui->epoch.epochs[ idx ].start_slot,
                                                                                   slot_cnt,
                                                                                   staked_cnt,
                                                                                   fd_type_pun_const( hdr + 5UL ),
                                                                                   excluded_stake ) );
      fd_memcpy( gui->epoch.epochs[ idx ].stakes, fd_type_pun_const( hdr+5UL ), staked_cnt*sizeof(gui->epoch.epochs[ idx ].stakes[ 0 ]) );

      fd_gui_printf_epoch( gui, idx );
      fd_hcache_snap_ws_broadcast( gui->hcache );
      break;
    }
    case FD_PLUGIN_MSG_BECAME_LEADER: {
      // static long last_became = 0;
      // long current_became = fd_log_wallclock();
      // FD_LOG_NOTICE(( "%lu nanos since we last became leader txn_info_json->acquired_txns %lu", current_became - last_became, gui->summary.txn_info_json->acquired_txns ));
      // last_became = current_became;
      if( FD_UNLIKELY( slot<gui->summary.became_leader_high_slot ) ) {
        FD_LOG_ERR(( "unexpected leader slot regression %lu->%lu", gui->summary.became_leader_high_slot, slot ));
      }
      if( FD_UNLIKELY( gui->summary.became_leader_high_slot == 0 ) ) {
        /* First time we became leader this instance started.
           Take a snapshot of counters. */
        fd_gui_sample_counters( gui );
        fd_gui_txn_info_t * txn_info = gui->summary.txn_info_this;
        fd_memcpy( gui->summary.txn_info_prev, txn_info, sizeof(gui->summary.txn_info_prev[ 0 ]) );
        fd_memset( txn_info, 0, sizeof(*txn_info) );
        txn_info->acquired_txns_leftover = gui->summary.txn_info_prev->buffered_txns;
      }
      gui->summary.became_leader_high_slot = slot;
      break;
    }
    case FD_PLUGIN_MSG_DONE_PACKING: {
      if( FD_UNLIKELY( slot<gui->summary.became_leader_high_slot ) ) {
        FD_LOG_NOTICE(( "DONE_PACKING slot regression %lu->%lu might have been a fork switch", gui->summary.became_leader_high_slot, slot ));
      } else if( FD_UNLIKELY( slot>gui->summary.became_leader_high_slot ) ) {
        FD_LOG_ERR(( "DONE_PACKING came for slot %lu largest known leader slot %lu", slot, gui->summary.became_leader_high_slot ));
      } else {
        fd_gui_sample_counters( gui );
        /* Store counters for the slot we just finished. */
        fd_gui_set_txn_info_for_slot( gui, slot, gui->summary.txn_info_json );
        /* Initialize things for the upcoming slot. */
        fd_gui_txn_info_t * txn_info = gui->summary.txn_info_this;
        fd_memcpy( gui->summary.txn_info_prev, txn_info, sizeof(gui->summary.txn_info_prev[ 0 ]) );
        fd_memset( txn_info, 0, sizeof(*txn_info) );
        txn_info->acquired_txns_leftover = gui->summary.txn_info_prev->buffered_txns;
      }
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
    default:
      FD_LOG_ERR(( "Unhandled plugin msg: 0x%lx", plugin_msg ));
      break;
  }

  FD_LOG_NOTICE(( "plugin_msg 0x%lx handled in %lu nanos", plugin_msg, fd_log_wallclock() - current ));
}
