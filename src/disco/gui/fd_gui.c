#include "fd_gui.h"
#include "fd_gui_printf.h"
#include "fd_gui_metrics.h"
#include "fd_gui_hist.h"

#include "../metrics/fd_metrics.h"
#include "../../discof/gossip/fd_gossip_tile.h"
#include "../bundle/fd_bundle_tile.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../third_party/cjson/cJSON.h"
#include "../../disco/genesis/fd_genesis_cluster.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../shred/fd_shred_tile.h"

#include <stdio.h>

FD_STATIC_ASSERT( FD_FEC_SHRED_CNT==32UL, timeline_fec_ordinal_contract );
FD_STATIC_ASSERT( FD_GUI_TXN_BATCH_MAX_TXN<=UCHAR_MAX, txn_batch_count_fits );
FD_STATIC_ASSERT( FD_MAX_TXN_PER_SLOT<=UINT_MAX, txn_batch_member_idx_fits );

fd_gui_timeline_granularity_t const fd_gui_timeline_granularities[ FD_GUI_TIMELINE_GRANULARITY_CNT ] = {
  { "250ms",    250000000UL, FD_GUI_TIMELINE_STORED_250MS, 1UL },
  { "500ms",    500000000UL, FD_GUI_TIMELINE_STORED_250MS, 2UL },
  { "1s",      1000000000UL, FD_GUI_TIMELINE_STORED_250MS, 4UL },
  { "2s",      2000000000UL, FD_GUI_TIMELINE_STORED_2S,    1UL },
  { "4s",      4000000000UL, FD_GUI_TIMELINE_STORED_2S,    2UL },
  { "8s",      8000000000UL, FD_GUI_TIMELINE_STORED_2S,    4UL },
  { "15s",    15000000000UL, FD_GUI_TIMELINE_STORED_15S,   1UL },
  { "30s",    30000000000UL, FD_GUI_TIMELINE_STORED_15S,   2UL },
  { "1m",     60000000000UL, FD_GUI_TIMELINE_STORED_15S,   4UL },
  { "2m",    120000000000UL, FD_GUI_TIMELINE_STORED_2M,    1UL },
  { "4m",    240000000000UL, FD_GUI_TIMELINE_STORED_2M,    2UL },
  { "8m",    480000000000UL, FD_GUI_TIMELINE_STORED_2M,    4UL },
  { "15m",   900000000000UL, FD_GUI_TIMELINE_STORED_15M,   1UL },
  { "30m",  1800000000000UL, FD_GUI_TIMELINE_STORED_15M,   2UL },
  { "1h",   3600000000000UL, FD_GUI_TIMELINE_STORED_15M,   4UL },
  { "2h",   7200000000000UL, FD_GUI_TIMELINE_STORED_2H,    1UL },
  { "4h",  14400000000000UL, FD_GUI_TIMELINE_STORED_2H,    2UL },
  { "8h",  28800000000000UL, FD_GUI_TIMELINE_STORED_2H,    4UL },
  { "12h", 43200000000000UL, FD_GUI_TIMELINE_STORED_12H,   1UL },
  { "1d",  86400000000000UL, FD_GUI_TIMELINE_STORED_12H,   2UL }
};

ulong const fd_gui_timeline_stored_granularity_ns[ FD_GUI_TIMELINE_STORED_GRANULARITY_CNT ] = {
  250000000UL, 2000000000UL, 15000000000UL, 120000000000UL,
  900000000000UL, 7200000000000UL, 43200000000000UL
};

ulong const fd_gui_timeline_stored_granularity_off[ FD_GUI_TIMELINE_STORED_GRANULARITY_CNT ] = {
  FD_GUI_TIMELINE_250MS_OFF, FD_GUI_TIMELINE_2S_OFF,  FD_GUI_TIMELINE_15S_OFF,
  FD_GUI_TIMELINE_2M_OFF,    FD_GUI_TIMELINE_15M_OFF, FD_GUI_TIMELINE_2H_OFF,
  FD_GUI_TIMELINE_12H_OFF
};

FD_FN_CONST ulong
fd_gui_align( void ) {
  return 128UL;
}

ulong
fd_gui_footprint( ulong tile_cnt ) {
  FD_TEST( tile_cnt && tile_cnt <=FD_TOPO_MAX_TILES );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_gui_align(),            sizeof(fd_gui_t) );
  l = FD_LAYOUT_APPEND( l, fd_gui_rate_deque_align(), fd_gui_rate_deque_footprint() ); /* ingress_maxq */
  l = FD_LAYOUT_APPEND( l, fd_gui_rate_deque_align(), fd_gui_rate_deque_footprint() ); /* egress_maxq  */
  l = FD_LAYOUT_APPEND( l, fd_gui_hist_align(),       fd_gui_hist_footprint() );
  return FD_LAYOUT_FINI( l, fd_gui_align() );
}

static inline ulong
fd_gui_fec_event_cache_idx( uint   slot,
                            ushort idx,
                            uchar  event ) {
  FD_STATIC_ASSERT( !(FD_GUI_FEC_EVENT_CACHE_CNT & (FD_GUI_FEC_EVENT_CACHE_CNT-1UL)), fec_event_cache_pow2 );
  ulong key = ((ulong)slot<<24) | ((ulong)idx<<8) | (ulong)event;
  return fd_ulong_hash( key ) & (FD_GUI_FEC_EVENT_CACHE_CNT-1UL);
}

/* Materialize the minimum timestamp observed for each
   (slot,FEC-ordinal,event) key.  This gives repair-request and receive events
   the first matching shred timestamp, replay-done the first replay completion
   touching the FEC, and published the common FEC publication timestamp.
   Slot-complete uses the same reducer with a null ordinal and remains one
   slot-wide row.

   A direct-mapped cache keeps the hot working set cheap.  On collision, a new
   candidate is appended; FEC granularity queries perform the authoritative
   reduction across retained candidates. */
static void
fd_gui_fec_event_append( fd_gui_t * gui,
                         ulong      slot,
                         ulong      idx,
                         ulong      event,
                         long       now,
                         long       timestamp ) {
  fd_gui_slot_history_event_t value = {
    .timestamp = fd_gui_hist_ts_clamp( now, timestamp ),
    .slot      = (uint)slot,
    .idx       = (ushort)idx,
    .event     = (uchar)event
  };

  fd_gui_fec_event_cache_entry_t * cached = &gui->fec_events[ fd_gui_fec_event_cache_idx( value.slot, value.idx, value.event ) ];
  if( FD_LIKELY( cached->valid &&
                 cached->slot ==value.slot &&
                 cached->idx  ==value.idx  &&
                 cached->event==value.event ) ) {
    if( FD_LIKELY( cached->timestamp<=value.timestamp ) ) return;
  }

  if( FD_LIKELY( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, now, value.timestamp, &value ) ) ) {
    cached->timestamp = value.timestamp;
    cached->slot      = value.slot;
    cached->idx       = value.idx;
    cached->event     = value.event;
    cached->valid     = 1U;
  }
}

static void
fd_gui_shred_event_append( fd_gui_t * gui,
                           ulong      slot,
                           ulong      shred_idx,
                           ulong      fec_idx,
                           ulong      event,
                           long       now,
                           long       timestamp ) {
  fd_gui_slot_history_event_t value = {
    .timestamp = timestamp,
    .slot      = (uint)slot,
    .idx       = (ushort)shred_idx,
    .event     = (uchar)event
  };
  fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, now, timestamp, &value );
  fd_gui_fec_event_append( gui, slot, fec_idx, event, now, timestamp );
}

static inline int
fd_gui_shreds_window_is_empty( fd_gui_t * gui,
                               long       after_ns,
                               long       before_ns ) {
  if( FD_UNLIKELY( !gui->db ) ) return 1;

  fd_gui_hist_iter_t it;
  if( FD_UNLIKELY( fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_SHRED_EVENTS, after_ns, before_ns, NULL, NULL ) ) ) return 1;
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_slot_history_event_t const * e = (fd_gui_slot_history_event_t const *)it.rec;
    if( FD_UNLIKELY( e->timestamp<after_ns || e->timestamp>before_ns ) ) continue;
    fd_gui_hist_range_end( &it );
    return 0;
  }
  fd_gui_hist_range_end( &it );
  return 1;
}

static inline void
fd_gui_build_tile_order( fd_gui_t * gui ) {
  ulong tile_cnt   = gui->topo->tile_cnt;
  ulong order_cnt  = 0UL;
  uchar placed[ FD_TOPO_MAX_TILES ] = {0};

  char const * const tile_display_order[] = {
    "gossvf", "gossip", "snapct", "snapld", "snapdc", "snapin", "snapwr",
    "net", "shred", "repair", "replay", "execrp", "tower", "txsend", "sign",
    "quic", "verify", "dedup", "pack", "execle", "poh"
  };

  for( ulong n=0UL; n<sizeof(tile_display_order)/sizeof(tile_display_order[0]); n++ ) {
    for( ulong i=0UL; i<tile_cnt; i++ ) {
      if( FD_LIKELY( placed[ i ] ) ) continue;
      if( FD_UNLIKELY( !strcmp( gui->topo->tiles[ i ].name, tile_display_order[ n ] ) ) ) {
        gui->summary.tile[ order_cnt++ ] = i;
        placed[ i ] = 1;
      }
    }
  }

  for( ulong i=0UL; i<tile_cnt; i++ ) {
    if( FD_UNLIKELY( !placed[ i ] ) ) gui->summary.tile[ order_cnt++ ] = i;
  }

  gui->summary.tile_cnt = order_cnt;
}

void *
fd_gui_new( void *                   shmem,
            fd_http_server_t *       http,
            char const *             version,
            char const *             cluster,
            uchar const *            identity_key,
            int                      has_vote_key,
            uchar const *            vote_key,
            int                      is_full_client,
            int                      snapshots_enabled,
            int                      is_voting,
            int                      schedule_strategy,
            char const *             wfs_expected_bank_hash_cstr,
            ushort                   expected_shred_version,
            char const *             accounts_database_path,
            char const *             gui_database_path,
            void *                   db,
            fd_alloc_t *             alloc,
            fd_topo_t const *        topo,
            fd_accdb_shmem_t const * accdb_shmem,
            long                     now ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( topo->tile_cnt>FD_TOPO_MAX_TILES ) ) {
    FD_LOG_WARNING(( "too many tiles" ));
    return NULL;
  }

  ulong tile_cnt = topo->tile_cnt;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gui_t * gui              = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),            sizeof(fd_gui_t) );
  void *     ingress_maxq_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_rate_deque_align(), fd_gui_rate_deque_footprint() );
  void *     egress_maxq_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_rate_deque_align(), fd_gui_rate_deque_footprint() );
  void *     hist_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_hist_align(),       fd_gui_hist_footprint() );

  gui->http        = http;
  gui->alloc       = alloc;
  gui->topo        = topo;
  gui->accdb_shmem = accdb_shmem;
  gui->tick_per_ns = fd_tempo_tick_per_ns( NULL );
  gui->tile_cnt    = tile_cnt;

  gui->db   = db;
  gui->hist = fd_gui_hist_join( fd_gui_hist_new( hist_mem, (fd_gui_store_t const *)db ) );
  if( FD_UNLIKELY( !gui->hist ) ) {
    FD_LOG_WARNING(( "fd_gui_hist_new failed" ));
    return NULL;
  }

  gui->summary.ingress_maxq = fd_gui_rate_deque_join( fd_gui_rate_deque_new( ingress_maxq_mem ) );
  gui->summary.egress_maxq  = fd_gui_rate_deque_join( fd_gui_rate_deque_new( egress_maxq_mem  ) );

  gui->summary.network_stats_has_prev = 0;
  gui->summary.net_rate_prev_ts       = 0L;
  for( ulong i=0UL; i<FD_GUI_NET_PROTO_CNT; i++ ) {
    fd_gui_ema_init( &gui->summary.ingress_ema[ i ], now, FD_GUI_NETWORK_EMA_HALF_LIFE_NS );
    fd_gui_ema_init( &gui->summary.egress_ema [ i ], now, FD_GUI_NETWORK_EMA_HALF_LIFE_NS );
  }

  gui->leader_active = 0;
  gui->leader_slot_pending     = ULONG_MAX;
  gui->leader_bank_seq_pending = ULONG_MAX;

  gui->summary.slot_tower  = ULONG_MAX;
  gui->summary.slot_tower_bank_seq = ULONG_MAX;
  gui->summary.schedule_strategy = schedule_strategy;


  gui->next_sample_1sec      = now;
  gui->next_sample_200millis = now;
  gui->next_sample_100millis = now;
  gui->next_sample_50millis  = now;
  gui->next_sample_40millis  = now;
  gui->next_sample_25millis  = now;
  gui->next_sample_10millis  = now;

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
  fd_cstr_ncpy( gui->summary.accounts_database_path, accounts_database_path, sizeof(gui->summary.accounts_database_path) );
  fd_cstr_ncpy( gui->summary.gui_database_path, gui_database_path, sizeof(gui->summary.gui_database_path) );
  gui->summary.startup_time_nanos            = gui->next_sample_200millis;
  gui->summary.expected_shred_version        = expected_shred_version;
  gui->summary.wfs_enabled          = 0;
  gui->summary.wfs_bank_hash[ 0UL ] = '\0';

  {
    fd_cstr_ncpy( gui->summary.wfs_bank_hash, wfs_expected_bank_hash_cstr, sizeof(gui->summary.wfs_bank_hash) );
    gui->summary.wfs_enabled = !!strcmp( wfs_expected_bank_hash_cstr, "" );

    if( FD_UNLIKELY( snapshots_enabled ) ) {
      gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_JOINING_GOSSIP;
      gui->summary.boot_progress.joining_gossip_time_nanos = gui->next_sample_200millis;
      memset( gui->summary.boot_progress.loading_snapshot, 0, sizeof(gui->summary.boot_progress.loading_snapshot) );
      for( ulong i=0UL; i<FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT; i++ ) {
        gui->summary.boot_progress.loading_snapshot[ i ].reset_cnt = ULONG_MAX; /* ensures other fields are reset initially */
        gui->summary.boot_progress.loading_snapshot[ i ].slot = ULONG_MAX;
      }
      gui->summary.boot_progress.catching_up_time_nanos        = 0L;
      gui->summary.boot_progress.catching_up_first_replay_slot = ULONG_MAX;
      gui->summary.boot_progress.wfs_total_stake     = 0UL;
      gui->summary.boot_progress.wfs_connected_stake = 0UL;
      gui->summary.boot_progress.wfs_total_peers     = 0UL;
      gui->summary.boot_progress.wfs_connected_peers = 0UL;
      gui->summary.boot_progress.wfs_attempt         = 0UL;
    } else {
      fd_memset( &gui->summary.boot_progress, 0, sizeof(gui->summary.boot_progress) );
      gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_RUNNING;
    }
  }

  gui->summary.identity_account_balance      = 0UL;
  gui->summary.vote_account_balance          = 0UL;
  gui->summary.vote_commission               = USHORT_MAX;
  gui->summary.estimated_slot_duration_nanos = 0UL;

  gui->summary.vote_distance = 0UL;
  gui->summary.vote_state = is_voting ? FD_GUI_VOTE_STATE_VOTING : FD_GUI_VOTE_STATE_NON_VOTING;

  gui->summary.sock_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "sock"   );
  gui->summary.net_tile_cnt    = fd_topo_tile_name_cnt( gui->topo, "net"    );
  gui->summary.quic_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "quic"   );
  gui->summary.verify_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "verify" );
  gui->summary.resolh_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "resolh" );
  gui->summary.resolv_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "resolv" );
  gui->summary.bank_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "bank"   );
  gui->summary.execle_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "execle" );
  gui->summary.execrp_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "execrp" );
  gui->summary.shred_tile_cnt  = fd_topo_tile_name_cnt( gui->topo, "shred"  );

  fd_gui_build_tile_order( gui );

  gui->summary.slot_rooted                   = ULONG_MAX;
  gui->summary.slot_optimistically_confirmed = ULONG_MAX;
  gui->summary.slot_estimated                = ULONG_MAX;
  gui->summary.slot_caught_up                = ULONG_MAX;
  gui->summary.slot_repair                   = ULONG_MAX;
  gui->summary.slot_turbine                  = ULONG_MAX;
  gui->summary.slot_reset                    = ULONG_MAX;
  gui->summary.slot_storage                  = ULONG_MAX;
  gui->summary.active_fork_cnt               = 1UL;

  memset( gui->summary.skip_rate, 0, sizeof(gui->summary.skip_rate) );
  gui->summary.skip_rate[ 0 ].epoch = ULONG_MAX;
  gui->summary.skip_rate[ 1 ].epoch = ULONG_MAX;

  for( ulong i=0UL; i < (FD_GUI_REPAIR_SLOT_HISTORY_SZ+1UL); i++ )  gui->summary.slots_max_repair[ i ].slot  = ULONG_MAX;
  for( ulong i=0UL; i < (FD_GUI_TURBINE_SLOT_HISTORY_SZ+1UL); i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;

  for( ulong i=0UL; i < FD_GUI_TURBINE_RECV_TIMESTAMPS; i++ ) gui->turbine_slots[ i ].slot = ULONG_MAX;

  gui->summary.estimated_tps_history_idx = 0UL;
  memset( gui->summary.estimated_tps_history, 0, sizeof(gui->summary.estimated_tps_history) );

  memset( gui->summary.txn_waterfall_reference, 0, sizeof(gui->summary.txn_waterfall_reference) );
  memset( gui->summary.txn_waterfall_current,   0, sizeof(gui->summary.txn_waterfall_current)   );

  memset( gui->summary.tile_stats_reference, 0, sizeof(gui->summary.tile_stats_reference) );
  memset( gui->summary.tile_stats_current, 0, sizeof(gui->summary.tile_stats_current) );

  gui->summary.progcache_history_idx = 0UL;
  memset( gui->summary.progcache_hits_history,    0, sizeof(gui->summary.progcache_hits_history) );
  memset( gui->summary.progcache_lookups_history, 0, sizeof(gui->summary.progcache_lookups_history) );
  gui->summary.progcache_hits_1min    = 0UL;
  gui->summary.progcache_lookups_1min = 0UL;

  memset( gui->summary.accounts_stats_reference, 0, sizeof(gui->summary.accounts_stats_reference) );
  memset( gui->summary.accounts_stats_current,   0, sizeof(gui->summary.accounts_stats_current  ) );
  gui->summary.accounts_stats_have_reference = 0;
  gui->summary.accdb->accdb_win_idx   = 0UL;
  gui->summary.accdb->accdb_win_count = 0UL;
  memset( gui->summary.accdb->accdb_win_dt_nanos,           0, sizeof(gui->summary.accdb->accdb_win_dt_nanos)           );
  memset( gui->summary.accdb->agg_acquired_win,             0, sizeof(gui->summary.accdb->agg_acquired_win)             );
  memset( gui->summary.accdb->agg_acquired_writable_win,    0, sizeof(gui->summary.accdb->agg_acquired_writable_win)    );
  memset( gui->summary.accdb->agg_bytes_read_win,           0, sizeof(gui->summary.accdb->agg_bytes_read_win)           );
  memset( gui->summary.accdb->agg_bytes_copied_win,         0, sizeof(gui->summary.accdb->agg_bytes_copied_win)         );
  memset( gui->summary.accdb->agg_bytes_written_win,        0, sizeof(gui->summary.accdb->agg_bytes_written_win)        );
  memset( gui->summary.accdb->agg_bytes_written_accdb_win,  0, sizeof(gui->summary.accdb->agg_bytes_written_accdb_win)  );
  memset( gui->summary.accdb->agg_read_ops_win,             0, sizeof(gui->summary.accdb->agg_read_ops_win)             );
  memset( gui->summary.accdb->agg_write_ops_win,            0, sizeof(gui->summary.accdb->agg_write_ops_win)            );
  memset( gui->summary.accdb->agg_relocated_bytes_win,      0, sizeof(gui->summary.accdb->agg_relocated_bytes_win)      );
  memset( gui->summary.accdb->agg_misses_win,               0, sizeof(gui->summary.accdb->agg_misses_win)               );
  memset( gui->summary.accdb->class_acq_win,                0, sizeof(gui->summary.accdb->class_acq_win)                );
  memset( gui->summary.accdb->class_acq_wr_win,             0, sizeof(gui->summary.accdb->class_acq_wr_win)             );
  memset( gui->summary.accdb->class_not_found_win,          0, sizeof(gui->summary.accdb->class_not_found_win)          );
  memset( gui->summary.accdb->class_evicted_win,            0, sizeof(gui->summary.accdb->class_evicted_win)            );
  memset( gui->summary.accdb->class_preevicted_win,         0, sizeof(gui->summary.accdb->class_preevicted_win)         );
  memset( gui->summary.accdb->class_commit_new_win,         0, sizeof(gui->summary.accdb->class_commit_new_win)         );
  memset( gui->summary.accdb->class_commit_over_win,        0, sizeof(gui->summary.accdb->class_commit_over_win)        );

  gui->summary.accdb->partition_cnt = 0UL;
  memset( gui->summary.accdb->partition_read_ops_win,        0, sizeof(gui->summary.accdb->partition_read_ops_win)        );
  memset( gui->summary.accdb->partition_bytes_read_win,      0, sizeof(gui->summary.accdb->partition_bytes_read_win)      );
  memset( gui->summary.accdb->partition_write_ops_win,       0, sizeof(gui->summary.accdb->partition_write_ops_win)       );
  memset( gui->summary.accdb->partition_bytes_written_win,   0, sizeof(gui->summary.accdb->partition_bytes_written_win)   );
  memset( gui->summary.accdb->partitions,                    0, sizeof(gui->summary.accdb->partitions)                    );
  memset( gui->summary.accdb->partition_prev_read_ops,       0, sizeof(gui->summary.accdb->partition_prev_read_ops)       );
  memset( gui->summary.accdb->partition_prev_bytes_read,     0, sizeof(gui->summary.accdb->partition_prev_bytes_read)     );
  memset( gui->summary.accdb->partition_prev_write_ops,      0, sizeof(gui->summary.accdb->partition_prev_write_ops)      );
  memset( gui->summary.accdb->partition_prev_bytes_written,  0, sizeof(gui->summary.accdb->partition_prev_bytes_written)  );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    fd_gui_ema_init( &gui->summary.accdb->tier_fill_bps_ema[ k ], now, FD_GUI_ACCDB_EMA_HALF_LIFE_NS );
    fd_gui_ema_init( &gui->summary.accdb->tier_free_bps_ema[ k ], now, FD_GUI_ACCDB_EMA_HALF_LIFE_NS );
  }
  gui->summary.accdb->tier_sample_nanos              = LONG_MAX;
  gui->summary.accdb->next_compaction_remaining_secs = 0.0;
  gui->summary.accdb->next_compaction_partition_idx  = ULONG_MAX;

  /* Build the per-tile accdb slot table from the topology.  Order
     matters only for stable JSON ordering: RW joiners first, RO
     joiners, then snapwr at the end. */
  gui->summary.accdb->accdb_tile_cnt = 0UL;
  static const struct { char const * name; uchar kind; } accdb_kinds[] = {
    { "execle", FD_GUI_ACCDB_TILE_KIND_RW     },
    { "execrp", FD_GUI_ACCDB_TILE_KIND_RW     },
    { "replay", FD_GUI_ACCDB_TILE_KIND_RW     },
    { "tower",  FD_GUI_ACCDB_TILE_KIND_RW     },
    { "rpc",    FD_GUI_ACCDB_TILE_KIND_RO     },
    { "resolv", FD_GUI_ACCDB_TILE_KIND_RO     },
    { "snapwr", FD_GUI_ACCDB_TILE_KIND_SNAPWR },
    { "accdb",  FD_GUI_ACCDB_TILE_KIND_ACCDB  },
  };
  for( ulong k=0UL; k<sizeof(accdb_kinds)/sizeof(accdb_kinds[0]); k++ ) {
    ulong cnt = fd_topo_tile_name_cnt( gui->topo, accdb_kinds[ k ].name );
    for( ulong i=0UL; i<cnt; i++ ) {
      ulong t_idx = fd_topo_find_tile( gui->topo, accdb_kinds[ k ].name, i );
      if( FD_UNLIKELY( t_idx==ULONG_MAX ) ) continue;
      if( FD_UNLIKELY( gui->summary.accdb->accdb_tile_cnt>=FD_GUI_MAX_ACCDB_TILES ) ) {
        FD_LOG_ERR(( "too many accdb consumer tiles (limit %lu)", FD_GUI_MAX_ACCDB_TILES ));
      }
      ulong slot = gui->summary.accdb->accdb_tile_cnt++;
      gui->summary.accdb->accdb_tile_topo_idx[ slot ] = (ushort)t_idx;
      gui->summary.accdb->accdb_tile_kind    [ slot ] = accdb_kinds[ k ].kind;
    }
  }
  memset( gui->summary.accdb->tile_cur_acquired,           0, sizeof(gui->summary.accdb->tile_cur_acquired)           );
  memset( gui->summary.accdb->tile_cur_acquired_writable,  0, sizeof(gui->summary.accdb->tile_cur_acquired_writable)  );
  memset( gui->summary.accdb->tile_cur_bytes_read,         0, sizeof(gui->summary.accdb->tile_cur_bytes_read)         );
  memset( gui->summary.accdb->tile_cur_bytes_copied,       0, sizeof(gui->summary.accdb->tile_cur_bytes_copied)       );
  memset( gui->summary.accdb->tile_cur_bytes_written,      0, sizeof(gui->summary.accdb->tile_cur_bytes_written)      );
  memset( gui->summary.accdb->tile_cur_read_ops,           0, sizeof(gui->summary.accdb->tile_cur_read_ops)           );
  memset( gui->summary.accdb->tile_cur_write_ops,          0, sizeof(gui->summary.accdb->tile_cur_write_ops)          );
  memset( gui->summary.accdb->tile_cur_misses,             0, sizeof(gui->summary.accdb->tile_cur_misses)             );
  memset( gui->summary.accdb->tile_cur_evicted,            0, sizeof(gui->summary.accdb->tile_cur_evicted)            );
  memset( gui->summary.accdb->tile_cur_committed,          0, sizeof(gui->summary.accdb->tile_cur_committed)          );
  memset( gui->summary.accdb->tile_cur_acquire_calls,      0, sizeof(gui->summary.accdb->tile_cur_acquire_calls)      );
  memset( gui->summary.accdb->tile_cur_status,             0, sizeof(gui->summary.accdb->tile_cur_status)             );
  memset( gui->summary.accdb->tile_prev_acquired,          0, sizeof(gui->summary.accdb->tile_prev_acquired)          );
  memset( gui->summary.accdb->tile_prev_acquired_writable, 0, sizeof(gui->summary.accdb->tile_prev_acquired_writable) );
  memset( gui->summary.accdb->tile_prev_bytes_read,        0, sizeof(gui->summary.accdb->tile_prev_bytes_read)        );
  memset( gui->summary.accdb->tile_prev_bytes_copied,      0, sizeof(gui->summary.accdb->tile_prev_bytes_copied)      );
  memset( gui->summary.accdb->tile_prev_bytes_written,     0, sizeof(gui->summary.accdb->tile_prev_bytes_written)     );
  memset( gui->summary.accdb->tile_prev_read_ops,          0, sizeof(gui->summary.accdb->tile_prev_read_ops)          );
  memset( gui->summary.accdb->tile_prev_write_ops,         0, sizeof(gui->summary.accdb->tile_prev_write_ops)         );
  memset( gui->summary.accdb->tile_prev_misses,            0, sizeof(gui->summary.accdb->tile_prev_misses)            );
  memset( gui->summary.accdb->tile_prev_evicted,           0, sizeof(gui->summary.accdb->tile_prev_evicted)           );
  memset( gui->summary.accdb->tile_prev_committed,         0, sizeof(gui->summary.accdb->tile_prev_committed)         );
  memset( gui->summary.accdb->tile_prev_acquire_calls,     0, sizeof(gui->summary.accdb->tile_prev_acquire_calls)     );
  memset( gui->summary.accdb->tile_acquired_win,           0, sizeof(gui->summary.accdb->tile_acquired_win)           );
  memset( gui->summary.accdb->tile_acquired_writable_win,  0, sizeof(gui->summary.accdb->tile_acquired_writable_win)  );
  memset( gui->summary.accdb->tile_bytes_read_win,         0, sizeof(gui->summary.accdb->tile_bytes_read_win)         );
  memset( gui->summary.accdb->tile_bytes_copied_win,       0, sizeof(gui->summary.accdb->tile_bytes_copied_win)       );
  memset( gui->summary.accdb->tile_bytes_written_win,      0, sizeof(gui->summary.accdb->tile_bytes_written_win)      );
  memset( gui->summary.accdb->tile_read_ops_win,           0, sizeof(gui->summary.accdb->tile_read_ops_win)           );
  memset( gui->summary.accdb->tile_write_ops_win,          0, sizeof(gui->summary.accdb->tile_write_ops_win)          );
  memset( gui->summary.accdb->tile_misses_win,             0, sizeof(gui->summary.accdb->tile_misses_win)             );
  memset( gui->summary.accdb->tile_evicted_win,            0, sizeof(gui->summary.accdb->tile_evicted_win)            );
  memset( gui->summary.accdb->tile_committed_win,          0, sizeof(gui->summary.accdb->tile_committed_win)          );
  memset( gui->summary.accdb->tile_acquire_calls_win,      0, sizeof(gui->summary.accdb->tile_acquire_calls_win)      );

  memset( gui->summary.accdb->tile_sparkline_bucket_start_nanos, 0, sizeof(gui->summary.accdb->tile_sparkline_bucket_start_nanos) );
  memset( gui->summary.accdb->tile_sparkline_acq_bucket,         0, sizeof(gui->summary.accdb->tile_sparkline_acq_bucket)         );
  memset( gui->summary.accdb->tile_sparkline_acq_wr_bucket,      0, sizeof(gui->summary.accdb->tile_sparkline_acq_wr_bucket)      );
  memset( gui->summary.accdb->tile_sparkline_acq_history,        0, sizeof(gui->summary.accdb->tile_sparkline_acq_history)        );
  memset( gui->summary.accdb->tile_sparkline_acq_wr_history,     0, sizeof(gui->summary.accdb->tile_sparkline_acq_wr_history)     );
  memset( gui->summary.accdb->tile_sparkline_count,              0, sizeof(gui->summary.accdb->tile_sparkline_count)              );

  memset( gui->summary.tile_timers_reference, 0, sizeof(gui->summary.tile_timers_reference) );
  memset( gui->summary.tile_timers_current,   0, sizeof(gui->summary.tile_timers_current)   );
  memset( gui->summary.tile_timers_packed,    0, sizeof(gui->summary.tile_timers_packed)    );

  gui->landed_vote_cnt = 0UL;

  gui->block_engine.has_block_engine = 0;

  gui->epoch.current_epoch      = ULONG_MAX;
  gui->epoch.has_epoch_schedule = 0;
  gui->epoch.stored_epoch_cnt   = 0UL;

  gui->shreds.leader_shred_cnt        = 0UL;
  gui->shreds.broadcast_watermark_ns  = now;
  memset( gui->fec_events, 0, sizeof(gui->fec_events) );
  gui->timeline_day_max               = ULONG_MAX;
  gui->timeline_skipped_slot_watermark     = ULONG_MAX;
  gui->timeline_skipped_bank_seq_watermark = ULONG_MAX;
  gui->timeline_skipped_coverage_start_ns  = LONG_MAX;
  gui->timeline_skipped_coverage_end_ns    = LONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_SHRED_BUF_CNT; i++ ) gui->timeline_shreds[ i ].slot = ULONG_MAX;
  gui->summary.catch_up_repair_sz     = 0UL;
  gui->summary.catch_up_turbine_sz    = 0UL;

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

  gui->summary.vote_distance = 0UL;
  if( FD_LIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_NON_VOTING ) ) gui->summary.vote_state = FD_GUI_VOTE_STATE_VOTING;
  gui->landed_vote_cnt = 0UL;

  fd_gui_printf_identity_key( gui );
  fd_http_server_ws_broadcast( gui->http );
  fd_gui_printf_vote_distance( gui );
  fd_http_server_ws_broadcast( gui->http );
  fd_gui_printf_vote_state( gui );
  fd_http_server_ws_broadcast( gui->http );
  fd_gui_printf_late_votes_history( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_ws_open( fd_gui_t * gui,
                ulong      ws_conn_id,
                long now ) {
  void (* printers[] )( fd_gui_t * gui ) = {
    fd_gui_printf_boot_progress,
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
    fd_gui_printf_tps_history,
    fd_gui_printf_tiles,
    fd_gui_printf_schedule_strategy,
    fd_gui_printf_identity_balance,
    fd_gui_printf_vote_balance,
    fd_gui_printf_vote_commission,
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
    fd_gui_printf_late_votes_history,
    fd_gui_printf_health
  };

  ulong printers_len = sizeof(printers) / sizeof(printers[0]);
  for( ulong i=0UL; i<printers_len; i++ ) {
    printers[ i ]( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  {
    fd_gui_printf_live_program_cache( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );

    if( FD_LIKELY( gui->summary.accounts_stats_have_reference ) ) {
      fd_gui_printf_accounts_stats( gui );
      FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    }
  }

  if( FD_LIKELY( gui->block_engine.has_block_engine ) ) {
    fd_gui_printf_block_engine( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  if( FD_LIKELY( gui->epoch.current_epoch!=ULONG_MAX ) ) {
    for( ulong e=gui->epoch.current_epoch; e<=gui->epoch.current_epoch+1UL; e++ ) {
      if( FD_LIKELY( fd_gui_epoch( gui, e ) ) ) {
        fd_gui_printf_skip_rate( gui, e );
        FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
        fd_gui_printf_epoch( gui, e );
        FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
      }
    }

    fd_gui_printf_skipped_history( gui, gui->epoch.current_epoch );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    fd_gui_printf_skipped_history_cluster( gui, gui->epoch.current_epoch );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  /* rebroadcast 10s of historical shred data */
  long const shred_history_start = now-10L*1000L*1000L*1000L;
  if( FD_LIKELY( !fd_gui_shreds_window_is_empty( gui, shred_history_start, now ) ) ) {
    fd_gui_printf_shred_rebroadcast( gui, shred_history_start, now );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }
}



static inline ushort
fd_gui_tile_timers_pct( ulong delta, ulong total ) {
  if( FD_UNLIKELY( !total ) ) return USHORT_MAX;
  double percent = ( (double)delta / (double)total ) * 100.0;
  long   hundredths = (long)( percent * 100.0 );
  if( FD_UNLIKELY( hundredths<0L ) ) hundredths = 0L;
  if( FD_UNLIKELY( hundredths>(USHORT_MAX-1U) ) ) hundredths = (USHORT_MAX-1U);
  return (ushort)hundredths;
}

void
fd_gui_tile_timers_diff( fd_gui_tile_timers_hist_t *  out,
                         fd_gui_tile_timers_t const * prev,
                         fd_gui_tile_timers_t const * cur,
                         ulong                        tile_idx,
                         long                         sample_time_nanos ) {
  memset( out, 0, sizeof(*out) );
  out->sample_time_nanos = sample_time_nanos;
  out->tile_idx = (ushort)tile_idx;

  ulong cur_total = 0UL, prev_total = 0UL;
  for( ulong j=0UL; j<FD_METRICS_ENUM_TILE_REGIME_CNT; j++ ) {
    cur_total += cur->timers[ j ]; prev_total += prev->timers[ j ];
  }
  ulong busy = cur_total - prev_total;
  for( ulong j=0UL; j<FD_METRICS_ENUM_TILE_REGIME_CNT; j++ ) {
    out->timers[ j ] = fd_gui_tile_timers_pct( cur->timers[ j ] - prev->timers[ j ], busy );
  }
  if( FD_UNLIKELY( !busy ) ) {
    out->idle_ratio = USHORT_MAX;
  } else {
    ulong idle = cur->timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_POSTFRAG_IDX   ] - prev->timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_POSTFRAG_IDX   ];
    ulong bp   = cur->timers[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_PREFRAG_IDX ] - prev->timers[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_PREFRAG_IDX ];
    out->idle_ratio = fd_gui_tile_timers_pct( idle+bp, busy );
  }

  ulong cur_ctot = 0UL, prev_ctot = 0UL;
  for( ulong j=0UL; j<FD_METRICS_ENUM_CPU_REGIME_CNT; j++ ) { cur_ctot += cur->sched_timers[ j ]; prev_ctot += prev->sched_timers[ j ]; }
  ulong cbusy = cur_ctot - prev_ctot;
  for( ulong j=0UL; j<FD_METRICS_ENUM_CPU_REGIME_CNT; j++ ) {
    out->sched_timers[ j ] = fd_gui_tile_timers_pct( cur->sched_timers[ j ] - prev->sched_timers[ j ], cbusy );
  }

  out->alive    = (uchar)fd_ulong_if( cur->status==2U, 2UL, (ulong)( cur->heartbeat>prev->heartbeat ) );
  out->in_backp = (uchar)( !!cur->in_backp );
  out->last_cpu = cur->last_cpu;

  out->backp_msgs     = cur->backp_cnt;
  out->nvcsw          = cur->nvcsw;
  out->nivcsw         = cur->nivcsw;
  out->minflt         = cur->minflt;
  out->majflt         = cur->majflt;
  out->interrupts     = cur->interrupts;
  out->tlb_shootdowns = cur->tlb_shootdowns;
  out->timer_ticks    = cur->timer_ticks;
}

static void
fd_gui_tile_timers_snap( fd_gui_t * gui, long now ) {
  fd_gui_tile_timers_t * cur = gui->summary.tile_timers_current;
  fd_memcpy( gui->summary.tile_timers_reference, cur, gui->tile_cnt * sizeof(fd_gui_tile_timers_t) );
  for( ulong i=0UL; i<gui->topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &gui->topo->tiles[ i ];
    /* NULL when the tile's metrics live in a workspace not mapped to
       this tile (e.g. bench tiles use the "bench" workspace, not
       "metric_in"). */
    if( FD_UNLIKELY( !tile->metrics ) ) continue;
    volatile ulong const * tile_metrics = fd_metrics_tile( tile->metrics );

    cur[ i ].sample_time_nanos = now;

    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_HOUSEKEEPING_IDX    ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING )    ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_HOUSEKEEPING_IDX   ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING )   ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_HOUSEKEEPING_IDX ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING ) ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_PREFRAG_IDX         ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG )         ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_PREFRAG_IDX        ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_PREFRAG )        ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_PREFRAG_IDX      ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG )      ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_POSTFRAG_IDX        ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG )        ];
    cur[ i ].timers[ FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_POSTFRAG_IDX       ] = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_POSTFRAG )       ];

    cur[ i ].sched_timers[ FD_METRICS_ENUM_CPU_REGIME_V_WAIT_IDX      ] = tile_metrics[ MIDX( COUNTER, TILE, CPU_DURATION_NANOS_WAIT )      ];
    cur[ i ].sched_timers[ FD_METRICS_ENUM_CPU_REGIME_V_USER_IDX      ] = tile_metrics[ MIDX( COUNTER, TILE, CPU_DURATION_NANOS_USER )      ];
    cur[ i ].sched_timers[ FD_METRICS_ENUM_CPU_REGIME_V_SYSTEM_IDX    ] = tile_metrics[ MIDX( COUNTER, TILE, CPU_DURATION_NANOS_SYSTEM )    ];
    cur[ i ].sched_timers[ FD_METRICS_ENUM_CPU_REGIME_V_IDLE_IDX      ] = tile_metrics[ MIDX( COUNTER, TILE, CPU_DURATION_NANOS_IDLE )      ];
    cur[ i ].sched_timers[ FD_METRICS_ENUM_CPU_REGIME_V_INTERRUPT_IDX ] = tile_metrics[ MIDX( COUNTER, TILE, CPU_DURATION_NANOS_INTERRUPT ) ];

    cur[ i ].in_backp  = (int)tile_metrics[ MIDX(GAUGE, TILE, IN_BACKPRESSURE) ];
    cur[ i ].status    = (uchar)tile_metrics[ MIDX( GAUGE, TILE, STATUS ) ];
    cur[ i ].heartbeat = tile_metrics[ MIDX( GAUGE, TILE, HEARTBEAT_TIMESTAMP_NANOS ) ];
    cur[ i ].backp_cnt = tile_metrics[ MIDX( COUNTER, TILE, BACKPRESSURE ) ];
    cur[ i ].nvcsw     = tile_metrics[ MIDX( COUNTER, TILE, CONTEXT_SWITCH_VOLUNTARY ) ];
    cur[ i ].nivcsw    = tile_metrics[ MIDX( COUNTER, TILE, CONTEXT_SWITCH_INVOLUNTARY ) ];
    cur[ i ].minflt    = tile_metrics[ MIDX( COUNTER, TILE, PAGE_FAULT_MINOR ) ];
    cur[ i ].majflt    = tile_metrics[ MIDX( COUNTER, TILE, PAGE_FAULT_MAJOR ) ];
    cur[ i ].last_cpu  = (ushort)tile_metrics[ MIDX( GAUGE, TILE, LAST_CPU ) ];
    cur[ i ].interrupts     = tile_metrics[ MIDX( COUNTER, TILE, IRQ_PREEMPTED ) ];
    cur[ i ].tlb_shootdowns = tile_metrics[ MIDX( COUNTER, TILE, TLB_SHOOTDOWN ) ];
    cur[ i ].timer_ticks    = tile_metrics[ MIDX( COUNTER, TILE, TIMER_TICK ) ];
  }

  for( ulong i=0UL; i<gui->tile_cnt; i++ ) {
    cur[ i ].tile_idx = i;
    fd_gui_tile_timers_diff( &gui->summary.tile_timers_packed[ i ], &gui->summary.tile_timers_reference[ i ], &cur[ i ], i, now );
  }
}

static void
fd_gui_scheduler_counts_snap( fd_gui_t * gui, long now ) {
  ulong pack_tile_idx = fd_topo_find_tile( gui->topo, "pack", 0UL );
  if( FD_UNLIKELY( pack_tile_idx==ULONG_MAX ) ) return;

  fd_gui_scheduler_counts_t cur[ 1 ];

  fd_topo_tile_t const * pack = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "pack", 0UL ) ];
  volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );

  cur->sample_time_ns = now;

  cur->regular     = pack_metrics[ MIDX( GAUGE, PACK, TXN_AVAILABLE_REGULAR ) ];
  cur->votes       = pack_metrics[ MIDX( GAUGE, PACK, TXN_AVAILABLE_VOTES ) ];
  cur->conflicting = pack_metrics[ MIDX( GAUGE, PACK, TXN_AVAILABLE_CONFLICTING ) ];
  cur->bundles     = pack_metrics[ MIDX( GAUGE, PACK, TXN_AVAILABLE_BUNDLES ) ];

  fd_gui_hist_ts_append( gui, FD_GUI_HIST_SCHEDULER_COUNTS, now, now, cur );
}

static void
fd_gui_estimated_tps_snap( fd_gui_t * gui ) {
  ulong vote_failed     = 0UL;
  ulong vote_success    = 0UL;
  ulong nonvote_success = 0UL;
  ulong nonvote_failed  = 0UL;

  if( FD_LIKELY( gui->summary.slot_tower==ULONG_MAX ) ) return;
  ulong first_replay_slot = fd_gui_first_replay_slot( gui );
  for( ulong i=0UL; i<fd_ulong_min( gui->summary.slot_tower+1UL, MAX_SLOTS_PER_EPOCH ); i++ ) {
    ulong _slot = gui->summary.slot_tower-i;
    if( FD_UNLIKELY( first_replay_slot!=ULONG_MAX && _slot<first_replay_slot ) ) break;
    fd_gui_slot_t const * slot = fd_gui_slot_get_canon( gui, _slot );
    if( FD_UNLIKELY( !slot ) ) continue;
    if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) continue; /* Slot is on this fork but was never completed, must have been in root path on boot. */
    if( FD_UNLIKELY( slot->completed_time+FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS*1000L*1000L*1000L<gui->next_sample_200millis ) ) break; /* Slot too old. */
    if( FD_UNLIKELY( slot->skip!=FD_GUI_SKIP_STATUS_NOT_SKIPPED ) ) continue; /* Skipped slots don't count to TPS. */
    if( FD_UNLIKELY( slot->vote_failed==UINT_MAX ) ) continue; /* Slot transaction counts not yet populated. */
    vote_failed     += slot->vote_failed;
    vote_success    += slot->vote_success;
    nonvote_success += slot->nonvote_success;
    nonvote_failed  += slot->nonvote_failed;
  }

  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ].vote_failed = vote_failed;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ].vote_success = vote_success;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ].nonvote_success = nonvote_success;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ].nonvote_failed = nonvote_failed;
  gui->summary.estimated_tps_history_idx = (gui->summary.estimated_tps_history_idx+1UL) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;
}

static void
fd_gui_network_stats_snap( fd_gui_t *               gui,
                           fd_gui_network_stats_t * cur ) {
  fd_topo_t const * topo = gui->topo;
  ulong gossvf_tile_cnt = fd_topo_tile_name_cnt( topo, "gossvf" );
  ulong gossip_tile_cnt = fd_topo_tile_name_cnt( topo, "gossip" );
  ulong shred_tile_cnt  = fd_topo_tile_name_cnt( topo, "shred" );
  ulong net_tile_cnt    = fd_topo_tile_name_cnt( topo, "net" );
  ulong quic_tile_cnt   = fd_topo_tile_name_cnt( topo, "quic" );

  cur->in.gossip   = fd_gui_metrics_gossip_total_ingress_bytes( topo, gossvf_tile_cnt );
  cur->out.gossip  = fd_gui_metrics_gossip_total_egress_bytes( topo, gossip_tile_cnt );
  cur->in.turbine  = fd_gui_metrics_sum_tiles_counter( topo, "shred", shred_tile_cnt, MIDX( COUNTER, SHRED, SHRED_TURBINE_RX_BYTES ) );

  cur->out.turbine = 0UL;
  cur->out.repair  = 0UL;
  cur->out.rserve  = 0UL;
  cur->out.tpu     = 0UL;
  for( ulong i=0UL; i<net_tile_cnt; i++ ) {
    ulong net_tile_idx = fd_topo_find_tile( topo, "net", i );
    if( FD_UNLIKELY( net_tile_idx==ULONG_MAX ) ) continue;
    fd_topo_tile_t const * net = &topo->tiles[ net_tile_idx ];
    for( ulong j=0UL; j<net->in_cnt; j++ ) {
      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "shred_net" ) ) ) {
          cur->out.turbine += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ];
      }

      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "repair_net" ) ) ) {
          cur->out.repair += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ];
      }
      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "rserve_net" ) ) ) {
          cur->out.rserve += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ];
      }

      if( FD_UNLIKELY( !strcmp( topo->links[ net->in_link_id[ j ] ].name, "send_net" ) ) ) {
          cur->out.tpu += fd_metrics_link_in( net->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ];
      }
    }
  }

  cur->in.repair = fd_gui_metrics_sum_tiles_counter( topo, "shred", shred_tile_cnt, MIDX( COUNTER, SHRED, SHRED_REPAIR_RX_BYTES ) );
  ulong repair_tile_idx = fd_topo_find_tile( topo, "repair", 0UL );
  if( FD_LIKELY( repair_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * repair = &topo->tiles[ repair_tile_idx ];

    for( ulong i=0UL; i<repair->in_cnt; i++ ) {
      if( FD_UNLIKELY( !strcmp( topo->links[ repair->in_link_id[ i ] ].name, "net_repair" ) ) ) {
          cur->in.repair += fd_metrics_link_in( repair->metrics, i )[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ];
      }
    }
  }

  cur->in.rserve = 0UL;
  ulong rserve_tile_idx = fd_topo_find_tile( topo, "rserve", 0UL );
  if( FD_LIKELY( rserve_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * rserve = &topo->tiles[ rserve_tile_idx ];

    for( ulong i=0UL; i<rserve->in_cnt; i++ ) {
      if( FD_UNLIKELY( !strcmp( topo->links[ rserve->in_link_id[ i ] ].name, "net_rserve" ) ) ) {
          cur->in.rserve += fd_metrics_link_in( rserve->metrics, i )[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ];
      }
    }
  }

  cur->in.tpu = 0UL;
  for( ulong i=0UL; i<quic_tile_cnt; i++ ) {
    ulong quic_tile_idx = fd_topo_find_tile( topo, "quic", i );
    if( FD_UNLIKELY( quic_tile_idx==ULONG_MAX ) ) continue;
    fd_topo_tile_t const * quic = &topo->tiles[ quic_tile_idx ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    cur->in.tpu += quic_metrics[ MIDX( COUNTER, QUIC, PKT_RX_BYTES ) ];
  }

  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong * bundle_metrics = fd_metrics_tile( bundle->metrics );
    cur->in.tpu += bundle_metrics[ MIDX( COUNTER, BUNDLE, PROTOBUF_RX_BYTES ) ];
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

static void
fd_gui_network_rate_max_update( fd_gui_t * gui,
                                long       now ) {
  fd_gui_network_stats_t * cur  = gui->summary.network_stats_current;
  fd_gui_network_stats_t * prev = gui->summary.network_stats_prev;

  /* On the first sample we have no previous value. */
  if( FD_UNLIKELY( !gui->summary.network_stats_has_prev ) ) {
    *prev = *cur;
    gui->summary.network_stats_has_prev = 1;
    gui->summary.net_rate_prev_ts       = now;
    return;
  }

  ulong d_in[ FD_GUI_NET_PROTO_CNT ];
  d_in[ 0 ] = fd_ulong_sat_sub( cur->in.turbine, prev->in.turbine );
  d_in[ 1 ] = fd_ulong_sat_sub( cur->in.gossip,  prev->in.gossip  );
  d_in[ 2 ] = fd_ulong_sat_sub( cur->in.tpu,     prev->in.tpu     );
  d_in[ 3 ] = fd_ulong_sat_sub( cur->in.repair,  prev->in.repair  );
  d_in[ 4 ] = fd_ulong_sat_sub( cur->in.rserve,  prev->in.rserve  );
  d_in[ 5 ] = fd_ulong_sat_sub( cur->in.metric,  prev->in.metric  );

  ulong d_out[ FD_GUI_NET_PROTO_CNT ];
  d_out[ 0 ] = fd_ulong_sat_sub( cur->out.turbine, prev->out.turbine );
  d_out[ 1 ] = fd_ulong_sat_sub( cur->out.gossip,  prev->out.gossip  );
  d_out[ 2 ] = fd_ulong_sat_sub( cur->out.tpu,     prev->out.tpu     );
  d_out[ 3 ] = fd_ulong_sat_sub( cur->out.repair,  prev->out.repair  );
  d_out[ 4 ] = fd_ulong_sat_sub( cur->out.rserve,  prev->out.rserve  );
  d_out[ 5 ] = fd_ulong_sat_sub( cur->out.metric,  prev->out.metric  );

  /* Compute per-protocol instantaneous bytes/sec rate and feed the EMA. */
  long dt_ns = now - gui->summary.net_rate_prev_ts;
  if( FD_LIKELY( dt_ns>0L ) ) {
    double dt_sec = (double)dt_ns / 1.0e9;

    for( ulong i=0UL; i<FD_GUI_NET_PROTO_CNT; i++ ) {
      double rate_in  = (double)d_in[ i ]  / dt_sec;
      double rate_out = (double)d_out[ i ] / dt_sec;

      fd_gui_ema_advance( &gui->summary.ingress_ema[ i ], now, rate_in  );
      fd_gui_ema_advance( &gui->summary.egress_ema [ i ], now, rate_out );
    }
  }
  gui->summary.net_rate_prev_ts = now;

  /* Track max total EMA in a rolling 5-minute window using monotonic
     deques.

     Invariant: deque entries are strictly decreasing in value from
     head to tail.  The head is always the current window maximum.

     Insert:  pop tail entries whose value <= new value (they can
              never become the maximum), then push the new entry.
     Expire:  pop head entries older than 5 minutes. */
  if( FD_LIKELY( gui->summary.ingress_ema[ 0 ].last_update_nanos ) ) {
    double sum_in  = 0.0;
    double sum_out = 0.0;
    for( ulong i=0UL; i<FD_GUI_NET_PROTO_CNT; i++ ) {
      sum_in  += gui->summary.ingress_ema[ i ].value;
      sum_out += gui->summary.egress_ema[ i ].value;
    }

    while( !fd_gui_rate_deque_empty( gui->summary.ingress_maxq ) && fd_gui_rate_deque_peek_head_const( gui->summary.ingress_maxq )->ts_nanos<now-FD_GUI_NET_RATE_MAX_WINDOW_NS ) {
      fd_gui_rate_deque_pop_head( gui->summary.ingress_maxq );
    }
    while( !fd_gui_rate_deque_empty( gui->summary.ingress_maxq ) && fd_gui_rate_deque_peek_tail_const( gui->summary.ingress_maxq )->value<=sum_in ) {
      fd_gui_rate_deque_pop_tail( gui->summary.ingress_maxq );
    }
    if( FD_UNLIKELY( fd_gui_rate_deque_full( gui->summary.ingress_maxq ) ) ) {
      fd_gui_rate_deque_pop_tail( gui->summary.ingress_maxq );
    }
    fd_gui_rate_deque_push_tail( gui->summary.ingress_maxq, (fd_gui_rate_entry_t){ .ts_nanos=now, .value=sum_in } );

    while( !fd_gui_rate_deque_empty( gui->summary.egress_maxq ) && fd_gui_rate_deque_peek_head_const( gui->summary.egress_maxq )->ts_nanos<now-FD_GUI_NET_RATE_MAX_WINDOW_NS ) {
      fd_gui_rate_deque_pop_head( gui->summary.egress_maxq );
    }
    while( !fd_gui_rate_deque_empty( gui->summary.egress_maxq ) && fd_gui_rate_deque_peek_tail_const( gui->summary.egress_maxq )->value<=sum_out ) {
      fd_gui_rate_deque_pop_tail( gui->summary.egress_maxq );
    }
    if( FD_UNLIKELY( fd_gui_rate_deque_full( gui->summary.egress_maxq ) ) ) {
      fd_gui_rate_deque_pop_tail( gui->summary.egress_maxq );
    }
    fd_gui_rate_deque_push_tail( gui->summary.egress_maxq, (fd_gui_rate_entry_t){ .ts_nanos=now, .value=sum_out } );
  }

  *prev = *cur;
}

/* Snapshot accdb statistics by reading the accdb tile's metric page
   (for gauges) and summing counters across all tiles that join accdb
   (executors, replay, tower, rpc, resolv, plus the accdb tile itself).
   The result feeds the GUI "Accounts" page. */

static void
fd_gui_accounts_stats_snap( fd_gui_t *                gui,
                            fd_gui_accounts_stats_t * cur ) {
  fd_topo_t const * topo = gui->topo;

  memset( cur, 0, sizeof(*cur) );
  cur->sample_time_nanos = fd_log_wallclock();

  ulong accdb_tile_idx = fd_topo_find_tile( topo, "accdb", 0UL );
  if( FD_UNLIKELY( accdb_tile_idx==ULONG_MAX ) ) return;

  /* Gauges + accdb-tile-only counters. */
  fd_topo_tile_t const * accdb = &topo->tiles[ accdb_tile_idx ];
  volatile ulong const * am    = fd_metrics_tile( accdb->metrics );

  cur->accounts_total           = am[ MIDX( GAUGE,   ACCDB, ACCOUNT_COUNT           ) ];
  cur->accounts_capacity        = am[ MIDX( GAUGE,   ACCDB, ACCOUNT_CAPACITY        ) ];
  cur->disk_allocated_bytes     = am[ MIDX( GAUGE,   ACCDB, DISK_ALLOCATED_BYTES    ) ];
  cur->disk_current_bytes       = am[ MIDX( GAUGE,   ACCDB, DISK_CURRENT_BYTES      ) ];
  cur->disk_used_bytes          = am[ MIDX( GAUGE,   ACCDB, DISK_USED_BYTES         ) ];
  cur->in_compaction            = am[ MIDX( GAUGE,   ACCDB, IN_COMPACTION           ) ];
  cur->compactions_requested    = am[ MIDX( COUNTER, ACCDB, COMPACTION_REQUESTED    ) ];
  cur->compactions_completed    = am[ MIDX( COUNTER, ACCDB, COMPACTION_COMPLETED    ) ];
  cur->accounts_relocated_bytes = am[ MIDX( COUNTER, ACCDB, ACCOUNT_RELOCATED_BYTES ) ];
  cur->bytes_written_accdb      = am[ MIDX( COUNTER, ACCDB, BYTES_WRITTEN           ) ];

  /* The accdb tile owns the prewrite and compaction writes; include
     those in the aggregate bytes_written / write_ops so the IO panel
     reflects all on-disk write activity, not just consumer-driven
     commits. */
  cur->bytes_written += am[ MIDX( COUNTER, ACCDB, BYTES_WRITTEN    ) ];
  cur->write_ops     += am[ MIDX( COUNTER, ACCDB, WRITE_OPERATION  ) ];

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    cur->cache_class_used         [ c ] = am[ MIDX( GAUGE, ACCDB, CACHE_CLASS_USED            ) + c ];
    cur->cache_class_max          [ c ] = am[ MIDX( GAUGE, ACCDB, CACHE_CLASS_MAX             ) + c ];
    cur->cache_class_reserved     [ c ] = am[ MIDX( GAUGE, ACCDB, CACHE_CLASS_RESERVED        ) + c ];
    cur->cache_class_target_used  [ c ] = am[ MIDX( GAUGE, ACCDB, CACHE_CLASS_TARGET_USED     ) + c ];
    cur->cache_class_low_water_used[c ] = am[ MIDX( GAUGE, ACCDB, CACHE_CLASS_LOW_WATER_USED  ) + c ];
    cur->preevicted_per_class     [ c ] = am[ MIDX( COUNTER, ACCDB, ACCOUNT_PREEVICTED        ) + c ];
  }

  /* Walk the per-tile slot table built at init.  Each slot reads its
     tile's accdb counters according to its kind (RW, RO, or SNAPWR),
     accumulates into the aggregate (cur->*), and stashes the per-tile
     cumulative values into gui->summary.accdb->tile_cur_* for the
     per-tile rate window pushes done later in
     fd_gui_printf_accounts_stats. */
  for( ulong s=0UL; s<gui->summary.accdb->accdb_tile_cnt; s++ ) {
    ulong t_idx = (ulong)gui->summary.accdb->accdb_tile_topo_idx[ s ];
    uchar kind  = gui->summary.accdb->accdb_tile_kind[ s ];
    volatile ulong const * m = fd_metrics_tile( topo->tiles[ t_idx ].metrics );

    gui->summary.accdb->tile_cur_status[ s ] = (uchar)m[ MIDX( GAUGE, TILE, STATUS ) ];

    ulong t_acq=0UL, t_acw=0UL, t_misses=0UL, t_evicted=0UL, t_committed=0UL;
    ulong t_bytes_read=0UL, t_bytes_copied=0UL, t_bytes_written=0UL;
    ulong t_read_ops=0UL, t_write_ops=0UL;
    ulong t_acquire_calls=0UL;

    switch( kind ) {
#   define DO_RW( TILE_UPPER )                                                                                                    \
        t_bytes_read    = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BYTES_READ      ) ];                                                \
        t_bytes_copied  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BYTES_COPIED    ) ];                                                \
        t_bytes_written = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BYTES_WRITTEN   ) ];                                                \
        t_read_ops      = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_READ_OPERATION  ) ];                                                \
        t_write_ops     = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_WRITE_OPERATION ) ];                                                \
        t_acquire_calls = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BATCH_ACQUIRED  ) ];                                                \
        for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {                                                                     \
          ulong _acq = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_ACQUIRED          ) + c ];                                     \
          ulong _acw = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_WRITABLE_ACQUIRED ) + c ];                                     \
          ulong _nf  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_NOT_FOUND         ) + c ];                                     \
          ulong _ev  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_EVICTED           ) + c ];                                     \
          ulong _cn  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_COMMITTED_NEW        ) + c ];                                  \
          ulong _co  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_COMMITTED_OVERWRITE  ) + c ];                                  \
          t_acq+=_acq; t_acw+=_acw; t_misses+=_nf; t_evicted+=_ev; t_committed+=_cn+_co;                                          \
          cur->acquired_per_class            [ c ] += _acq;                                                                       \
          cur->acquired_writable_per_class   [ c ] += _acw;                                                                       \
          cur->not_found_per_class           [ c ] += _nf;                                                                        \
          cur->evicted_per_class             [ c ] += _ev;                                                                        \
          cur->committed_new_per_class       [ c ] += _cn;                                                                        \
          cur->committed_overwrite_per_class [ c ] += _co;                                                                        \
        }
      case FD_GUI_ACCDB_TILE_KIND_RW:
        if(      !strcmp( topo->tiles[ t_idx ].name, "execle" ) ) { DO_RW( EXECLE ); }
        else if( !strcmp( topo->tiles[ t_idx ].name, "execrp" ) ) { DO_RW( EXECRP ); }
        else if( !strcmp( topo->tiles[ t_idx ].name, "replay" ) ) { DO_RW( REPLAY ); }
        else if( !strcmp( topo->tiles[ t_idx ].name, "tower"  ) ) { DO_RW( TOWER  ); }
        cur->acquired          += t_acq;
        cur->acquired_writable += t_acw;
        cur->bytes_read        += t_bytes_read;
        cur->bytes_copied      += t_bytes_copied;
        cur->bytes_written     += t_bytes_written;
        cur->read_ops          += t_read_ops;
        cur->write_ops         += t_write_ops;
        break;
#   undef DO_RW

#   define DO_RO( TILE_UPPER )                                                                                                    \
        t_bytes_read    = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BYTES_READ     ) ];                                                 \
        t_bytes_copied  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BYTES_COPIED   ) ];                                                 \
        t_read_ops      = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_READ_OPERATION ) ];                                                 \
        t_acquire_calls = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_BATCH_ACQUIRED ) ];                                                 \
        for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {                                                                     \
          ulong _acq = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_ACQUIRED  ) + c ];                                            \
          ulong _nf  = m[ MIDX( COUNTER, TILE_UPPER, ACCDB_ACCOUNT_NOT_FOUND ) + c ];                                            \
          t_acq+=_acq; t_misses+=_nf;                                                                                             \
          cur->acquired_per_class [ c ] += _acq;                                                                                  \
          cur->not_found_per_class[ c ] += _nf;                                                                                   \
        }
      case FD_GUI_ACCDB_TILE_KIND_RO:
        if( !strcmp( topo->tiles[ t_idx ].name, "rpc"    ) ) { DO_RO( RPC    ); }
        else if( !strcmp( topo->tiles[ t_idx ].name, "resolv" ) ) { DO_RO( RESOLV ); }
        cur->acquired     += t_acq;
        cur->bytes_read   += t_bytes_read;
        cur->bytes_copied += t_bytes_copied;
        cur->read_ops     += t_read_ops;
        break;
#   undef DO_RO

      case FD_GUI_ACCDB_TILE_KIND_SNAPWR:
        /* snapwr writes account data to disk directly during snapshot
           load.  It does not declare the accdb counter surface, only a
           BytesWritten gauge.  Include in the aggregate so the IO panel
           reflects load-time disk activity. */
        t_bytes_written = m[ MIDX( GAUGE, SNAPWR, BYTES_WRITTEN ) ];
        cur->bytes_written += t_bytes_written;
        break;

      case FD_GUI_ACCDB_TILE_KIND_ACCDB:
        /* The accdb tile owns prewrite and compaction writes.  Its own
           bytes_written/write_ops were already folded into the aggregate
           above (see ACCDB_BYTES_WRITTEN / ACCDB_WRITE_OPS reads).  Here
           we only stash per-slot values so the per-tile row reflects
           them; do not re-add to cur->* or we'd double-count.  The accdb
           tile does not expose acquired/not_found/committed (no account
           joiner) or read_ops/bytes_copied.  Preevicts are owned by the
           accdb tile's background preevict pass, so map them to the
           per-tile evicted column for this row. */
        t_bytes_read    = m[ MIDX( COUNTER, ACCDB, BYTES_READ      ) ];
        t_bytes_written = m[ MIDX( COUNTER, ACCDB, BYTES_WRITTEN   ) ];
        t_write_ops     = m[ MIDX( COUNTER, ACCDB, WRITE_OPERATION ) ];
        for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
          t_evicted += m[ MIDX( COUNTER, ACCDB, ACCOUNT_PREEVICTED ) + c ];
        }
        break;
    }

    gui->summary.accdb->tile_cur_acquired         [ s ] = t_acq;
    gui->summary.accdb->tile_cur_acquired_writable[ s ] = t_acw;
    gui->summary.accdb->tile_cur_bytes_read       [ s ] = t_bytes_read;
    gui->summary.accdb->tile_cur_bytes_copied     [ s ] = t_bytes_copied;
    gui->summary.accdb->tile_cur_bytes_written    [ s ] = t_bytes_written;
    gui->summary.accdb->tile_cur_read_ops         [ s ] = t_read_ops;
    gui->summary.accdb->tile_cur_write_ops        [ s ] = t_write_ops;
    gui->summary.accdb->tile_cur_misses           [ s ] = t_misses;
    gui->summary.accdb->tile_cur_evicted          [ s ] = t_evicted;
    gui->summary.accdb->tile_cur_committed        [ s ] = t_committed;
    gui->summary.accdb->tile_cur_acquire_calls    [ s ] = t_acquire_calls;
  }

  if( FD_UNLIKELY( !gui->accdb_shmem ) ) return;

  /* Snapshot per-partition utilization and fragmentation and also
     their respective per-tier rate of growth. Actively-compacting
     partitions excluded so relocation churn does not degrade estimates. */
  ulong pcnt = fd_ulong_min( fd_accdb_shmem_partition_max( gui->accdb_shmem ), FD_GUI_MAX_PARTITIONS );
  gui->summary.accdb->partition_cnt = pcnt;

  double tier_fill_delta[ FD_ACCDB_COMPACTION_LAYER_CNT ] = { 0.0 };
  double tier_free_delta[ FD_ACCDB_COMPACTION_LAYER_CNT ] = { 0.0 };
  ulong  compaction_idx   = ULONG_MAX;
  ulong  compaction_layer = FD_ACCDB_COMPACTION_LAYER_CNT;
  ulong  compaction_state = 0UL;
  for( ulong p=0UL; p<pcnt; p++ ) {
    fd_accdb_shmem_partition_info_t   prev_info =  gui->summary.accdb->partitions[ p ];
    fd_accdb_shmem_partition_info_t * info      = &gui->summary.accdb->partitions[ p ];
    fd_accdb_shmem_partition_info( gui->accdb_shmem, p, info );

    if( FD_UNLIKELY( info->compaction_state && ( compaction_state<info->compaction_state || ( compaction_state==info->compaction_state && info->layer<compaction_layer ) ) ) ) {
      compaction_idx   = p;
      compaction_layer = info->layer;
      compaction_state = info->compaction_state;
    }

    if( FD_LIKELY( info->layer<FD_ACCDB_COMPACTION_LAYER_CNT ) ) {
      /* Only the <=3 write-head partitions advance, and freed bytes
         land in a handful of partitions per 100ms snap. */
      if( FD_UNLIKELY( info->write_offset>prev_info.write_offset ) )
        tier_fill_delta[ info->layer ] += (double)(info->write_offset-prev_info.write_offset);
      if( FD_UNLIKELY( info->compaction_state!=2 && info->bytes_freed>prev_info.bytes_freed ) )
        tier_free_delta[ info->layer ] += (double)(info->bytes_freed-prev_info.bytes_freed);
    }
  }

  /* First snap has no valid deltas. */
  if( FD_LIKELY( gui->summary.accdb->tier_sample_nanos!=LONG_MAX ) ) {
    double dt_sec = (double)(cur->sample_time_nanos-gui->summary.accdb->tier_sample_nanos)/1e9;
    if( FD_LIKELY( dt_sec>0.0 ) ) {
      for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
        fd_gui_ema_advance( &gui->summary.accdb->tier_fill_bps_ema[ k ], cur->sample_time_nanos, tier_fill_delta[ k ]/dt_sec );
        fd_gui_ema_advance( &gui->summary.accdb->tier_free_bps_ema[ k ], cur->sample_time_nanos, tier_free_delta[ k ]/dt_sec );
      }
    }
  }
  gui->summary.accdb->tier_sample_nanos = cur->sample_time_nanos;

  /* Estimate next compaction time/partition. */
  double next_secs = 0.0;
  ulong  next_idx  = ULONG_MAX;
  double partition_sz = (double)fd_accdb_shmem_partition_sz( gui->accdb_shmem );
  double tier_live_bytes[ FD_ACCDB_COMPACTION_LAYER_CNT ] = { 0.0 };
  for( ulong p=0UL; p<pcnt; p++ ) {
    fd_accdb_shmem_partition_info_t const * info = &gui->summary.accdb->partitions[ p ];
    if( info->layer<FD_ACCDB_COMPACTION_LAYER_CNT && info->compaction_state!=2 && info->write_offset>info->bytes_freed && info->compaction_offset<info->write_offset )
      tier_live_bytes[ info->layer ] += (double)(info->write_offset-info->bytes_freed);
  }
  for( ulong p=0UL; p<pcnt; p++ ) {
    fd_accdb_shmem_partition_info_t const * info = &gui->summary.accdb->partitions[ p ];
    if( FD_LIKELY( info->compaction_state || !info->write_offset ) ) continue;
    if( FD_UNLIKELY( info->layer>=FD_ACCDB_COMPACTION_LAYER_CNT ) ) continue;
    if( FD_UNLIKELY( info->compaction_offset>=info->write_offset ) ) continue; /* compacted, awaiting reclaim */

    double free_bps  = gui->summary.accdb->tier_free_bps_ema[ info->layer ].value;
    double live      = info->write_offset>info->bytes_freed ? (double)(info->write_offset-info->bytes_freed) : 0.0;
    double frag_rate = tier_live_bytes[ info->layer ]>0.0 ? free_bps*live/tier_live_bytes[ info->layer ] : 0.0;
    double deficit   = (double)FD_ACCDB_COMPACTION_THRESHOLD_PCT/100.0*partition_sz - (double)info->bytes_freed;
    double frag_secs = deficit<=0.0 ? 0.0 : ( frag_rate>0.0 ? deficit/frag_rate : -1.0 );
    double fill_secs = 0.0;
    if( FD_UNLIKELY( info->is_write_head ) ) {
      double fill_bps = gui->summary.accdb->tier_fill_bps_ema[ info->layer ].value;
      fill_secs = fill_bps>0.0 ? (partition_sz-(double)info->write_offset)/fill_bps : -1.0;
    }

    if( FD_UNLIKELY( frag_secs<0.0 || fill_secs<0.0 ) ) continue; /* no usable rate estimate (EMA warm-up) */
    double est = fmax( frag_secs, fill_secs );
    if( next_idx==ULONG_MAX || est<next_secs ) {
      next_secs = est;
      next_idx  = p;
    }
  }

  int has_compaction = compaction_idx!=ULONG_MAX;
  gui->summary.accdb->next_compaction_remaining_secs = fd_double_if( has_compaction, 0.0,            next_secs );
  gui->summary.accdb->next_compaction_partition_idx  = fd_ulong_if(  has_compaction, compaction_idx, next_idx  );
}

/* Snapshot all of the data from metrics to construct a view of the
   transaction waterfall.

   Tiles are sampled in reverse pipeline order: this helps prevent data
   discrepancies where a later tile has "seen" more transactions than an
   earlier tile, which shouldn't typically happen. */

static void
fd_gui_txn_waterfall_snap( fd_gui_t *               gui,
                           fd_gui_txn_waterfall_t * cur ) {
  memset( cur, 0, sizeof(fd_gui_txn_waterfall_t) );
  fd_topo_t const * topo = gui->topo;

  for( ulong i=0UL; i<gui->summary.bank_tile_cnt; i++ ) {
    fd_topo_tile_t const * bank = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];

    volatile ulong const * bank_metrics = fd_metrics_tile( bank->metrics );
    cur->out.block_success += bank_metrics[ MIDX( COUNTER, BANK, TXN_EXECUTED_SUCCESS ) ];

    cur->out.block_fail +=
        bank_metrics[ MIDX( COUNTER, BANK, TXN_EXECUTED_FAILED ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TXN_FEE_ONLY        ) ];

    cur->out.bank_invalid +=
        bank_metrics[ MIDX( COUNTER, BANK, TXN_LOAD_ADDRESS_TABLE_ACCOUNT_UNINITIALIZED ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TXN_LOAD_ADDRESS_TABLE_ACCOUNT_NOT_FOUND ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TXN_LOAD_ADDRESS_TABLE_INVALID_ACCOUNT_OWNER ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TXN_LOAD_ADDRESS_TABLE_INVALID_ACCOUNT_DATA ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TXN_LOAD_ADDRESS_TABLE_INVALID_LOOKUP_INDEX  ) ];

    cur->out.bank_invalid +=
        bank_metrics[ MIDX( COUNTER, BANK, TXN_PROCESSING_FAILED ) ];
  }

  for( ulong i=0UL; i<gui->summary.execle_tile_cnt; i++ ) {
    fd_topo_tile_t const * execle = &topo->tiles[ fd_topo_find_tile( topo, "execle", i ) ];

    volatile ulong const * execle_metrics = fd_metrics_tile( execle->metrics );

    cur->out.block_success += execle_metrics[ MIDX( COUNTER, EXECLE, TXN_LANDED_LANDED_SUCCESS ) ];
    cur->out.block_fail    +=
        execle_metrics[ MIDX( COUNTER, EXECLE, TXN_LANDED_LANDED_FEES_ONLY ) ]
      + execle_metrics[ MIDX( COUNTER, EXECLE, TXN_LANDED_LANDED_FAILED ) ];
    cur->out.bank_invalid  += execle_metrics[ MIDX( COUNTER, EXECLE, TXN_LANDED_UNLANDED ) ];

    cur->out.bank_nonce_already_advanced += execle_metrics[ MIDX( COUNTER, EXECLE, TXN_RESULT_NONCE_ALREADY_ADVANCED ) ];
    cur->out.bank_nonce_advance_failed   += execle_metrics[ MIDX( COUNTER, EXECLE, TXN_RESULT_NONCE_ADVANCE_FAILED ) ];
    cur->out.bank_nonce_wrong_blockhash  += execle_metrics[ MIDX( COUNTER, EXECLE, TXN_RESULT_NONCE_WRONG_BLOCKHASH ) ];
  }

  ulong pack_tile_idx = fd_topo_find_tile( topo, "pack", 0UL );
  if( pack_tile_idx!=ULONG_MAX ) {
    fd_topo_tile_t const * pack = &topo->tiles[ pack_tile_idx ];
    volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );

    cur->out.pack_invalid_bundle =
        pack_metrics[ MIDX( COUNTER, PACK, TXN_PARTIAL_BUNDLE ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_RESULT_INSERTION_FAILED ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_RESULT_CREATION_FAILED ) ];

    cur->out.pack_invalid =
        pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_INSTR_ACCT_CNT ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_NONCE_CONFLICT ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_BUNDLE_BLACKLIST ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_INVALID_NONCE ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_WRITE_SYSVAR ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_ESTIMATION_FAIL ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_DUPLICATE_ACCOUNT ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_TOO_MANY_ACCOUNTS ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_TOO_LARGE ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_ADDR_LUT ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_UNAFFORDABLE ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_DUPLICATE ) ]
      - pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_RESULT_INSERTION_FAILED ) ]; /* so we don't double count this, since its already accounted for in invalid_bundle */

    cur->out.pack_expired = pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_EXPIRED ) ] +
                            pack_metrics[ MIDX( COUNTER, PACK, TXN_EXPIRED ) ] +
                            pack_metrics[ MIDX( COUNTER, PACK, TXN_DELETED ) ] +
                            pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_NONCE_PRIORITY ) ];

    cur->out.pack_already_executed = pack_metrics[ MIDX( COUNTER, PACK, TXN_ALREADY_EXECUTED ) ];

    cur->out.pack_leader_slow = pack_metrics[ MIDX( COUNTER, PACK, TXN_INSERTED_PRIORITY ) ];

    cur->out.pack_wait_full =
        pack_metrics[ MIDX( COUNTER, PACK, TXN_EXTRA_DROPPED ) ];

    cur->out.pack_retained = pack_metrics[ MIDX( GAUGE, PACK, TXN_AVAILABLE ) ];

    ulong inserted_to_extra = pack_metrics[ MIDX( COUNTER, PACK, TXN_EXTRA_INSERTED ) ];
    ulong inserted_from_extra = pack_metrics[ MIDX( COUNTER, PACK, TXN_EXTRA_RETRIEVED ) ]
                                + pack_metrics[ MIDX( COUNTER, PACK, TXN_EXTRA_DROPPED ) ];
    cur->out.pack_retained += fd_ulong_if( inserted_to_extra>=inserted_from_extra, inserted_to_extra-inserted_from_extra, 0UL );

    cur->in.pack_cranked =
        pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_RESULT_INSERTED ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_RESULT_INSERTION_FAILED ) ]
      + pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_RESULT_CREATION_FAILED ) ];
  }

  for( ulong i=0UL; i<gui->summary.resolh_tile_cnt; i++ ) {
    fd_topo_tile_t const * resolv = &topo->tiles[ fd_topo_find_tile( topo, "resolh", i ) ];
    volatile ulong const * resolv_metrics = fd_metrics_tile( resolv->metrics );

    cur->out.resolv_no_ledger += resolv_metrics[ MIDX( COUNTER, RESOLH, TXN_NO_BANK ) ];
    cur->out.resolv_expired += resolv_metrics[ MIDX( COUNTER, RESOLH, BLOCKHASH_EXPIRED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLH, TXN_BUNDLE_PEER_FAILED  ) ];
    cur->out.resolv_lut_failed += resolv_metrics[ MIDX( COUNTER, RESOLH, LUT_RESOLVED_ACCOUNT_NOT_FOUND ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLH, LUT_RESOLVED_INVALID_ACCOUNT_OWNER ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLH, LUT_RESOLVED_INVALID_ACCOUNT_DATA ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLH, LUT_RESOLVED_ACCOUNT_UNINITIALIZED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLH, LUT_RESOLVED_INVALID_LOOKUP_INDEX ) ];
    cur->out.resolv_ancient += resolv_metrics[ MIDX( COUNTER, RESOLH, STASH_OPERATION_OVERRUN ) ];

    ulong inserted_to_resolv = resolv_metrics[ MIDX( COUNTER, RESOLH, STASH_OPERATION_INSERTED ) ];
    ulong removed_from_resolv = resolv_metrics[ MIDX( COUNTER, RESOLH, STASH_OPERATION_OVERRUN ) ]
                              + resolv_metrics[ MIDX( COUNTER, RESOLH, STASH_OPERATION_PUBLISHED ) ]
                              + resolv_metrics[ MIDX( COUNTER, RESOLH, STASH_OPERATION_REMOVED ) ];
    cur->out.resolv_retained += fd_ulong_if( inserted_to_resolv>=removed_from_resolv, inserted_to_resolv-removed_from_resolv, 0UL );
  }

  for( ulong i=0UL; i<gui->summary.resolv_tile_cnt; i++ ) {
    fd_topo_tile_t const * resolv = &topo->tiles[ fd_topo_find_tile( topo, "resolv", i ) ];
    volatile ulong const * resolv_metrics = fd_metrics_tile( resolv->metrics );

    cur->out.resolv_no_ledger += resolv_metrics[ MIDX( COUNTER, RESOLV, TXN_NO_BANK ) ];
    cur->out.resolv_expired += resolv_metrics[ MIDX( COUNTER, RESOLV, BLOCKHASH_EXPIRED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, TXN_BUNDLE_PEER_FAILED  ) ];
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

  ulong dedup_tile_idx = fd_topo_find_tile( topo, "dedup", 0UL );
  if( FD_UNLIKELY( dedup_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * dedup = &topo->tiles[ dedup_tile_idx ];
    volatile ulong const * dedup_metrics = fd_metrics_tile( dedup->metrics );

    cur->out.dedup_duplicate = dedup_metrics[ MIDX( COUNTER, DEDUP, TXN_RESULT_DEDUP_FAILURE ) ]
                             + dedup_metrics[ MIDX( COUNTER, DEDUP, TXN_RESULT_BUNDLE_PEER_FAILURE ) ];
  }

  for( ulong i=0UL; i<gui->summary.verify_tile_cnt; i++ ) {
    fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
    volatile ulong const * verify_metrics = fd_metrics_tile( verify->metrics );

    for( ulong j=0UL; j<gui->summary.quic_tile_cnt; j++ ) {
      /* TODO: Not precise... even if 1 frag gets skipped, it could have been for this verify tile. */
      cur->out.verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_POLLING_OVERRUN_OFF ] / gui->summary.verify_tile_cnt;
      cur->out.verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_READING_OVERRUN_OFF ];
    }

    cur->out.verify_failed    += verify_metrics[ MIDX( COUNTER, VERIFY, TXN_RESULT_VERIFY_FAILURE ) ] +
                                 verify_metrics[ MIDX( COUNTER, VERIFY, TXN_RESULT_BUNDLE_PEER_FAILURE ) ];
    cur->out.verify_parse     += verify_metrics[ MIDX( COUNTER, VERIFY, TXN_RESULT_PARSE_FAILURE ) ];
    cur->out.verify_duplicate += verify_metrics[ MIDX( COUNTER, VERIFY, TXN_RESULT_DEDUP_FAILURE ) ];
  }

  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    cur->out.tpu_udp_invalid  += quic_metrics[ MIDX( COUNTER, QUIC, LEGACY_TXN_UNDERSIZE    ) ];
    cur->out.tpu_udp_invalid  += quic_metrics[ MIDX( COUNTER, QUIC, LEGACY_TXN_OVERSIZE     ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_UNDERSIZE           ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_OVERSIZE            ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, TXN_OVERSIZE            ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_CRYPTO_FAILED       ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_NO_CONN             ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_SRC_INVALID         ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_NET_HEADER_INVALID  ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_HEADER_INVALID      ) ];
    cur->out.quic_abandoned   += quic_metrics[ MIDX( COUNTER, QUIC, TXN_ABANDONED           ) ];
    cur->out.quic_frag_drop   += quic_metrics[ MIDX( COUNTER, QUIC, TXN_OVERRUN             ) ];

    for( ulong j=0UL; j<gui->summary.net_tile_cnt; j++ ) {
      /* TODO: Not precise... net frags that were skipped might not have been destined for QUIC tile */
      /* TODO: Not precise... even if 1 frag gets skipped, it could have been for this QUIC tile */
      cur->out.quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_POLLING_OVERRUN_OFF ] / gui->summary.quic_tile_cnt;
      cur->out.quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_FRAG_READING_OVERRUN_OFF ];
    }
  }

  for( ulong i=0UL; i<gui->summary.net_tile_cnt; i++ ) {
    fd_topo_tile_t const * net = &topo->tiles[ fd_topo_find_tile( topo, "net", i ) ];
    volatile ulong * net_metrics = fd_metrics_tile( net->metrics );

    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_RING_FULL ) ];
    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_OTHER_DROPPED ) ];
    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_FILL_RING_EMPTY ) ];
  }

  ulong bundle_txns_received = 0UL;
  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong const * bundle_metrics = fd_metrics_tile( bundle->metrics );

    bundle_txns_received = bundle_metrics[ MIDX( COUNTER, BUNDLE, TXN_RX ) ];
  }

  {
    cur->in.gossip = 0UL;
    for( ulong i=0UL; i<gui->summary.verify_tile_cnt; i++ ) {
      fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
      volatile ulong const * verify_metrics = fd_metrics_tile( verify->metrics );
      cur->in.gossip += verify_metrics[ MIDX( COUNTER, VERIFY, VOTE_GOSSIP_RX ) ];
    }
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

    cur->in.quic += quic_metrics[ MIDX( COUNTER, QUIC, TXN_RX_QUIC_FAST ) ];
    cur->in.quic += quic_metrics[ MIDX( COUNTER, QUIC, TXN_RX_QUIC_FRAG ) ];
    cur->in.udp  += quic_metrics[ MIDX( COUNTER, QUIC, TXN_RX_UDP       ) ];
  }
}

static void
fd_gui_tile_stats_snap( fd_gui_t *                     gui,
                        fd_gui_txn_waterfall_t const * waterfall,
                        fd_gui_tile_stats_t *          stats,
                        long                           now ) {
  memset( stats, 0, sizeof(fd_gui_tile_stats_t) );
  fd_topo_t const * topo = gui->topo;

  stats->sample_time_nanos = now;

  for( ulong i=0UL; i<gui->summary.net_tile_cnt; i++ ) {
    fd_topo_tile_t const * net = &topo->tiles[ fd_topo_find_tile( topo, "net", i ) ];
    volatile ulong * net_metrics = fd_metrics_tile( net->metrics );

    stats->net_in_rx_bytes  += net_metrics[ MIDX( COUNTER, NET, PKT_RX_BYTES ) ];
    stats->net_out_tx_bytes += net_metrics[ MIDX( COUNTER, NET, PKT_TX_BYTES ) ];
  }

  for( ulong i=0UL; i<gui->summary.sock_tile_cnt; i++ ) {
    fd_topo_tile_t const * sock = &topo->tiles[ fd_topo_find_tile( topo, "sock", i ) ];
    volatile ulong * sock_metrics = fd_metrics_tile( sock->metrics );

    stats->net_in_rx_bytes  += sock_metrics[ MIDX( COUNTER, SOCK, PKT_RX_BYTES ) ];
    stats->net_out_tx_bytes += sock_metrics[ MIDX( COUNTER, SOCK, PKT_TX_BYTES ) ];
  }

  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    stats->quic_conn_cnt += quic_metrics[ MIDX( GAUGE, QUIC, CONN_IN_USE ) ];
  }

  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong * bundle_metrics = fd_metrics_tile( bundle->metrics );
    stats->bundle_rtt_smoothed_nanos = bundle_metrics[ MIDX( GAUGE, BUNDLE, RTT_SMOOTHED_NANOS ) ];

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

  ulong pack_tile_idx = fd_topo_find_tile( topo, "pack", 0UL );
  if( pack_tile_idx!=ULONG_MAX ) {
    fd_topo_tile_t const * pack  = &topo->tiles[ pack_tile_idx ];
    volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );
    stats->pack_buffer_cnt      = pack_metrics[ MIDX( GAUGE, PACK, TXN_AVAILABLE ) ];
    stats->pack_buffer_capacity = pack->pack.max_pending_transactions;
  }

  stats->bank_txn_exec_cnt = waterfall->out.block_fail + waterfall->out.block_success;

  fd_gui_hist_ts_append( gui, FD_GUI_HIST_TILE_STATS, now, now, stats );
}

static void
fd_gui_run_boot_progress( fd_gui_t * gui, long now ) {
  fd_topo_tile_t const * snapct = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapct", 0UL ) ];
  volatile ulong * snapct_metrics = fd_metrics_tile( snapct->metrics );

  fd_topo_tile_t const * snapdc = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapdc", 0UL ) ];
  volatile ulong * snapdc_metrics = fd_metrics_tile( snapdc->metrics );

  fd_topo_tile_t const * snapin = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapin", 0UL ) ];
  volatile ulong * snapin_metrics = fd_metrics_tile( snapin->metrics );

  fd_topo_tile_t const * snapwr = &gui->topo->tiles[ fd_topo_find_tile( gui->topo, "snapwr", 0UL ) ];
  volatile ulong * snapwr_metrics = fd_metrics_tile( snapwr->metrics );

  /* Backtest topologies have no gossip tile; treat wait-for-supermajority
     as done. */
  ulong            wfs_state       = FD_GOSSIP_WFS_STATE_DONE;
  volatile ulong * gossip_metrics  = NULL;
  ulong            gossip_tile_idx = fd_topo_find_tile( gui->topo, "gossip", 0UL );
  if( FD_LIKELY( gossip_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * gossip = &gui->topo->tiles[ gossip_tile_idx ];
    gossip_metrics = fd_metrics_tile( gossip->metrics );
    wfs_state = gossip_metrics[ MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STATE ) ];
  }

  ulong snapshot_phase = snapct_metrics[ MIDX( GAUGE, SNAPCT, STATE ) ];

  /* Backtest topologies have no turbine, so the regular catch-up
     detection (turbine slot vs. replayed slot) can never trigger.
     Consider replay caught up at the first tower root after the
     snapshot finishes loading. */
  if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX &&
                   snapshot_phase==FD_SNAPCT_STATE_SHUTDOWN &&
                   gui->summary.slot_tower!=ULONG_MAX &&
                   fd_topo_find_tile( gui->topo, "backt", 0UL )!=ULONG_MAX ) ) {
    gui->summary.slot_caught_up = gui->summary.slot_tower;
    gui->summary.boot_progress.catching_up_time_nanos = now;

    fd_gui_printf_slot_caught_up( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  /* state transitions */
  if( FD_UNLIKELY( gui->summary.slot_caught_up!=ULONG_MAX ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_RUNNING;
    for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
      fd_gui_ema_init( &gui->summary.accdb->tier_fill_bps_ema[ k ], now, FD_GUI_ACCDB_EMA_HALF_LIFE_NS );
      fd_gui_ema_init( &gui->summary.accdb->tier_free_bps_ema[ k ], now, FD_GUI_ACCDB_EMA_HALF_LIFE_NS );
    }
  } else if( FD_LIKELY( snapshot_phase == FD_SNAPCT_STATE_SHUTDOWN && wfs_state==FD_GOSSIP_WFS_STATE_DONE && gui->summary.slots_max_turbine[ 0 ].slot!=ULONG_MAX && gui->summary.slot_tower!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( gui->summary.wfs_enabled ) ) {
      if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX ) ) {
        ulong snap_inc  = gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].slot;
        ulong snap_full = gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].slot;
        gui->summary.slot_caught_up = fd_ulong_if( snap_inc!=ULONG_MAX, snap_inc, snap_full );
        gui->summary.boot_progress.catching_up_time_nanos = now;

        fd_gui_printf_slot_caught_up( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
      gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_RUNNING;
      for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
        fd_gui_ema_init( &gui->summary.accdb->tier_fill_bps_ema[ k ], now, FD_GUI_ACCDB_EMA_HALF_LIFE_NS );
        fd_gui_ema_init( &gui->summary.accdb->tier_free_bps_ema[ k ], now, FD_GUI_ACCDB_EMA_HALF_LIFE_NS );
      }
    } else {
      gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP;
    }
  } else if( FD_UNLIKELY( snapshot_phase == FD_SNAPCT_STATE_SHUTDOWN && wfs_state==FD_GOSSIP_WFS_STATE_WAIT ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY;
  } else if( FD_LIKELY( snapshot_phase==FD_SNAPCT_STATE_READING_FULL_FILE
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_FULL_FILE_FINI
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_FULL_FILE_DONE
                     || snapshot_phase==FD_SNAPCT_STATE_READING_FULL_HTTP
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_FINI
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_DONE ) ) {
    gui->summary.boot_progress.phase = FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT;
  } else if( FD_LIKELY( snapshot_phase==FD_SNAPCT_STATE_READING_INCREMENTAL_FILE
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_FINI
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_DONE
                     || snapshot_phase==FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_FINI
                     || snapshot_phase==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_DONE ) ) {
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
      ulong _retry_cnt = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_RETRY ) ], snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_RETRY ) ]);

      /* reset boot state if necessary */
      if( FD_UNLIKELY( gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_cnt!=_retry_cnt ) ) {
        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_time_nanos = now;
        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_cnt = _retry_cnt;
      }

      ulong _total_bytes                   = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_SIZE_BYTES ) ],                 snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_SIZE_BYTES ) ]                );
      ulong _read_bytes                    = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ],                 snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) ]                 );
      ulong _decompress_decompressed_bytes = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN ) ], snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN ) ] );
      ulong _decompress_compressed_bytes   = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_COMPRESSED_BYTES_READ ) ],      snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ ) ]      );
      ulong _insert_bytes                  = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapin_metrics[ MIDX( GAUGE, SNAPIN, FULL_BYTES_READ ) ],                 snapin_metrics[ MIDX( GAUGE, SNAPIN, INCREMENTAL_BYTES_READ ) ]                 );
      ulong _snapwr_in_bytes               = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, snapwr_metrics[ MIDX( GAUGE, SNAPWR, FULL_BYTES_READ ) ],                 snapwr_metrics[ MIDX( GAUGE, SNAPWR, INCREMENTAL_BYTES_READ ) ]                 );

      ulong _insert_accounts_total         = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNT_LOADED ) ];
      ulong _insert_accounts_baseline      = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, 0UL, gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].insert_accounts_current );
      ulong _insert_accounts               = fd_ulong_sat_sub( _insert_accounts_total, _insert_accounts_baseline );

      ulong _snapwr_accounts_total         = snapwr_metrics[ MIDX( GAUGE, SNAPWR, ACCOUNTS_WRITTEN ) ];
      ulong _snapwr_accounts_baseline      = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, 0UL, gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].snapwr_accounts_current );
      ulong _snapwr_accounts               = fd_ulong_sat_sub( _snapwr_accounts_total, _snapwr_accounts_baseline );

      ulong _snapwr_out_total              = snapwr_metrics[ MIDX( GAUGE, SNAPWR, BYTES_WRITTEN ) ];
      ulong _snapwr_out_baseline           = fd_ulong_if( snapshot_idx==FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, 0UL, gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].snapwr_out_bytes_decompressed );
      ulong _snapwr_out_bytes              = fd_ulong_sat_sub( _snapwr_out_total, _snapwr_out_baseline );

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
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].insert_accounts_current   = _insert_accounts;

      /* snapwr (snapshot write) stage */
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].snapwr_in_bytes_decompressed  = _snapwr_in_bytes;
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].snapwr_out_bytes_decompressed = _snapwr_out_bytes;
      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].snapwr_accounts_current       = _snapwr_accounts;

      break;
    }
    case FD_GUI_BOOT_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY: {
      /* Only reachable when the topology has a gossip tile. */
      gui->summary.boot_progress.wfs_total_stake     = gossip_metrics[ MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKE_TOTAL ) ];
      gui->summary.boot_progress.wfs_connected_stake = gossip_metrics[ MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKE_ONLINE ) ];
      gui->summary.boot_progress.wfs_total_peers     = gossip_metrics[ MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKED_PEER_TOTAL ) ];
      gui->summary.boot_progress.wfs_connected_peers = gossip_metrics[ MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKED_PEER_ONLINE ) ];
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
fd_gui_try_insert_run_length_slot( ulong * slots, ulong capacity, ulong * slots_sz, ulong slot ) {
  /* catch up history is run-length encoded */
  ulong range_idx = fd_sort_up_ulong_split( slots, *slots_sz, slot );
  if( FD_UNLIKELY( range_idx<(*slots_sz)-1UL              && range_idx%2UL==0UL && slots[ range_idx ]<=slot && slots[ range_idx+1UL ]>=slot ) ) return;
  if( FD_UNLIKELY( range_idx<(*slots_sz) && range_idx>0UL && range_idx%2UL==1UL && slots[ range_idx-1UL ]<=slot && slots[ range_idx ]>=slot ) ) return;

  slots[ (*slots_sz)++ ] = slot;
  slots[ (*slots_sz)++ ] = slot;

  fd_sort_up_ulong_insert( slots, (*slots_sz) );

  /* colesce ranges */
  ulong removed = 0UL;
  for( ulong i=1UL; i<(*slots_sz)-1UL; i+=2 ) {
    if( FD_UNLIKELY( slots[ i ]+1UL==slots[ i+1UL ] ) ) {
      slots[ i ]     = ULONG_MAX;
      slots[ i+1UL ] = ULONG_MAX;
      removed += 2;
    }
  }

  if( FD_UNLIKELY( (*slots_sz)>=removed+capacity-2UL && (*slots_sz)>=4UL ) ) {
    /* We are at capacity, start coalescing earlier intervals. */
    slots[ 1 ] = ULONG_MAX;
    slots[ 2 ] = ULONG_MAX;
    removed += 2;
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

    if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX ) ) fd_gui_try_insert_run_length_slot( gui->summary.catch_up_repair, FD_GUI_REPAIR_CATCH_UP_HISTORY_SZ, &gui->summary.catch_up_repair_sz, slot );
  }
}

void
fd_gui_handle_repair_request( fd_gui_t * gui, ulong slot, ulong shred_idx, long now ) {
  fd_gui_shred_event_append( gui, slot, shred_idx, shred_idx/FD_FEC_SHRED_CNT, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, now, now );
}

static void
fd_gui_progcache_sample( fd_gui_t * gui ) {
  fd_topo_t const * topo = gui->topo;

  ulong hits    = 0UL;
  ulong lookups = 0UL;

  for( ulong i=0UL; i<gui->summary.execrp_tile_cnt; i++ ) {
    fd_topo_tile_t const * execrp = &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ];
    volatile ulong const * metrics = fd_metrics_tile( execrp->metrics );

    lookups += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_LOOKUP ) ];
    hits    += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_HIT    ) ];
  }

  /* The execrp tile writes lookups before hits in metrics_write, so
     reading lookups first then hits here means we may observe the
     new hits before the new lookups, giving hits > lookups
     momentarily.  Clamp to maintain the invariant hits <= lookups. */

  hits = fd_ulong_min( hits, lookups );

  ulong ring_idx       = gui->summary.progcache_history_idx % FD_GUI_PROGCACHE_HISTORY_CNT;
  ulong oldest_hits    = gui->summary.progcache_hits_history   [ ring_idx ];
  ulong oldest_lookups = gui->summary.progcache_lookups_history[ ring_idx ];

  gui->summary.progcache_hits_history   [ ring_idx ] = hits;
  gui->summary.progcache_lookups_history[ ring_idx ] = lookups;
  gui->summary.progcache_history_idx = gui->summary.progcache_history_idx + 1UL;

  ulong hits_1min    = hits    - oldest_hits;
  ulong lookups_1min = lookups - oldest_lookups;
  hits_1min = fd_ulong_min( hits_1min, lookups_1min );

  gui->summary.progcache_hits_1min    = hits_1min;
  gui->summary.progcache_lookups_1min = lookups_1min;
}

int
fd_gui_poll( fd_gui_t * gui, long now ) {
  if( FD_LIKELY( now>gui->next_sample_1sec ) ) {
    fd_gui_hist_evict_step( gui );

    for( ulong i=0UL; i<gui->tile_cnt; i++ ) {
      fd_gui_hist_ts_append( gui, FD_GUI_HIST_TILE_TIMERS, now, now, &gui->summary.tile_timers_packed[ i ] );
    }

    gui->next_sample_1sec += 1000L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_200millis ) ) {
    fd_gui_estimated_tps_snap( gui );
    fd_gui_printf_estimated_tps( gui );
    fd_http_server_ws_broadcast( gui->http );

    if( FD_LIKELY( !gui->leader_active ) ) {
      for( ulong i=0UL; i<gui->tile_cnt; i++ ) {
        fd_gui_hist_ts_append( gui, FD_GUI_HIST_TILE_TIMERS, now, now, &gui->summary.tile_timers_packed[ i ] );
      }
    }

    gui->next_sample_200millis += 200L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_100millis ) ) {
    fd_gui_txn_waterfall_snap( gui, gui->summary.txn_waterfall_current );
    fd_gui_printf_live_txn_waterfall( gui, gui->summary.txn_waterfall_reference, gui->summary.txn_waterfall_current, 0UL /* TODO: REAL NEXT LEADER SLOT */ );
    fd_http_server_ws_broadcast( gui->http );

    if( FD_LIKELY( gui->leader_active ) ) {
      gui->summary.txn_waterfall_current->sample_time_nanos = now;
      fd_gui_hist_ts_append( gui, FD_GUI_HIST_TXN_WATERFALL, now, now, gui->summary.txn_waterfall_current );
    }

    fd_gui_network_stats_snap( gui, gui->summary.network_stats_current );
    fd_gui_network_rate_max_update( gui, now );
    fd_gui_printf_live_network_metrics( gui, gui->summary.network_stats_current );
    fd_http_server_ws_broadcast( gui->http );

    *gui->summary.tile_stats_reference = *gui->summary.tile_stats_current;
    fd_gui_tile_stats_snap( gui, gui->summary.txn_waterfall_current, gui->summary.tile_stats_current, now );
    fd_gui_printf_live_tile_stats( gui, gui->summary.tile_stats_reference, gui->summary.tile_stats_current );
    fd_http_server_ws_broadcast( gui->http );

    {
      fd_gui_progcache_sample( gui );
      fd_gui_printf_live_program_cache( gui );
      fd_http_server_ws_broadcast( gui->http );

      *gui->summary.accounts_stats_reference = *gui->summary.accounts_stats_current;
      fd_gui_accounts_stats_snap( gui, gui->summary.accounts_stats_current );
      fd_gui_printf_accounts_stats( gui );
      fd_http_server_ws_broadcast( gui->http );
      gui->summary.accounts_stats_have_reference = 1;
    }

    if( FD_UNLIKELY( gui->summary.boot_progress.phase!=FD_GUI_BOOT_PROGRESS_TYPE_RUNNING ) ) {
      fd_gui_run_boot_progress( gui, now );
      if( FD_UNLIKELY( memcmp( &gui->summary.boot_progress, &gui->summary.prev_boot_progress, sizeof(fd_gui_boot_progress_t) ) ) ) {
        gui->summary.prev_boot_progress = gui->summary.boot_progress;
        fd_gui_printf_boot_progress( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    }

    ulong bundle_tile_idx = fd_topo_find_tile( gui->topo, "bundle", 0UL );
    if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
      volatile ulong const * bundle_metrics = fd_metrics_tile( gui->topo->tiles[ bundle_tile_idx ].metrics );
      int cur_state = (int)bundle_metrics[ MIDX( GAUGE, BUNDLE, STATE ) ];
      if( FD_UNLIKELY( cur_state != gui->block_engine.status ) ) {
        gui->block_engine.status = cur_state;
        fd_gui_printf_block_engine( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    }

    fd_gui_printf_health( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_100millis += 100L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_50millis ) ) {
    if( FD_LIKELY( !fd_gui_shreds_window_is_empty( gui, gui->shreds.broadcast_watermark_ns, now ) ) ) {
      fd_gui_printf_shred_updates( gui, gui->shreds.broadcast_watermark_ns, now );
      fd_http_server_ws_broadcast( gui->http );
    }
    gui->shreds.broadcast_watermark_ns = now;

    /* We get the repair slot from the sampled metric after catching up
       and from incoming shred data before catchup. This makes the
       catchup progress bar look complete while also keeping the
       overview slots vis correct.  TODO: do this properly using frags
       sent over a link */
    if( FD_LIKELY( gui->summary.slot_caught_up!=ULONG_MAX ) ) {
      /* Backtest topologies have no repair tile. */
      ulong repair_tile_idx = fd_topo_find_tile( gui->topo, "repair", 0UL );
      if( FD_LIKELY( repair_tile_idx!=ULONG_MAX ) ) {
        fd_topo_tile_t const * repair = &gui->topo->tiles[ repair_tile_idx ];
        volatile ulong const * repair_metrics = fd_metrics_tile( repair->metrics );
        ulong slot = repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ];
        fd_gui_handle_repair_slot( gui, slot, now );
      }
    }

    gui->next_sample_50millis += 50L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_40millis ) ) {
    fd_gui_tile_timers_snap( gui, now );

    fd_gui_printf_live_tile_timers( gui );
    fd_http_server_ws_broadcast( gui->http );

    fd_gui_printf_live_tile_metrics( gui );
    fd_http_server_ws_broadcast( gui->http );

    if( FD_LIKELY( gui->leader_active ) ) {
      for( ulong i=0UL; i<gui->tile_cnt; i++ ) {
        fd_gui_hist_ts_append( gui, FD_GUI_HIST_TILE_TIMERS, now, now, &gui->summary.tile_timers_packed[ i ] );
      }
    }

    gui->next_sample_40millis += 40L*1000L*1000L;
    return 1;
  }

  if( FD_LIKELY( now>gui->next_sample_10millis ) ) {
    if( FD_UNLIKELY( gui->leader_active ) ) fd_gui_scheduler_counts_snap( gui, now );

    fd_gui_printf_server_time_nanos( gui, now );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_10millis += 10L*1000L*1000L;
    return 1;
  }

  return 0;
}

int
fd_gui_request_slot( fd_gui_t *    gui,
                     ulong         ws_conn_id,
                     ulong         request_id,
                     cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;
  fd_gui_slot_t const * slot = fd_gui_slot_get_canon_safe( gui, _slot );
  if( FD_UNLIKELY( !slot || slot->skip==FD_GUI_SKIP_STATUS_UNKNOWN ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request( gui, _slot, request_id, slot );
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
  fd_gui_slot_t const * slot = fd_gui_slot_get_canon_safe( gui, _slot );
  if( FD_UNLIKELY( !slot || slot->skip==FD_GUI_SKIP_STATUS_UNKNOWN ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query_transactions", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_transactions_request( gui, _slot, request_id, slot );
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
  fd_gui_slot_t const * slot = fd_gui_slot_get_canon_safe( gui, _slot );
  if( FD_UNLIKELY( !slot || slot->skip==FD_GUI_SKIP_STATUS_UNKNOWN ) ) {
    fd_gui_printf_null_query_response( gui->http, "slot", "query_detailed", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request_detailed( gui, _slot, request_id, slot );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

static inline ulong
fd_gui_slot_duration( fd_gui_t * gui, fd_gui_slot_t const * cur ) {
  if( FD_UNLIKELY( cur->skip==FD_GUI_SKIP_STATUS_SKIPPED || cur->completed_time==LONG_MAX ) ) return ULONG_MAX;
  fd_gui_slot_t const * prev = fd_gui_slot_get_any( gui, cur->slot-1UL );
  long parent_completed_time = LONG_MAX;
  if( FD_LIKELY( prev && prev->skip!=FD_GUI_SKIP_STATUS_SKIPPED ) ) parent_completed_time = prev->completed_time;
  if( FD_UNLIKELY( parent_completed_time==LONG_MAX ) ) return ULONG_MAX;

  return (ulong)(cur->completed_time - parent_completed_time);
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

    if( slot->skip==FD_GUI_SKIP_STATUS_SKIPPED ) {
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
  if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX ) ) return;
  ulong first_replay_slot = fd_gui_first_replay_slot( gui );
  if( FD_UNLIKELY( first_replay_slot==ULONG_MAX ) ) return;
  if( FD_UNLIKELY( gui->summary.slot_rooted==ULONG_MAX ) ) return;

  fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, gui->summary.slot_rooted );
  if( FD_UNLIKELY( !epoch ) ) return;

  /* No new slots since the last update */
  if( FD_UNLIKELY( epoch->rankings_slot>gui->summary.slot_rooted ) ) return;

  /* Slots before first_replay_slot are unavailable. */
  epoch->rankings_slot = fd_ulong_max( epoch->rankings_slot, first_replay_slot );

  /* Update the rankings. Only look through slots we haven't already. */
  for( ulong s = gui->summary.slot_rooted; s>=epoch->rankings_slot; s--) {
    fd_gui_slot_t const * slot = fd_gui_slot_get_canon_safe( gui, s );
    if( FD_UNLIKELY( slot->skip==FD_GUI_SKIP_STATUS_UNKNOWN ) ) break;

    fd_gui_try_insert_ranking( gui, epoch->rankings, slot );
    if( FD_UNLIKELY( slot->mine ) ) fd_gui_try_insert_ranking( gui, epoch->my_rankings, slot );
  }

  epoch->rankings_slot = gui->summary.slot_rooted + 1UL;
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

static inline int
fd_gui_cjson_parse_ns( cJSON const * param,
                       long *        out ) {
  if( FD_UNLIKELY( !cJSON_IsString( param ) || !param->valuestring || !param->valuestring[ 0 ] ) ) return -1;

  ulong value = 0UL;
  for( char const * p=param->valuestring; *p; p++ ) {
    if( FD_UNLIKELY( *p<'0' || *p>'9' ) ) return -1;
    ulong digit = (ulong)(*p-'0');
    if( FD_UNLIKELY( value>((ulong)LONG_MAX-1UL-digit)/10UL ) ) return -1;
    value = 10UL*value + digit;
  }
  *out = (long)value;
  return 0;
}

/* cJSON stores decoded strings as NUL-terminated C strings without their
   decoded length.  Reject literal NUL bytes and escaped U+0000 before parsing
   so a value such as "1\u0000junk" cannot be observed below as "1". */

static inline int
fd_gui_json_has_nul( uchar const * data,
                     ulong         data_len ) {
  int in_string = 0;
  for( ulong i=0UL; i<data_len; i++ ) {
    uchar c = data[ i ];
    if( FD_UNLIKELY( !c ) ) return 1;
    if( c=='"' ) {
      in_string = !in_string;
      continue;
    }
    if( FD_LIKELY( !in_string || c!='\\' ) ) continue;
    if( FD_UNLIKELY( i+5UL<data_len && data[ i+1UL ]=='u' &&
                     data[ i+2UL ]=='0' && data[ i+3UL ]=='0' &&
                     data[ i+4UL ]=='0' && data[ i+5UL ]=='0' ) ) return 1;
    if( FD_LIKELY( i+1UL<data_len ) ) i++;
  }
  return 0;
}

static inline int
fd_gui_timeline_ws_send( fd_gui_t * gui,
                         ulong      ws_conn_id ) {
  return fd_http_server_ws_send( gui->http, ws_conn_id )
       ? FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED
       : 0;
}

static int
fd_gui_request_timeline_events( fd_gui_t *    gui,
                                ulong         ws_conn_id,
                                char const *  topic,
                                ulong         request_id,
                                cJSON const * params ) {
  const cJSON * start_param = cJSON_GetObjectItemCaseSensitive( params, "start_ns" );
  const cJSON * end_param   = cJSON_GetObjectItemCaseSensitive( params, "end_ns"   );
  const cJSON * granularity = cJSON_GetObjectItemCaseSensitive( params, "granularity" );

  long start_ns, end_ns;
  if( FD_UNLIKELY( fd_gui_cjson_parse_ns( start_param, &start_ns ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( fd_gui_cjson_parse_ns( end_param,   &end_ns   ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( end_ns<=start_ns ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( !cJSON_IsString( granularity ) || !granularity->valuestring ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  int err;
  if( !strcmp( granularity->valuestring, "shred" ) ) {
    err = fd_gui_printf_timeline_query_shreds( gui, topic, start_ns, end_ns, request_id );
  } else if( !strcmp( granularity->valuestring, "fec" ) ) {
    err = fd_gui_printf_timeline_query_fec_events( gui, topic, start_ns, end_ns, request_id );
  } else return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( err ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED;
  return fd_gui_timeline_ws_send( gui, ws_conn_id );
}

static int
fd_gui_request_timeline_txns( fd_gui_t *    gui,
                              ulong         ws_conn_id,
                              char const *  topic,
                              char const *  key,
                              ulong         request_id,
                              cJSON const * params ) {
  const cJSON * start_param = cJSON_GetObjectItemCaseSensitive( params, "start_ns" );
  const cJSON * end_param   = cJSON_GetObjectItemCaseSensitive( params, "end_ns"   );

  long start_ns, end_ns;
  if( FD_UNLIKELY( fd_gui_cjson_parse_ns( start_param, &start_ns ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( fd_gui_cjson_parse_ns( end_param,   &end_ns   ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( end_ns<=start_ns ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  int err;
  if( !strcmp( key, "query_txn_timestamps" ) ) {
    cJSON const * granularity = cJSON_GetObjectItemCaseSensitive( params, "granularity" );
    if( FD_UNLIKELY( !cJSON_IsString( granularity ) || !granularity->valuestring ) )
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    if( !strcmp( granularity->valuestring, "txn" ) ) {
      err = fd_gui_printf_timeline_query_txns( gui, topic, key, start_ns, end_ns, request_id );
    } else if( !strcmp( granularity->valuestring, "txn_batch" ) ) {
      err = fd_gui_printf_timeline_query_txn_batches( gui, topic, key, start_ns, end_ns, request_id );
    } else return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  } else {
    err = fd_gui_printf_timeline_query_txns( gui, topic, key, start_ns, end_ns, request_id );
  }
  if( FD_UNLIKELY( err ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED;
  return fd_gui_timeline_ws_send( gui, ws_conn_id );
}

static int
fd_gui_timeline_parse_ns_string( cJSON const * param,
                                 long *        out ) {
  if( FD_UNLIKELY( !cJSON_IsString( param ) || !param->valuestring || !param->valuestring[ 0 ] ) ) return -1;
  for( char const * p=param->valuestring; *p; p++ )
    if( FD_UNLIKELY( *p<'0' || *p>'9' ) ) return -1;
  ulong value = fd_cstr_to_ulong( param->valuestring );
  if( FD_UNLIKELY( value>(ulong)LONG_MAX ) ) return -1;
  *out = (long)value;
  return 0;
}

static int
fd_gui_timeline_parse_granularity( char const * name,
                                   ulong *      idx ) {
  for( ulong i=0UL; i<FD_GUI_TIMELINE_GRANULARITY_CNT; i++ ) {
    if( !strcmp( name, fd_gui_timeline_granularities[ i ].name ) ) { *idx=i; return 0; }
  }
  return -1;
}

static int
fd_gui_request_timeline_agg( fd_gui_t *    gui,
                             ulong         ws_conn_id,
                             char const *  key,
                             ulong         request_id,
                             cJSON const * params ) {
  cJSON const * start_param = cJSON_GetObjectItemCaseSensitive( params, "start_ns"    );
  cJSON const * end_param   = cJSON_GetObjectItemCaseSensitive( params, "end_ns"      );
  cJSON const * gran_param  = cJSON_GetObjectItemCaseSensitive( params, "granularity" );
  long start_ns, end_ns;
  if( FD_UNLIKELY( fd_gui_timeline_parse_ns_string( start_param, &start_ns ) ||
                   fd_gui_timeline_parse_ns_string( end_param,   &end_ns   ) ||
                   !cJSON_IsString( gran_param ) || !gran_param->valuestring ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  if( FD_UNLIKELY( end_ns<=start_ns ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong granularity_idx;
  if( FD_UNLIKELY( fd_gui_timeline_parse_granularity( gran_param->valuestring, &granularity_idx ) ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong granularity_ns = fd_gui_timeline_granularities[ granularity_idx ].duration_ns;
  ulong first_bucket   = (ulong)start_ns/granularity_ns;
  ulong last_bucket    = ((ulong)end_ns-1UL)/granularity_ns;
  ulong bucket_cnt     = last_bucket-first_bucket+1UL;
  if( FD_UNLIKELY( bucket_cnt>FD_GUI_TIMELINE_QUERY_MAX_BUCKETS ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  if( FD_UNLIKELY( fd_gui_printf_timeline_query_agg( gui, key, gran_param->valuestring, granularity_idx,
                                                     (long)(first_bucket*granularity_ns), bucket_cnt,
                                                     request_id ) ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED;
  return fd_gui_timeline_ws_send( gui, ws_conn_id );
}

int
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len ) {
  if( FD_UNLIKELY( fd_gui_json_has_nul( data, data_len ) ) )
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

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
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "timeline" ) &&
                        !strcmp( key->valuestring, "query_shreds" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_timeline_events( gui, ws_conn_id, topic->valuestring, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "timeline" ) &&
                        ( !strcmp( key->valuestring, "query_agg_slots" ) ||
                          !strcmp( key->valuestring, "query_agg_shreds" ) ||
                          !strcmp( key->valuestring, "query_agg_compute" ) ||
                          !strcmp( key->valuestring, "query_agg_txn" ) ||
                          !strcmp( key->valuestring, "query_agg_revenue" ) ) ) ) {
    cJSON const * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_timeline_agg( gui, ws_conn_id, key->valuestring, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "timeline" ) &&
                        ( !strcmp( key->valuestring, "query_txn_timestamps" ) ||
                          !strcmp( key->valuestring, "query_txn_meta"       ) ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_timeline_txns( gui, ws_conn_id, topic->valuestring, key->valuestring, id, params );
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

static inline uchar
slot_get_skip_status( fd_gui_t * gui, ulong _slot ) {
  ulong tower_slot = gui->summary.slot_tower;
  if( FD_UNLIKELY( tower_slot==ULONG_MAX || _slot>=tower_slot ) ) return FD_GUI_SKIP_STATUS_UNKNOWN;

  const ulong max_consecutive_skips = 1024UL; /* TODO: prove derivation */

  /* Find the nearest landed canonical descendant and walk its lineage
     down to obtain positive skip proof. */
  ulong anchor_slot     = ULONG_MAX;
  ulong anchor_bank_seq = ULONG_MAX;
  ulong search_hi       = fd_ulong_min( _slot+max_consecutive_skips, tower_slot );
  for( ulong s=_slot+1UL; s<=search_hi; s++ ) {
    fd_gui_hist_kv_slot_iter_t it[ 1 ];
    /* Equivocation-safe */
    for( fd_gui_hist_kv_iter_begin( gui, it, FD_GUI_HIST_SLOT, s ); it->rec; fd_gui_hist_kv_iter_next( it ) ) {
      fd_gui_slot_t const * rec = (fd_gui_slot_t const *)it->rec;
      if( FD_LIKELY( rec->skip==FD_GUI_SKIP_STATUS_NOT_SKIPPED ) ) {
        anchor_slot     = s;
        anchor_bank_seq = it->bank_seq;
        break;
      }
    }
    if( FD_UNLIKELY( anchor_slot!=ULONG_MAX ) ) break;
  }
  if( FD_UNLIKELY( anchor_slot==ULONG_MAX ) ) return FD_GUI_SKIP_STATUS_UNKNOWN; /* no descendant found */

  /* Walk the canonical fork back up. */
  ulong cur_slot     = anchor_slot;
  ulong cur_bank_seq = anchor_bank_seq;
  for( ulong steps=0UL; steps<max_consecutive_skips; steps++ ) {
    fd_gui_hist_slot_key_t key;
    key.slot = cur_slot; key.bank_seq = cur_bank_seq;
    fd_gui_slot_t const * cmeta = (fd_gui_slot_t const *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_SLOT, &key );
    if( FD_UNLIKELY( !cmeta ) ) return FD_GUI_SKIP_STATUS_UNKNOWN; /* lineage broken / aged out */

    ulong parent_slot     = cmeta->parent_slot;
    ulong parent_bank_seq = cmeta->parent_bank_seq;
    if( FD_UNLIKELY( parent_slot==ULONG_MAX ) ) return FD_GUI_SKIP_STATUS_UNKNOWN; /* Couldn't find _slot */
    if( FD_LIKELY( parent_slot==_slot ) ) return FD_GUI_SKIP_STATUS_NOT_SKIPPED;   /* _slot is on this lineage */
    if( FD_LIKELY( parent_slot< _slot ) ) return FD_GUI_SKIP_STATUS_SKIPPED;       /* lineage steps over _slot: skipped */
    cur_slot     = parent_slot;
    cur_bank_seq = parent_bank_seq;
  }
  return FD_GUI_SKIP_STATUS_UNKNOWN;
}

fd_gui_slot_t *
fd_gui_slot_get_canon_safe( fd_gui_t * gui, ulong _slot ) {
  fd_gui_slot_t * slot = fd_gui_slot_get_canon( gui, _slot );

  if( FD_LIKELY( slot ) ) {
    return slot;
  } else {
    uchar level = FD_GUI_SLOT_LEVEL_COMPLETED;
    if( FD_LIKELY( gui->summary.slot_optimistically_confirmed!=ULONG_MAX && _slot<gui->summary.slot_optimistically_confirmed ) ) level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
    if( FD_LIKELY( gui->summary.slot_rooted!=ULONG_MAX && _slot<gui->summary.slot_rooted ) ) level = FD_GUI_SLOT_LEVEL_ROOTED;

    *gui->skipped_scratch = (fd_gui_slot_t){
      .slot             = _slot,
      .bank_seq         = ULONG_MAX,
      .parent_bank_seq  = ULONG_MAX,
      .parent_slot      = fd_gui_slot_skipped_get_parent( gui, _slot ),
      .vote_slot        = ULONG_MAX,
      .completed_time   = LONG_MAX,
      .parent_completed_time = LONG_MAX,
      .max_compute_units= UINT_MAX,
      .mine             = (uchar)(fd_gui_slot_is_mine( gui, _slot ) & 1),
      .skip             = slot_get_skip_status( gui, _slot ),
      .level            = level,
      .compute_units    = UINT_MAX,
      .transaction_fee  = ULONG_MAX,
      .priority_fee     = ULONG_MAX,
      .tips             = ULONG_MAX,
      .shred_cnt        = UINT_MAX,
      .block_shred_cnt  = UINT_MAX,
      .turbine_shred_cnt       = UINT_MAX,
      .repair_shred_cnt        = UINT_MAX,
      .reconstructed_shred_cnt = UINT_MAX,
      .published_shred_cnt     = UINT_MAX,
      .vote_latency_exact = FD_GUI_VOTE_LATENCY_NOT_VOTED,
      .is_voter         = 0,
      .vote_success     = UINT_MAX,
      .vote_failed      = UINT_MAX,
      .nonvote_success  = UINT_MAX,
      .nonvote_failed   = UINT_MAX,
    };
    return gui->skipped_scratch;
  }
}

void
fd_gui_handle_epoch_info( fd_gui_t *                  gui,
                          fd_epoch_info_msg_t const * epoch_info,
                          long                        now ) {
  FD_TEST( epoch_info->staked_vote_cnt<=MAX_STAKE_WEIGHTS );
  FD_TEST( epoch_info->slot_cnt<=MAX_SLOTS_PER_EPOCH );
  FD_TEST( epoch_info->staked_vote_cnt );

  if( FD_UNLIKELY( !gui->epoch.has_epoch_schedule ) ) {
    gui->epoch.epoch_schedule     = epoch_info->epoch_schedule;
    gui->epoch.has_epoch_schedule = 1;
  }

  fd_vote_stake_weight_t const * stake_weights = fd_epoch_info_msg_stake_weights( epoch_info );
  fd_memcpy( gui->epoch.stakes_scratch, stake_weights, epoch_info->staked_vote_cnt*sizeof(fd_vote_stake_weight_t) );

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.lsched_scratch,
                                                                             epoch_info->epoch,
                                                                             epoch_info->start_slot,
                                                                             epoch_info->slot_cnt,
                                                                             epoch_info->staked_vote_cnt,
                                                                             gui->epoch.stakes_scratch ) );
  FD_TEST( lsched );

  int created = 0;
  fd_gui_epoch_t * epoch = fd_gui_epoch_get_or_create( gui, epoch_info->epoch, &created );
  FD_TEST( epoch );

  if( FD_LIKELY( created ) ) {
    epoch->epoch          = epoch_info->epoch;
    epoch->start_slot     = epoch_info->start_slot;
    epoch->slot_cnt       = epoch_info->slot_cnt;
    epoch->start_time     = LONG_MAX;
    epoch->end_time       = LONG_MAX;
    epoch->target_slot_duration_ns = (long)epoch_info->ns_per_slot;
    epoch->my_total_slots = 0UL;
    epoch->my_skipped_slots = 0UL;
    epoch->rankings_slot  = epoch_info->start_slot;
    memset( epoch->rankings,    (int)(UINT_MAX), sizeof(epoch->rankings)    );
    memset( epoch->my_rankings, (int)(UINT_MAX), sizeof(epoch->my_rankings) );
    memset( epoch->latency_exact, (int)FD_GUI_VOTE_LATENCY_NOT_VOTED, sizeof(epoch->latency_exact) );
    memset( epoch->is_voter,      0,                                 sizeof(epoch->is_voter)      );
    memset( epoch->skipped,       0,                                 sizeof(epoch->skipped)       );
    epoch->epoch_schedule = epoch_info->epoch_schedule;
    epoch->pub_cnt        = lsched->pub_cnt;
    epoch->stakes_cnt     = epoch_info->staked_vote_cnt;
    fd_memcpy( epoch->pub,    lsched->pub,   epoch->pub_cnt*sizeof(fd_pubkey_t) );
    fd_memcpy( epoch->sched,  lsched->sched, fd_ulong_min( lsched->sched_cnt, FD_GUI_EPOCH_SCHED_CNT )*sizeof(uint) );
    fd_memcpy( epoch->stakes, gui->epoch.stakes_scratch, epoch->stakes_cnt*sizeof(fd_vote_stake_weight_t) );
  }

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );

  if( FD_UNLIKELY( gui->epoch.current_epoch==ULONG_MAX ) ) {
    gui->epoch.current_epoch = epoch_info->epoch;
  } else {
    gui->epoch.current_epoch = fd_ulong_max( gui->epoch.current_epoch, epoch_info->epoch>0UL ? epoch_info->epoch-1UL : 0UL );
  }

  epoch->start_time = now;
  for( ulong i=0UL; i<fd_ulong_min( fd_ulong_sat_sub( epoch_info->start_slot, 1UL ), MAX_SLOTS_PER_EPOCH ); i++ ) {
    fd_gui_slot_t const * slot = fd_gui_slot_get_any( gui, epoch_info->start_slot-i );
    if( FD_UNLIKELY( !slot ) ) break;
    else if( FD_UNLIKELY( slot->skip==FD_GUI_SKIP_STATUS_SKIPPED ) ) continue;
    epoch->start_time = slot->parent_completed_time;
    break;
  }

  fd_gui_printf_epoch( gui, epoch_info->epoch );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_handle_shred( fd_gui_t * gui,
                     ulong      slot,
                     ulong      shred_idx,
                     ulong      fec_set_idx,
                     int        is_turbine,
                     long       tsorig,
                     long       now ) {
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

    if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX ) ) fd_gui_try_insert_run_length_slot( gui->summary.catch_up_turbine, FD_GUI_TURBINE_CATCH_UP_HISTORY_SZ, &gui->summary.catch_up_turbine_sz, slot );
  }

  fd_gui_shred_event_append( gui, slot, shred_idx, fec_set_idx/FD_FEC_SHRED_CNT,
                             fd_ulong_if( is_turbine, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR ),
                             now, tsorig );
}

static fd_gui_timeline_shred_accum_t *
fd_gui_timeline_shred_accum( fd_gui_t * gui,
                             ulong      slot ) {
  FD_STATIC_ASSERT( !(FD_GUI_TIMELINE_SHRED_BUF_CNT & (FD_GUI_TIMELINE_SHRED_BUF_CNT-1UL)), timeline_shred_buf_pow2 );
  fd_gui_timeline_shred_accum_t * accum = &gui->timeline_shreds[ slot & (FD_GUI_TIMELINE_SHRED_BUF_CNT-1UL) ];
  if( FD_UNLIKELY( accum->slot!=slot ) ) {
    /* Do not let late repair traffic for an old slot displace a newer
       in-flight slot that aliases the same direct-mapped entry. */
    if( FD_UNLIKELY( accum->slot!=ULONG_MAX && slot<accum->slot ) ) return NULL;
    *accum = (fd_gui_timeline_shred_accum_t){ .slot=slot };
  }
  return accum;
}

#define FD_GUI_TIMELINE_METRIC_TURBINE       (0)
#define FD_GUI_TIMELINE_METRIC_REPAIR        (1)
#define FD_GUI_TIMELINE_METRIC_RECONSTRUCTED (2)
#define FD_GUI_TIMELINE_METRIC_PUBLISHED     (3)

static void
fd_gui_timeline_event_delta( fd_gui_t * gui,
                             ulong      slot,
                             long       timestamp_ns,
                             int        metric,
                             ulong      value );

static inline uint
fd_gui_timeline_uint_add( uint value,
                          uint delta ) {
  uint max_value = UINT_MAX-1U; /* UINT_MAX is the unknown sentinel */
  return delta>max_value-value ? max_value : value+delta;
}

static fd_gui_slot_t *
fd_gui_timeline_completed_slot( fd_gui_t * gui,
                                ulong      slot ) {
  fd_gui_hist_kv_slot_iter_t it[ 1 ];
  for( fd_gui_hist_kv_iter_begin( gui, it, FD_GUI_HIST_SLOT, slot ); it->rec; fd_gui_hist_kv_iter_next( it ) ) {
    fd_gui_slot_t * candidate = (fd_gui_slot_t *)it->rec;
    if( FD_LIKELY( candidate->completed_time!=LONG_MAX ) ) return candidate;
  }
  return NULL;
}

static void
fd_gui_timeline_slot_sources_known( fd_gui_slot_t * slot ) {
#define SOURCE_KNOWN(field) do {   \
    if( slot->field==UINT_MAX ) {  \
      slot->field = 0U;            \
    }                              \
  } while(0)
  SOURCE_KNOWN( turbine_shred_cnt       );
  SOURCE_KNOWN( repair_shred_cnt        );
  SOURCE_KNOWN( reconstructed_shred_cnt );
#undef SOURCE_KNOWN
}

void
fd_gui_timeline_handle_shred( fd_gui_t * gui,
                              ulong      slot,
                              uint       source ) {
  if( FD_UNLIKELY( source!=SHRED_SIG_SRC_TURBINE &&
                   source!=SHRED_SIG_SRC_REPAIR &&
                   source!=SHRED_SIG_SRC_RECONSTRUCTED ) ) return;

  fd_gui_timeline_shred_accum_t * accum = fd_gui_timeline_shred_accum( gui, slot );
  if( FD_UNLIKELY( !accum ) ) return;
  if( FD_UNLIKELY( accum->completed ) ) {
    fd_gui_slot_t * completed = fd_gui_timeline_completed_slot( gui, slot );
    if( FD_UNLIKELY( !completed ) ) return;
    fd_gui_timeline_slot_sources_known( completed );
    if( source==SHRED_SIG_SRC_TURBINE ) {
      completed->turbine_shred_cnt = fd_gui_timeline_uint_add( completed->turbine_shred_cnt, 1U );
    } else if( source==SHRED_SIG_SRC_REPAIR ) {
      completed->repair_shred_cnt = fd_gui_timeline_uint_add( completed->repair_shred_cnt, 1U );
    } else {
      completed->reconstructed_shred_cnt = fd_gui_timeline_uint_add( completed->reconstructed_shred_cnt, 1U );
    }
    return;
  }

  accum->sources_known = 1;
  if(      source==SHRED_SIG_SRC_TURBINE       ) accum->turbine       = fd_gui_timeline_uint_add( accum->turbine,       1U );
  else if( source==SHRED_SIG_SRC_REPAIR        ) accum->repair        = fd_gui_timeline_uint_add( accum->repair,        1U );
  else if( source==SHRED_SIG_SRC_RECONSTRUCTED ) accum->reconstructed = fd_gui_timeline_uint_add( accum->reconstructed, 1U );
}

void
fd_gui_timeline_handle_fec( fd_gui_t * gui,
                            ulong      slot,
                            int        published,
                            long       timestamp_ns,
                            uint       turbine_shred_cnt,
                            uint       repair_shred_cnt,
                            uint       reconstructed_shred_cnt ) {
  uint fec_shred_cnt = 2U*(uint)FD_FEC_SHRED_CNT; /* data plus coding */

  /* All aggregate shred fields share the FEC completion timestamp.  A
     completed FEC makes every source contribution known, including zero. */
  fd_gui_timeline_event_delta( gui, slot, timestamp_ns, FD_GUI_TIMELINE_METRIC_TURBINE,       turbine_shred_cnt       );
  fd_gui_timeline_event_delta( gui, slot, timestamp_ns, FD_GUI_TIMELINE_METRIC_REPAIR,        repair_shred_cnt        );
  fd_gui_timeline_event_delta( gui, slot, timestamp_ns, FD_GUI_TIMELINE_METRIC_RECONSTRUCTED, reconstructed_shred_cnt );
  fd_gui_timeline_event_delta( gui, slot, timestamp_ns, FD_GUI_TIMELINE_METRIC_PUBLISHED,     published ? fec_shred_cnt : 0UL );

  fd_gui_timeline_shred_accum_t * accum = fd_gui_timeline_shred_accum( gui, slot );
  if( FD_UNLIKELY( !accum ) ) return;
  if( FD_UNLIKELY( accum->completed ) ) {
    fd_gui_slot_t * completed = fd_gui_timeline_completed_slot( gui, slot );
    if( FD_UNLIKELY( !completed ) ) return;
    if( completed->block_shred_cnt==UINT_MAX ) completed->block_shred_cnt = 0U;
    completed->block_shred_cnt = fd_gui_timeline_uint_add( completed->block_shred_cnt, fec_shred_cnt );

    fd_gui_timeline_slot_sources_known( completed );
    if( published ) {
      if( completed->published_shred_cnt==UINT_MAX ) completed->published_shred_cnt = 0U;
      completed->published_shred_cnt = fd_gui_timeline_uint_add( completed->published_shred_cnt, fec_shred_cnt );
    }
    return;
  }

  accum->shreds_known  = 1;
  accum->sources_known   = 1;
  accum->shreds = fd_gui_timeline_uint_add( accum->shreds, fec_shred_cnt );
  if( published ) {
    accum->published_known = 1;
    accum->published = fd_gui_timeline_uint_add( accum->published, fec_shred_cnt );
  }
}

void
fd_gui_timeline_complete_slot( fd_gui_t *      gui,
                               ulong           slot,
                               fd_gui_slot_t * dst ) {
  fd_gui_timeline_shred_accum_t * accum = &gui->timeline_shreds[ slot & (FD_GUI_TIMELINE_SHRED_BUF_CNT-1UL) ];
  if( FD_UNLIKELY( accum->slot!=slot ) ) {
    if( FD_UNLIKELY( accum->slot!=ULONG_MAX && slot<accum->slot ) ) return;
    *accum = (fd_gui_timeline_shred_accum_t){ .slot=slot, .completed=1 };
    return;
  }
  if( dst && accum->shreds_known ) dst->block_shred_cnt = accum->shreds;
  if( dst && accum->sources_known ) {
    dst->turbine_shred_cnt       = accum->turbine;
    dst->repair_shred_cnt        = accum->repair;
    dst->reconstructed_shred_cnt = accum->reconstructed;
  }
  if( dst && accum->published_known ) dst->published_shred_cnt = accum->published;
  *accum = (fd_gui_timeline_shred_accum_t){ .slot=slot, .completed=1 };
}

void
fd_gui_handle_leader_fec( fd_gui_t * gui,
                          ulong      slot,
                          ulong      fec_shred_cnt,
                          int        is_end_of_slot,
                          long       tsorig,
                          long       now ) {
  for( ulong i=gui->shreds.leader_shred_cnt; i<gui->shreds.leader_shred_cnt+fec_shred_cnt; i++ ) {
    fd_gui_shred_event_append( gui, slot, i, i/FD_FEC_SHRED_CNT, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED, now, tsorig );
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
                             long       tspub_ns,
                             long       now ) {
  for( ulong i = start_shred_idx; i<end_shred_idx; i++ ) {
    /*
      We're leaving this state transition out due to its proximity to
      FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, but if we ever wanted
      to send this data to the frontend we could.

      fd_gui_shred_event_append( gui, slot, i, i/FD_FEC_SHRED_CNT,
                                 FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_START, now, tsorig_ns );
    */

    fd_gui_shred_event_append( gui, slot, i, i/FD_FEC_SHRED_CNT, FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, now, tspub_ns );
  }
}

/* fd_gui_compute_vote_latency walks the fork whose landing block is
   (landed_slot, landed_bank_seq) down toward voted_slot.  On success
   (voted_slot is an ancestor on this fork) returns 1 and writes
   voted_slot's bank_seq on this fork to *out_voted_bank_seq and the
   skip-discounted latency to *out_exact.  Returns 0 if voted_slot is
   not an ancestor on this fork, or the ancestry is not yet
   replayed/linked. */

static int
fd_gui_compute_vote_latency( fd_gui_t * gui,
                             ulong      landed_slot,
                             ulong      landed_bank_seq,
                             ulong      voted_slot,
                             ulong *    out_voted_bank_seq,
                             ulong *    out_exact ) {
  ulong on_fork_between = 0UL;
  ulong cur_slot        = landed_slot;
  ulong cur_bank_seq    = landed_bank_seq;
  for( ulong steps=0UL; steps<1024UL; steps++ ) {
    fd_gui_slot_t const * c = fd_gui_slot_get( gui, cur_slot, cur_bank_seq );
    if( FD_UNLIKELY( !c ) ) return 0;
    ulong pslot = c->parent_slot;
    ulong pseq  = c->parent_bank_seq;
    if( FD_UNLIKELY( pslot==ULONG_MAX ) ) return 0;
    if( FD_UNLIKELY( pslot<voted_slot ) ) return 0;
    if( FD_LIKELY( pslot==voted_slot ) ) {
      *out_voted_bank_seq = pseq;
      *out_exact          = 1UL + on_fork_between;
      return 1;
    }
    on_fork_between++;
    cur_slot     = pslot;
    cur_bank_seq = pseq;
  }
  return 0;
}

/* fd_gui_record_vote_latency records the minimum vote_latency_exact
   observed for the (voted_slot, voted_bank_seq) fork. */

static void
fd_gui_record_vote_latency( fd_gui_t * gui,
                            ulong      voted_slot,
                            ulong      voted_bank_seq,
                            uchar      vote_latency_exact ) {
  vote_latency_exact = (uchar)fd_ulong_min( vote_latency_exact, FD_GUI_VOTE_LATENCY_MAX );

  fd_gui_slot_t * slot = fd_gui_slot_get( gui, voted_slot, voted_bank_seq );
  if( FD_LIKELY( slot ) && FD_LIKELY( vote_latency_exact<slot->vote_latency_exact ) ) {
    slot->vote_latency_exact = vote_latency_exact;
    fd_gui_printf_slot( gui, voted_slot, slot );
    fd_http_server_ws_broadcast( gui->http );
  }
}

static fd_gui_timeline_day_t *
fd_gui_timeline_day_create( fd_gui_t * gui,
                            ulong      day_idx ) {
  fd_gui_hist_timeline_day_key_t key = { .day=day_idx };
  fd_gui_timeline_day_t * day = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key );
  if( FD_LIKELY( day ) ) {
    gui->timeline_day_max = gui->timeline_day_max==ULONG_MAX ? day_idx : fd_ulong_max( gui->timeline_day_max, day_idx );
    return day;
  }

  /* The KV ring reclaims a physical prefix, so first insertion of each day
     must remain monotonic.  A missing older day has already fallen outside
     the retained horizon. */
  if( FD_UNLIKELY( gui->timeline_day_max!=ULONG_MAX && day_idx<gui->timeline_day_max ) ) return NULL;
  fd_gui_timeline_day_t const * oldest = fd_gui_store_kv_get_any( (fd_gui_store_t *)gui->db,
                                                                  (ulong)FD_GUI_HIST_TIMELINE_DAY,
                                                                  NULL );
  if( FD_UNLIKELY( oldest && day_idx<oldest->day ) ) return NULL;

  day = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_TIMELINE_DAY, &key );
  if( FD_UNLIKELY( !day ) ) return NULL;
  memset( day, 0xFF, sizeof(*day) );
  day->day = day_idx;
  gui->timeline_day_max = day_idx;
  return day;
}

/* Return the retained record for an event's UTC day, creating records only
   while time moves forward.  When advancing across a gap, create the day
   immediately preceding the event first.  This keeps the common midnight
   late-arrival case writable without permitting an old event to reorder the
   KV ring. */

static fd_gui_timeline_day_t *
fd_gui_timeline_day_for_event( fd_gui_t * gui,
                               ulong      day_idx ) {
  fd_gui_hist_timeline_day_key_t key = { .day=day_idx };
  fd_gui_timeline_day_t * day = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key );
  if( FD_LIKELY( day ) ) {
    gui->timeline_day_max = gui->timeline_day_max==ULONG_MAX ? day_idx : fd_ulong_max( gui->timeline_day_max, day_idx );
    return day;
  }

  if( FD_UNLIKELY( gui->timeline_day_max!=ULONG_MAX && day_idx<=gui->timeline_day_max ) ) return NULL;

  if( FD_LIKELY( day_idx ) ) {
    ulong preceding_day = day_idx-1UL;
    if( gui->timeline_day_max==ULONG_MAX || preceding_day>gui->timeline_day_max ) {
      if( FD_UNLIKELY( !fd_gui_timeline_day_create( gui, preceding_day ) ) ) return NULL;
    }
  }
  return fd_gui_timeline_day_create( gui, day_idx );
}

static inline void
fd_gui_timeline_ulong_add( ulong * value,
                           ulong   delta ) {
  ulong max_value = ULONG_MAX-1UL; /* ULONG_MAX is the unknown sentinel */
  *value = delta>max_value-*value ? max_value : *value+delta;
}

static void
fd_gui_timeline_event_delta( fd_gui_t * gui,
                             ulong      slot,
                             long       timestamp_ns,
                             int        metric,
                             ulong      value ) {
  if( FD_UNLIKELY( slot==ULONG_MAX || timestamp_ns<0L || value==ULONG_MAX ) ) return;
  ulong ts_ns   = (ulong)timestamp_ns;
  ulong day_idx = ts_ns/(ulong)FD_GUI_TIMELINE_DAY_NS;
  ulong day_ns  = ts_ns%(ulong)FD_GUI_TIMELINE_DAY_NS;
  fd_gui_timeline_day_t * day = fd_gui_timeline_day_for_event( gui, day_idx );
  if( FD_UNLIKELY( !day ) ) return;

  for( ulong g=0UL; g<FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong idx = fd_gui_timeline_stored_granularity_off[ g ] + day_ns/fd_gui_timeline_stored_granularity_ns[ g ];
    day->start_slot[ idx ] = day->start_slot[ idx ]==ULONG_MAX ? slot : fd_ulong_min( day->start_slot[ idx ], slot );
    day->end_slot  [ idx ] = day->end_slot  [ idx ]==ULONG_MAX ? slot : fd_ulong_max( day->end_slot  [ idx ], slot );
    ulong * dst;
    switch( metric ) {
      case FD_GUI_TIMELINE_METRIC_TURBINE:       dst = &day->turbine      [ idx ]; break;
      case FD_GUI_TIMELINE_METRIC_REPAIR:        dst = &day->repair       [ idx ]; break;
      case FD_GUI_TIMELINE_METRIC_RECONSTRUCTED: dst = &day->reconstructed[ idx ]; break;
      case FD_GUI_TIMELINE_METRIC_PUBLISHED:     dst = &day->published    [ idx ]; break;
      default: return;
    }
    if( *dst==ULONG_MAX ) *dst = value;
    else                  fd_gui_timeline_ulong_add( dst, value );
  }
}

void
fd_gui_timeline_handle_txn( fd_gui_t * gui,
                            ulong      slot,
                            long       timestamp_ns,
                            ulong      compute_units,
                            ulong      max_compute_units,
                            ulong      transaction_fee,
                            ulong      priority_fee,
                            ulong      tips,
                            int        is_simple_vote,
                            int        txn_succeeded ) {
  if( FD_UNLIKELY( slot==ULONG_MAX || timestamp_ns<0L ) ) return;

  ulong ts_ns   = (ulong)timestamp_ns;
  ulong day_idx = ts_ns/(ulong)FD_GUI_TIMELINE_DAY_NS;
  ulong day_ns  = ts_ns%(ulong)FD_GUI_TIMELINE_DAY_NS;
  fd_gui_timeline_day_t * day = fd_gui_timeline_day_for_event( gui, day_idx );
  if( FD_UNLIKELY( !day ) ) return;

#define TIMELINE_ADD(field,value) do {                                 \
    ulong _v = (value);                                                \
    if( _v!=ULONG_MAX ) {                                              \
      if( day->field[ idx ]==ULONG_MAX ) day->field[ idx ] = _v;       \
      else fd_gui_timeline_ulong_add( &day->field[ idx ], _v );        \
    }                                                                 \
  } while(0)

  for( ulong g=0UL; g<FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong idx = fd_gui_timeline_stored_granularity_off[ g ] + day_ns/fd_gui_timeline_stored_granularity_ns[ g ];
    day->start_slot[ idx ] = day->start_slot[ idx ]==ULONG_MAX ? slot : fd_ulong_min( day->start_slot[ idx ], slot );
    day->end_slot  [ idx ] = day->end_slot  [ idx ]==ULONG_MAX ? slot : fd_ulong_max( day->end_slot  [ idx ], slot );
    TIMELINE_ADD( compute_units, compute_units    );
    if( max_compute_units!=ULONG_MAX )
      day->max_compute[ idx ] = day->max_compute[ idx ]==ULONG_MAX
                              ? max_compute_units
                              : fd_ulong_max( day->max_compute[ idx ], max_compute_units );
    TIMELINE_ADD( txn_fees,  transaction_fee );
    TIMELINE_ADD( prio_fees, priority_fee    );
    TIMELINE_ADD( tips,      tips            );
    TIMELINE_ADD( nonvote_success, !is_simple_vote &&  txn_succeeded );
    TIMELINE_ADD( nonvote_failed,  !is_simple_vote && !txn_succeeded );
    TIMELINE_ADD( vote_success,     is_simple_vote &&  txn_succeeded );
    TIMELINE_ADD( vote_failed,      is_simple_vote && !txn_succeeded );
  }
#undef TIMELINE_ADD
}

static inline void
fd_gui_timeline_skipped_inc( uint * value ) {
  if( FD_UNLIKELY( *value==UINT_MAX ) ) *value = 1U;
  else if( FD_LIKELY( *value<UINT_MAX-1U ) ) (*value)++;
}

/* Attribute one skipped slot to every stored tier.  Skipped slots are
   synthetic timeline events, so they do not affect the observed
   start_slot/end_slot bounds. */

static void
fd_gui_timeline_skipped_add( fd_gui_t * gui,
                             long       timestamp_ns ) {
  ulong ts_ns   = (ulong)timestamp_ns;
  ulong day_idx = ts_ns/(ulong)FD_GUI_TIMELINE_DAY_NS;
  ulong day_ns  = ts_ns%(ulong)FD_GUI_TIMELINE_DAY_NS;

  fd_gui_hist_timeline_day_key_t key = { .day=day_idx };
  fd_gui_timeline_day_t * day = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key );
  FD_TEST( day ); /* The full covered day range is prepared before writes. */

  for( ulong g=0UL; g<FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong idx = fd_gui_timeline_stored_granularity_off[ g ] + day_ns/fd_gui_timeline_stored_granularity_ns[ g ];
    fd_gui_timeline_skipped_inc( &day->skipped[ idx ] );
  }
}

/* Ensure every UTC day in the newly classified interval exists before any
   skipped counts are written.  This makes the subsequent reverse ancestry
   walk safe even when it crosses midnight. */

static int
fd_gui_timeline_skipped_prepare_days( fd_gui_t * gui,
                                      long       start_ns,
                                      long       end_ns ) {
  if( FD_UNLIKELY( start_ns<0L || end_ns<start_ns ) ) return 0;

  ulong first_day = (ulong)start_ns/(ulong)FD_GUI_TIMELINE_DAY_NS;
  ulong last_day  = (ulong)end_ns  /(ulong)FD_GUI_TIMELINE_DAY_NS;
  for( ulong day=first_day;; day++ ) {
    if( FD_UNLIKELY( !fd_gui_timeline_day_create( gui, day ) ) ) return 0;
    if( FD_LIKELY( day==last_day ) ) break;
  }
  return 1;
}

static int
fd_gui_timeline_skipped_can_prepare_days( fd_gui_t * gui,
                                          long       start_ns,
                                          long       end_ns ) {
  ulong first_day = (ulong)start_ns/(ulong)FD_GUI_TIMELINE_DAY_NS;
  ulong last_day  = (ulong)end_ns  /(ulong)FD_GUI_TIMELINE_DAY_NS;
  for( ulong day=first_day;; day++ ) {
    fd_gui_hist_timeline_day_key_t key = { .day=day };
    if( FD_UNLIKELY( !fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key ) &&
                     gui->timeline_day_max!=ULONG_MAX && day<gui->timeline_day_max ) ) return 0;
    if( FD_LIKELY( day==last_day ) ) break;
  }
  return 1;
}

/* Find the oldest landed slot that can anchor this OC update.  Once a
   watermark exists, the new OC lineage must reach that exact fork record.
   For the first OC event, use the longest retained suffix with valid,
   nondecreasing completion timestamps. */

static int
fd_gui_timeline_skipped_find_anchor( fd_gui_t *              gui,
                                     fd_gui_slot_t const *    tip,
                                     fd_gui_slot_t const **   anchor_out ) {
  int have_watermark = gui->timeline_skipped_slot_watermark!=ULONG_MAX;
  if( FD_UNLIKELY( !tip || tip->completed_time==LONG_MAX || tip->completed_time<0L ) ) return 0;
  if( FD_UNLIKELY( !fd_gui_timeline_skipped_can_prepare_days( gui, tip->completed_time, tip->completed_time ) ) ) return 0;

  fd_gui_slot_t const * c = tip;
  for(;;) {
    if( FD_UNLIKELY( have_watermark && c->slot<gui->timeline_skipped_slot_watermark ) ) return 0;

    if( have_watermark && c->slot==gui->timeline_skipped_slot_watermark ) {
      if( FD_UNLIKELY( c->bank_seq!=gui->timeline_skipped_bank_seq_watermark ||
                       c->completed_time!=gui->timeline_skipped_coverage_end_ns ) ) return 0;
      *anchor_out = c;
      return 1;
    }

    ulong pslot = c->parent_slot;
    ulong pseq  = c->parent_bank_seq;
    if( FD_UNLIKELY( pslot==ULONG_MAX || pseq==ULONG_MAX || pslot>=c->slot ) ) {
      if( FD_UNLIKELY( have_watermark ) ) return 0;
      *anchor_out = c;
      return 1;
    }

    fd_gui_slot_t const * p = fd_gui_slot_get( gui, pslot, pseq );
    if( FD_UNLIKELY( !p || p->completed_time==LONG_MAX || p->completed_time<0L ||
                     p->completed_time>c->completed_time ) ) {
      if( FD_UNLIKELY( have_watermark ) ) return 0;
      *anchor_out = c;
      return 1;
    }
    if( FD_UNLIKELY( !fd_gui_timeline_skipped_can_prepare_days( gui, p->completed_time, c->completed_time ) ) ) {
      if( FD_UNLIKELY( have_watermark ) ) return 0;
      *anchor_out = c;
      return 1;
    }
    c = p;
  }
}

/* Record every skipped numeric slot between consecutive landed slots on the
   optimistically confirmed fork.  The completion-time interval is divided
   into one equal segment per numeric slot transition, and a skipped slot is
   placed at the midpoint of its segment. */

static void
fd_gui_timeline_skipped_update( fd_gui_t *           gui,
                                fd_gui_slot_t const * tip_in ) {
  if( FD_UNLIKELY( !tip_in ) ) return;
  ulong tip_slot     = tip_in->slot;
  ulong tip_bank_seq = tip_in->bank_seq;
  long  tip_time     = tip_in->completed_time;
  if( FD_UNLIKELY( gui->timeline_skipped_slot_watermark!=ULONG_MAX &&
                   tip_slot<=gui->timeline_skipped_slot_watermark ) ) return;

  fd_gui_slot_t const * anchor = NULL;
  if( FD_UNLIKELY( !fd_gui_timeline_skipped_find_anchor( gui, tip_in, &anchor ) ) ) return;
  if( FD_UNLIKELY( !fd_gui_timeline_skipped_prepare_days( gui, anchor->completed_time, tip_time ) ) ) return;

  /* Creating day records can evict old slot history under space pressure.
     Reacquire and revalidate the path before writing any counts.  A first OC
     backfill may shorten to the still-retained suffix; an incremental update
     still has to reach its exact watermark. */
  fd_gui_slot_t const * tip = fd_gui_slot_get( gui, tip_slot, tip_bank_seq );
  if( FD_UNLIKELY( !tip || tip->completed_time!=tip_time ) ) return;
  if( FD_UNLIKELY( !fd_gui_timeline_skipped_find_anchor( gui, tip, &anchor ) ) ) return;
  if( FD_UNLIKELY( !fd_gui_timeline_skipped_prepare_days( gui, anchor->completed_time, tip_time ) ) ) return;

  fd_gui_slot_t const * c = tip;
  while( c!=anchor ) {
    fd_gui_slot_t const * p = fd_gui_slot_get( gui, c->parent_slot, c->parent_bank_seq );
    FD_TEST( p ); /* find_anchor validated this exact path. */

    ulong slot_delta = c->slot-p->slot;
    ulong time_delta = (ulong)(c->completed_time-p->completed_time);
    for( ulong k=1UL; k<slot_delta; k++ ) {
      uint128 segment_midpoint = ((uint128)2UL*(uint128)k)-(uint128)1UL;
      uint128 segment_cnt      =  (uint128)2UL*(uint128)slot_delta;
      ulong offset_ns = (ulong)((segment_midpoint*(uint128)time_delta)/segment_cnt);
      fd_gui_timeline_skipped_add( gui, p->completed_time+(long)offset_ns );
    }
    c = p;
  }

  if( FD_UNLIKELY( gui->timeline_skipped_coverage_start_ns==LONG_MAX ) )
    gui->timeline_skipped_coverage_start_ns = anchor->completed_time;
  gui->timeline_skipped_coverage_end_ns        = tip_time;
  gui->timeline_skipped_slot_watermark         = tip_slot;
  gui->timeline_skipped_bank_seq_watermark     = tip_bank_seq;
}

void
fd_gui_handle_root_advanced( fd_gui_t * gui,
                             ulong      _slot,
                             ulong      bank_seq,
                             long       now FD_PARAM_UNUSED ) {
  fd_gui_slot_t * root = fd_gui_slot_get( gui, _slot, bank_seq );
  if( FD_UNLIKELY( !root ) ) return;

  /* Rooting only ever advances. */
  if( FD_UNLIKELY( gui->summary.slot_rooted!=ULONG_MAX && _slot<=gui->summary.slot_rooted ) ) return;

  ulong prev_rooted = gui->summary.slot_rooted;

  gui->summary.slot_rooted = _slot;
  fd_gui_printf_root_slot( gui );
  fd_http_server_ws_broadcast( gui->http );

  for( ulong cslot=_slot, cbank_seq=bank_seq; ; ) {
    fd_gui_slot_t * c = fd_gui_slot_get( gui, cslot, cbank_seq );
    if( FD_UNLIKELY( !c || c->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    c->level = FD_GUI_SLOT_LEVEL_ROOTED;

    fd_gui_printf_slot( gui, cslot, c );
    fd_http_server_ws_broadcast( gui->http );

    /* Finalize vote latencies from votes that landed in this block. */
    for( ulong r=0UL; r<gui->landed_vote_cnt; r++ ) {
      if( FD_UNLIKELY( gui->landed_votes[ r ].landed_slot!=cslot || gui->landed_votes[ r ].landed_bank_seq!=cbank_seq ) ) continue;
      ulong voted_slot = gui->landed_votes[ r ].voted_slot;
      ulong voted_bank_seq, exact;
      if( FD_UNLIKELY( !fd_gui_compute_vote_latency( gui, cslot, cbank_seq, voted_slot, &voted_bank_seq, &exact ) ) ) continue;
      exact = (uchar)fd_ulong_min( exact, FD_GUI_VOTE_LATENCY_MAX );
      fd_gui_record_vote_latency( gui, voted_slot, voted_bank_seq, (uchar)exact );

      fd_gui_epoch_t * vepoch = fd_gui_get_epoch_by_slot( gui, voted_slot );
      if( FD_UNLIKELY( !vepoch ) ) continue;
      ulong vidx = voted_slot - vepoch->start_slot;
      if( FD_UNLIKELY( vidx>=vepoch->slot_cnt ) ) continue;
      if( FD_LIKELY( exact<vepoch->latency_exact[ vidx ] ) ) {
        vepoch->latency_exact[ vidx ] = (uchar)exact;
      }
    }

    fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, cslot );
    if( FD_LIKELY( epoch ) ) {
      ulong cidx = cslot - epoch->start_slot;
      if( FD_LIKELY( cidx<epoch->slot_cnt ) ) {
        epoch->is_voter[ cidx ] = c->is_voter;

        /* This slot is on the rooted fork, so it was not skipped. */
        epoch->skipped[ cidx ] = 0;
      }
    }

    ulong pslot = c->parent_slot, pseq = c->parent_bank_seq;
    if( FD_UNLIKELY( pslot==ULONG_MAX || pslot>=cslot ) ) break;

    /* Record and republish newly rooted skipped slots. */
    for( ulong s=pslot+1UL; s<cslot; s++ ) {
      if( FD_UNLIKELY( prev_rooted!=ULONG_MAX && s<=prev_rooted ) ) continue; /* already rooted earlier */

      fd_gui_epoch_t * sepoch = fd_gui_get_epoch_by_slot( gui, s );
      if( FD_LIKELY( sepoch ) ) {
        ulong sidx = s - sepoch->start_slot;
        if( FD_LIKELY( sidx<sepoch->slot_cnt ) ) sepoch->skipped[ sidx ] = 1;
      }

      if( FD_UNLIKELY( prev_rooted==ULONG_MAX ) ) continue;

      fd_gui_slot_t const * skipped = fd_gui_slot_get_canon_safe( gui, s );
      if( FD_UNLIKELY( skipped->skip!=FD_GUI_SKIP_STATUS_SKIPPED ) ) continue;
      fd_gui_printf_slot( gui, s, skipped );
      fd_http_server_ws_broadcast( gui->http );
    }

    cslot = pslot; cbank_seq = pseq;
  }

  ulong rooted_slot = gui->summary.slot_rooted;
  ulong w = 0UL;
  for( ulong r=0UL; r<gui->landed_vote_cnt; r++ ) {
    if( FD_UNLIKELY( gui->landed_votes[ r ].landed_slot<=rooted_slot ) ) continue;
    gui->landed_votes[ w++ ] = gui->landed_votes[ r ];
  }
  gui->landed_vote_cnt = w;
}

void
fd_gui_handle_oc_advanced( fd_gui_t * gui,
                           ulong      _slot,
                           ulong      bank_seq,
                           long       now ) {
  (void)now;

  fd_gui_slot_t * live_slot = fd_gui_slot_get( gui, _slot, bank_seq );
  if( FD_UNLIKELY( !live_slot ) ) return;

  fd_gui_slot_t const * slot = fd_gui_slot_get_canon( gui, _slot );
  int on_canonical_fork = ( slot && slot->bank_seq==bank_seq );
  if( FD_UNLIKELY( !on_canonical_fork ) ) return; /* we've since switched forks so this update is invalid */

  fd_gui_timeline_skipped_update( gui, live_slot );

  ulong prev_oc = gui->summary.slot_optimistically_confirmed;

  int advanced = 0;
  if( FD_LIKELY( _slot!=prev_oc ) ) {
    gui->summary.slot_optimistically_confirmed = _slot;
    fd_gui_printf_optimistically_confirmed_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
    advanced = ( prev_oc==ULONG_MAX || _slot>prev_oc );
  }

  for( ulong cslot=_slot, cbank_seq=bank_seq; ; ) {
    fd_gui_slot_t * c = fd_gui_slot_get( gui, cslot, cbank_seq );
    if( FD_UNLIKELY( !c || c->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    if( FD_LIKELY( c->level<FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED ) ) {
      c->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
      fd_gui_printf_slot( gui, cslot, c );
      fd_http_server_ws_broadcast( gui->http );
    }

    ulong pslot = c->parent_slot, pseq = c->parent_bank_seq;
    if( FD_UNLIKELY( pslot==ULONG_MAX || pslot>=cslot ) ) break;

    /* Republish skipped slots as well. */
    if( FD_LIKELY( advanced ) ) {
      for( ulong s=pslot+1UL; s<cslot; s++ ) {
        if( FD_UNLIKELY( prev_oc!=ULONG_MAX && s<=prev_oc ) ) continue; /* already OC'd earlier */
        if( FD_UNLIKELY( gui->summary.slot_rooted!=ULONG_MAX && s<gui->summary.slot_rooted ) ) continue; /* already rooted: handled by root advance */
        fd_gui_slot_t const * skipped = fd_gui_slot_get_canon_safe( gui, s );
        if( FD_UNLIKELY( skipped->skip!=FD_GUI_SKIP_STATUS_SKIPPED ) ) continue;
        fd_gui_printf_slot( gui, s, skipped );
        fd_http_server_ws_broadcast( gui->http );
      }
    }

    cslot = pslot; cbank_seq = pseq;
  }
}

void
fd_gui_handle_genesis_hash( fd_gui_t *        gui,
                            fd_hash_t const * msg ) {
  FD_BASE58_ENCODE_32_BYTES( msg->uc, hash_cstr );
  ulong cluster = fd_genesis_cluster_identify(hash_cstr);
  char const * cluster_name = fd_genesis_cluster_name(cluster);

  if( FD_LIKELY( strcmp( gui->summary.cluster, cluster_name ) ) ) {
    gui->summary.cluster = fd_genesis_cluster_name(cluster);
    fd_gui_printf_cluster( gui );
    fd_http_server_ws_broadcast( gui->http );
  }
}

void
fd_gui_handle_block_engine_update( fd_gui_t *                              gui,
                                   fd_bundle_block_engine_update_t const * update ) {
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

  fd_gui_printf_block_engine( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_handle_snapshot_update( fd_gui_t *                 gui,
                               fd_snapct_update_t const * msg ) {
  FD_TEST( msg && fd_cstr_nlen( msg->read_path, 1 ) );

  ulong snapshot_idx = fd_ulong_if( msg->type==FD_SNAPCT_SNAPSHOT_TYPE_FULL, FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX, FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX );

  char const * filename = strrchr( msg->read_path, '/' );

  /* Skip the '/'  */
  if( FD_LIKELY( filename ) ) filename++;
  else                        filename = msg->read_path;

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

void
fd_gui_stage_snapshot_manifest( fd_gui_t *                    gui,
                                 fd_snapshot_manifest_t const * manifest ) {
  ulong attempt = 0UL;
  for( ulong i=0UL; i<manifest->hard_fork_cnt; i++ ) {
    if( FD_UNLIKELY( manifest->hard_forks[ i ].slot==manifest->slot ) ) {
      attempt = manifest->hard_forks[ i ].cnt;
      break;
    }
  }
  gui->summary.boot_progress.wfs_attempt = attempt;
}

static void
fd_gui_broadcast_skip_rate( fd_gui_t * gui,
                            ulong      epoch ) {
  fd_gui_epoch_t const * rec = fd_gui_epoch( gui, epoch );
  if( FD_UNLIKELY( !rec ) ) return;

  ulong slot = epoch % 2UL;
  if( FD_LIKELY( gui->summary.skip_rate[ slot ].epoch  ==epoch
              && gui->summary.skip_rate[ slot ].skipped==rec->my_skipped_slots
              && gui->summary.skip_rate[ slot ].total  ==rec->my_total_slots ) ) return;

  gui->summary.skip_rate[ slot ].epoch   = epoch;
  gui->summary.skip_rate[ slot ].skipped = rec->my_skipped_slots;
  gui->summary.skip_rate[ slot ].total   = rec->my_total_slots;

  fd_gui_printf_skip_rate( gui, epoch );
  fd_http_server_ws_broadcast( gui->http );
}

static void
handle_tower_slot( fd_gui_t * gui, ulong reset_slot, ulong reset_bank_seq, long now FD_PARAM_UNUSED ) {
  FD_TEST( reset_slot!=ULONG_MAX );

  ulong prev_reset_slot     = gui->summary.slot_tower;
  ulong prev_reset_bank_seq = gui->summary.slot_tower_bank_seq;
  gui->summary.slot_tower   = reset_slot;
  gui->summary.slot_tower_bank_seq = reset_bank_seq;

  /* reset_slot is guaranteed present (returnable_frag deferred this
     update until replay recorded it). */
  FD_TEST( fd_gui_slot_get( gui, gui->summary.slot_tower, gui->summary.slot_tower_bank_seq ) );

  /* reset_slot has not changed */
  if( FD_UNLIKELY( prev_reset_slot!=ULONG_MAX && reset_slot==prev_reset_slot && reset_bank_seq!=ULONG_MAX && reset_bank_seq==prev_reset_bank_seq ) ) return;

  fd_gui_printf_completed_slot( gui );
  fd_http_server_ws_broadcast( gui->http );

  /* ensure a history exists */
  if( FD_UNLIKELY( prev_reset_slot==ULONG_MAX || gui->summary.slot_rooted==ULONG_MAX ) ) return;

  /* slot complete received out of order on the same fork? */
  FD_TEST( fd_gui_slot_is_ancestor( gui, prev_reset_slot, gui->summary.slot_tower ) || !fd_gui_slot_is_ancestor( gui, gui->summary.slot_tower, prev_reset_slot ) );

  /* Switch forks. */
  for( ulong slot=fd_ulong_max( gui->summary.slot_tower, prev_reset_slot ); slot>gui->summary.slot_rooted; slot-- ) {
    int skipped_old = slot<=prev_reset_slot && fd_gui_slot_is_skipped( gui, gui->summary.slot_rooted, prev_reset_slot, prev_reset_bank_seq, slot );
    int skipped_new = slot<=gui->summary.slot_tower && fd_gui_slot_is_skipped( gui, gui->summary.slot_rooted, gui->summary.slot_tower, reset_bank_seq, slot );
    if( FD_LIKELY( skipped_old!=skipped_new ) ) {
      fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, slot );
      if( FD_LIKELY( epoch && fd_gui_slot_is_mine( gui, slot ) ) ) {
        if( skipped_new ) epoch->my_skipped_slots = fd_ulong_sat_add( epoch->my_skipped_slots, 1UL );
        else              epoch->my_skipped_slots = fd_ulong_sat_sub( epoch->my_skipped_slots, 1UL );
      }
    }

    /* Publish new/changed slots */
    if( FD_LIKELY( skipped_old!=skipped_new || slot>prev_reset_slot ) ) {
      fd_gui_printf_slot( gui, slot, fd_gui_slot_get_canon_safe( gui, slot ) );
      fd_http_server_ws_broadcast( gui->http );
    }

    /* Persist skip status */
    fd_gui_slot_t * canon = fd_gui_slot_get_canon( gui, slot );
    ulong canon_bank_seq = canon ? canon->bank_seq : ULONG_MAX; /* canon, if any, IS slot */
    fd_gui_hist_kv_slot_iter_t it[ 1 ];
    for( fd_gui_hist_kv_iter_begin( gui, it, FD_GUI_HIST_SLOT, slot ); it->rec; fd_gui_hist_kv_iter_next( it ) ) {
      ((fd_gui_slot_t *)it->rec)->skip = fd_uchar_if( it->bank_seq==canon_bank_seq, FD_GUI_SKIP_STATUS_NOT_SKIPPED, FD_GUI_SKIP_STATUS_SKIPPED );
    }
  }

  for( ulong e=gui->epoch.current_epoch; e<=gui->epoch.current_epoch+1UL; e++ ) fd_gui_broadcast_skip_rate( gui, e );
}

static inline void
set_vote_state( fd_gui_t * gui,
                int        vote_state ) {
  if( FD_UNLIKELY( gui->summary.vote_state!=vote_state ) ) {
    gui->summary.vote_state = vote_state;
    fd_gui_printf_vote_state( gui );
    fd_http_server_ws_broadcast( gui->http );
  }
}

static inline void
publish_vote_status( fd_gui_t * gui,
                     int        is_voting ) {
  if( FD_UNLIKELY( !is_voting ) ) {
    set_vote_state( gui, FD_GUI_VOTE_STATE_NON_VOTING );
    return;
  }

  fd_gui_slot_t * slot = fd_gui_slot_get( gui, gui->summary.slot_tower, gui->summary.slot_tower_bank_seq );
  FD_TEST( slot );

  if( FD_UNLIKELY( gui->summary.slot_tower==ULONG_MAX ) ) return;

  if( FD_UNLIKELY( slot->vote_slot==ULONG_MAX ) ) {
    /* Voting is enabled but no vote has landed yet. */
    set_vote_state( gui, FD_GUI_VOTE_STATE_DELINQUENT );
    return;
  }

  /* Snapshot the fields before the inner loop (which re-resolves slots). */
  ulong vote_slot  = slot->vote_slot;
  ulong reset_slot = gui->summary.slot_tower;

  ulong vote_distance = reset_slot-vote_slot;
  if( FD_LIKELY( vote_distance<FD_GUI_MAX_VOTE_DISTANCE ) ) {
    for( ulong s=vote_slot; s<reset_slot; s++ ) {
      if( FD_UNLIKELY( !fd_gui_slot_get_canon( gui, s ) ) ) vote_distance--;
    }
  }

  if( FD_UNLIKELY( gui->summary.vote_distance!=vote_distance ) ) {
    gui->summary.vote_distance = vote_distance;
    fd_gui_printf_vote_distance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( vote_slot==ULONG_MAX || vote_distance>150UL ) ) {
    set_vote_state( gui, FD_GUI_VOTE_STATE_DELINQUENT );
  } else {
    set_vote_state( gui, FD_GUI_VOTE_STATE_VOTING );
  }
}

/* fd_gui_handle_tower_update handles updates from the tower tile, which
   manages consensus related fork switching, rooting, slot confirmation.

   The gui tile consumes tower_out via returnable_frag and defers any
   update whose replay_slot has not yet been recorded from replay, so by
   the time this runs both tower->replay_slot and tower->reset_slot are
   guaranteed to have a DB record. */
void
fd_gui_handle_tower_update( fd_gui_t *                   gui,
                            fd_tower_slot_done_t const * tower,
                            long                         now ) {
  if( FD_UNLIKELY( tower->active_fork_cnt!=gui->summary.active_fork_cnt ) ) {
    gui->summary.active_fork_cnt = tower->active_fork_cnt;
    fd_gui_printf_active_fork_cnt( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  fd_gui_slot_t * replay_slot = fd_gui_slot_get( gui, tower->replay_slot, tower->replay_bank_seq );
  FD_TEST( replay_slot );
  replay_slot->is_voter = (uchar)(!!tower->is_voting);

  /* Handle already-rooted edge case. */
  if( FD_UNLIKELY( replay_slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) {
    fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, tower->replay_slot );
    if( FD_LIKELY( epoch ) ) {
      ulong cidx = tower->replay_slot - epoch->start_slot;
      if( FD_LIKELY( cidx<epoch->slot_cnt ) ) epoch->is_voter[ cidx ] = replay_slot->is_voter;
    }
  }

  if( FD_LIKELY( tower->reset_slot!=ULONG_MAX ) ) {
    handle_tower_slot( gui, tower->reset_slot, tower->reset_bank_seq, now );
    publish_vote_status( gui, tower->is_voting );
  } else if( FD_UNLIKELY( !tower->is_voting ) ) {
    /* NON_VOTING does not need a reset slot, unlike publish_vote_status. */
    set_vote_state( gui, FD_GUI_VOTE_STATE_NON_VOTING );
  }

  if( FD_LIKELY( gui->summary.slot_reset!=tower->reset_slot ) ) {
    gui->summary.slot_reset = tower->reset_slot;
    fd_gui_printf_reset_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( tower->vote_acct_bal!=ULONG_MAX && gui->summary.vote_account_balance!=tower->vote_acct_bal ) ) {
    gui->summary.vote_account_balance = tower->vote_acct_bal;
    fd_gui_printf_vote_balance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( gui->summary.vote_commission!=tower->vote_acct_com ) ) {
    gui->summary.vote_commission = tower->vote_acct_com;
    fd_gui_printf_vote_commission( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  /* Update vote latencies.  This is the speculative, true correct
     latencies are published as a vote's landed slot is rooted. */
  for( ulong r=0UL; r<gui->landed_vote_cnt; r++ ) {
    if( FD_UNLIKELY( gui->landed_votes[ r ].landed_slot>gui->summary.slot_tower ) ) continue;

    ulong voted_bank_seq, exact;
    if( FD_UNLIKELY( !fd_gui_compute_vote_latency( gui, gui->landed_votes[ r ].landed_slot, gui->landed_votes[ r ].landed_bank_seq, gui->landed_votes[ r ].voted_slot, &voted_bank_seq, &exact ) ) ) continue;
    exact = (uchar)fd_ulong_min( exact, FD_GUI_VOTE_LATENCY_MAX );
    fd_gui_slot_t * slot = fd_gui_slot_get( gui, gui->landed_votes[ r ].voted_slot, voted_bank_seq );
    if( FD_UNLIKELY( !slot ) ) continue;

    if( FD_LIKELY( exact>=slot->vote_latency_exact ) ) continue;
    fd_gui_record_vote_latency( gui, gui->landed_votes[ r ].voted_slot, voted_bank_seq, (uchar)exact );
  }
}

void
fd_gui_stage_landed_vote( fd_gui_t * gui,
                          ulong      landed_slot,
                          ulong      landed_bank_seq,
                          ulong      voted_slot ) {
  if( FD_UNLIKELY( voted_slot==ULONG_MAX || voted_slot>=landed_slot ) ) return;

  /* Handle already-rooted edge case. */
  if( FD_UNLIKELY( gui->summary.slot_rooted!=ULONG_MAX && landed_slot<=gui->summary.slot_rooted ) ) {
    fd_gui_slot_t const * canon = fd_gui_slot_get_canon( gui, landed_slot );
    if( FD_UNLIKELY( !canon || canon->bank_seq!=landed_bank_seq ) ) return;
    ulong voted_bank_seq, exact;
    if( FD_UNLIKELY( !fd_gui_compute_vote_latency( gui, landed_slot, landed_bank_seq, voted_slot, &voted_bank_seq, &exact ) ) ) return;
    exact = (uchar)fd_ulong_min( exact, FD_GUI_VOTE_LATENCY_MAX );
    fd_gui_record_vote_latency( gui, voted_slot, voted_bank_seq, (uchar)exact );

    fd_gui_epoch_t * vepoch = fd_gui_get_epoch_by_slot( gui, voted_slot );
    if( FD_UNLIKELY( !vepoch ) ) return;
    ulong vidx = voted_slot - vepoch->start_slot;
    if( FD_UNLIKELY( vidx>=vepoch->slot_cnt ) ) return;
    if( FD_LIKELY( exact<vepoch->latency_exact[ vidx ] ) ) {
      vepoch->latency_exact[ vidx ] = (uchar)exact;
    }
    return;
  }

  if( FD_UNLIKELY( gui->landed_vote_cnt>=FD_GUI_LANDED_VOTE_MAX ) ) return;

  gui->landed_votes[ gui->landed_vote_cnt ].landed_slot     = landed_slot;
  gui->landed_votes[ gui->landed_vote_cnt ].landed_bank_seq = landed_bank_seq;
  gui->landed_votes[ gui->landed_vote_cnt ].voted_slot      = voted_slot;
  gui->landed_vote_cnt++;
}

static inline long
fd_gui_replay_tick_to_nanos( fd_gui_t const * gui,
                             long             now,
                             long             tick_now,
                             long             tick ) {
  if( FD_UNLIKELY( tick==LONG_MAX ) ) return LONG_MAX;
  return now + (long)((double)(tick-tick_now) / gui->tick_per_ns);
}

typedef fd_gui_store_replay_txn_t const * fd_gui_batch_txn_ptr_t;

#define SORT_NAME fd_gui_batch_exec_txn_sort
#define SORT_KEY_T fd_gui_batch_txn_ptr_t
#define SORT_BEFORE(a,b) (((a)->txn_exec_idx<(b)->txn_exec_idx) || \
                          (((a)->txn_exec_idx==(b)->txn_exec_idx) && \
                           (((a)->load_start_ns<(b)->load_start_ns) || \
                            (((a)->load_start_ns==(b)->load_start_ns) && \
                             (((a)->commit_end_ns<(b)->commit_end_ns) || \
                              (((a)->commit_end_ns==(b)->commit_end_ns) && ((a)->txn_idx<(b)->txn_idx)))))))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME fd_gui_batch_sigverify_txn_sort
#define SORT_KEY_T fd_gui_batch_txn_ptr_t
#define SORT_BEFORE(a,b) (((a)->txn_sigverify_exec_idx<(b)->txn_sigverify_exec_idx) || \
                          (((a)->txn_sigverify_exec_idx==(b)->txn_sigverify_exec_idx) && \
                           (((a)->sigverify_start_ns<(b)->sigverify_start_ns) || \
                            (((a)->sigverify_start_ns==(b)->sigverify_start_ns) && \
                             (((a)->sigverify_end_ns<(b)->sigverify_end_ns) || \
                              (((a)->sigverify_end_ns==(b)->sigverify_end_ns) && ((a)->txn_idx<(b)->txn_idx)))))))
#include "../../util/tmpl/fd_sort.c"

struct fd_gui_txn_batch_work {
  ulong first;
  ulong cnt;
  ulong tile_idx;
  ulong representative_txn_idx;
  long  start_ns;
  long  end_ns;
  uchar success;
};
typedef struct fd_gui_txn_batch_work fd_gui_txn_batch_work_t;

struct fd_gui_txn_batch_scratch {
  fd_gui_batch_txn_ptr_t *  exec_txns;
  fd_gui_batch_txn_ptr_t *  sig_txns;
  fd_gui_txn_batch_work_t * exec_batches;
  fd_gui_txn_batch_work_t * sig_batches;
  ulong *                   heap;
};
typedef struct fd_gui_txn_batch_scratch fd_gui_txn_batch_scratch_t;

static void
fd_gui_txn_batch_scratch_delete( fd_gui_t *                     gui,
                                 fd_gui_txn_batch_scratch_t * scratch ) {
  if( scratch->heap         ) fd_alloc_free( gui->alloc, scratch->heap         );
  if( scratch->sig_batches  ) fd_alloc_free( gui->alloc, scratch->sig_batches  );
  if( scratch->exec_batches ) fd_alloc_free( gui->alloc, scratch->exec_batches );
  if( scratch->sig_txns     ) fd_alloc_free( gui->alloc, scratch->sig_txns     );
  if( scratch->exec_txns    ) fd_alloc_free( gui->alloc, scratch->exec_txns    );
  fd_memset( scratch, 0, sizeof(*scratch) );
}

static int
fd_gui_txn_batch_scratch_new( fd_gui_t *                     gui,
                              fd_gui_txn_batch_scratch_t * scratch,
                              ulong                          txn_cap ) {
  fd_memset( scratch, 0, sizeof(*scratch) );
  scratch->exec_txns    = fd_alloc_malloc( gui->alloc, alignof(fd_gui_batch_txn_ptr_t),  txn_cap*sizeof(fd_gui_batch_txn_ptr_t)  );
  scratch->sig_txns     = fd_alloc_malloc( gui->alloc, alignof(fd_gui_batch_txn_ptr_t),  txn_cap*sizeof(fd_gui_batch_txn_ptr_t)  );
  scratch->exec_batches = fd_alloc_malloc( gui->alloc, alignof(fd_gui_txn_batch_work_t), txn_cap*sizeof(fd_gui_txn_batch_work_t) );
  scratch->sig_batches  = fd_alloc_malloc( gui->alloc, alignof(fd_gui_txn_batch_work_t), txn_cap*sizeof(fd_gui_txn_batch_work_t) );
  scratch->heap         = fd_alloc_malloc( gui->alloc, alignof(ulong),                   txn_cap*sizeof(ulong)                   );
  if( FD_UNLIKELY( !scratch->exec_txns || !scratch->sig_txns || !scratch->exec_batches || !scratch->sig_batches || !scratch->heap ) ) {
    fd_gui_txn_batch_scratch_delete( gui, scratch );
    return -1;
  }
  return 0;
}

static inline long
fd_gui_txn_batch_span( fd_gui_txn_batch_work_t const * batch ) {
  return fd_long_sat_sub( batch->end_ns, batch->start_ns );
}

#define SORT_NAME fd_gui_txn_batch_order_sort
#define SORT_KEY_T fd_gui_txn_batch_work_t
#define SORT_BEFORE(a,b) (((a).representative_txn_idx<(b).representative_txn_idx) || \
                          (((a).representative_txn_idx==(b).representative_txn_idx) && \
                           (((a).tile_idx<(b).tile_idx) || \
                            (((a).tile_idx==(b).tile_idx) && ((a).start_ns<(b).start_ns)))))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME fd_gui_txn_batch_keep_sort
#define SORT_KEY_T fd_gui_txn_batch_work_t
#define SORT_BEFORE(a,b) ((fd_gui_txn_batch_span(&(a))>fd_gui_txn_batch_span(&(b))) || \
                          ((fd_gui_txn_batch_span(&(a))==fd_gui_txn_batch_span(&(b))) && \
                           (((a).cnt>(b).cnt) || \
                            (((a).cnt==(b).cnt) && ((a).representative_txn_idx<(b).representative_txn_idx)))))
#include "../../util/tmpl/fd_sort.c"

static inline int
fd_gui_txn_batch_near( long prev_end_ns,
                       long next_start_ns ) {
  return next_start_ns<=fd_long_sat_add( prev_end_ns, FD_GUI_TXN_BATCH_GAP_NS );
}

static ulong
fd_gui_txn_batch_build_lane( fd_gui_batch_txn_ptr_t const * txns,
                             ulong                          txn_cnt,
                             int                            sigverify,
                             fd_gui_txn_batch_work_t *      batches ) {
  ulong batch_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_gui_store_replay_txn_t const * txn = txns[ i ];
    ulong tile_idx = sigverify ? txn->txn_sigverify_exec_idx : txn->txn_exec_idx;
    long  start_ns = sigverify ? txn->sigverify_start_ns     : txn->load_start_ns;
    long  end_ns   = sigverify ? txn->sigverify_end_ns       : txn->commit_end_ns;
    uchar success  = (uchar)(txn->error_code==0U);

    int merge = 0;
    if( batch_cnt ) {
      fd_gui_txn_batch_work_t * batch = &batches[ batch_cnt-1UL ];
      fd_gui_store_replay_txn_t const * prev = txns[ i-1UL ];
      long prev_end_ns = sigverify ? prev->sigverify_end_ns : prev->commit_end_ns;
      merge = batch->tile_idx==tile_idx &&
              batch->success ==success  &&
              batch->cnt     <FD_GUI_TXN_BATCH_MAX_TXN &&
              fd_gui_txn_batch_near( prev_end_ns, start_ns );
    }

    if( FD_UNLIKELY( !merge ) ) {
      batches[ batch_cnt++ ] = (fd_gui_txn_batch_work_t) {
        .first                  = i,
        .cnt                    = 1UL,
        .tile_idx               = tile_idx,
        .representative_txn_idx = txn->txn_idx,
        .start_ns               = start_ns,
        .end_ns                 = end_ns,
        .success                = success
      };
    } else {
      fd_gui_txn_batch_work_t * batch = &batches[ batch_cnt-1UL ];
      batch->cnt++;
      batch->start_ns = fd_long_min( batch->start_ns, start_ns );
      batch->end_ns   = fd_long_max( batch->end_ns,   end_ns   );
    }
  }
  return batch_cnt;
}

static void
fd_gui_txn_batch_recompute_sigverify( fd_gui_txn_batch_work_t *      batch,
                                      fd_gui_batch_txn_ptr_t const * txns ) {
  fd_gui_store_replay_txn_t const * first = txns[ batch->first ];
  batch->tile_idx               = first->txn_sigverify_exec_idx;
  batch->representative_txn_idx = first->txn_idx;
  batch->success                = (uchar)(first->error_code==0U);
  batch->start_ns               = first->sigverify_start_ns;
  batch->end_ns                 = first->sigverify_end_ns;
  for( ulong i=1UL; i<batch->cnt; i++ ) {
    fd_gui_store_replay_txn_t const * txn = txns[ batch->first+i ];
    batch->start_ns = fd_long_min( batch->start_ns, txn->sigverify_start_ns );
    batch->end_ns   = fd_long_max( batch->end_ns,   txn->sigverify_end_ns   );
  }
}

static inline int
fd_gui_txn_batch_wider( fd_gui_txn_batch_work_t const * a,
                        fd_gui_txn_batch_work_t const * b ) {
  long a_span = fd_gui_txn_batch_span( a );
  long b_span = fd_gui_txn_batch_span( b );
  if( a_span!=b_span ) return a_span>b_span;
  if( a->cnt!=b->cnt ) return a->cnt>b->cnt;
  return a->representative_txn_idx<b->representative_txn_idx;
}

static void
fd_gui_txn_batch_heap_push( ulong *                         heap,
                            ulong *                         heap_cnt,
                            ulong                           idx,
                            fd_gui_txn_batch_work_t const * batches ) {
  ulong child = (*heap_cnt)++;
  while( child ) {
    ulong parent = (child-1UL)>>1;
    if( !fd_gui_txn_batch_wider( &batches[ idx ], &batches[ heap[ parent ] ] ) ) break;
    heap[ child ] = heap[ parent ];
    child = parent;
  }
  heap[ child ] = idx;
}

static ulong
fd_gui_txn_batch_heap_pop( ulong *                         heap,
                           ulong *                         heap_cnt,
                           fd_gui_txn_batch_work_t const * batches ) {
  ulong result = heap[ 0 ];
  ulong idx    = heap[ --(*heap_cnt) ];
  ulong parent = 0UL;
  while( (parent<<1)+1UL<*heap_cnt ) {
    ulong child = (parent<<1)+1UL;
    if( child+1UL<*heap_cnt && fd_gui_txn_batch_wider( &batches[ heap[ child+1UL ] ], &batches[ heap[ child ] ] ) ) child++;
    if( !fd_gui_txn_batch_wider( &batches[ heap[ child ] ], &batches[ idx ] ) ) break;
    heap[ parent ] = heap[ child ];
    parent = child;
  }
  if( *heap_cnt ) heap[ parent ] = idx;
  return result;
}

static ulong
fd_gui_txn_batch_sigverify_split_at( fd_gui_txn_batch_work_t const * batch,
                                     fd_gui_batch_txn_ptr_t const *  txns ) {
  ulong best_off  = 1UL;
  long  best_gap  = LONG_MIN;
  ulong midpoint2 = batch->cnt;
  for( ulong off=1UL; off<batch->cnt; off++ ) {
    fd_gui_store_replay_txn_t const * prev = txns[ batch->first+off-1UL ];
    fd_gui_store_replay_txn_t const * next = txns[ batch->first+off     ];
    long gap = fd_long_sat_sub( next->sigverify_start_ns, prev->sigverify_end_ns );
    ulong off2           = 2UL*off;
    ulong best_off2      = 2UL*best_off;
    ulong distance2      = off2     >midpoint2 ? off2     -midpoint2 : midpoint2-off2;
    ulong best_distance2 = best_off2>midpoint2 ? best_off2-midpoint2 : midpoint2-best_off2;
    if( gap>best_gap || (gap==best_gap && distance2<best_distance2) ) {
      best_gap = gap;
      best_off = off;
    }
  }
  return best_off;
}

static int
fd_gui_txn_batch_normalize_sigverify( fd_gui_txn_batch_work_t *      batches,
                                      ulong *                        batch_cnt,
                                      ulong                          target_cnt,
                                      fd_gui_batch_txn_ptr_t const * txns,
                                      ulong *                        heap ) {
  if( *batch_cnt>target_cnt ) {
    fd_gui_txn_batch_keep_sort_inplace( batches, *batch_cnt );
    *batch_cnt = target_cnt;
    return 0;
  }
  if( *batch_cnt==target_cnt ) return 0;

  ulong heap_cnt = 0UL;
  for( ulong i=0UL; i<*batch_cnt; i++ )
    if( batches[ i ].cnt>1UL ) fd_gui_txn_batch_heap_push( heap, &heap_cnt, i, batches );

  /* The heap avoids rescanning all candidate batches for every split.
     Finding the internal gap scans at most FD_GUI_TXN_BATCH_MAX_TXN-1
     entries.  The fixed 32-member cap bounds all repeated gap scans per
     original batch, so work cannot become quadratic in the slot transaction
     count. */
  while( *batch_cnt<target_cnt ) {
    if( FD_UNLIKELY( !heap_cnt ) ) return -1;
    ulong idx       = fd_gui_txn_batch_heap_pop( heap, &heap_cnt, batches );
    ulong split_off = fd_gui_txn_batch_sigverify_split_at( &batches[ idx ], txns );
    fd_gui_txn_batch_work_t right = batches[ idx ];
    right.first += split_off;
    right.cnt   -= split_off;
    batches[ idx ].cnt = split_off;
    fd_gui_txn_batch_recompute_sigverify( &batches[ idx ], txns );
    fd_gui_txn_batch_recompute_sigverify( &right,          txns );
    ulong right_idx = (*batch_cnt)++;
    batches[ right_idx ] = right;
    if( batches[ idx       ].cnt>1UL ) fd_gui_txn_batch_heap_push( heap, &heap_cnt, idx,       batches );
    if( batches[ right_idx ].cnt>1UL ) fd_gui_txn_batch_heap_push( heap, &heap_cnt, right_idx, batches );
  }
  return 0;
}

static inline uint128
fd_gui_txn_batch_stage_duration( long start_ns,
                                 long end_ns ) {
  return (uint128)(ulong)fd_long_max( fd_long_sat_sub( end_ns, start_ns ), 0L );
}

/* Returns floor(span*cumulative/total) without overflowing.  cumulative is
   at most total, and total is the sum of at most four durations for each of
   the at most 32 transactions in a batch.  The bitwise multiply/divide keeps
   the intermediate remainder below three times total. */
static ulong
fd_gui_txn_batch_scale_offset( ulong   span,
                               uint128 cumulative,
                               uint128 total ) {
  if( FD_UNLIKELY( !total || !cumulative ) ) return 0UL;
  if( FD_UNLIKELY( cumulative>=total ) ) return span;

  uint128 remainder = (uint128)0;
  ulong   quotient  = 0UL;
  for( int bit=62; bit>=0; bit-- ) {
    remainder <<= 1;
    if( span & (1UL<<bit) ) remainder += cumulative;
    ulong digit = 0UL;
    if( remainder>=total ) { remainder-=total; digit++; }
    if( remainder>=total ) { remainder-=total; digit++; }
    quotient = (quotient<<1) + digit;
  }
  return quotient;
}

static long
fd_gui_txn_batch_project_stage_start( long    load_start_ns,
                                      long    commit_end_ns,
                                      uint128 cumulative,
                                      uint128 total ) {
  long span = fd_long_max( fd_long_sat_sub( commit_end_ns, load_start_ns ), 0L );
  ulong offset = fd_gui_txn_batch_scale_offset( (ulong)span, cumulative, total );
  return fd_long_min( commit_end_ns, fd_long_sat_add( load_start_ns, (long)offset ) );
}

static void
fd_gui_txn_batch_record( fd_gui_store_replay_txn_batch_t * record,
                         ulong                              batch_idx,
                         fd_gui_txn_batch_work_t const *    exec_batch,
                         fd_gui_batch_txn_ptr_t const *     exec_txns,
                         fd_gui_txn_batch_work_t const *    sigverify_batch,
                         fd_gui_batch_txn_ptr_t const *     sigverify_txns ) {
  fd_memset( record, 0, sizeof(*record) );
  fd_gui_store_replay_txn_t const * representative = exec_txns[ exec_batch->first ];
  record->slot                    = representative->slot;
  record->batch_idx               = batch_idx;
  record->txn_idx                 = representative->txn_idx;
  record->txn_exec_idx            = exec_batch->tile_idx;
  record->txn_sigverify_exec_idx  = sigverify_batch->tile_idx;
  record->error_code              = representative->error_code;
  record->exec_txn_cnt            = (uchar)exec_batch->cnt;
  record->sigverify_txn_cnt       = (uchar)sigverify_batch->cnt;
  record->load_start_ns           = LONG_MAX;
  record->check_start_ns          = LONG_MAX;
  record->exec_start_ns           = LONG_MAX;
  record->commit_start_ns         = LONG_MAX;
  record->commit_end_ns           = LONG_MIN;
  record->sigverify_start_ns      = LONG_MAX;
  record->sigverify_end_ns        = LONG_MIN;

  uint128 stage_duration[ 4 ] = { (uint128)0, (uint128)0, (uint128)0, (uint128)0 };
  int     stage_present [ 4 ] = { 0, 0, 0, 0 };
  for( ulong i=0UL; i<exec_batch->cnt; i++ ) {
    fd_gui_store_replay_txn_t const * txn = exec_txns[ exec_batch->first+i ];
    record->exec_txn_idx[ i ] = (uint)txn->txn_idx;
    record->load_start_ns = fd_long_min( record->load_start_ns, txn->load_start_ns );
    record->commit_end_ns = fd_long_max( record->commit_end_ns, txn->commit_end_ns );

    long const stage_start[ 4 ] = {
      txn->load_start_ns,
      txn->check_start_ns,
      txn->exec_start_ns,
      txn->commit_start_ns
    };
    for( ulong stage=0UL; stage<4UL; stage++ ) {
      if( stage_start[ stage ]==LONG_MAX ) continue;
      stage_present[ stage ] = 1;
      long stage_end_ns = txn->commit_end_ns;
      for( ulong next=stage+1UL; next<4UL; next++ ) {
        if( stage_start[ next ]!=LONG_MAX ) {
          stage_end_ns = stage_start[ next ];
          break;
        }
      }
      stage_duration[ stage ] += fd_gui_txn_batch_stage_duration( stage_start[ stage ], stage_end_ns );
    }
  }

  uint128 total_duration = stage_duration[ 0 ] + stage_duration[ 1 ] +
                           stage_duration[ 2 ] + stage_duration[ 3 ];
  uint128 cumulative = stage_duration[ 0 ];
  if( stage_present[ 1 ] )
    record->check_start_ns = fd_gui_txn_batch_project_stage_start( record->load_start_ns, record->commit_end_ns,
                                                                   cumulative, total_duration );
  cumulative += stage_duration[ 1 ];
  if( stage_present[ 2 ] )
    record->exec_start_ns = fd_gui_txn_batch_project_stage_start( record->load_start_ns, record->commit_end_ns,
                                                                  cumulative, total_duration );
  cumulative += stage_duration[ 2 ];
  if( stage_present[ 3 ] )
    record->commit_start_ns = fd_gui_txn_batch_project_stage_start( record->load_start_ns, record->commit_end_ns,
                                                                    cumulative, total_duration );

  for( ulong i=0UL; i<sigverify_batch->cnt; i++ ) {
    fd_gui_store_replay_txn_t const * txn = sigverify_txns[ sigverify_batch->first+i ];
    record->sigverify_txn_idx[ i ] = (uint)txn->txn_idx;
    record->sigverify_start_ns = fd_long_min( record->sigverify_start_ns, txn->sigverify_start_ns );
    record->sigverify_end_ns   = fd_long_max( record->sigverify_end_ns,   txn->sigverify_end_ns   );
  }
  record->completion_time_ns = fd_long_max( record->sigverify_end_ns, record->commit_end_ns );
}

static int
fd_gui_txn_batch_collect_slot( fd_gui_t *                gui,
                               ulong                     slot,
                               long                      min_completion_ns,
                               long                      max_completion_ns,
                               fd_gui_batch_txn_ptr_t * txns,
                               ulong                     txn_cap,
                               ulong *                   txn_cnt ) {
  ulong observed = 0UL;
  fd_gui_hist_iter_t it;
  int err = fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN,
                                     min_completion_ns, max_completion_ns, NULL, NULL );
  if( FD_UNLIKELY( err ) ) return err;
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_t const * txn = it.rec;
    if( txn->slot!=slot ) continue;
    if( FD_UNLIKELY( observed>=txn_cap ) ) break;
    txns[ observed++ ] = txn;
  }
  fd_gui_hist_range_end( &it );
  *txn_cnt = observed;
  return err;
}

static int
fd_gui_materialize_replay_txn_batches( fd_gui_t * gui,
                                       ulong      slot,
                                       long       min_completion_ns,
                                       long       max_completion_ns,
                                       ulong      expected_txn_cnt,
                                       long       now ) {
  if( FD_UNLIKELY( !gui->db || !gui->alloc || !expected_txn_cnt ) ) return 0;
  ulong const txn_cap = fd_ulong_min( expected_txn_cnt, FD_MAX_TXN_PER_SLOT );
  if( FD_UNLIKELY( !txn_cap ) ) return 0;

  fd_gui_txn_batch_scratch_t scratch[ 1 ];
  if( FD_UNLIKELY( fd_gui_txn_batch_scratch_new( gui, scratch, txn_cap ) ) ) return -1;

  ulong txn_cnt = 0UL;
  int err = fd_gui_txn_batch_collect_slot( gui, slot, min_completion_ns, max_completion_ns,
                                           scratch->exec_txns, txn_cap, &txn_cnt );
  if( FD_UNLIKELY( err || !txn_cnt ) ) goto cleanup;

  fd_memcpy( scratch->sig_txns, scratch->exec_txns, txn_cnt*sizeof(fd_gui_batch_txn_ptr_t) );
  fd_gui_batch_exec_txn_sort_inplace     ( scratch->exec_txns, txn_cnt );
  fd_gui_batch_sigverify_txn_sort_inplace( scratch->sig_txns,  txn_cnt );
  ulong exec_batch_cnt = fd_gui_txn_batch_build_lane( scratch->exec_txns, txn_cnt, 0, scratch->exec_batches );
  ulong sig_batch_cnt  = fd_gui_txn_batch_build_lane( scratch->sig_txns,  txn_cnt, 1, scratch->sig_batches  );
  if( FD_UNLIKELY( fd_gui_txn_batch_normalize_sigverify( scratch->sig_batches, &sig_batch_cnt, exec_batch_cnt,
                                                         scratch->sig_txns, scratch->heap ) ) ) {
    err = -1;
    goto cleanup;
  }

  fd_gui_txn_batch_order_sort_inplace( scratch->exec_batches, exec_batch_cnt );
  fd_gui_txn_batch_order_sort_inplace( scratch->sig_batches,  sig_batch_cnt  );
  for( ulong i=0UL; i<exec_batch_cnt; i++ ) {
    fd_gui_store_replay_txn_batch_t record;
    fd_gui_txn_batch_record( &record, i, &scratch->exec_batches[ i ], scratch->exec_txns,
                                         &scratch->sig_batches [ i ], scratch->sig_txns );
    if( FD_UNLIKELY( fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, now, record.completion_time_ns, &record ) ) ) err = -1;
  }

cleanup:
  fd_gui_txn_batch_scratch_delete( gui, scratch );
  return err;
}

void
fd_gui_handle_replay_txn( fd_gui_t *                         gui,
                          fd_replay_txn_executed_t const * txn,
                          long                               now ) {
  if( FD_UNLIKELY( txn->tick_sigverify_done==LONG_MAX || txn->tick_commit_end==LONG_MAX ) ) return;

  long tick_now        = fd_tickcount();
  long completion_tick = fd_long_max( txn->tick_sigverify_done, txn->tick_commit_end );

  uint  pack_flags             = 0U;
  ulong compute_units_requested = fd_pack_compute_cost( TXN( txn->txn ), txn->txn->payload,
                                                        &pack_flags, NULL, NULL, NULL, NULL, NULL );

  fd_gui_store_replay_txn_t rec = {
    .completion_time_ns      = fd_gui_replay_tick_to_nanos( gui, now, tick_now, completion_tick ),
    .slot                    = txn->slot,
    .txn_idx                 = txn->index_in_slot,
    .txn_exec_idx            = txn->exec_tile_idx,
    .txn_sigverify_exec_idx  = txn->sigverify_exec_tile_idx,
    .sigverify_start_ns      = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_sigverify_disp ),
    .sigverify_end_ns        = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_sigverify_done ),
    .load_start_ns           = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_load_start ),
    .check_start_ns          = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_check_start ),
    .exec_start_ns           = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_exec_start ),
    .commit_start_ns         = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_commit_start ),
    .commit_end_ns           = fd_gui_replay_tick_to_nanos( gui, now, tick_now, txn->tick_commit_end ),
    .transaction_fee         = txn->transaction_fee,
    .priority_fee            = txn->priority_fee,
    .tips                    = txn->tips,
    .compute_units_requested = (uint)compute_units_requested,
    .compute_units_consumed  = txn->compute_units_consumed,
    .error_code              = (uint)(-(long)txn->txn_err),
    .is_committable          = (uchar)!!txn->runtime_is_committable,
    .is_fees_only            = (uchar)!!txn->runtime_is_fees_only,
    .is_simple_vote          = (uchar)!!txn->runtime_is_simple_vote
  };
  fd_memcpy( rec.signature,
             txn->txn->payload + TXN( txn->txn )->signature_off,
             FD_TXN_SIGNATURE_SZ );

  fd_gui_timeline_handle_txn( gui, rec.slot, rec.commit_end_ns,
                              (ulong)rec.compute_units_consumed, txn->max_compute_units,
                              rec.transaction_fee, rec.priority_fee, rec.tips,
                              rec.is_simple_vote, !rec.error_code );
  fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, now, rec.completion_time_ns, &rec );
}

void
fd_gui_handle_replay_update( fd_gui_t *                         gui,
                             fd_replay_slot_completed_t const * slot_completed,
                             ulong                              vote_slot,
                             long                               now ) {
  ulong txn_cnt = 0UL;
  if( slot_completed->vote_success    !=ULONG_MAX &&
      slot_completed->vote_failed     !=ULONG_MAX &&
      slot_completed->nonvote_success !=ULONG_MAX &&
      slot_completed->nonvote_failed  !=ULONG_MAX ) {
    txn_cnt = fd_ulong_sat_add( slot_completed->vote_success, slot_completed->vote_failed );
    txn_cnt = fd_ulong_sat_add( txn_cnt, slot_completed->nonvote_success );
    txn_cnt = fd_ulong_sat_add( txn_cnt, slot_completed->nonvote_failed  );
    txn_cnt = fd_ulong_min( txn_cnt, FD_MAX_TXN_PER_SLOT );
  }
  if( FD_LIKELY( txn_cnt &&
                 slot_completed->first_transaction_scheduled_nanos>0L &&
                 slot_completed->completion_time_nanos>0L ) ) {
    long const slack_ns = 2L*1000L*1000L*1000L;
    long lo_ns = fd_long_sat_sub( slot_completed->first_transaction_scheduled_nanos, slack_ns );
    long hi_ns = fd_long_sat_add( slot_completed->completion_time_nanos,             slack_ns );
    fd_gui_materialize_replay_txn_batches( gui, slot_completed->slot, lo_ns, hi_ns, txn_cnt, now );
  }

  if( FD_LIKELY( gui->summary.slot_storage!=slot_completed->storage_slot ) ) {
    gui->summary.slot_storage = slot_completed->storage_slot;
    fd_gui_printf_storage_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( slot_completed->identity_balance!=ULONG_MAX && gui->summary.identity_account_balance!=slot_completed->identity_balance ) ) {
    gui->summary.identity_account_balance = slot_completed->identity_balance;

    fd_gui_printf_identity_balance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_UNLIKELY( gui->summary.boot_progress.catching_up_first_replay_slot==ULONG_MAX ) ) {
    gui->summary.boot_progress.catching_up_first_replay_slot = slot_completed->slot;
  }

  fd_gui_slot_t * slot = fd_gui_slot_get_or_create( gui,
                                                    slot_completed->slot,
                                                    slot_completed->parent_slot,
                                                    slot_completed->bank_seq,
                                                    slot_completed->parent_bank_seq );
  fd_gui_timeline_complete_slot( gui, slot_completed->slot, slot );
  if( FD_UNLIKELY( !slot ) ) return; /* record could not be created / was evicted */

  slot->completed_time    = slot_completed->completion_time_nanos;
  slot->parent_slot       = slot_completed->parent_slot;
  slot->max_compute_units = fd_uint_if( slot_completed->cost_tracker.block_cost_limit==ULONG_MAX, slot->max_compute_units, (uint)slot_completed->cost_tracker.block_cost_limit );

  fd_gui_slot_t const * parent = fd_gui_slot_parent_get( gui, slot );
  slot->parent_completed_time = parent ? parent->completed_time : LONG_MAX;

  if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_COMPLETED ) ) {
    /* Typically a slot goes from INCOMPLETE to COMPLETED but it can
       happen that it starts higher.  One such case is when we
       optimistically confirm a higher slot that skips this one, but
       then later we replay this one anyway to track the bank fork. */

    if( FD_LIKELY( gui->summary.slot_optimistically_confirmed!=ULONG_MAX && slot_completed->slot<gui->summary.slot_optimistically_confirmed ) ) {
      /* Cluster might have already optimistically confirmed by the time
         we finish replaying it. */
      slot->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
    } else {
      slot->level = FD_GUI_SLOT_LEVEL_COMPLETED;
    }
  }
  slot->vote_failed     = fd_uint_if( slot_completed->vote_failed==ULONG_MAX,     slot->vote_failed,     (uint)slot_completed->vote_failed     );
  slot->vote_success    = fd_uint_if( slot_completed->vote_success==ULONG_MAX,    slot->vote_success,    (uint)slot_completed->vote_success    );
  slot->nonvote_success = fd_uint_if( slot_completed->nonvote_success==ULONG_MAX, slot->nonvote_success, (uint)slot_completed->nonvote_success );
  slot->nonvote_failed  = fd_uint_if( slot_completed->nonvote_failed==ULONG_MAX,  slot->nonvote_failed,  (uint)slot_completed->nonvote_failed  );

  slot->transaction_fee   = slot_completed->transaction_fee;
  slot->priority_fee      = slot_completed->priority_fee;
  slot->tips              = slot_completed->tips;
  slot->compute_units     = fd_uint_if( slot_completed->cost_tracker.block_cost==ULONG_MAX, slot->compute_units, (uint)slot_completed->cost_tracker.block_cost );
  slot->shred_cnt         = fd_uint_if( slot_completed->shred_cnt==ULONG_MAX, slot->shred_cnt, (uint)slot_completed->shred_cnt );
  slot->vote_slot         = vote_slot;
  slot->block_hash        = slot_completed->block_hash;

  fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, slot_completed->slot );
  if( FD_UNLIKELY( epoch && slot_completed->slot==epoch->start_slot+epoch->slot_cnt-1UL ) ) epoch->end_time = slot->completed_time;

  if( FD_UNLIKELY( slot->mine ) ) {
    fd_gui_leader_slot_t * lmeta = fd_gui_slot_leader_get_or_create( gui, slot_completed->slot, slot_completed->bank_seq );
    if( FD_LIKELY( lmeta ) ) lmeta->block_hash = slot_completed->block_hash;

    fd_gui_epoch_t const * epoch = fd_gui_get_epoch_by_slot( gui, slot_completed->slot );
    if( FD_LIKELY( epoch ) ) fd_gui_broadcast_skip_rate( gui, epoch->epoch );
  }

  /* Add a "slot complete" event for all of the shreds in this slot */
  fd_gui_shred_event_append( gui, slot_completed->slot, USHORT_MAX, USHORT_MAX,
                             FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, now, slot_completed->completion_time_nanos );

  /* Set skip status based on the current tower-derived canonical fork. */
  fd_gui_slot_t * canon = fd_gui_slot_get_canon( gui, slot_completed->slot );
  slot->skip = fd_uchar_if( canon && canon->bank_seq==slot_completed->bank_seq, FD_GUI_SKIP_STATUS_NOT_SKIPPED, FD_GUI_SKIP_STATUS_UNKNOWN );

  /* fixes race if we just sample right after replay's SLOT_COMPLETE */
  if( FD_LIKELY( gui->summary.slot_caught_up!=ULONG_MAX ) ) {
    /* Backtest topologies have no repair tile. */
    ulong repair_tile_idx = fd_topo_find_tile( gui->topo, "repair", 0UL );
    if( FD_LIKELY( repair_tile_idx!=ULONG_MAX ) ) {
      fd_topo_tile_t const * repair = &gui->topo->tiles[ repair_tile_idx ];
      volatile ulong const * repair_metrics = fd_metrics_tile( repair->metrics );
      ulong slot = repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ];
      fd_gui_handle_repair_slot( gui, slot, now );
    }
  }

  /* Update slot_turbine when we are leader. */
  if( FD_UNLIKELY( gui->summary.slots_max_turbine[ 0 ].slot!=ULONG_MAX && slot_completed->slot > gui->summary.slots_max_turbine[ 0 ].slot ) ) {
    fd_gui_try_insert_ephemeral_slot( gui->summary.slots_max_turbine, FD_GUI_TURBINE_SLOT_HISTORY_SZ, slot_completed->slot, now );
  }

  int slot_turbine_hist_full = gui->summary.slots_max_turbine[ FD_GUI_TURBINE_SLOT_HISTORY_SZ-1UL ].slot!=ULONG_MAX;
  if( FD_UNLIKELY( gui->summary.slot_caught_up==ULONG_MAX && slot_turbine_hist_full && gui->summary.slots_max_turbine[ 0 ].slot < (slot_completed->slot + 3UL) ) ) {
    gui->summary.slot_caught_up = slot_completed->slot + 4UL;

    fd_gui_printf_slot_caught_up( gui );
    fd_http_server_ws_broadcast( gui->http );
  }
}

void
fd_gui_became_leader( fd_gui_t * gui,
                      ulong      _slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units FD_PARAM_UNUSED,
                      ulong      max_microblocks,
                      ulong      bank_seq ) {
  if( FD_UNLIKELY( fd_gui_slot_is_mine( gui, _slot ) && !fd_gui_slot_is_mine( gui, _slot-1UL ) ) ) {
    gui->leader_active = 1;
  }

  fd_gui_leader_slot_t * lslot = fd_gui_slot_leader_get_or_create( gui, _slot, bank_seq );
  if( FD_UNLIKELY( !lslot ) ) return;

  lslot->leader_start_time = fd_long_if( lslot->leader_start_time==LONG_MAX, start_time_nanos, lslot->leader_start_time );
  lslot->leader_end_time   = end_time_nanos;
  lslot->max_microblocks   = max_microblocks;
  if( FD_LIKELY( lslot->microblocks_upper_bound==UINT_MAX ) ) lslot->microblocks_upper_bound = (uint)max_microblocks;
}

void
fd_gui_unbecame_leader( fd_gui_t *                gui,
                        ulong                     _slot,
                        fd_done_packing_t const * done_packing ) {
  if( FD_UNLIKELY( fd_gui_slot_is_mine( gui, _slot ) && !fd_gui_slot_is_mine( gui, _slot+1UL ) ) ) {
    gui->leader_active = 0;
  }

  fd_gui_leader_slot_t * lslot = fd_gui_slot_leader_get_any( gui, _slot );
  if( FD_UNLIKELY( !lslot ) ) return;
  lslot->microblocks_upper_bound = (uint)done_packing->microblocks_in_slot;
  fd_memcpy( lslot->scheduler_stats, done_packing, sizeof(fd_done_packing_t) );
  lslot->unbecame_leader = 1;

  if( FD_LIKELY( !lslot->has_waterfall ) ) {
    gui->leader_slot_pending     = lslot->slot;
    gui->leader_bank_seq_pending = lslot->bank_seq;
  }
}

void
fd_gui_done_draining( fd_gui_t * gui,
                      long       now ) {
  if( FD_UNLIKELY( gui->leader_slot_pending==ULONG_MAX ) ) return;

  fd_gui_leader_slot_t * lslot = fd_gui_slot_leader_get( gui, gui->leader_slot_pending, gui->leader_bank_seq_pending );
  gui->leader_slot_pending     = ULONG_MAX;
  gui->leader_bank_seq_pending = ULONG_MAX;
  if( FD_UNLIKELY( !lslot || lslot->has_waterfall ) ) return;

  fd_gui_txn_waterfall_t waterfall[ 1 ];
  fd_gui_txn_waterfall_snap( gui, waterfall );
  waterfall->sample_time_nanos = now;

  fd_memcpy( lslot->waterfall_reference, gui->summary.txn_waterfall_reference, sizeof(fd_gui_txn_waterfall_t) );
  fd_memcpy( lslot->waterfall,           waterfall,                             sizeof(fd_gui_txn_waterfall_t) );
  lslot->has_waterfall = 1;

  fd_memcpy( gui->summary.txn_waterfall_reference, waterfall, sizeof(fd_gui_txn_waterfall_t) );
}

void
fd_gui_microblock_execution_begin( fd_gui_t *   gui,
                                   long         tspub_ns,
                                   ulong        _slot,
                                   fd_txn_e_t * txns,
                                   ulong        txn_cnt,
                                   uint         microblock_idx,
                                   ulong        pack_txn_idx,
                                   ulong        bank_seq,
                                   long         now ) {
  fd_gui_leader_slot_t * lslot = fd_gui_slot_leader_get_or_create( gui, _slot, bank_seq );
  if( FD_UNLIKELY( !lslot ) ) return;

  lslot->leader_start_time = fd_long_if( lslot->leader_start_time==LONG_MAX, tspub_ns, lslot->leader_start_time );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn_payload = txns[ i ].txnp;
    fd_txn_t * txn = TXN( txn_payload );

    ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * txn->signature_cnt;
    ulong priority_rewards                    = ULONG_MAX;
    ulong requested_execution_cus             = ULONG_MAX;
    ulong precompile_sigs                     = ULONG_MAX;
    ulong requested_loaded_accounts_data_cost = ULONG_MAX;
    ulong allocated_data                      = ULONG_MAX;
    uint _flags = 0U;
    ulong cost_estimate = fd_pack_compute_cost( txn, txn_payload->payload, &_flags, &requested_execution_cus, &priority_rewards, &precompile_sigs, &requested_loaded_accounts_data_cost, &allocated_data );
    sig_rewards += FD_PACK_FEE_PER_SIGNATURE * precompile_sigs;
    sig_rewards = sig_rewards * FD_PACK_TXN_FEE_BURN_PCT / 100UL;

    ulong txn_idx = pack_txn_idx + i;
    uchar flags = (uchar)FD_GUI_TXN_FLAGS_STARTED;
    flags |= (uchar)fd_uint_if( !!(txn_payload->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE), FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE, 0U );
    flags |= (uchar)fd_uint_if( (txn_payload->flags & FD_TXN_P_FLAGS_BUNDLE) || (txn_payload->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE), FD_GUI_TXN_FLAGS_FROM_BUNDLE, 0U );

    fd_gui_store_txn_start_t rec = {
      .slot                    = _slot,
      .bank_seq                = bank_seq,
      .txn_idx                 = txn_idx,
      .transaction_fee         = sig_rewards,
      .priority_fee            = priority_rewards,
      .timestamp_arrival_nanos = txn_payload->scheduler_arrival_time_nanos,
      .microblock_start_ns     = tspub_ns,
      .compute_units_requested = (uint)(cost_estimate & 0x1FFFFFU),
      .microblock_idx          = microblock_idx,
      .source_ipv4             = txn_payload->source_ipv4,
      .source_tpu              = txn_payload->source_tpu,
      .flags                   = flags
    };
    fd_memcpy( rec.signature, txn_payload->payload + txn->signature_off, FD_SHA512_HASH_SZ );
    fd_gui_hist_ts_append( gui, FD_GUI_HIST_TXN_START, now, tspub_ns, &rec );
  }

  /* At the moment, bank publishes at most 1 transaction per microblock,
     even if it received microblocks with multiple transactions
     (i.e. a bundle). This means that we need to calculate microblock
     count here based on the transaction count. */
  lslot->begin_microblocks += (uint)txn_cnt;
}

static void
fd_gui_stage_leader_block_votes( fd_gui_t *   gui,
                                 ulong        landed_slot,
                                 ulong        landed_bank_seq,
                                 fd_txn_p_t * txn_p ) {
  if( FD_LIKELY( !(txn_p->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) || (txn_p->flags & (FD_TXN_P_FLAGS_FEES_ONLY | FD_TXN_P_FLAGS_RESULT_MASK)) ) ) return;

  fd_txn_t const * txn     = TXN( txn_p );
  uchar const *    payload = txn_p->payload;

  fd_compact_tower_sync_serde_t tower_sync[ 1 ];
  if( FD_UNLIKELY( !fd_txn_parse_simple_vote( txn, payload, tower_sync ) ) ) return;

  fd_acct_addr_t const * accs = fd_txn_get_acct_addrs( txn, payload );
  if( FD_UNLIKELY( memcmp( &accs[ 0 ], gui->summary.identity_key->uc, sizeof(fd_pubkey_t) ) ) ) return; /* not our identity */
  if( FD_UNLIKELY( gui->summary.has_vote_key && memcmp( &accs[ txn->signature_cnt==1 ? 1 : 2 ], gui->summary.vote_key->uc, sizeof(fd_pubkey_t) ) ) ) return; /* not our vote account */

  ulong cur = fd_ulong_if( tower_sync->root==ULONG_MAX, 0UL, tower_sync->root );
  for( ulong i=0UL; i<tower_sync->lockouts_cnt; i++ ) {
    if( FD_UNLIKELY( __builtin_uaddl_overflow( cur, tower_sync->lockouts[ i ].offset, &cur ) ) ) return;
    fd_gui_stage_landed_vote( gui, landed_slot, landed_bank_seq, cur );
  }
}

void
fd_gui_microblock_execution_end( fd_gui_t *     gui,
                                 long           tspub_ns,
                                 ulong          bank_idx,
                                 ulong          _slot,
                                 ulong          txn_cnt,
                                 fd_txn_p_t *   txns,
                                 ulong          pack_txn_idx,
                                 fd_txn_ns_dt_t txn_ns_dt,
                                 ulong          tips,
                                 ulong          bank_seq,
                                 long           now ) {
  if( FD_UNLIKELY( 1UL!=txn_cnt ) ) FD_LOG_ERR(( "gui expects 1 txn per microblock from bank, found %lu", txn_cnt ));

  fd_gui_leader_slot_t * lslot = fd_gui_slot_leader_get_or_create( gui, _slot, bank_seq );
  if( FD_UNLIKELY( !lslot ) ) return;

  lslot->leader_start_time = fd_long_if( lslot->leader_start_time==LONG_MAX, tspub_ns, lslot->leader_start_time );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn_p = &txns[ i ];
    ulong txn_idx = pack_txn_idx + i;

    uchar flags = (uchar)FD_GUI_TXN_FLAGS_ENDED;
    flags |= (uchar)fd_uint_if( !!(txn_p->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS), FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK, 0U );

    fd_gui_store_txn_end_t rec = {
      .slot                    = _slot,
      .bank_seq                = bank_seq,
      .txn_idx                 = txn_idx,
      .timestamp_arrival_nanos = txn_p->scheduler_arrival_time_nanos,
      .microblock_end_ns       = tspub_ns,
      .txn_ns_dt               = txn_ns_dt,
      .tips                    = tips,
      .compute_units_consumed  = (uint)(txn_p->execle_cu.actual_consumed_cus & 0x1FFFFFU),
      .bank_idx                = (uint)(bank_idx & 0x3FU),
      .error_code              = (uint)((txn_p->flags >> 24) & 0x3FU),
      .flags                   = flags
    };
    fd_gui_hist_ts_append( gui, FD_GUI_HIST_TXN_END, now, tspub_ns, &rec );

    /* Record our own votes that land in our own leader block. */
    fd_gui_stage_leader_block_votes( gui, _slot, bank_seq, txn_p );
  }

  lslot->end_microblocks = lslot->end_microblocks + (uint)txn_cnt;
}
