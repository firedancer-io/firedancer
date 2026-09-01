#define _GNU_SOURCE
#include <linux/futex.h> /* FUTEX_WAKE */
#include <sys/syscall.h> /* SYS_futex */
#include <unistd.h> /* syscall(2) */

#include "fd_replay_tile.h"
#include "fd_replay_tile_private.h"
#include "fd_block_marker.h"
#include "fd_sched.h"
#include "fd_execrp.h"
#include "generated/fd_replay_tile_seccomp.h"

#include "../admin/fd_adminctl.h"
#include "../genesis/fd_genesi_tile.h"
#include "../poh/fd_poh.h"
#include "../poh/fd_poh_tile.h"
#include "../tower/fd_tower_tile.h"
#include "../votor/fd_votor_tile.h"
#include "../resolv/fd_resolv_tile.h"
#include "../restore/utils/fd_ssload.h"

#include "../../disco/tiles.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../disco/shred/fd_shred_tile.h"
#include "../../disco/pack/fd_pack.h"
#include "../backup/fd_snapmk_tile.h"
#include "../reasm/fd_reasm.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/genesis/fd_genesis_cluster.h"
#include "../../discof/genesis/genesis_hash.h"
#include "../../util/pod/fd_pod.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/progcache/fd_progcache_admin.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../repair/fd_repair_tile.h"
#include "../rotor/fd_rotor_tile.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_stack.h"

#include "../../flamenco/runtime/sysvar/fd_sysvar_cache.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_stake_history.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h"
#include "../../flamenco/runtime/program/fd_precompiles.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"
#include "../../flamenco/runtime/tests/fd_dump_pb.h"
#include "../../disco/events/fd_event_report.h"

/* Replay concepts:

   - Blocks are aggregations of entries aka. microblocks which are
     groupings of txns and are constructed by the block producer (see
     fd_pack).

   - Entries are grouped into entry batches by the block producer (see
     fd_pack / fd_shredder).

   - Entry batches are divided into chunks known as shreds by the block
     producer (see fd_shredder).

   - Shreds are grouped into forward-error-correction sets (FEC sets) by
     the block producer (see fd_shredder).

   - Shreds are transmitted to the rest of the cluster via the Turbine
     protocol (see fd_shredder / fd_shred).

   - Once enough shreds within a FEC set are received to recover the
     entirety of the shred data encoded by that FEC set, the receiver
     can "complete" the FEC set (see fd_fec_resolver).

   - If shreds in the FEC set are missing such that it can't complete,
     the receiver can use the Repair protocol to request missing shreds
     in FEC set (see fd_repair).

  -  The current Repair protocol does not support requesting coding
     shreds.  As a result, some FEC sets might be actually complete
     (contain all data shreds).  Repair currently hacks around this by
     forcing completion but the long-term solution is to add support for
     fec_repairing coding shreds via Repair.

  - FEC sets are delivered in partial-order to the Replay tile by the
    Repair tile.  Currently Replay only supports replaying entry batches
    so FEC sets need to reassembled into an entry batch before they can
    be replayed.  The new Dispatcher will change this by taking a FEC
    set as input instead. */

#define IN_KIND_SNAP       ( 0)
#define IN_KIND_GENESIS    ( 1)
#define IN_KIND_IPECHO     ( 2)
#define IN_KIND_TOWER      ( 3)
#define IN_KIND_RESOLV     ( 4)
#define IN_KIND_POH        ( 5)
#define IN_KIND_EXECRP     ( 6)
#define IN_KIND_REPAIR     ( 7)
#define IN_KIND_TXSEND     ( 8)
#define IN_KIND_RPC        ( 9)
#define IN_KIND_GOSSIP_OUT (10)
#define IN_KIND_SNAPMK     (11)
#define IN_KIND_ADMIN      (12)
#define IN_KIND_VOTOR      (13)

#define DEBUG_LOGGING 0

/* The first bank that the replay tile produces either for genesis
   or the snapshot boot will always be at bank index 0. */
#define FD_REPLAY_BOOT_BANK_SEQ (0UL)

static inline ulong
fd_block_id_ele_get_idx( fd_block_id_ele_t * ele_arr, fd_block_id_ele_t * ele ) {
  return (ulong)(ele - ele_arr);
}

static inline fd_block_id_ele_t *
fd_block_id_ele_query( fd_replay_tile_t * ctx,
                       fd_hash_t const * block_id,
                       ulong slot ) {
  if( !ctx->alpenglow ) {
    return fd_block_id_map_ele_query( ctx->block_id_map, block_id, NULL, ctx->block_id_arr );
  } else {
    ag_block_id_t key = ag_block_id( slot, block_id->uc );
    return fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key, NULL, ctx->block_id_arr );
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}
FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong chain_cnt = fd_block_id_map_chain_cnt_est( tile->replay.max_live_slots );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_t),           sizeof(fd_replay_tile_t) );
  l = FD_LAYOUT_APPEND( l, fd_runtime_stack_align(),            fd_runtime_stack_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKED_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_block_id_ele_t),          sizeof(fd_block_id_ele_t) * tile->replay.max_live_slots );
  if( !tile->replay.alpenglow ) {
    l = FD_LAYOUT_APPEND( l, fd_block_id_map_align(),             fd_block_id_map_footprint( chain_cnt ) );
  } else {
    l = FD_LAYOUT_APPEND( l, fd_ag_block_id_map_align(),          fd_ag_block_id_map_footprint( chain_cnt ) );
  }
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),                 fd_txncache_footprint( tile->replay.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),                    fd_accdb_footprint( tile->replay.max_live_slots ) );
  if( !tile->replay.alpenglow ) {
  l = FD_LAYOUT_APPEND( l, fd_reasm_align(),                    fd_reasm_footprint( tile->replay.fec_max ) );
  }
  l = FD_LAYOUT_APPEND( l, alignof(fd_reception_stats_t),       sizeof(fd_reception_stats_t)*tile->replay.max_live_slots );
  l = FD_LAYOUT_APPEND( l, fd_sched_align(),                    fd_sched_footprint( tile->replay.sched_depth, tile->replay.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_vote_tracker_align(),             fd_vote_tracker_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),              fd_capture_ctx_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(fd_dump_proto_ctx_t),        sizeof(fd_dump_proto_ctx_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_event_block_completed_t), sizeof(fd_event_block_completed_t) );
  l = FD_LAYOUT_APPEND( l, fd_timing_slot_pool_align(),         fd_timing_slot_pool_footprint( FD_REPLAY_TXN_TIMING_SLOTS ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                      tile->replay.max_live_slots*sizeof(ulong) );

  if( FD_UNLIKELY( tile->replay.dump_block_to_pb ) ) {
    l = FD_LAYOUT_APPEND( l, fd_block_dump_context_align(), fd_block_dump_context_footprint() );
  }

  l = FD_LAYOUT_FINI( l, scratch_align() );

  return l;
}

static inline void
metrics_write( fd_replay_tile_t * ctx ) {
  fd_accdb_flush_metrics( ctx->accdb );

  FD_MCNT_SET  ( REPLAY, STORE_QUERY_ACQUIRED,      ctx->metrics.store_query_acquire      );
  FD_MCNT_SET  ( REPLAY, STORE_QUERY_RELEASED,      ctx->metrics.store_query_release      );
  FD_MHIST_COPY( REPLAY, STORE_QUERY_WAIT_SECONDS, ctx->metrics.store_query_wait         );
  FD_MHIST_COPY( REPLAY, STORE_QUERY_WORK_SECONDS, ctx->metrics.store_query_work         );
  FD_MCNT_SET  ( REPLAY, STORE_QUERIED,              ctx->metrics.store_query_cnt          );
  FD_MCNT_SET  ( REPLAY, STORE_QUERY_MISSING,      ctx->metrics.store_query_missing_cnt  );
  FD_MGAUGE_SET( REPLAY, STORE_QUERY_MERKLE_ROOT_SAMPLE,         ctx->metrics.store_query_mr           );
  FD_MGAUGE_SET( REPLAY, STORE_QUERY_MISSING_MERKLE_ROOT_SAMPLE, ctx->metrics.store_query_missing_mr   );

  FD_MGAUGE_SET( REPLAY, ROOT_SLOT, ctx->consensus_root_slot==ULONG_MAX ? 0UL : ctx->consensus_root_slot );
  ulong leader_slot = ctx->leader_bank ? ctx->leader_bank->f.slot : 0UL;

  if( FD_LIKELY( ctx->leader_bank ) ) {
    FD_MGAUGE_SET( REPLAY, NEXT_LEADER_SLOT, leader_slot );
    FD_MGAUGE_SET( REPLAY, LEADER_SLOT, leader_slot );
  } else {
    FD_MGAUGE_SET( REPLAY, NEXT_LEADER_SLOT, ctx->next_leader_slot==ULONG_MAX ? 0UL : ctx->next_leader_slot );
    FD_MGAUGE_SET( REPLAY, LEADER_SLOT, 0UL );
  }
  FD_MGAUGE_SET( REPLAY, RESET_SLOT, ctx->reset_slot==ULONG_MAX ? 0UL : ctx->reset_slot );

  FD_MGAUGE_SET( REPLAY, BANK_LIVE, fd_banks_pool_used_cnt( ctx->banks ) );

  ulong reasm_free = ctx->reasm ? fd_reasm_free( ctx->reasm ) : 0UL;
  FD_MGAUGE_SET( REPLAY, REASSEMBLY_FREE, reasm_free );

  FD_MCNT_SET( REPLAY, SLOT_REPLAYED, ctx->metrics.slots_total );
  FD_MCNT_SET( REPLAY, TXN_PROCESSED, ctx->metrics.transactions_total );

  FD_MGAUGE_SET( REPLAY, REASSEMBLY_LATEST_SLOT,      ctx->metrics.reasm_latest_slot );
  FD_MGAUGE_SET( REPLAY, REASSEMBLY_LATEST_FEC_INDEX, ctx->metrics.reasm_latest_fec_idx );

  fd_sched_metrics_write( ctx->sched );

  FD_MCNT_SET( REPLAY, FEC_SCHED_FULL,          ctx->metrics.sched_full );
  FD_MCNT_SET( REPLAY, FEC_REASSEMBLY_EMPTY,    ctx->metrics.reasm_empty );
  FD_MCNT_SET( REPLAY, FEC_LEADER_BID_WAIT,     ctx->metrics.leader_bid_wait );
  FD_MCNT_SET( REPLAY, FEC_BANK_FULL,           ctx->metrics.banks_full );
  FD_MCNT_SET( REPLAY, STORAGE_ROOT_BEHIND, ctx->metrics.storage_root_behind );

  fd_progcache_admin_metrics_t const * pcm = &fd_progcache_admin_metrics_g;
  FD_MCNT_SET( REPLAY, PROGCACHE_ROOTED, pcm->root_cnt );

  fd_wksp_mon_t * wm = fd_wksp_mon_tick( ctx->progcache_wksp_mon, fd_tickcount() );
  FD_MGAUGE_SET( REPLAY, PROGCACHE_FREE_PARTITION,             wm->free_cnt       );
  FD_MGAUGE_SET( REPLAY, PROGCACHE_FREE_BYTES,                 wm->free_sz        );
  FD_MGAUGE_SET( REPLAY, PROGCACHE_SIZE_BYTES,                 wm->wksp->data_max );
  FD_MGAUGE_SET( REPLAY, PROGCACHE_FREE_PARTITION_MAX_BYTES,   wm->free_max_sz    );
  FD_MGAUGE_SET( REPLAY, PROGCACHE_USED_PARTITION_MEDIAN_BYTES, wm->part_median_sz );
  FD_MGAUGE_SET( REPLAY, PROGCACHE_USED_PARTITION_MEAN_BYTES,   wm->part_mean_sz   );

  FD_ACCDB_METRICS_WRITE( REPLAY, fd_accdb_metrics( ctx->accdb ) );
}

static ushort
replay_voter_rank( fd_replay_tile_t * ctx,
                   fd_bank_t *        bank,
                   ulong              epoch ) {
  if( FD_LIKELY( !ctx->alpenglow ) ) return USHORT_MAX;

  ulong fork_id    = bank->vote_stakes_fork_id;
  ulong fork_epoch = fd_vote_stakes_fork_epoch( fork_id );
  int   iter_kind  = FD_VOTE_STAKES_ITER_T_2;
  if( FD_UNLIKELY( epoch!=fork_epoch ) ) {
    if( FD_UNLIKELY( !fork_epoch || epoch!=fork_epoch-1UL ) ) return USHORT_MAX;
    iter_kind = FD_VOTE_STAKES_ITER_T_3;
  }

  fd_vote_stakes_t const * vote_stakes = fd_bank_vote_stakes( bank );
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, iter_kind, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, iter_kind, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, iter_kind, iter ) ) {
    fd_pubkey_t vote_key;
    fd_pubkey_t identity;
    ushort     rank;
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, iter_kind, iter, &vote_key, &identity,
                             NULL, NULL, NULL, NULL, NULL, &rank, NULL );
    if( FD_UNLIKELY( fd_pubkey_eq( &identity, ctx->identity_pubkey ) ) ) return rank;
  }
  return USHORT_MAX;
}

static int
replay_reward_cert_voted( fd_replay_tile_t * ctx,
                          fd_bank_t *        bank,
                          ulong     *        slot_out,
                          ushort    *        rank_out ) {
  if( FD_LIKELY( !ctx->alpenglow ) ) return 0;

  fd_reward_cert_t const * skip  = fd_sched_get_skip_reward_cert ( ctx->sched, bank->idx );
  fd_reward_cert_t const * notar = fd_sched_get_notar_reward_cert( ctx->sched, bank->idx );
  if( FD_LIKELY( !skip && !notar ) ) return 0;

  ulong  reward_slot  = skip ? skip->slot : notar->slot;
  ulong  reward_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, reward_slot, NULL );
  ushort rank         = replay_voter_rank( ctx, bank, reward_epoch );

  *slot_out = reward_slot;
  *rank_out = rank;

  if( FD_UNLIKELY( rank==USHORT_MAX ) ) { return 0; }

  ulong word = (ulong)rank>>6;
  ulong bit  = 1UL<<( (ulong)rank & 63UL );
  return ( !!skip  && rank<skip ->nbits && !!( skip ->signer_set[ word ] & bit ) ) ||
         ( !!notar && rank<notar->nbits && !!( notar->signer_set[ word ] & bit ) );
}

static void
publish_epoch_info( fd_replay_tile_t *  ctx,
                    fd_stem_context_t * stem,
                    fd_bank_t *         bank,
                    int                 next_epoch ) {
  fd_epoch_schedule_t const * schedule = &bank->f.epoch_schedule;
  ulong epoch = fd_slot_to_epoch( schedule, bank->f.slot, NULL ) + fd_ulong_if( next_epoch, 1UL, 0UL );

  fd_features_t const * features = &bank->f.features;

  fd_runtime_stack_t * runtime_stack = ctx->runtime_stack;

  fd_epoch_info_msg_t * epoch_info_msg = fd_chunk_to_laddr( ctx->epoch_out->mem, ctx->epoch_out->chunk );

  epoch_info_msg->staked_vote_cnt   = next_epoch ? runtime_stack->epoch_weights.next_stake_weights_cnt : runtime_stack->epoch_weights.stake_weights_cnt;
  epoch_info_msg->staked_id_cnt     = next_epoch ? runtime_stack->epoch_weights.next_id_weights_cnt    : runtime_stack->epoch_weights.id_weights_cnt;
  epoch_info_msg->epoch_schedule    = *schedule;
  epoch_info_msg->features          = *features;
  epoch_info_msg->epoch             = epoch;
  epoch_info_msg->start_slot        = fd_epoch_slot0( schedule, epoch );
  epoch_info_msg->slot_cnt          = fd_epoch_slot_cnt( schedule, epoch );
  epoch_info_msg->ns_per_slot       = fd_slot_params_at_slot( bank, epoch_info_msg->start_slot ).ns_per_slot;

  fd_vote_stake_weight_t * stake_weights = fd_type_pun( epoch_info_msg + 1 );
  fd_vote_stake_weight_t * src_stake_weights = next_epoch ? runtime_stack->epoch_weights.next_stake_weights : runtime_stack->epoch_weights.stake_weights;
  memcpy( stake_weights, src_stake_weights, epoch_info_msg->staked_vote_cnt * sizeof(fd_vote_stake_weight_t) );

  fd_stake_weight_t * id_weights = fd_epoch_info_msg_id_weights( epoch_info_msg );
  fd_stake_weight_t * src_id_weights = next_epoch ? runtime_stack->epoch_weights.next_id_weights : runtime_stack->epoch_weights.id_weights;
  fd_memcpy( id_weights, src_id_weights, epoch_info_msg->staked_id_cnt * sizeof(fd_stake_weight_t) );

  ulong epoch_info_sz = fd_epoch_info_msg_sz( epoch_info_msg->staked_vote_cnt, epoch_info_msg->staked_id_cnt );
  ulong epoch_info_sig = 4UL;
  fd_stem_publish( stem, ctx->epoch_out->idx, epoch_info_sig, ctx->epoch_out->chunk, epoch_info_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->epoch_out->chunk = fd_dcache_compact_next( ctx->epoch_out->chunk, epoch_info_sz, ctx->epoch_out->chunk0, ctx->epoch_out->wmark );

  fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, epoch_info_msg );
  fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
}

/**********************************************************************/
/* Transaction execution state machine helpers                        */
/**********************************************************************/

static inline void
timing_slot_release( fd_replay_tile_t * ctx,
                     ulong              bank_idx ) {
  ulong tslot = ctx->timing_slot_of_bank[ bank_idx ];
  if( FD_LIKELY( tslot!=fd_timing_slot_pool_idx_null( ctx->timing_slot_pool ) ) ) {
    fd_timing_slot_pool_idx_release( ctx->timing_slot_pool, tslot );
    ctx->timing_slot_of_bank[ bank_idx ] = fd_timing_slot_pool_idx_null( ctx->timing_slot_pool );
  }
}

static void
replay_block_start( fd_replay_tile_t * ctx,
                    ulong              bank_idx,
                    ulong              parent_bank_idx,
                    ulong              slot ) {
  long before = fd_clock_tile_now( ctx->clock );

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  FD_CHECK_CRIT( bank, "invariant violation: bank is NULL" );
  FD_CHECK_CRIT( bank->state==FD_BANK_STATE_INIT, "invariant violation: bank is not in correct state" );

  bank->preparation_begin_nanos = before;

  FD_TEST( ctx->timing_slot_of_bank[ bank_idx ]==fd_timing_slot_pool_idx_null( ctx->timing_slot_pool ) );
  if( FD_LIKELY( fd_timing_slot_pool_free( ctx->timing_slot_pool ) ) ) {
    ulong tslot = fd_timing_slot_pool_idx_acquire( ctx->timing_slot_pool );
    fd_timing_slot_pool_ele( ctx->timing_slot_pool, tslot )->cnt = 0UL;
    ctx->timing_slot_of_bank[ bank_idx ] = tslot;
  }

  fd_bank_t * parent_bank = fd_banks_bank_query( ctx->banks, parent_bank_idx );
  FD_CHECK_CRIT( parent_bank, "invariant violation: parent bank is NULL" );
  FD_CHECK_CRIT( parent_bank->state==FD_BANK_STATE_FROZEN || parent_bank->state==FD_BANK_STATE_PRUNABLE, "invariant violation: parent bank is not in correct state" );

  /* Clone the bank from the parent.  We must special case the first
     slot that is executed as the snapshot does not provide a parent
     block id. */

  bank = fd_banks_clone_from_parent( ctx->banks, bank_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for bank index %lu", bank_idx ));
  }
  bank->f.slot = slot;
  bank->txncache_fork_id     = fd_txncache_attach_child ( ctx->txncache,  parent_bank->txncache_fork_id  );
  bank->progcache_fork_id    = fd_progcache_attach_child( ctx->progcache, parent_bank->progcache_fork_id );
  bank->accdb_fork_id        = fd_accdb_attach_child    ( ctx->accdb,     parent_bank->accdb_fork_id     );
  bank->parent_accdb_fork_id = parent_bank->accdb_fork_id;

  ulong new_epoch  = fd_slot_to_epoch( &parent_bank->f.epoch_schedule, slot, NULL );
  ulong root_epoch = fd_slot_to_epoch( &parent_bank->f.epoch_schedule, ctx->published_root_slot, NULL );
  if( FD_UNLIKELY( new_epoch>root_epoch+1UL ) ) {
    FD_LOG_CRIT(( "firedancer replay does not support replaying more than one epoch ahead of the current root" ));
  }

  /* Update required runtime state and handle potential boundary. */

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( ctx->banks, bank, ctx->accdb, ctx->runtime_stack, ctx->capture_ctx, &is_epoch_boundary );

  ulong max_tick_height;
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS!=fd_runtime_compute_max_tick_height( parent_bank->f.ticks_per_slot, slot, &max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, parent_bank->f.ticks_per_slot ));
  }
  bank->f.max_tick_height = max_tick_height;
  if( FD_UNLIKELY( ctx->alpenglow ) ) {
    /* in alpenglow, we expect only one tick per block.  Instead of
       adjusting max tick height, we match agave behavior by setting
       tick height to max tick height - 1. These fields must stay in
       line with agave behavior. */
    bank->f.tick_height = bank->f.max_tick_height - 1UL;
    bank->f.slot_params.hashes_per_tick = 1UL;
  }
  fd_sched_set_poh_params( ctx->sched, bank->idx, bank->f.tick_height, bank->f.max_tick_height, bank->f.slot_params.hashes_per_tick, &parent_bank->f.poh );

  FD_LOG_DEBUG(( "replay_block_start: bank_idx=%lu slot=%lu parent_bank_idx=%lu", bank_idx, slot, parent_bank_idx ));
}

static void
cost_tracker_snap( fd_bank_t * bank, fd_replay_slot_completed_t * slot_info ) {
  if( FD_LIKELY( bank->cost_tracker_pool_idx!=ULONG_MAX ) ) {
    fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_query( bank );
    if( FD_UNLIKELY( cost_tracker->block_cost_limit==0UL ) ) {
      memset( &slot_info->cost_tracker, -1 /* ULONG_MAX */, sizeof(slot_info->cost_tracker) );
    } else {
      slot_info->cost_tracker.block_cost                   = cost_tracker->block_cost;
      slot_info->cost_tracker.allocated_accounts_data_size = cost_tracker->allocated_accounts_data_size;
      slot_info->cost_tracker.block_cost_limit             = cost_tracker->block_cost_limit;
      slot_info->cost_tracker.account_cost_limit           = cost_tracker->account_cost_limit;
    }
  } else {
    memset( &slot_info->cost_tracker, -1 /* ULONG_MAX */, sizeof(slot_info->cost_tracker) );
  }
  slot_info->cost_tracker.pool_idx = bank->cost_tracker_pool_idx;
}

static int
sched_dead_reason_to_event( int sched_reason ) {
  switch( sched_reason ) {
    case FD_SCHED_DEAD_REASON_UNPARSEABLE_CONTENT:         return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_UNPARSEABLE_CONTENT;
    case FD_SCHED_DEAD_REASON_SHORT_BLOCK:                 return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_SHORT_BLOCK;
    case FD_SCHED_DEAD_REASON_TOO_MANY_TXNS:               return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TOO_MANY_TXNS;
    case FD_SCHED_DEAD_REASON_TOO_MANY_MICROBLOCKS:        return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TOO_MANY_MICROBLOCKS;
    case FD_SCHED_DEAD_REASON_DUPLICATE_ACCOUNT:           return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_DUPLICATE_ACCOUNT;
    case FD_SCHED_DEAD_REASON_TRAILING_ENTRY:              return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TRAILING_ENTRY;
    case FD_SCHED_DEAD_REASON_TOO_MANY_TICKS:              return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TOO_MANY_TICKS;
    case FD_SCHED_DEAD_REASON_TOO_FEW_TICKS:               return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TOO_FEW_TICKS;
    case FD_SCHED_DEAD_REASON_ZERO_MICROBLOCKS:            return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ZERO_MICROBLOCKS;
    case FD_SCHED_DEAD_REASON_WRONG_HASHES_PER_TICK:       return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_WRONG_HASHES_PER_TICK;
    case FD_SCHED_DEAD_REASON_INCONSISTENT_TICK_HASHES:    return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_INCONSISTENT_TICK_HASHES;
    case FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW:        return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TICK_HASHES_OVERFLOW;
    case FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW_INGEST: return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TICK_HASHES_OVERFLOW_INGEST;
    case FD_SCHED_DEAD_REASON_ZERO_HASH_TICK:              return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ZERO_HASH_TICK;
    case FD_SCHED_DEAD_REASON_ZERO_HASH_TICK_INGEST:       return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ZERO_HASH_TICK_INGEST;
    case FD_SCHED_DEAD_REASON_TICK_HASH_MISMATCH:          return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TICK_HASH_MISMATCH;
    case FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH:         return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ENTRY_HASH_MISMATCH;
    case FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH_INGEST:  return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ENTRY_HASH_MISMATCH_INGEST;
    case FD_SCHED_DEAD_REASON_DEAD_ANCESTOR:               return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_PARENT_DEAD;
    case FD_SCHED_DEAD_REASON_BAD_FOOTER:                  return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER;
    default: FD_LOG_CRIT(( "unmapped scheduler dead reason %d", sched_reason ));
  }
}

static int
sched_block_dead_reason_to_event( fd_replay_tile_t * ctx, ulong bank_idx ) {
  if( FD_UNLIKELY( fd_sched_block_is_discarded( ctx->sched, bank_idx ) ) ) return FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD;
  return sched_dead_reason_to_event( fd_sched_get_dead_reason( ctx->sched, bank_idx ) );
}

static void
block_completed_event_fill_reception( fd_replay_tile_t *           ctx,
                                      fd_event_block_completed_t * ev,
                                      fd_hash_t const *            mr,
                                      ulong                        slot ) {
  ev->lowest_verified_fec_index    = UINT_MAX;
  ev->last_completed_fec_set_index = UINT_MAX;

  if( !ctx->reasm ) return;

  fd_reasm_fec_t * chain_tip = fd_reasm_query( ctx->reasm, mr );
  if( FD_LIKELY( chain_tip ) ) {
    ulong n = 0UL;
    fd_reasm_fec_t * f = chain_tip;
    for( ; f && f->slot==slot; f = fd_reasm_parent( ctx->reasm, f ) ) {
      n++;
      if( f->eqvoc ) ev->equivocation_detected_shred = 1;
    }
    ev->fec_set_count = n;

    /* The walk's terminating FEC is the parent block's final one: its
       merkle root is the parent block id.  Recover parent_slot from it
       too, for rows whose bank never learned it. */
    if( f ) {
      fd_memcpy( ev->parent_block_id, f->key.uc, sizeof(ev->parent_block_id) );
      if( !ev->parent_slot ) ev->parent_slot = f->slot;
    }

    fd_reception_stats_t * stats = &ctx->reception_stats[ slot % ctx->reception_stats_cnt ];
    /* If there's a mismatch in the slot's stats, we just ignore it and
       return.  This can only happen in the case where there is a large
       jump in the slot number and it exactly matches the expected
       slot's modulo with max_live_slots. */
    if( FD_UNLIKELY( stats->slot!=slot ) ) return;
    fd_fec_complete_metrics_t const * m = &stats->metrics;
    ev->last_completed_fec_set_index = stats->fec_set_idx;
    ev->turbine_shred_count       = m->blk_turbine_cnt;
    ev->repair_shred_count        = m->blk_repair_cnt;
    ev->recovered_shred_count     = m->blk_recovered_cnt;
    ev->data_shred_count          = m->blk_data_cnt;
    ev->parity_shred_count        = m->blk_parity_cnt;
    ev->chain_confirmed           = !!m->blk_chain_confirmed;
    ev->slot_complete_flag        = !!m->blk_slot_complete;
    ev->lowest_verified_fec_index = m->blk_lowest_verified_fec;

    ev->repair_request_window_count         = m->blk_req_window_cnt;
    ev->repair_request_highest_window_count = m->blk_req_highest_cnt;
    ev->repair_request_orphan_count         = m->blk_req_orphan_cnt;
    ev->repair_responses_received           = m->blk_repair_responses;
    ev->repair_requests_retransmitted       = m->blk_req_retransmit_cnt;
    ev->repair_failed_chain_verify          = !!m->blk_chain_verify_failed;
    ev->first_shred_received_time           = m->blk_first_shred_ts_nanos;
    ev->last_shred_received_time            = m->blk_last_shred_ts_nanos;
    ev->first_repair_request_time           = m->blk_first_req_ts_nanos;
    ev->last_repair_received_time           = m->blk_last_repair_resp_ts_nanos;
  }
}

static void
block_completed_event_fill_bank( fd_replay_tile_t *           ctx,
                                 fd_event_block_completed_t * ev,
                                 fd_bank_t *                  bank ) {
  fd_bank_t * parent_bank = fd_banks_get_parent( ctx->banks, bank );

  int   prepared = bank->preparation_begin_nanos!=0L;
  ulong slot     = prepared ? bank->f.slot : ctx->block_id_arr[ bank->idx ].slot;

  ev->bank_seq    = bank->bank_seq;
  ev->slot        = slot;
  ev->parent_slot = prepared                    ? bank->f.parent_slot
                  : bank->parent_idx!=ULONG_MAX ? ctx->block_id_arr[ bank->parent_idx ].slot
                  :                               0UL;
  if(      FD_LIKELY( prepared )                ) ev->epoch = bank->f.epoch;
  else if( FD_LIKELY( ctx->notified_root_bank ) ) ev->epoch = fd_slot_to_epoch( &ctx->notified_root_bank->f.epoch_schedule, slot, NULL );
  fd_block_id_ele_t const * ele = &ctx->block_id_arr[ bank->idx ];
  fd_memcpy( ev->block_id, ctx->alpenglow ? ele->dmr.uc : ele->latest_mr.uc, sizeof(ev->block_id) );
  if( FD_LIKELY( bank->block_completed_nanos ) ) fd_memcpy( ev->bank_hash, bank->f.bank_hash.uc, sizeof(ev->bank_hash) );

  ev->first_fec_set_received_time      = bank->is_leader ? 0UL : (ulong)bank->first_fec_set_received_nanos;
  ev->preparation_begin_time           = (ulong)bank->preparation_begin_nanos;
  ev->first_transaction_scheduled_time = (ulong)bank->first_transaction_scheduled_nanos;
  ev->last_transaction_finished_time   = (ulong)bank->last_transaction_finished_nanos;
  ev->block_completed_time             = (ulong)bank->block_completed_nanos;
  ev->parent_block_completed_time      = parent_bank ? (ulong)parent_bank->block_completed_nanos : 0UL;

  if( FD_UNLIKELY( bank->cost_tracker_pool_idx!=ULONG_MAX ) ) {
    fd_cost_tracker_t const * ct = fd_bank_cost_tracker_query( bank );
    ev->cost_tracker_block_cost                   = ct->block_cost;
    ev->cost_tracker_allocated_accounts_data_size = ct->allocated_accounts_data_size;
    ev->cost_tracker_block_cost_limit             = ct->block_cost_limit;
    ev->cost_tracker_account_cost_limit           = ct->account_cost_limit;
  }

  ev->bank_idx = bank->idx;
  if( FD_LIKELY( prepared ) ) {
    ev->txncache_fork_id            = bank->txncache_fork_id.val;
    ev->progcache_fork_id           = bank->progcache_fork_id;
    ev->accdb_fork_id               = bank->accdb_fork_id.val;
    ev->vote_stakes_fork_id         = bank->vote_stakes_fork_id;
    ev->collector_overrides_fork_id = bank->collector_overrides_fork_id;
    ev->stake_rewards_fork_id       = bank->stake_rewards_fork_id;
    ev->epoch_credits_fork_id       = bank->epoch_credits_fork_id;
    ev->stake_delegations_fork_id   = bank->stake_delegations_fork_id;
    ev->cost_tracker_pool_idx       = bank->cost_tracker_pool_idx;
  }

  block_completed_event_fill_reception( ctx, ev, &ctx->block_id_arr[ bank->idx ].latest_mr, slot );
}

static int
pack_end_reason_to_event( int reason ) {
  switch( reason ) {
    case FD_PACK_END_SLOT_REASON_TIME:       return FD_EVENT_BLOCK_COMPLETED_PACK_END_REASON_TIME;
    case FD_PACK_END_SLOT_REASON_MICROBLOCK: return FD_EVENT_BLOCK_COMPLETED_PACK_END_REASON_MICROBLOCK_LIMIT;
    case FD_PACK_END_SLOT_REASON_ABANDONED:  return FD_EVENT_BLOCK_COMPLETED_PACK_END_REASON_ABANDONED;
    default:                                 FD_LOG_CRIT(( "unmapped pack end reason %d", reason ));
  }
}

static void
block_completed_event_fill_leader( fd_replay_tile_t *           ctx,
                                   fd_event_block_completed_t * ev,
                                   fd_bank_t *                  bank ) {
  FD_TEST( ctx->leader_stats.slot==bank->f.slot );

  ev->became_leader_time     = (ulong)ctx->leader_stats.became_leader_nanos;
  ev->leader_slot_start_time = (ulong)ctx->leader_stats.leader_slot_start_nanos;

  ev->first_fec_set_received_time = (ulong)ctx->leader_stats.first_fec_returned_nanos;
  ev->recovered_shred_count = 0UL;

  ev->microblock_count = ctx->leader_stats.microblock_count;
  ev->pack_block_cost  = ctx->leader_stats.pack_block_cost;
  ev->pack_vote_cost   = ctx->leader_stats.pack_vote_cost;
  ev->pack_data_bytes  = ctx->leader_stats.pack_data_bytes;
  ev->bundle_txn_count = ctx->leader_stats.bundle_txn_count;
  ev->pack_start_time  = (ulong)ctx->leader_stats.pack_start_nanos;
  ev->pack_end_time    = (ulong)ctx->leader_stats.pack_end_nanos;
  ev->pack_end_reason  = pack_end_reason_to_event( ctx->leader_stats.pack_end_reason );
}

static void
block_completed_event_fill_leader_txn_timing( fd_replay_tile_t *           ctx,
                                              fd_event_block_completed_t * ev,
                                              fd_bank_t *                  bank ) {
  ulong tidx = ctx->leader_stats.timing_table_idx;
  if( FD_UNLIKELY( !ctx->leader_txn_timing || tidx>=FD_LEADER_TXN_TIMING_TABLE_CNT ) ) return;
  fd_leader_txn_timing_table_t const * table = &ctx->leader_txn_timing[ tidx ];
  if( FD_UNLIKELY( table->slot!=bank->f.slot ) ) return;

  ulong cnt = fd_ulong_min( table->cnt, FD_EVENT_BLOCK_COMPLETED_TXN_TIMING_MAX );
  long  first_dispatch = LONG_MAX;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_leader_txn_timing_rec_t const * rec = &table->rec[ i ];
    first_dispatch = fd_long_min( first_dispatch, rec->dispatched_ticks );
    ev->txn_timing[ i ] = (fd_event_block_completed_txn_timing_t){
      .received_time   = (ulong)rec->received_ns,
      .dispatched_time = rec->dispatched_ticks==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, rec->dispatched_ticks ),
      .replayed_time   = rec->replayed_ticks  ==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, rec->replayed_ticks   ),
      .poh_mixed_time  = rec->poh_mixed_ticks ==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, rec->poh_mixed_ticks  ),
    };
  }
  ev->txn_timing_cnt = cnt;

  ev->first_transaction_scheduled_time = first_dispatch==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, first_dispatch );
}

static void
report_block_completed( fd_replay_tile_t *                 ctx,
                        fd_bank_t *                        bank,
                        int                                is_leader,
                        fd_replay_slot_completed_t const * slot_info ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  fd_event_block_completed_t * ev = ctx->block_completed_event;
  memset( ev, 0, FD_EVENT_BLOCK_COMPLETED_PREFIX_SZ );

  block_completed_event_fill_bank( ctx, ev, bank );

  if( FD_LIKELY( slot_info->cost_tracker.block_cost_limit!=ULONG_MAX ) ) {
    ev->cost_tracker_block_cost                   = slot_info->cost_tracker.block_cost;
    ev->cost_tracker_allocated_accounts_data_size = slot_info->cost_tracker.allocated_accounts_data_size;
    ev->cost_tracker_block_cost_limit             = slot_info->cost_tracker.block_cost_limit;
    ev->cost_tracker_account_cost_limit           = slot_info->cost_tracker.account_cost_limit;
  }
  ev->cost_tracker_pool_idx = slot_info->cost_tracker.pool_idx;

  ev->root_slot    = ctx->consensus_root_slot;
  ev->storage_slot = ctx->published_root_slot;
  ev->caught_up            = !!ctx->caught_up;
  ev->turbine_slot         = ctx->catch_up_max_fec_slot==ULONG_MAX ? 0UL : ctx->catch_up_max_fec_slot;
  ev->fork_width           = ctx->banks->curr_fork_width;
  ev->snapshot_in_progress = !!ctx->snapmk.active;
  ev->live_bank_count      = fd_banks_pool_used_cnt( ctx->banks );
  ev->is_leader    = is_leader;

  ev->pack_end_reason = FD_EVENT_BLOCK_COMPLETED_PACK_END_REASON_NOT_LEADER;
  if( FD_UNLIKELY( is_leader ) ) block_completed_event_fill_leader( ctx, ev, bank );

  ev->dead             = 0;
  ev->dead_reason      = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD;
  ev->dead_time        = 0UL;
  ev->abandoned        = 0;
  ev->abandoned_reason = FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED;
  ev->abandoned_time   = 0UL;

  if( FD_UNLIKELY( is_leader ) ) {
    block_completed_event_fill_leader_txn_timing( ctx, ev, bank );
  } else {
    ulong tslot = ctx->timing_slot_of_bank[ bank->idx ];
    if( FD_LIKELY( tslot!=fd_timing_slot_pool_idx_null( ctx->timing_slot_pool ) ) ) {
      fd_replay_txn_timing_slot_t const * slot = fd_timing_slot_pool_ele( ctx->timing_slot_pool, tslot );
      ulong cnt = fd_ulong_min( slot->cnt, FD_EVENT_BLOCK_COMPLETED_TXN_TIMING_MAX );
      for( ulong i=0UL; i<cnt; i++ ) {
        fd_replay_txn_timing_t const * t = &slot->rec[ i ];
        ev->txn_timing[ i ] = (fd_event_block_completed_txn_timing_t){
          .received_time             = (ulong)t->received_ns, /* already wallclock */
          .parsed_time               = t->parsed_ticks        ==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, t->parsed_ticks         ),
          .sigverify_dispatched_time = t->sigverify_disp_ticks==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, t->sigverify_disp_ticks ),
          .sigverify_done_time       = t->sigverify_done_ticks==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, t->sigverify_done_ticks ),
          .dispatched_time           = t->exec_disp_ticks     ==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, t->exec_disp_ticks      ),
          .replayed_time             = t->exec_done_ticks     ==LONG_MAX ? 0UL : (ulong)fd_clock_epoch_y( ctx->clock->epoch, t->exec_done_ticks      ),
        };
      }
      ev->txn_timing_cnt = cnt;
    }
  }

  if( FD_UNLIKELY( !ev->first_transaction_scheduled_time ) ) ev->first_transaction_scheduled_time = ev->last_transaction_finished_time;

  fd_event_report_block_completed( ev );
}

static void
publish_slot_completed( fd_replay_tile_t *  ctx,
                        fd_stem_context_t * stem,
                        fd_bank_t *         bank,
                        int                 is_initial,
                        int                 is_leader,
                        ulong               execution_fees_pre_settle,
                        ulong               priority_fees_pre_settle ) {

  ulong slot = bank->f.slot;

  if( FD_UNLIKELY( ctx->alpenglow ) ) ctx->reset_slot = fd_ulong_max( ctx->reset_slot, slot );

  if( FD_UNLIKELY( is_initial ) ) bank->block_completed_nanos = fd_clock_tile_now( ctx->clock );

  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ bank->idx ];

  /* HACKY: hacky way of checking if we should send a null parent block
     id */
  fd_hash_t block_id        = ctx->alpenglow ? block_id_ele->dmr : block_id_ele->latest_mr;
  fd_hash_t parent_block_id = {0};
  if( FD_LIKELY( !is_initial ) ) {
    fd_block_id_ele_t const * parent_ele = &ctx->block_id_arr[ bank->parent_idx ];
    parent_block_id = ctx->alpenglow ? parent_ele->dmr : parent_ele->latest_mr;
  }

  fd_hash_t const * bank_hash  = &bank->f.bank_hash;
  fd_hash_t const * block_hash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( block_hash );

  if( FD_LIKELY( !is_initial ) ) fd_txncache_finalize_fork( ctx->txncache, bank->txncache_fork_id, 0UL, block_hash->uc );

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong slot_idx;
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, &slot_idx );

  ctx->metrics.slots_total++;
  ctx->metrics.transactions_total = bank->f.parent_txn_count + bank->f.txn_count;

  /* Caught up once replay completes a slot within a few slots of the
     cluster tip.  Require the tip to have advanced a few times first so
     a brief view of the tip right after boot does not count. */
  if( FD_UNLIKELY( !ctx->caught_up && !is_initial &&
                   ctx->catch_up_tip_advance_cnt>=12UL &&
                   ctx->catch_up_max_fec_slot<slot+3UL ) ) {
    ctx->caught_up = 1;
    double boot_secs = (double)(fd_log_wallclock()-ctx->boot_timestamp_nanos)/1e9;
    FD_LOG_NOTICE(( "caught up to cluster at slot %s%lu%s %s(%.1f seconds since boot)%s",
                    fd_log_style_bold(), slot, fd_log_style_normal(),
                    fd_log_style_dim(), boot_secs, fd_log_style_normal() ));
  }

  fd_replay_slot_completed_t * slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  slot_info->slot                  = slot;
  slot_info->root_slot             = ctx->consensus_root_slot;
  slot_info->storage_slot          = ctx->published_root_slot;
  slot_info->epoch                 = epoch;
  slot_info->slot_in_epoch         = slot_idx;
  slot_info->slots_per_epoch       = fd_epoch_slot_cnt( epoch_schedule, epoch );
  slot_info->block_height          = bank->f.block_height;
  slot_info->parent_slot           = bank->f.parent_slot;
  slot_info->block_id              = block_id;
  slot_info->parent_block_id       = parent_block_id;
  slot_info->bank_hash             = *bank_hash;
  slot_info->block_hash            = *block_hash;
  slot_info->transaction_count     = bank->f.parent_txn_count + bank->f.txn_count;

  fd_inflation_t inflation = bank->f.inflation;
  slot_info->inflation.foundation      = inflation.foundation;
  slot_info->inflation.foundation_term = inflation.foundation_term;
  slot_info->inflation.terminal        = inflation.terminal;
  slot_info->inflation.initial         = inflation.initial;
  slot_info->inflation.taper           = inflation.taper;

  fd_rent_t rent = bank->f.rent;
  slot_info->rent.burn_percent            = rent.burn_percent;
  slot_info->rent.lamports_per_uint8_year = rent.lamports_per_uint8_year;
  slot_info->rent.exemption_threshold     = rent.exemption_threshold;

  slot_info->first_fec_set_received_nanos      = bank->first_fec_set_received_nanos;
  slot_info->preparation_begin_nanos           = bank->preparation_begin_nanos;
  slot_info->first_transaction_scheduled_nanos = bank->first_transaction_scheduled_nanos;
  slot_info->last_transaction_finished_nanos   = bank->last_transaction_finished_nanos;
  slot_info->completion_time_nanos             = fd_clock_tile_now( ctx->clock );
  if( !slot_info->first_transaction_scheduled_nanos ) { /* edge case: empty slot */
    slot_info->first_transaction_scheduled_nanos = slot_info->last_transaction_finished_nanos;
  }

  /* refcnt should be incremented by 1 for each consumer that uses
     `bank_idx`.  Each consumer should decrement the bank's refcnt once
     they are done using the bank. */
  if( FD_LIKELY( !ctx->alpenglow ) ) bank->refcnt++; /* tower_tile */
  if( FD_LIKELY( ctx->rpc_enabled ) ) bank->refcnt++; /* rpc tile */
  slot_info->bank_idx = bank->idx;
  slot_info->bank_seq = bank->bank_seq;
  slot_info->accdb_fork_id = bank->accdb_fork_id;
  FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt incremented to %lu for tower, rpc", bank->idx, slot, bank->refcnt ));

  fd_bank_t * parent_bank = fd_banks_get_parent( ctx->banks, bank );
  slot_info->parent_bank_idx = parent_bank ? parent_bank->idx      : ULONG_MAX;
  slot_info->parent_bank_seq = parent_bank ? parent_bank->bank_seq : ULONG_MAX;
  if( FD_LIKELY( parent_bank ) ) {
    ulong total_txn_cnt          = bank->f.txn_count;
    ulong nonvote_txn_cnt        = bank->f.nonvote_txn_count;
    ulong failed_txn_cnt         = bank->f.failed_txn_count;
    ulong nonvote_failed_txn_cnt = bank->f.nonvote_failed_txn_count;

    slot_info->nonvote_success = nonvote_txn_cnt - nonvote_failed_txn_cnt;
    slot_info->nonvote_failed  = nonvote_failed_txn_cnt;
    slot_info->vote_failed     = failed_txn_cnt - nonvote_failed_txn_cnt;
    slot_info->vote_success    = total_txn_cnt - nonvote_txn_cnt - slot_info->vote_failed;
  } else {
    slot_info->vote_failed     = ULONG_MAX;
    slot_info->vote_success    = ULONG_MAX;
    slot_info->nonvote_success = ULONG_MAX;
    slot_info->nonvote_failed  = ULONG_MAX;
  }

  slot_info->is_leader = is_leader;
  slot_info->transaction_fee = execution_fees_pre_settle;
  slot_info->transaction_fee -= (slot_info->transaction_fee>>1); /* burn */
  slot_info->priority_fee = priority_fees_pre_settle;
  slot_info->tips = bank->f.tips;
  slot_info->shred_cnt = bank->f.shred_cnt;
  slot_info->voted = replay_reward_cert_voted( ctx, bank, &slot_info->voted_slot, &slot_info->voted_rank );

  FD_BASE58_ENCODE_32_BYTES( slot_info->block_id.uc, block_id_b58 );
  FD_BASE58_ENCODE_32_BYTES( bank->f.bank_hash.uc, bank_hash_b58 );
  FD_BASE58_ENCODE_32_BYTES( bank->f.poh.uc, poh_hash_b58 );
  FD_LOG_DEBUG(( "finished replaying slot %lu with (block id %s, bank hash %s, PoH hash %s, transactions %lu, votes %lu, shreds %lu, CUs used %lu, fees %lu) "
                 "and timings [since parent fini %ld ns, started prepare %ld ns, started dispatching transactions %ld ns, finished executing transactions %ld ns, finished block %ld ns]",
                 bank->f.slot, block_id_b58,
                 bank_hash_b58,
                 poh_hash_b58,
                 bank->f.txn_count,
                 bank->f.txn_count - bank->f.nonvote_txn_count,
                 bank->f.shred_cnt,
                 bank->f.total_compute_units_used,
                 execution_fees_pre_settle + priority_fees_pre_settle,
                 !!parent_bank ? parent_bank->block_completed_nanos - bank->first_fec_set_received_nanos : LONG_MAX,
                 bank->preparation_begin_nanos - bank->first_fec_set_received_nanos,
                 bank->first_transaction_scheduled_nanos - bank->preparation_begin_nanos,
                 bank->last_transaction_finished_nanos - bank->first_transaction_scheduled_nanos,
                 bank->block_completed_nanos - bank->last_transaction_finished_nanos ));

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_SLOT_COMPLETED, ctx->replay_out->chunk, sizeof(fd_replay_slot_completed_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_completed_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  /* Skip the telemetry event for the initial boot block (snapshot /
     genesis): it was not replayed. */
  if( FD_LIKELY( !is_initial ) ) report_block_completed( ctx, bank, is_leader, slot_info );
  timing_slot_release( ctx, bank->idx );
}

static void
report_block_incomplete( fd_replay_tile_t * ctx,
                         ulong              slot,
                         fd_hash_t const *  block_id,
                         fd_bank_t *        bank,
                         int                dead_reason,
                         int                abandoned_reason ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  fd_event_block_completed_t * ev = ctx->block_completed_event;
  memset( ev, 0, FD_EVENT_BLOCK_COMPLETED_PREFIX_SZ );
  if( FD_LIKELY( bank ) ) {
    block_completed_event_fill_bank( ctx, ev, bank );
    ev->is_leader = !!bank->is_leader;
  } else {
    ev->slot = slot;
    if( FD_LIKELY( ctx->notified_root_bank ) ) ev->epoch = fd_slot_to_epoch( &ctx->notified_root_bank->f.epoch_schedule, slot, NULL );
    fd_memcpy( ev->block_id, block_id->uc, sizeof(ev->block_id) );
    block_completed_event_fill_reception( ctx, ev, block_id, slot );
  }
  ev->root_slot    = ctx->consensus_root_slot;
  ev->storage_slot = ctx->published_root_slot;
  ev->caught_up            = !!ctx->caught_up;
  ev->turbine_slot         = ctx->catch_up_max_fec_slot==ULONG_MAX ? 0UL : ctx->catch_up_max_fec_slot;
  ev->fork_width           = ctx->banks->curr_fork_width;
  ev->snapshot_in_progress = !!ctx->snapmk.active;
  ev->live_bank_count      = fd_banks_pool_used_cnt( ctx->banks );

  int  dead      = dead_reason     !=FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD;
  int  abandoned = abandoned_reason!=FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED;
  long now       = fd_clock_tile_now( ctx->clock );

  ev->dead             = dead;
  ev->dead_reason      = dead_reason;
  ev->dead_time        = dead      ? (ulong)now : 0UL;
  ev->abandoned        = abandoned;
  ev->abandoned_reason = abandoned_reason;
  ev->abandoned_time   = abandoned ? (ulong)now : 0UL;

  ev->pack_end_reason = FD_EVENT_BLOCK_COMPLETED_PACK_END_REASON_NOT_LEADER;
  if( FD_UNLIKELY( bank && bank->is_leader ) ) {
    block_completed_event_fill_leader( ctx, ev, bank );
    block_completed_event_fill_leader_txn_timing( ctx, ev, bank );
  }

  fd_event_report_block_completed( ev );
}

static void
publish_slot_dead( fd_replay_tile_t *  ctx,
                   fd_stem_context_t * stem,
                   ulong               slot,
                   fd_hash_t const *   block_id ) {
  fd_replay_slot_dead_t * slot_dead = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  slot_dead->slot                   = slot;
  slot_dead->block_id               = *block_id;
  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_SLOT_DEAD, ctx->replay_out->chunk, sizeof(fd_replay_slot_dead_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_dead_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
publish_txn_executed( fd_replay_tile_t *  ctx,
                      fd_stem_context_t * stem,
                      ulong               bank_idx,
                      ulong               txn_idx ) {
  fd_sched_txn_info_t * txn_info = fd_sched_get_txn_info( ctx->sched, txn_idx );

  FD_TEST( txn_info->index_in_slot<FD_MAX_TXN_PER_SLOT );
  ulong tslot = ctx->timing_slot_of_bank[ bank_idx ];
  if( FD_LIKELY( tslot!=fd_timing_slot_pool_idx_null( ctx->timing_slot_pool ) ) ) {
    fd_replay_txn_timing_slot_t * slot = fd_timing_slot_pool_ele( ctx->timing_slot_pool, tslot );
    fd_replay_txn_timing_t * t = &slot->rec[ txn_info->index_in_slot ];
    t->received_ns          = txn_info->received_ns;
    t->parsed_ticks         = txn_info->tick_parsed;
    t->sigverify_disp_ticks = txn_info->tick_sigverify_disp;
    t->sigverify_done_ticks = txn_info->tick_sigverify_done;
    t->exec_disp_ticks      = txn_info->tick_exec_disp;
    t->exec_done_ticks      = txn_info->tick_exec_done;
    slot->cnt = fd_ulong_max( slot->cnt, txn_info->index_in_slot+1UL );
  }

  fd_replay_txn_executed_t * txn_executed = fd_type_pun( fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk ) );
  *txn_executed->txn = *fd_sched_get_txn( ctx->sched, txn_idx );
  txn_executed->txn_err = txn_info->txn_err;
  txn_executed->is_committable = !!(txn_info->flags&FD_SCHED_TXN_IS_COMMITTABLE);
  txn_executed->is_fees_only = !!(txn_info->flags&FD_SCHED_TXN_IS_FEES_ONLY);
  txn_executed->is_noop = !!(txn_info->flags&FD_SCHED_TXN_IS_NOOP);
  txn_executed->is_simple_vote = txn_info->is_simple_vote;
  txn_executed->tick_parsed = txn_info->tick_parsed;
  txn_executed->tick_sigverify_disp = txn_info->tick_sigverify_disp;
  txn_executed->tick_sigverify_done = txn_info->tick_sigverify_done;
  txn_executed->tick_exec_disp = txn_info->tick_exec_disp;
  txn_executed->tick_exec_done = txn_info->tick_exec_done;

  txn_executed->tick_load_start = txn_info->tick_load_start;
  txn_executed->tick_check_start = txn_info->tick_check_start;
  txn_executed->tick_exec_start = txn_info->tick_exec_start;
  txn_executed->tick_commit_start = txn_info->tick_commit_start;
  txn_executed->tick_commit_end = txn_info->tick_commit_end;

  txn_executed->slot = txn_info->slot;
  txn_executed->bank_seq = txn_info->bank_seq;
  txn_executed->index_in_slot = txn_info->index_in_slot;
  txn_executed->exec_tile_idx = txn_info->exec_tile_idx;
  txn_executed->sigverify_exec_tile_idx = txn_info->sigverify_exec_tile_idx;
  txn_executed->compute_units_consumed = txn_info->compute_units_consumed;
  txn_executed->max_compute_units = txn_info->max_compute_units;
  txn_executed->transaction_fee = txn_info->transaction_fee;
  txn_executed->priority_fee = txn_info->priority_fee;
  txn_executed->tips = txn_info->tips;
  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_TXN_EXECUTED, ctx->replay_out->chunk, sizeof(*txn_executed), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(*txn_executed), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
mark_bank_dead( fd_replay_tile_t *  ctx,
                fd_stem_context_t * stem,
                ulong               bank_idx,
                int                 dead_reason,
                int                 abandoned_reason );

static void
replay_block_finalize( fd_replay_tile_t *  ctx,
                       fd_stem_context_t * stem,
                       fd_bank_t *         bank ) {
  bank->last_transaction_finished_nanos = fd_clock_tile_now( ctx->clock );

  /* Set poh hash in bank. */
  fd_hash_t * poh = fd_sched_get_poh( ctx->sched, bank->idx );
  bank->f.poh = *poh;

  /* Set shred count in bank. */
  bank->f.shred_cnt = fd_sched_get_shred_cnt( ctx->sched, bank->idx );

  ulong execution_fees_pre_settle = bank->f.execution_fees;
  ulong priority_fees_pre_settle  = bank->f.priority_fees;

  fd_footer_certs_t certs[1];
  fd_footer_certs_t const * certs_opt = NULL;
  ulong footer_time_nanos = 0UL;
  if( FD_UNLIKELY( ctx->alpenglow ) ) {
    certs->fast_final_cert   = fd_sched_get_fast_final_cert  ( ctx->sched, bank->idx );
    certs->final_cert        = fd_sched_get_final_cert       ( ctx->sched, bank->idx );
    certs->final_notar_cert  = fd_sched_get_final_notar_cert ( ctx->sched, bank->idx );
    certs->skip_reward_cert  = fd_sched_get_skip_reward_cert ( ctx->sched, bank->idx );
    certs->notar_reward_cert = fd_sched_get_notar_reward_cert( ctx->sched, bank->idx );
    // TODO missing cert verify - inline to replay or use new verify tiles
    certs_opt        = certs;
    footer_time_nanos = fd_sched_get_footer_producer_time_nanos( ctx->sched, bank->idx );
  }

  /* Do hashing and other end-of-block processing. */
  if( FD_UNLIKELY( fd_runtime_block_execute_finalize( bank, ctx->accdb, ctx->capture_ctx, certs_opt, footer_time_nanos ) ) ) {
    mark_bank_dead( ctx, stem, bank->idx, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
    return;
  }

  if( FD_UNLIKELY( ctx->alpenglow ) ) {
    fd_hash_t const * footer_bank_hash = fd_sched_get_footer_bank_hash( ctx->sched, bank->idx );
    if( FD_UNLIKELY( memcmp( footer_bank_hash->uc, bank->f.bank_hash.uc, sizeof(fd_hash_t) ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( footer_bank_hash->uc,   footer_bank_hash_b58   );
      FD_BASE58_ENCODE_32_BYTES( bank->f.bank_hash.uc, executed_bank_hash_b58 );
      FD_LOG_WARNING(( "slot %lu: bank hash mismatch, footer declares %s but executed %s. ", bank->f.slot, footer_bank_hash_b58, executed_bank_hash_b58 ));
      mark_bank_dead( ctx, stem, bank->idx, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
      return;
    } else {
      FD_BASE58_ENCODE_32_BYTES( footer_bank_hash->uc,   footer_bank_hash_b58 );
      FD_BASE58_ENCODE_32_BYTES( bank->f.bank_hash.uc, executed_bank_hash_b58 );
      FD_LOG_INFO(( "slot %lu: bank hash matches, footer declares %s, executed %s", bank->f.slot, footer_bank_hash_b58, executed_bank_hash_b58 ));
    }
  }

  /* Copy out cost tracker fields before freezing */
  fd_replay_slot_completed_t * slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  cost_tracker_snap( bank, slot_info );

  /* fetch identity balance infrequently and after set-identity. */
  slot_info->identity_balance = ULONG_MAX;
  if( FD_UNLIKELY( ctx->identity_dirty || bank->f.slot%4096UL==0UL ) ) {
    ctx->identity_dirty = 0;
    slot_info->identity_balance = fd_accdb_lamports( ctx->accdb, bank->accdb_fork_id, ctx->identity_pubkey->uc );
  }

  /* Mark the bank as frozen. */
  fd_block_id_ele_t const * block_id_ele = &ctx->block_id_arr[ bank->idx ];
  bank->f.block_id = ctx->alpenglow ? block_id_ele->dmr : block_id_ele->latest_mr;
  fd_banks_mark_bank_frozen( bank );
  bank->block_completed_nanos = fd_clock_tile_now( ctx->clock );

  /**********************************************************************/
  /* Bank hash comparison, and halt if there's a mismatch after replay  */
  /**********************************************************************/

  /* Must be last so we can measure completion time correctly, even
     though we could technically do this before the hash cmp and vote
     tower stuff. */
  publish_slot_completed( ctx, stem, bank, 0, 0 /* is_leader */, execution_fees_pre_settle, priority_fees_pre_settle );

  /* If enabled, dump the block to a file and reset the dumping
     context state */
  if( FD_UNLIKELY( ctx->dump_proto_ctx && ctx->dump_proto_ctx->dump_block_to_pb ) ) {
    fd_dump_block_to_protobuf( ctx->block_dump_ctx, ctx->banks, bank, ctx->accdb, ctx->dump_proto_ctx, ctx->runtime_stack );
    fd_block_dump_context_reset( ctx->block_dump_ctx );
  }
}

/**********************************************************************/
/* Leader bank management                                             */
/**********************************************************************/

static fd_bank_t *
prepare_leader_bank( fd_replay_tile_t * ctx,
                     fd_bank_t *        parent_bank,
                     ulong              slot,
                     long               now ) {

  /* Make sure that we are not already leader. */
  FD_TEST( ctx->leader_bank==NULL );

  ctx->leader_bank = fd_banks_new_bank( ctx->banks, parent_bank->idx, now, 1 );
  if( FD_UNLIKELY( !ctx->leader_bank ) ) {
    FD_LOG_CRIT(( "invariant violation: leader bank is NULL for slot %lu", slot ));
  }

  ctx->leader_bank = fd_banks_clone_from_parent( ctx->banks, ctx->leader_bank->idx );
  if( FD_UNLIKELY( !ctx->leader_bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for slot %lu", slot ));
  }

  ctx->leader_bank->preparation_begin_nanos = now;

  ctx->leader_bank->f.slot = slot;

  /* Clear the previous occupant of this reused bank idx from whichever
     map it is currently keyed in. */
  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ ctx->leader_bank->idx ];
  if( !ctx->alpenglow && FD_LIKELY( fd_block_id_map_ele_query( ctx->block_id_map, &block_id_ele->latest_mr, NULL, ctx->block_id_arr )==block_id_ele ) ) {
    FD_TEST( fd_block_id_map_ele_remove( ctx->block_id_map, &block_id_ele->latest_mr, NULL, ctx->block_id_arr ) );
  } else if( ctx->alpenglow && FD_LIKELY( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &block_id_ele->block_info, NULL, ctx->block_id_arr )==block_id_ele ) ) {
    FD_TEST( fd_ag_block_id_map_ele_remove( ctx->ag_block_id_map, &block_id_ele->block_info, NULL, ctx->block_id_arr ) );
  }

  block_id_ele->block_id_seen  = 0;
  block_id_ele->slot           = slot;
  block_id_ele->bank_seq       = ctx->leader_bank->bank_seq;
  block_id_ele->latest_fec_idx = 0U;

  ctx->leader_bank->txncache_fork_id     = fd_txncache_attach_child ( ctx->txncache,  parent_bank->txncache_fork_id  );
  ctx->leader_bank->progcache_fork_id    = fd_progcache_attach_child( ctx->progcache, parent_bank->progcache_fork_id );
  ctx->leader_bank->accdb_fork_id        = fd_accdb_attach_child    ( ctx->accdb,     parent_bank->accdb_fork_id     );
  ctx->leader_bank->parent_accdb_fork_id = parent_bank->accdb_fork_id;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( ctx->banks, ctx->leader_bank, ctx->accdb, ctx->runtime_stack, ctx->capture_ctx, &is_epoch_boundary );

  ulong max_tick_height;
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS!=fd_runtime_compute_max_tick_height( parent_bank->f.ticks_per_slot, slot, &max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, parent_bank->f.ticks_per_slot ));
  }
  ctx->leader_bank->f.max_tick_height = max_tick_height;

  /* Now that a bank has been created for the leader slot, increment the
     reference count until we are done with the leader slot. */
  ctx->leader_bank->refcnt++;

  return ctx->leader_bank;
}

static inline void
maybe_switch_identity( fd_replay_tile_t * ctx ) {

  if( FD_LIKELY( fd_keyswitch_state_query( ctx->keyswitch )!=FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) return;

  /* Switch identity */

  FD_LOG_DEBUG(( "keyswitch: switching identity" ));

  memcpy( ctx->identity_pubkey, ctx->keyswitch->bytes, 32UL );
  ctx->identity_dirty = 1;

  fd_node_info_write_begin( ctx->node_info );
  ctx->node_info->info.identity = *ctx->identity_pubkey;
  fd_node_info_write_end  ( ctx->node_info );

  fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );

  /* The next leader slot will be incorrect now that the identity has
     switched.  The next leader slot normally gets updated based on the
     reset slot returned by tower. */
  ulong min_leader_slot = fd_ulong_max( ctx->reset_slot+1UL, fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot+1UL ) );
  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, min_leader_slot, ctx->identity_pubkey );
  ctx->next_leader_tickcount = LONG_MAX;
  if( FD_LIKELY( ctx->next_leader_slot != ULONG_MAX && ctx->is_booted ) ) {
    /* If we are booted, we have a reset_bank, so use it to set
       next_leader_tickcount. If we are not booted, then we don't need
       to set next_leader_tickcount as it will be set when we boot. */
    fd_block_id_ele_t * block_id_ele = fd_block_id_ele_query( ctx, ctx->alpenglow ? &ctx->reset_dmr : &ctx->reset_cmr, ctx->reset_slot );
    if( FD_LIKELY( block_id_ele ) ) {
      fd_bank_t * reset_bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
      if( FD_LIKELY( reset_bank && reset_bank->bank_seq==block_id_ele->bank_seq && reset_bank->state!=FD_BANK_STATE_PRUNABLE ) ) {
        double slot_duration_ticks = (double)reset_bank->f.slot_params.ns_per_slot_adjusted*ctx->tick_per_ns;
        ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*slot_duration_ticks) + fd_tickcount();
      }
    }
  }

  ctx->identity_vote_rooted = 0;
  ctx->identity_idx++;
  fd_vote_tracker_reset( ctx->vote_tracker );
}

static void
publish_leader_footer( fd_replay_tile_t *  ctx,
                       fd_stem_context_t * stem,
                       fd_bank_t const *   bank,
                       ulong               producer_time_nanos ) {
  fd_replay_leader_footer_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  msg->slot = bank->f.slot;

  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant                          = FOOTER;
  marker->footer.bank_hash                 = bank->f.bank_hash;
  marker->footer.block_producer_time_nanos = producer_time_nanos;

  /* TODO add the certs */

  FD_TEST( !fd_block_marker_ser( marker, msg->footer, sizeof(msg->footer), &msg->sz ) );

  ulong sz = sizeof(fd_replay_leader_footer_t);
  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_LEADER_FOOTER, ctx->replay_out->chunk, sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sz, ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
publish_reset( fd_replay_tile_t *  ctx,
               fd_stem_context_t * stem,
               fd_bank_t *         bank ) {
  if( FD_UNLIKELY( ctx->replay_out->idx==ULONG_MAX ) ) return;

  fd_hash_t const * block_hash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( block_hash );

  fd_poh_reset_t * reset = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );

  reset->bank_idx         = bank->idx;
  reset->timestamp        = fd_clock_tile_now( ctx->clock );
  reset->completed_slot   = bank->f.slot;
  reset->hashcnt_per_tick = bank->f.slot_params.hashes_per_tick;
  reset->ticks_per_slot   = bank->f.ticks_per_slot;
  reset->tick_duration_ns = bank->f.slot_params.ns_per_slot_adjusted/reset->ticks_per_slot;
  fd_memcpy( reset->completed_cmr,       ctx->reset_cmr.uc, sizeof(fd_hash_t) );
  fd_memcpy( reset->completed_dmr,       ctx->reset_dmr.uc, sizeof(fd_hash_t) );
  fd_memcpy( reset->completed_blockhash, block_hash->uc,    sizeof(fd_hash_t) );

  ulong ticks_per_slot = bank->f.ticks_per_slot;
  if( FD_UNLIKELY( reset->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    reset->max_microblocks_in_slot = ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    reset->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ticks_per_slot*(reset->hashcnt_per_tick-1UL) );
  }
  reset->next_leader_slot = ctx->next_leader_slot;
  reset->wfs_paused       = !ctx->wfs_complete;

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_RESET, ctx->replay_out->chunk, sizeof(fd_poh_reset_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_reset_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
try_become_leader_ag( fd_replay_tile_t *        ctx,
                      fd_stem_context_t *       stem,
                      fd_votor_leader_t const * leader ) {

  ulong             leader_slot     =  leader->start_slot;
  ulong             parent_slot     =  leader->parent_slot;
  fd_hash_t const * parent_block_id = &leader->parent_block_id;

  FD_TEST( leader_slot>parent_slot );
  FD_TEST( ctx->highwater_leader_slot==ULONG_MAX || leader_slot>ctx->highwater_leader_slot );

  if( FD_UNLIKELY( ctx->is_leader ) ) {
    FD_LOG_WARNING(( "ignoring leader trigger from votor for slot %lu because slot %lu is still in progress", leader_slot, ctx->highwater_leader_slot ));
    return;
  }

  if( FD_UNLIKELY( ctx->replay_out->idx==ULONG_MAX || !ctx->wfs_complete ) ) return;
  if( FD_UNLIKELY( ctx->halt_leader || !ctx->supports_leader ) ) return;
  if( FD_UNLIKELY( !fd_banks_can_start_bank( ctx->banks ) ) ) {
    FD_LOG_WARNING(( "ignoring leader trigger from votor for slot %lu because no bank can be started", leader_slot ));
    return;
  }

  fd_block_id_ele_t * block_id_ele = fd_block_id_ele_query( ctx, parent_block_id, parent_slot );
  if( FD_UNLIKELY( !block_id_ele ) ) {
    FD_LOG_WARNING(( "ignoring leader trigger from votor because parent block has been evicted (slot=%lu)", parent_slot ));
    return;
  }
  fd_bank_t * reset_bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
  if( FD_UNLIKELY( !reset_bank || reset_bank->bank_seq!=block_id_ele->bank_seq || reset_bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_LOG_WARNING(( "ignoring leader trigger from votor because parent bank has been evicted (slot=%lu)", parent_slot ));
    return;
  }
  if( FD_UNLIKELY( reset_bank->state!=FD_BANK_STATE_FROZEN ) ) {
    FD_LOG_WARNING(( "ignoring leader trigger from votor because parent bank is not frozen (slot=%lu)", parent_slot ));
    return;
  }
  FD_TEST( reset_bank->f.slot==parent_slot );

  ctx->reset_cmr             = block_id_ele->latest_mr;
  ctx->reset_dmr             = *parent_block_id;
  ctx->reset_slot            = parent_slot;
  ctx->reset_timestamp_nanos = fd_clock_tile_now( ctx->clock );

  long now = fd_tickcount();
  ctx->next_leader_slot      = leader_slot;
  ctx->next_leader_tickcount = now;

  publish_reset( ctx, stem, reset_bank );

  long now_nanos = fd_clock_epoch_y( ctx->clock->epoch, now );

  ctx->is_leader = 1;
  ctx->recv_poh  = 0;

  memset( &ctx->leader_stats, 0, sizeof(ctx->leader_stats) );
  ctx->leader_stats.slot                = ctx->next_leader_slot;
  ctx->leader_stats.timing_table_idx    = ULONG_MAX;
  ctx->leader_stats.became_leader_nanos = now_nanos;
  ctx->leader_stats.leader_slot_start_nanos = fd_clock_epoch_y( ctx->clock->epoch, ctx->next_leader_tickcount );

  FD_TEST( ctx->highwater_leader_slot==ULONG_MAX || ctx->highwater_leader_slot<ctx->next_leader_slot );
  ctx->highwater_leader_slot = ctx->next_leader_slot;

  FD_LOG_INFO(( "becoming leader for slot %lu, parent slot is %lu", ctx->next_leader_slot, ctx->reset_slot ));

  fd_bank_t * bank = prepare_leader_bank( ctx, reset_bank, ctx->next_leader_slot, now_nanos );

  fd_bundle_crank_tip_payment_config_t config[1] = { 0 };
  fd_pubkey_t tip_receiver_owner = {0};

  if( FD_UNLIKELY( ctx->bundle.enabled ) ) {
    fd_acct_addr_t tip_payment_config[1];
    fd_acct_addr_t tip_receiver[1];
    fd_bundle_crank_get_addresses( ctx->bundle.gen, bank->f.epoch, tip_payment_config, tip_receiver );

    fd_acc_t tip_config_acc = fd_accdb_read_one( ctx->accdb, bank->accdb_fork_id, tip_payment_config->b );
    if( FD_UNLIKELY( !tip_config_acc.lamports ) ) {
      FD_BASE58_ENCODE_32_BYTES( tip_payment_config->b, tip_config_acc_b58 );
      FD_LOG_WARNING(( "tip payment config account %s does not exist", tip_config_acc_b58 ));
      fd_accdb_unread_one( ctx->accdb, &tip_config_acc );
    } else if( FD_UNLIKELY( tip_config_acc.data_len<sizeof(fd_bundle_crank_tip_payment_config_t) ) ) {
      FD_LOG_HEXDUMP_WARNING(( "invalid tip payment config account data", tip_config_acc.data, tip_config_acc.data_len ));
      fd_accdb_unread_one( ctx->accdb, &tip_config_acc );
    } else {
      memcpy( config, tip_config_acc.data, sizeof(fd_bundle_crank_tip_payment_config_t) );
      fd_accdb_unread_one( ctx->accdb, &tip_config_acc );
    }

    /* It is possible that the tip receiver account does not exist yet
       if it is the first time in an epoch. */
    fd_acc_t tip_receiver_acc = fd_accdb_read_one( ctx->accdb, bank->accdb_fork_id, tip_receiver->b );
    if( FD_LIKELY( tip_receiver_acc.lamports ) ) {
      fd_memcpy( tip_receiver_owner.uc, tip_receiver_acc.owner, 32UL );
    }
    fd_accdb_unread_one( ctx->accdb, &tip_receiver_acc );
  }


  fd_became_leader_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  msg->slot                = ctx->next_leader_slot;
  msg->slot_start_ns       = now_nanos;
  msg->slot_end_ns         = now_nanos+(long)bank->f.slot_params.ns_per_slot_adjusted;
  msg->bank                = NULL;
  msg->bank_idx            = bank->idx;
  msg->bank_seq            = bank->bank_seq;
  msg->ticks_per_slot      = bank->f.ticks_per_slot;
  msg->hashcnt_per_tick    = bank->f.slot_params.hashes_per_tick;
  msg->tick_duration_ns    = bank->f.slot_params.ns_per_slot_adjusted/msg->ticks_per_slot;
  msg->bundle->config[0]   = config[0];
  memcpy( msg->bundle->last_blockhash,     bank->f.poh.hash,      sizeof(fd_hash_t)   );
  memcpy( msg->bundle->tip_receiver_owner, tip_receiver_owner.uc, sizeof(fd_pubkey_t) );

  if( FD_UNLIKELY( msg->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    msg->max_microblocks_in_slot = msg->ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    msg->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, msg->ticks_per_slot*(msg->hashcnt_per_tick-1UL) );
  }

  msg->total_skipped_ticks = 0UL; /* even when slots are skipped, ticks increment by exactly one for every block */
  msg->epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, ctx->next_leader_slot, NULL );

  fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_query( bank );

  msg->limits.slot_max_cost                     = ctx->larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : cost_tracker->block_cost_limit;
  msg->limits.slot_max_vote_cost                = FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND;
  msg->limits.slot_max_write_cost_per_acct      = cost_tracker->account_cost_limit;
  msg->limits.slot_max_allocated_data_per_block = cost_tracker->data_size_limit;
  msg->limits.slot_max_data_shreds              = bank->f.slot_params.max_shred_idx;

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_BECAME_LEADER, ctx->replay_out->chunk, sizeof(fd_became_leader_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_became_leader_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  ctx->next_leader_slot      = ULONG_MAX;
  ctx->next_leader_tickcount = LONG_MAX;
}

static int
try_fini_leader( fd_replay_tile_t *  ctx,
                 fd_stem_context_t * stem ) {

  /* If we are leader, we can only unbecome the leader iff we have
     received the poh hash from the poh tile and block id from reasm.
     The block id entry is claimed for the leader slot in
     prepare_leader_bank, so a slot mismatch here means the claim
     discipline broke. */

  if( FD_LIKELY( !ctx->is_leader ) ) return 0;
  if( !ctx->recv_poh ) return 0;
  if( !ctx->block_id_arr[ ctx->leader_bank->idx ].block_id_seen ) return 0;
  FD_TEST( ctx->block_id_arr[ ctx->leader_bank->idx ].slot==ctx->leader_bank->f.slot );

  ulong curr_slot = ctx->leader_bank->f.slot;

  ulong execution_fees_pre_settle;
  ulong priority_fees_pre_settle;

  if( FD_UNLIKELY( ctx->alpenglow ) ) {

    /* Already finalized above, when the footer was published. */

    execution_fees_pre_settle = ctx->leader_execution_fees;
    priority_fees_pre_settle  = ctx->leader_priority_fees;

  } else {

    ctx->leader_bank->last_transaction_finished_nanos = fd_clock_tile_now( ctx->clock );

    fd_sched_block_add_done( ctx->sched, ctx->leader_bank->idx, ctx->leader_bank->parent_idx, curr_slot );

    execution_fees_pre_settle = ctx->leader_bank->f.execution_fees;
    priority_fees_pre_settle  = ctx->leader_bank->f.priority_fees;

    fd_runtime_block_execute_finalize( ctx->leader_bank, ctx->accdb, ctx->capture_ctx, NULL, 0UL );
  }

  fd_replay_slot_completed_t * slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  cost_tracker_snap( ctx->leader_bank, slot_info );
  slot_info->identity_balance = ULONG_MAX;
  if( FD_UNLIKELY( ctx->identity_dirty || curr_slot%4096UL==0UL ) ) {
    ctx->identity_dirty         = 0;
    slot_info->identity_balance = fd_accdb_lamports( ctx->accdb, ctx->leader_bank->accdb_fork_id, ctx->identity_pubkey->uc );
  }

  ctx->leader_bank->f.block_id = ctx->alpenglow ? ctx->block_id_arr[ ctx->leader_bank->idx ].dmr : ctx->block_id_arr[ ctx->leader_bank->idx ].latest_mr;
  fd_banks_mark_bank_frozen( ctx->leader_bank );
  ctx->leader_bank->block_completed_nanos = fd_clock_tile_now( ctx->clock );

  publish_slot_completed( ctx, stem, ctx->leader_bank, 0, 1 /* is_leader */, execution_fees_pre_settle, priority_fees_pre_settle );

  /* The reference on the bank is finally no longer needed. */
  ctx->leader_bank->refcnt--;

  fd_bank_t * completed = ctx->leader_bank;

  /* We are no longer leader so we can clear the bank index we use for
     being the leader. */
  ctx->leader_bank = NULL;
  ctx->recv_poh    = 0;
  ctx->is_leader   = 0;

  maybe_switch_identity( ctx );

  if( FD_UNLIKELY( ctx->alpenglow && (curr_slot+1UL)%AG_SLOTS_PER_WINDOW ) ) {
    fd_votor_leader_t next[1] = {{
      .start_slot      = curr_slot+1UL,
      .parent_slot     = curr_slot,
      .parent_block_id = ctx->block_id_arr[ completed->idx ].dmr
    }};
    try_become_leader_ag( ctx, stem, next );
  }

  return 1;
}

static void
publish_root_advanced( fd_replay_tile_t *  ctx,
                       fd_stem_context_t * stem,
                       fd_bank_t *         bank ) {

  /* If the new consensus root is in the next epoch from the one the
     replay tile currently holds, send the next epoch's leader schedule.
     We can't use the new root's parent slot safely here. */
  if( FD_UNLIKELY( bank->f.epoch>fd_slot_to_epoch( &bank->f.epoch_schedule, ctx->notified_root_slot, NULL ) ) ) {
    fd_runtime_update_next_leaders( bank, ctx->runtime_stack );
    publish_epoch_info( ctx, stem, bank, 1 );
  }

  if( ctx->rpc_enabled ) {
    bank->refcnt++;
    FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt incremented to %lu for rpc", bank->idx, bank->f.slot, bank->refcnt ));
  }

  /* Increment the reference count on the consensus root bank to account
     for the number of resolv tiles that are waiting on it. */
  bank->refcnt += ctx->resolv_tile_cnt;
  FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt incremented to %lu for resolv", bank->idx, bank->f.slot, bank->refcnt ));

  fd_replay_root_advanced_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  msg->bank_idx  = bank->idx;
  msg->bank_seq  = bank->bank_seq;
  msg->slot      = bank->f.slot;
  msg->bank_hash = bank->f.bank_hash;

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_ROOT_ADVANCED, ctx->replay_out->chunk, sizeof(fd_replay_root_advanced_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_root_advanced_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

/* Determine the default slot params to use for slots where no
   reduce_slot_time feature gate is in effect. This is important for
   the inflation calculations, which use the slot times for
   historical slots as input. Therefore we need the same semantics
   as Agave, even after the reduce_slot_time feature gates are
   active. */
static fd_slot_params_t
restore_default_slot_params( fd_bank_t const * bank ) {

  /* A reduction is effective if the effective ns_per_slot is less than
     the 400ms value.
     https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L332-L350 */
  int reduction_effective = fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS,
                                                   &bank->f.features,
                                                   &bank->f.epoch_schedule,
                                                   bank->f.slot ).ns_per_slot < FD_SLOT_PARAMS_400MS.ns_per_slot;

  /* In order to behave correctly in real networks, if a reduction is
     effective then we use the 400ms slot params as the default. */
  if( reduction_effective ) {
    return FD_SLOT_PARAMS_400MS;
  }

  /* If a reduction is not effective, then we can rely on the slot
     times having remained constant throughout the lifetime of the
     cluster, and can use the slot params from the manifest. Note that
     in test clusters these may differ from the 400ms values. */
  return bank->f.slot_params;
}

static void
init_after_snapshot( fd_replay_tile_t *  ctx,
                     fd_stem_context_t * stem ) {
  /* snapin seeded the root stake delegations from the account stream.
     Refresh against the completed accdb to resolve duplicate account
     versions, remove stale entries, and calculate activation state. */
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_SEQ );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: replay bank is NULL at bank index %lu", FD_REPLAY_BOOT_BANK_SEQ ));
  }

  char const * one_offs[ 16UL ];
  for( ulong i=0UL; i<ctx->enable_features_cnt; i++ ) one_offs[ i ] = ctx->enable_features[ i ];
  fd_features_enable_one_offs( &bank->f.features, one_offs, (uint)ctx->enable_features_cnt, 0UL );

  /* Set slot params based on the feature gates in the snapshot,
     and assert that these are consistent with the values from the
     manifest. These assertions match Agave:
     https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L4839-L4869 */
  fd_slot_params_t manifest_params = bank->f.slot_params;
  bank->f.slot_params_default      = restore_default_slot_params( bank );
  bank->f.slot_params              = fd_slot_params_at_slot( bank, bank->f.slot );
  FD_TEST( bank->f.slot_params.ns_per_slot    == manifest_params.ns_per_slot  );
  FD_TEST( bank->f.slot_params.slots_per_year == manifest_params.slots_per_year );
  if( FD_LIKELY( manifest_params.hashes_per_tick ) ) {
    FD_TEST( bank->f.slot_params.hashes_per_tick==manifest_params.hashes_per_tick );
  }

  fd_runtime_update_next_leaders( bank, ctx->runtime_stack );
  fd_runtime_update_leaders( bank, ctx->runtime_stack );

  /* Typically, when we cross an epoch boundary during normal
     operation, we publish the stake weights for the new epoch.  But
     since we are starting from a snapshot, we need to publish two
     epochs worth of stake weights: the previous epoch (which is
     needed for voting on the current epoch), and the current epoch
     (which is needed for voting on the next epoch). */
  publish_epoch_info( ctx, stem, bank, 0 );
  publish_epoch_info( ctx, stem, bank, 1 );

  fd_progcache_reset( ctx->progcache );
  bank->progcache_fork_id = fd_progcache_fork_id_initial();

  bank->f.warmup_cooldown_rate_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.features.reduce_stake_warmup_cooldown, NULL );
  fd_stake_delegations_t * root_delegations = fd_banks_stake_delegations_root_query( ctx->banks );
  fd_stake_history_t stake_history_[1];
  fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history_view( &bank->f.sysvar_cache, stake_history_ );
  /* Despite claims like https://github.com/solana-program/stake/pull/81
     that the stake history sysvar is contiguous, testnet has in fact
     had a gap at epoch 386. */
  if( FD_UNLIKELY( !fd_sysvar_stake_history_is_contiguous( stake_history ) ) ) {
    FD_LOG_INFO(( "stake history sysvar (covering epoch %lu to %lu over %lu entries) is not contiguous; some fast paths will be disabled", stake_history->entries[ 0 ].epoch, stake_history->entries[ stake_history->len-1UL ].epoch, stake_history->len ));
  }
  fd_stake_delegations_refresh(
      root_delegations,
      bank->f.epoch,
      stake_history, /* may be NULL */
      &bank->f.warmup_cooldown_rate_epoch,
      FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
      ctx->accdb,
      bank->accdb_fork_id );
  bank->f.total_effective_stake    = root_delegations->effective_stake;
  bank->f.total_activating_stake   = root_delegations->activating_stake;
  bank->f.total_deactivating_stake = root_delegations->deactivating_stake;

  fd_vote_stakes_refresh( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, ctx->accdb, bank->accdb_fork_id );

  /* After both snapshots have been loaded in, we can determine if we should
     start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( ctx->banks, bank, ctx->accdb, ctx->runtime_stack, ctx->capture_ctx );

  /* Signals fd_startup_gate */
  FD_MGAUGE_SET( REPLAY, RUNTIME_STATUS, 1UL );
}

static inline int
try_become_leader( fd_replay_tile_t *  ctx,
                   fd_stem_context_t * stem ) {

  if( FD_LIKELY( ctx->next_leader_slot==ULONG_MAX ||
                 ctx->is_leader ||
                 (!ctx->identity_vote_rooted && ctx->wait_for_vote_to_start_leader) ||
                 ctx->replay_out->idx==ULONG_MAX ||
                 !ctx->wfs_complete ) ) {
    return 0;
  }

  /* If we have evicted the reset bank we can't become leader it may be
     inactive or have been resused, we can't become leader.  We may miss
     our leader slot if we happen to evict our reset bank.  As soon as
     we re-replay the slot, we will be able to become leader again. */
  fd_block_id_ele_t * block_id_ele = fd_block_id_map_ele_query( ctx->block_id_map, &ctx->reset_cmr, NULL, ctx->block_id_arr );
  if( FD_UNLIKELY( !block_id_ele ) ) return 0;
  fd_bank_t * reset_bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
  if( FD_UNLIKELY( !reset_bank || reset_bank->bank_seq!=block_id_ele->bank_seq || reset_bank->state==FD_BANK_STATE_PRUNABLE ) ) return 0;

  if( FD_UNLIKELY( !fd_banks_can_start_bank( ctx->banks ) ) ) return 0;
  if( FD_UNLIKELY( ctx->halt_leader ) ) return 0;
  if( !ctx->supports_leader ) return 0;

  FD_TEST( ctx->next_leader_slot>ctx->reset_slot );
  long now = fd_tickcount();
  if( FD_LIKELY( now<ctx->next_leader_tickcount ) ) return 0;

  /* If a prior leader is still in the process of publishing their slot,
     delay ours to let them finish ... unless they are so delayed that
     we risk getting skipped by the leader following us. 3*slot duration
     is a reasonable default here, although any value within our leader
     span could be considered reasonable.  This is arbitrary and chosen
     due to intuition.

     If we are becoming leader for a slot at an epoch boundary where a
     slot time reduction is taking effect, we have a choice for the
     grace period: give the previous leader maximal time to complete
     their slot, or use a shorter grace period reflecting the new
     shorter slot duration that the next leader after us will use to
     time out our slot. We choose the latter to minimize the risk of
     our slot getting skipped: a grace period based on the new shorter
     slot duration at next_leader_slot. This only matters for epoch
     boundaries where a slot time reduction is taking effect, so either
     choice is defensible. */
  ulong ns_per_slot_adjusted = fd_slot_params_at_slot( reset_bank, ctx->next_leader_slot ).ns_per_slot_adjusted;
  double slot_duration_ticks = (double)ns_per_slot_adjusted*ctx->tick_per_ns;
  if( FD_UNLIKELY( now<ctx->next_leader_tickcount+(long)(3.0*slot_duration_ticks) ) ) {
    /* TODO: Make the max_active_descendant calculation more efficient
       by caching it in the bank structure and updating it as banks are
       created and completed. */
    ulong max_active_descendant = 0UL;
    ulong child_idx = reset_bank->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_bank_t * child_bank = fd_banks_bank_query( ctx->banks, child_idx );
      max_active_descendant = fd_ulong_max( max_active_descendant, child_bank->f.slot );
      child_idx = child_bank->sibling_idx;
    }

    /* If the max_active_descendant is >= next_leader_slot, we waited
       too long and a leader after us started publishing to try and skip
       us.  Just start our leader slot immediately, we might win ... */
    if( FD_LIKELY( max_active_descendant>=ctx->reset_slot && max_active_descendant<ctx->next_leader_slot ) ) {
      /* If one of the leaders between the reset slot and our leader
         slot is in the process of publishing (they have a descendant
         bank that is in progress of being replayed), then keep waiting.
         We probably wouldn't get a leader slot out before they
         finished.

         Unless... we are past the deadline to start our slot by more
         than 3*(slot duration), in which case we should probably start
         it to avoid getting skipped by the leader behind us. */
      return 0;
    }
  }

  /* If we haven't started replaying the prior block, but we have
     finished replaying the second to last slot of the prior
     leader (and that leader is not us), we should give the prior leader
     a little more time. */
  if( FD_UNLIKELY( ctx->next_leader_slot==ctx->reset_slot+2UL && now<ctx->next_leader_tickcount+(long)(1.0*slot_duration_ticks) ) ) {

    fd_pubkey_t const * reset_leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, ctx->reset_slot );
    if( FD_UNLIKELY( reset_leader && !fd_memeq( reset_leader, ctx->identity_pubkey, 32UL ) ) ) return 0;
  }

  long now_nanos = fd_clock_epoch_y( ctx->clock->epoch, now );

  ctx->is_leader = 1;
  ctx->recv_poh  = 0;

  memset( &ctx->leader_stats, 0, sizeof(ctx->leader_stats) );
  ctx->leader_stats.slot                = ctx->next_leader_slot;
  ctx->leader_stats.timing_table_idx    = ULONG_MAX;
  ctx->leader_stats.became_leader_nanos = now_nanos;
  ctx->leader_stats.leader_slot_start_nanos = fd_clock_epoch_y( ctx->clock->epoch, ctx->next_leader_tickcount );

  FD_TEST( ctx->highwater_leader_slot==ULONG_MAX || ctx->highwater_leader_slot<ctx->next_leader_slot );
  ctx->highwater_leader_slot = ctx->next_leader_slot;

  FD_LOG_INFO(( "becoming leader for slot %lu, parent slot is %lu", ctx->next_leader_slot, ctx->reset_slot ));

  fd_bank_t * bank = prepare_leader_bank( ctx, reset_bank, ctx->next_leader_slot, now_nanos );

  fd_bundle_crank_tip_payment_config_t config[1] = { 0 };
  fd_pubkey_t tip_receiver_owner = {0};

  if( FD_UNLIKELY( ctx->bundle.enabled ) ) {
    fd_acct_addr_t tip_payment_config[1];
    fd_acct_addr_t tip_receiver[1];
    fd_bundle_crank_get_addresses( ctx->bundle.gen, bank->f.epoch, tip_payment_config, tip_receiver );

    fd_acc_t tip_config_acc = fd_accdb_read_one( ctx->accdb, bank->accdb_fork_id, tip_payment_config->b );
    if( FD_UNLIKELY( !tip_config_acc.lamports ) ) {
      FD_BASE58_ENCODE_32_BYTES( tip_payment_config->b, tip_config_acc_b58 );
      FD_LOG_WARNING(( "tip payment config account %s does not exist", tip_config_acc_b58 ));
      fd_accdb_unread_one( ctx->accdb, &tip_config_acc );
    } else if( FD_UNLIKELY( tip_config_acc.data_len<sizeof(fd_bundle_crank_tip_payment_config_t) ) ) {
      FD_LOG_HEXDUMP_WARNING(( "invalid tip payment config account data", tip_config_acc.data, tip_config_acc.data_len ));
      fd_accdb_unread_one( ctx->accdb, &tip_config_acc );
    } else {
      memcpy( config, tip_config_acc.data, sizeof(fd_bundle_crank_tip_payment_config_t) );
      fd_accdb_unread_one( ctx->accdb, &tip_config_acc );
    }

    /* It is possible that the tip receiver account does not exist yet
       if it is the first time in an epoch. */
    fd_acc_t tip_receiver_acc = fd_accdb_read_one( ctx->accdb, bank->accdb_fork_id, tip_receiver->b );
    if( FD_LIKELY( tip_receiver_acc.lamports ) ) {
      fd_memcpy( tip_receiver_owner.uc, tip_receiver_acc.owner, 32UL );
    }
    fd_accdb_unread_one( ctx->accdb, &tip_receiver_acc );
  }


  fd_became_leader_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  msg->slot                = ctx->next_leader_slot;
  msg->slot_start_ns       = now_nanos;
  msg->slot_end_ns         = now_nanos+(long)bank->f.slot_params.ns_per_slot_adjusted;
  msg->bank                = NULL;
  msg->bank_idx            = bank->idx;
  msg->bank_seq            = bank->bank_seq;
  msg->ticks_per_slot      = bank->f.ticks_per_slot;
  msg->hashcnt_per_tick    = bank->f.slot_params.hashes_per_tick;
  msg->tick_duration_ns    = bank->f.slot_params.ns_per_slot_adjusted/msg->ticks_per_slot;
  msg->bundle->config[0]   = config[0];
  memcpy( msg->bundle->last_blockhash,     bank->f.poh.hash,      sizeof(fd_hash_t)   );
  memcpy( msg->bundle->tip_receiver_owner, tip_receiver_owner.uc, sizeof(fd_pubkey_t) );

  if( FD_UNLIKELY( msg->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    msg->max_microblocks_in_slot = msg->ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    msg->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, msg->ticks_per_slot*(msg->hashcnt_per_tick-1UL) );
  }

  msg->total_skipped_ticks = msg->ticks_per_slot*(ctx->next_leader_slot-ctx->reset_slot);
  msg->epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, ctx->next_leader_slot, NULL );

  fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_query( bank );

  msg->limits.slot_max_cost                     = ctx->larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : cost_tracker->block_cost_limit;
  msg->limits.slot_max_vote_cost                = FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND;
  msg->limits.slot_max_write_cost_per_acct      = cost_tracker->account_cost_limit;
  msg->limits.slot_max_allocated_data_per_block = cost_tracker->data_size_limit;
  msg->limits.slot_max_data_shreds              = bank->f.slot_params.max_shred_idx;

  if( FD_UNLIKELY( msg->ticks_per_slot+msg->total_skipped_ticks>USHORT_MAX ) ) {
    /* There can be at most USHORT_MAX skipped ticks, because the
       parent_offset field in the shred data is only 2 bytes wide. */
    FD_LOG_ERR(( "too many skipped ticks %lu for slot %lu, chain must halt", msg->ticks_per_slot+msg->total_skipped_ticks, ctx->next_leader_slot ));
  }

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_BECAME_LEADER, ctx->replay_out->chunk, sizeof(fd_became_leader_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_became_leader_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  ctx->next_leader_slot      = ULONG_MAX;
  ctx->next_leader_tickcount = LONG_MAX;

  return 1;
}

/* https://github.com/anza-xyz/agave/blob/v4.3/runtime/src/block_component_processor.rs#L699-L765 */

static ulong
enforce_nanosecond_clock_bounds( fd_replay_tile_t * ctx,
                                 fd_bank_t *        bank,
                                 ulong              now_nanos ) {
  fd_pubkey_t alpenclock_addr;
  fd_alpenglow_pda( "alpenclock", &alpenclock_addr );

  fd_acc_t acc = fd_accdb_read_one( ctx->accdb, bank->accdb_fork_id, alpenclock_addr.uc );
  FD_CHECK_CRIT( acc.lamports && acc.data_len>=sizeof(ulong), "alpenclock account missing" ); /* Firedancer does not support producing the FIRST alpenglow block */
  long parent_nanos = (long)FD_LOAD( ulong, acc.data );
  fd_accdb_unread_one( ctx->accdb, &acc );

  ulong elapsed = fd_slot_params_slot_range_duration_ns( bank, bank->f.parent_slot+1UL, bank->f.slot+1UL /* inclusive */ );

  long lo = fd_long_sat_add( parent_nanos, 1L );
  long hi = fd_long_sat_add( parent_nanos, (long)fd_ulong_min( fd_ulong_sat_mul( elapsed, 2UL ), (ulong)LONG_MAX ) );

  return (ulong)fd_long_max( lo, fd_long_min( hi, (long)fd_ulong_min( now_nanos, (ulong)LONG_MAX ) ) );
}

static void
process_poh_message( fd_replay_tile_t *                 ctx,
                     fd_stem_context_t *                stem,
                     fd_poh_leader_slot_ended_t const * slot_ended ) {

  FD_TEST( ctx->is_booted );
  FD_TEST( ctx->is_leader );
  FD_TEST( ctx->leader_bank!=NULL );

  FD_TEST( ctx->highwater_leader_slot>=slot_ended->slot );
  FD_TEST( ctx->next_leader_slot>ctx->highwater_leader_slot );

  if( FD_LIKELY( ctx->leader_stats.slot==slot_ended->slot ) ) {
    ctx->leader_stats.microblock_count = slot_ended->microblock_count;
    ctx->leader_stats.pack_block_cost  = slot_ended->pack_block_cost;
    ctx->leader_stats.pack_vote_cost   = slot_ended->pack_vote_cost;
    ctx->leader_stats.pack_data_bytes  = slot_ended->pack_data_bytes;
    ctx->leader_stats.bundle_txn_count = slot_ended->bundle_txn_count;
    ctx->leader_stats.pack_end_reason  = slot_ended->pack_end_reason;
    ctx->leader_stats.pack_start_nanos = slot_ended->pack_start_ns;
    ctx->leader_stats.pack_end_nanos   = slot_ended->pack_end_ns;
    ctx->leader_stats.timing_table_idx = slot_ended->timing_table_idx;
  }

  if( FD_UNLIKELY( !slot_ended->completed ) ) {
    /* The leader slot was aborted by a reset mid-production.  The
       block-complete entry was never emitted, so no slot-complete FEC
       (and thus no block id) will ever arrive. */
    ulong bank_idx = ctx->leader_bank->idx;
    ctx->leader_bank->refcnt--;
    ctx->leader_bank = NULL;
    ctx->recv_poh    = 0;
    ctx->is_leader   = 0;
    mark_bank_dead( ctx, stem, bank_idx, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_RESET );
    maybe_switch_identity( ctx );
    return;
  }

  /* Update the poh hash in the bank.  We will want to maintain a refcnt
     on the bank until we have received the block id for the block after
     it has been shredded. */

  memcpy( &ctx->leader_bank->f.poh, slot_ended->blockhash, sizeof(fd_hash_t) );

  ctx->recv_poh = 1;

  if( FD_UNLIKELY( ctx->alpenglow ) ) {
    ctx->leader_bank->last_transaction_finished_nanos = fd_clock_tile_now( ctx->clock );
    fd_sched_block_add_done( ctx->sched, ctx->leader_bank->idx, ctx->leader_bank->parent_idx, ctx->leader_bank->f.slot );

    /* cache fees before runtime zeros */

    ctx->leader_execution_fees = ctx->leader_bank->f.execution_fees;
    ctx->leader_priority_fees  = ctx->leader_bank->f.priority_fees;

    ulong producer_time_nanos = enforce_nanosecond_clock_bounds( ctx, ctx->leader_bank, (ulong)fd_clock_tile_now( ctx->clock ) );

    fd_footer_certs_t certs[1]; /* TODO */
    fd_memset( certs, 0, sizeof(fd_footer_certs_t) );
    fd_runtime_block_execute_finalize( ctx->leader_bank, ctx->accdb, ctx->capture_ctx, certs, producer_time_nanos );

    publish_leader_footer( ctx, stem, ctx->leader_bank, producer_time_nanos );
  }
}

static void
store_xinsert( fd_store_t      * store,
               fd_hash_t const * merkle_root ) {
  fd_store_pool_t pool = {
      .pool    = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_mem_gaddr ),
      .ele     = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr ),
      .ele_max = store->fec_max
  };
  fd_store_fec_t * fec = fd_store_pool_acquire( &pool );
  if( FD_UNLIKELY( !fec ) ) FD_LOG_CRIT(( "fd_store_pool_acquire failed" ));
  fec->key.merkle_root = *merkle_root;
  fec->key.part_idx    = 0;
  fec->next            = fd_store_pool_idx_null();
  fec->data_sz         = 0UL;

  FD_STORE_XLOCK_BEGIN( store ) {
    fd_store_map_ele_insert( fd_wksp_laddr_fast( fd_store_wksp( store ), store->map_gaddr ), fec, pool.ele );
  } FD_STORE_XLOCK_END;
}

static void
boot_genesis( fd_replay_tile_t *        ctx,
              fd_stem_context_t *       stem,
              fd_genesis_meta_t const * meta ) {

  /* TODO boot_genesis for Alpenglow */

  /* If we are bootstrapping, we can't wait to wait for our identity
     vote to be rooted as this creates a circular dependency. */
  ctx->identity_vote_rooted = 1;

  ctx->caught_up = 1;

  uchar const * genesis_blob = (uchar const *)( meta+1 );
  FD_TEST( meta->bootstrap && meta->has_lthash );
  FD_TEST( fd_genesis_parse( ctx->genesis, genesis_blob, meta->blob_sz ) );

  fd_bank_t * bank = fd_banks_init_bank( ctx->banks );
  FD_TEST( bank );
  bank->f.slot = 0UL;
  FD_TEST( bank->idx==FD_REPLAY_BOOT_BANK_SEQ );

  static const fd_accdb_fork_id_t accdb_root = { .val = USHORT_MAX };
  bank->accdb_fork_id = fd_accdb_attach_child( ctx->accdb, accdb_root );
  bank->parent_accdb_fork_id = bank->accdb_fork_id;

  fd_runtime_read_genesis( ctx->banks, bank, ctx->accdb, NULL, &meta->genesis_hash, &meta->lthash, ctx->genesis, genesis_blob, ctx->runtime_stack );

  bank->txncache_fork_id  = fd_txncache_attach_child ( ctx->txncache, (fd_txncache_fork_id_t){USHORT_MAX} );
  bank->progcache_fork_id = fd_progcache_attach_child( ctx->progcache, fd_progcache_fork_id_initial()     );

  fd_hash_t const * block_hash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  fd_txncache_finalize_fork( ctx->txncache, bank->txncache_fork_id, 0UL, block_hash->uc );

  /* We call this after fd_runtime_read_genesis, which sets up the
     slot_bank needed in blockstore_init. */
  init_after_snapshot( ctx, stem );

  ctx->published_root_slot = 0UL;
  fd_sched_block_add_done( ctx->sched, bank->idx, ULONG_MAX, 0UL );

  bank->f.block_height = 1UL;

  ctx->consensus_root          = ctx->initial_block_id;
  ctx->consensus_root_slot     = 0UL;
  ctx->notified_root           = ctx->initial_block_id;
  ctx->notified_root_slot      = 0UL;
  ctx->notified_root_bank      = bank;
  ctx->published_root_slot     = 0UL;
  ctx->published_root_bank_idx = 0UL;
  if( FD_UNLIKELY( ctx->snapmk.full_interval_blocks ) ) {
    ulong interval = ctx->snapmk.full_interval_blocks;
    ctx->snapmk.next_full_block_height = ((bank->f.block_height/interval)+1UL)*interval;
  }
  if( FD_UNLIKELY( ctx->snapmk.incremental_interval_blocks ) ) {
    ulong interval = ctx->snapmk.incremental_interval_blocks;
    ctx->snapmk.next_incremental_block_height = ((bank->f.block_height/interval)+1UL)*interval;
  }

  ctx->reset_slot            = 0UL;
  ctx->reset_cmr             = ctx->initial_block_id;
  ctx->reset_dmr             = ctx->initial_block_id;
  ctx->reset_timestamp_nanos = fd_clock_tile_now( ctx->clock );
  ctx->next_leader_slot      = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, ctx->identity_pubkey );
  if( FD_LIKELY( ctx->next_leader_slot != ULONG_MAX ) ) {
    double slot_duration_ticks = (double)bank->f.slot_params.ns_per_slot_adjusted*ctx->tick_per_ns;
    ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*slot_duration_ticks) + fd_tickcount();
  } else {
    ctx->next_leader_tickcount = LONG_MAX;
  }

  ctx->has_cluster_type = 1;

  ctx->is_booted = 1;
  if( FD_LIKELY( !ctx->alpenglow ) ) try_become_leader( ctx, stem );

  fd_hash_t initial_block_id = ctx->initial_block_id;
  if( ctx->reasm ) {
    fd_reasm_fec_t * fec     = fd_reasm_init( ctx->reasm, &initial_block_id, 0 /* genesis slot */ );
    fec->bank_idx            = (uint)bank->idx;
    fec->bank_seq            = bank->bank_seq;
  }
  store_xinsert( ctx->store, &initial_block_id );

  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ 0 ];
  block_id_ele->latest_mr = initial_block_id;
  block_id_ele->dmr       = initial_block_id;
  block_id_ele->slot      = 0UL;
  block_id_ele->bank_seq  = bank->bank_seq;
  bank->f.block_id        = initial_block_id;

  if( FD_UNLIKELY( !ctx->alpenglow ) ) {
    FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );
  } else {
    block_id_ele->block_info = ag_block_id( 0UL, initial_block_id.uc );
    FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, block_id_ele, ctx->block_id_arr ) );
  }

  fd_replay_slot_completed_t * slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  cost_tracker_snap( bank, slot_info );

  slot_info->identity_balance = fd_accdb_lamports( ctx->accdb, bank->accdb_fork_id, ctx->identity_pubkey->uc );

  publish_slot_completed( ctx, stem, bank, 1, 0 /* is_leader */, 0, 0 );
  publish_root_advanced( ctx, stem, bank );
  publish_reset( ctx, stem, bank );
}

static inline void
maybe_verify_cluster_type( fd_replay_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->has_cluster_type || !ctx->has_genesis_hash ) ) {
    return;
  }

  FD_BASE58_ENCODE_32_BYTES( ctx->genesis_hash->uc, hash_cstr );
  ulong cluster = fd_genesis_cluster_identify( hash_cstr );
  /* Map pyth-related clusters to unknown. */
  switch( cluster ) {
    case FD_CLUSTER_PYTHNET:
    case FD_CLUSTER_PYTHTEST:
      cluster = FD_CLUSTER_UNKNOWN;
  }

  if( FD_UNLIKELY( cluster!=ctx->cluster_type ) ) {
    FD_LOG_ERR(( "Your genesis.bin file at `%s` has a genesis hash of `%s` which means the cluster is %s "
                 "but the snapshot you loaded is for a different cluster %s. If you are trying to join the "
                 "%s cluster, you can delete the genesis.bin file and restart the node to download the correct "
                 "genesis file automatically.",
                 ctx->genesis_path,
                 hash_cstr,
                 fd_genesis_cluster_name( cluster ),
                 fd_genesis_cluster_name( ctx->cluster_type ),
                 fd_genesis_cluster_name( cluster ) ));
  }
}

static void
on_snapshot_message( fd_replay_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               in_idx,
                     ulong               chunk,
                     ulong               sig ) {
  ulong msg = fd_ssmsg_sig_message( sig );
  if( FD_LIKELY( msg==FD_SSMSG_DONE ) ) {
    /* An end of message notification indicates the snapshot is loaded.
       Replay is able to start executing from this point onwards. */
    /* TODO: replay should finish booting. Could make replay a
       state machine and set the state here accordingly. */
    ctx->is_booted = 1;

    fd_bank_t * bank = fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_SEQ );
    if( FD_UNLIKELY( !bank ) ) {
      FD_LOG_CRIT(( "invariant violation: bank is NULL for bank index %lu", FD_REPLAY_BOOT_BANK_SEQ ));
    }

    ulong snapshot_slot = bank->f.slot;

    fd_hash_t bank_hash = bank->f.bank_hash;
    if( FD_UNLIKELY( ctx->wfs_enabled && memcmp( ctx->expected_bank_hash.uc, bank_hash.uc, sizeof(fd_hash_t) ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( ctx->expected_bank_hash.uc, expected_bank_hash_cstr );
      FD_BASE58_ENCODE_32_BYTES( bank_hash.uc,                 actual_bank_hash_cstr );
      FD_LOG_ERR(( "[consensus.wait_for_supermajority_with_bank_hash] expected_bank_hash=%s does not match snapshot slot"
                   "=%lu bank_hash=%s. If you are loading a snapshot from the network, check that the slot matches the "
                   "cluster restart slot. ", expected_bank_hash_cstr, snapshot_slot, actual_bank_hash_cstr ));
    }
    if( FD_UNLIKELY( ctx->wfs_enabled ) ) {
      FD_LOG_NOTICE(( "waiting for supermajority at snapshot slot %lu", snapshot_slot ));
    }

    /* Manifest message must arrive before DONE */
    if( FD_UNLIKELY( !ctx->has_expected_genesis_timestamp ) ) {
      FD_LOG_CRIT(( "snapshot DONE received before manifest" ));
    }

    /* FIXME: This is a hack when the block id of the snapshot slot
       is not provided in the snapshot (Agave versions <4.1). A
       possible solution is to get the block id of the snapshot slot
       from repair. */
    fd_hash_t manifest_block_id = ctx->has_manifest_block_id ? ctx->manifest_block_id : ctx->initial_block_id;

    FD_TEST( fd_sysvar_cache_restore( bank, ctx->accdb ) );
    /* Agave zeroes manifest rent_params; reload from sysvar account */
    FD_TEST( fd_sysvar_rent_read( ctx->accdb, bank->accdb_fork_id, &bank->f.rent ) );

    ctx->consensus_root          = manifest_block_id;
    ctx->consensus_root_slot     = snapshot_slot;
    ctx->notified_root           = manifest_block_id;
    ctx->notified_root_slot      = snapshot_slot;
    ctx->notified_root_bank      = bank;
    ctx->published_root_slot     = ctx->consensus_root_slot;
    ctx->published_root_bank_idx = 0UL;
    if( FD_UNLIKELY( ctx->snapmk.full_interval_blocks ) ) {
      ulong interval = ctx->snapmk.full_interval_blocks;
      ctx->snapmk.next_full_block_height = ((bank->f.block_height/interval)+1UL)*interval;
    }
    if( FD_UNLIKELY( ctx->snapmk.incremental_interval_blocks ) ) {
      ulong interval = ctx->snapmk.incremental_interval_blocks;
      ctx->snapmk.next_incremental_block_height = ((bank->f.block_height/interval)+1UL)*interval;
    }

    ctx->reset_slot            = snapshot_slot;
    ctx->reset_cmr             = manifest_block_id;
    ctx->reset_dmr             = manifest_block_id;
    ctx->reset_timestamp_nanos = fd_clock_tile_now( ctx->clock );
    ctx->next_leader_slot      = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, ctx->identity_pubkey );

    fd_sched_block_add_done( ctx->sched, bank->idx, ULONG_MAX, snapshot_slot );
    FD_TEST( bank->idx==0UL );

    fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ 0 ];
    block_id_ele->latest_mr      = manifest_block_id;
    block_id_ele->dmr            = manifest_block_id;
    block_id_ele->slot           = snapshot_slot;
    block_id_ele->bank_seq       = bank->bank_seq;
    block_id_ele->block_id_seen  = 1;
    block_id_ele->latest_fec_idx = 0U;
    bank->f.block_id             = manifest_block_id;

    if( !ctx->alpenglow ) {
      FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );
    } else {
      block_id_ele->block_info = ag_block_id( snapshot_slot, manifest_block_id.uc );
      FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, block_id_ele, ctx->block_id_arr ) );
    }

    /* We call this after fd_runtime_read_genesis, which sets up the
       slot_bank needed in blockstore_init. */
    init_after_snapshot( ctx, stem );

    if( FD_LIKELY( ctx->next_leader_slot != ULONG_MAX ) ) {
      double slot_duration_ticks = (double)bank->f.slot_params.ns_per_slot_adjusted*ctx->tick_per_ns;
      ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*slot_duration_ticks) + fd_tickcount();
    } else {
      ctx->next_leader_tickcount = LONG_MAX;
    }

    fd_replay_slot_completed_t * slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
    cost_tracker_snap( bank, slot_info );

    slot_info->identity_balance = fd_accdb_lamports( ctx->accdb, bank->accdb_fork_id, ctx->identity_pubkey->uc );

    publish_slot_completed( ctx, stem, bank, 1, 0 /* is_leader */, 0, 0 );
    publish_root_advanced( ctx, stem, bank );

    if( ctx->reasm ) {
    fd_reasm_fec_t * fec = fd_reasm_init( ctx->reasm, &manifest_block_id, snapshot_slot );
      fec->bank_idx        = (uint)bank->idx;
      fec->bank_seq        = bank->bank_seq;
    }
    store_xinsert( ctx->store, &manifest_block_id );

    return;
  }

  switch( msg ) {
    case FD_SSMSG_MANIFEST_FULL:
    case FD_SSMSG_MANIFEST_INCREMENTAL: {
      /* We may either receive a full snapshot manifest or an
         incremental snapshot manifest.  Note that this external message
         id is only used temporarily because replay cannot yet receive
         the firedancer-internal snapshot manifest message. */
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
        FD_LOG_ERR(( "chunk %lu from in %d corrupt, not in range [%lu,%lu]", chunk, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      /* Malformed manifests are rejected recoverably by snapin via
         fd_ssload_manifest_validate.  If recover fails here, then the
         bank is partially mutated, and we must abort. */
      if( FD_UNLIKELY( fd_ssload_recover( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ),
                                          ctx->banks,
                                          fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_SEQ ),
                                          ctx->blockhash_seed ) ) ) {
        FD_LOG_ERR(( "Snapshot manifest recovery failed, aborting." ));
      }

      ctx->has_cluster_type = 1;
      ctx->cluster_type     = fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_SEQ )->f.cluster_type;

      fd_snapshot_manifest_t const * manifest = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      /* hard_fork_cnt already validated by fd_ssload_recover. */
      ctx->hard_fork_cnt = manifest->hard_fork_cnt;
      for( ulong i=0UL; i<manifest->hard_fork_cnt; i++ ) {
        ctx->hard_forks[ i ] = manifest->hard_forks[ i ];
      }
      ctx->has_expected_genesis_timestamp = 1;
      ctx->expected_genesis_timestamp     = manifest->creation_time_seconds;
      ctx->has_manifest_block_id          = manifest->has_block_id;
      if( manifest->has_block_id ) memcpy( ctx->manifest_block_id.uc, manifest->block_id, 32UL );
      if( FD_UNLIKELY( msg==FD_SSMSG_MANIFEST_FULL ) ) {
        ctx->snapmk.base_slot = manifest->slot;
      }
      break;
    }
    default: {
      FD_LOG_ERR(( "Received unknown snapshot message with msg %lu", msg ));
      return;
    }
  }

  return;
}

static void
dispatch_task( fd_replay_tile_t *  ctx,
               fd_stem_context_t * stem,
               fd_sched_task_t *   task ) {

  switch( task->task_type ) {
    case FD_SCHED_TT_TXN_EXEC: {
      fd_txn_p_t * txn_p = fd_sched_get_txn( ctx->sched, task->txn_exec->txn_idx );

      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->txn_exec->bank_idx );
      FD_TEST( bank );

      /* Add the transaction to the block dumper if necessary. This
         logic doesn't need to be fork-aware since it's only meant to
         be used in backtest. */
      if( FD_UNLIKELY( ctx->dump_proto_ctx && ctx->dump_proto_ctx->dump_block_to_pb ) ) {
        fd_dump_block_to_protobuf_collect_tx( ctx->block_dump_ctx, txn_p );
      }

      bank->refcnt++;

      if( FD_UNLIKELY( !bank->first_transaction_scheduled_nanos ) ) bank->first_transaction_scheduled_nanos = fd_clock_tile_now( ctx->clock );

      fd_replay_out_link_t *   exec_out = ctx->exec_out;
      fd_execrp_txn_exec_msg_t * exec_msg = fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      memcpy( exec_msg->txn, txn_p, sizeof(fd_txn_p_t) );
      exec_msg->bank_idx = task->txn_exec->bank_idx;
      exec_msg->txn_idx  = task->txn_exec->txn_idx;
      memcpy( exec_msg->fec_merkle_root, ctx->block_id_arr[ task->txn_exec->bank_idx ].latest_mr.uc, 32UL );
      exec_msg->index_in_slot = fd_sched_get_txn_info( ctx->sched, task->txn_exec->txn_idx )->index_in_slot;
      if( FD_UNLIKELY( ctx->capture_ctx ) ) {
        exec_msg->capture_txn_idx = ctx->capture_ctx->current_txn_idx++;
      }
      fd_stem_publish( stem, exec_out->idx, (FD_EXECRP_TT_TXN_EXEC<<32) | task->txn_exec->exec_idx, exec_out->chunk, sizeof(*exec_msg), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
      exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*exec_msg), exec_out->chunk0, exec_out->wmark );
      break;
    }
    case FD_SCHED_TT_TXN_SIGVERIFY: {
      fd_txn_p_t * txn_p = fd_sched_get_txn( ctx->sched, task->txn_sigverify->txn_idx );

      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->txn_sigverify->bank_idx );
      FD_TEST( bank );
      bank->refcnt++;

      fd_replay_out_link_t *        exec_out = ctx->exec_out;
      fd_execrp_txn_sigverify_msg_t * exec_msg = fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      memcpy( exec_msg->txn, txn_p, sizeof(fd_txn_p_t) );
      exec_msg->bank_idx = task->txn_sigverify->bank_idx;
      exec_msg->txn_idx  = task->txn_sigverify->txn_idx;
      fd_stem_publish( stem, exec_out->idx, (FD_EXECRP_TT_TXN_SIGVERIFY<<32) | task->txn_sigverify->exec_idx, exec_out->chunk, sizeof(*exec_msg), 0UL, 0UL, 0UL );
      exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*exec_msg), exec_out->chunk0, exec_out->wmark );
      break;
    };
    case FD_SCHED_TT_POH_HASH: {
      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->poh_hash->bank_idx );
      FD_TEST( bank );
      bank->refcnt++;

      fd_replay_out_link_t *   exec_out = ctx->exec_out;
      fd_execrp_poh_hash_msg_t * exec_msg = fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      exec_msg->bank_idx = task->poh_hash->bank_idx;
      exec_msg->mblk_idx = task->poh_hash->mblk_idx;
      exec_msg->hashcnt  = task->poh_hash->hashcnt;
      memcpy( exec_msg->hash, task->poh_hash->hash, sizeof(fd_hash_t) );
      fd_stem_publish( stem, exec_out->idx, (FD_EXECRP_TT_POH_HASH<<32) | task->poh_hash->exec_idx, exec_out->chunk, sizeof(*exec_msg), 0UL, 0UL, 0UL );
      exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*exec_msg), exec_out->chunk0, exec_out->wmark );
      break;
    };
    default: {
      FD_LOG_CRIT(( "unexpected task type %lu", task->task_type ));
    }
  }
}

static void
mark_bank_dead( fd_replay_tile_t *  ctx,
                fd_stem_context_t * stem,
                ulong               bank_idx,
                int                 dead_reason,
                int                 abandoned_reason ) {
  ulong dead_idxs[ FD_BANKS_MAX_BANKS ];
  ulong dead_idxs_cnt = 0UL;
  fd_banks_mark_bank_dead( ctx->banks, bank_idx, dead_idxs, &dead_idxs_cnt );

  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ bank_idx ];
  if( block_id_ele->block_id_seen ) publish_slot_dead( ctx, stem, block_id_ele->slot, ctx->alpenglow ? &block_id_ele->dmr : &block_id_ele->latest_mr );

  /* Report each newly dead bank now (dead_idxs excludes already-dead,
     already-reported subtrees): the failing bank with its real reason and
     descendants as parent_dead, or the whole lineage with the caller's
     abandoned flavor.  Exactly one of the two reasons is set.
     A previously PRUNABLE (evicted) bank converted by this walk reports
     here like any other: eviction emits no row, and the sched-drain
     emission is gated on the state still being PRUNABLE.  Blocks still
     receiving FECs dedup the slot-completion report via dead_reported. */
  int abandoned = abandoned_reason!=FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED;
  for( ulong i=0UL; i<dead_idxs_cnt; i++ ) {
    fd_block_id_ele_t * ele = &ctx->block_id_arr[ dead_idxs[ i ] ];

    fd_reasm_fec_t *    fec = !ctx->alpenglow ? fd_reasm_query( ctx->reasm, &ele->latest_mr ) : NULL;
    if( !ctx->alpenglow && FD_LIKELY( fec ) ) { fec->bank_dead = (uchar)(abandoned ? 2U : 1U); fec->dead_reported = 1; }

    timing_slot_release( ctx, dead_idxs[ i ] );
    fd_bank_t * bank = fd_banks_bank_query( ctx->banks, dead_idxs[ i ] );
    int dr = abandoned                 ? FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD
           : dead_idxs[ i ]==bank_idx  ? dead_reason
           :                             FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_PARENT_DEAD;
    report_block_incomplete( ctx, ele->slot, ctx->alpenglow && ele->block_id_seen ? &ele->dmr : &ele->latest_mr, bank, dr, abandoned_reason );
  }
}

static int
try_replay( fd_replay_tile_t *  ctx,
            fd_stem_context_t * stem ) {

  if( FD_UNLIKELY( !ctx->is_booted ) ) return 0;

  int charge_busy = 0;
  fd_sched_task_t task[ 1 ];
  if( FD_UNLIKELY( !fd_sched_task_next_ready( ctx->sched, task ) ) ) {
    return charge_busy; /* Nothing to execute or do. */
  }

  charge_busy = 1;

  switch( task->task_type ) {
    case FD_SCHED_TT_BLOCK_START: {
      replay_block_start( ctx, task->block_start->bank_idx, task->block_start->parent_bank_idx, task->block_start->slot );
      fd_sched_task_done( ctx->sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL );
      break;
    }
    case FD_SCHED_TT_BLOCK_END: {
      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->block_end->bank_idx );
      if( FD_LIKELY( bank->state==FD_BANK_STATE_REPLAYABLE ) ) replay_block_finalize( ctx, stem, bank );
      fd_sched_task_done( ctx->sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL );
      break;
    }
    case FD_SCHED_TT_TXN_EXEC:
    case FD_SCHED_TT_TXN_SIGVERIFY:
    case FD_SCHED_TT_POH_HASH: {
      /* Common case: we have a transaction we need to execute. */
      dispatch_task( ctx, stem, task );
      break;
    }
    case FD_SCHED_TT_MARK_DEAD: {
      int dr = sched_block_dead_reason_to_event( ctx, task->mark_dead->bank_idx );
      int ar = dr==FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD ? FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED
                                                                 : FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED;
      mark_bank_dead( ctx, stem, task->mark_dead->bank_idx, dr, ar );
      break;
    }
    default: {
      FD_LOG_CRIT(( "unexpected task type %lu", task->task_type ));
    }
  }

  return charge_busy;
}

static int
can_process_fec( fd_replay_tile_t * ctx,
                 int *              evict_banks_out ) {
  /* We can process a FEC set if a few conditions are met:
     - sched has capacity
     - reasm has a FEC in its out queue ready to be processed
     - banks has capacity.  Evict if we don't (see below) */

  if( FD_UNLIKELY( fd_sched_can_ingest_cnt( ctx->sched )==0UL ) ) {
    FD_TEST( !fd_sched_is_drained( ctx->sched ) );
    ctx->metrics.sched_full++;
    return 0;
  }

  fd_reasm_fec_t * fec;
  if( FD_UNLIKELY( (fec = fd_reasm_peek( ctx->reasm ))==NULL ) ) {
    ctx->metrics.reasm_empty++;
    return 0;
  }

  fd_reasm_fec_t * parent = fd_reasm_parent( ctx->reasm, fec );
  FD_TEST( parent ); /* FEC must be connected */

  ctx->metrics.reasm_latest_slot    = fec->slot;
  ctx->metrics.reasm_latest_fec_idx = fec->fec_set_idx;

  /* If the FEC we are building off of is for a prunable bank, we must
     wait to process the FEC until the bank has been evicted. */
  fd_bank_t * parent_fec_bank = parent->bank_idx==UINT_MAX ? NULL : fd_banks_bank_query( ctx->banks, parent->bank_idx );
  if( FD_UNLIKELY( parent_fec_bank && parent_fec_bank->bank_seq==parent->bank_seq && parent_fec_bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_LOG_DEBUG(( "waiting to process FEC set (slot=%lu, fec_set_idx=%u) because parent bank is being pruned", fec->slot, fec->fec_set_idx ));
    return 0;
  }

  if( FD_UNLIKELY( ctx->is_leader && fec->fec_set_idx==0U && parent->bank_idx==ctx->leader_bank->idx ) ) {
    /* This guards against a rare race where we receive the FEC set for
       the slot right after our leader rotation before we freeze the
       bank for the last slot in our leader rotation.  Leader slot
       freezing happens only after if we've received the final PoH hash
       from the poh tile as well as the final FEC set for the leader
       slot.  So the race happens when FEC sets are delivered and
       processed sooner than the PoH hash, aka when the
       poh=>shred=>replay path for the block id beats the poh=>replay
       path for the poh hash.  To mitigate this race, we must block on
       ingesting the FEC set for the ensuing slot before the leader
       bank freezes, because that would violate ordering invariants in
       banks and sched. */
    FD_TEST( ctx->block_id_arr[ ctx->leader_bank->idx ].block_id_seen );
    FD_TEST( !ctx->recv_poh );
    ctx->metrics.leader_bid_wait++;
    return 0;
  }

  /* Should we evict banks if there are no more free banks?  The answer
     is it depends.  Eviction should only happen if we can make no
     forward replay progress.  This can only happen if:
     1. banks are full
     2. sched is drained: pending txns could complete a block and
        eventually advance the root.
     AND
     3. next reasm FEC needs a new bank.  A fec that chains off of a
        bank that is already allocated can be processed.  A FEC can
        require a new bank in three ways:
        - fec_set_idx==0: we don't have any free banks to provision a
          new bank for this FEC.
        - equivocation: a FEC may be in the middle of a block, but if
          it's the first equivocating FEC detected, we need to allocate
          a new bank for the version of the block.
        - backfill: the parent FEC's bank was never created or has been
          evicted and must be reconstructed. */

  int invalid_parent = !parent_fec_bank || parent_fec_bank->bank_seq!=parent->bank_seq;
  if( FD_UNLIKELY( !fd_banks_can_start_bank( ctx->banks ) ) ) {
    int is_new_block = fec->fec_set_idx==0U;
    int is_eqvoc     = fec->eqvoc && !parent->eqvoc;
    if( FD_UNLIKELY( is_new_block || is_eqvoc || invalid_parent ) ) {
      ctx->metrics.banks_full++;
      if( FD_UNLIKELY( fd_sched_is_drained( ctx->sched ) ) ) *evict_banks_out = 1;
      return 0;
    }
  }

  /* Otherwise, banks may not be full, so we can always create a new
     bank if needed.  Or, if banks are full, the current fec set's
     ancestor (idx 0) already created a bank for this slot. */
  return 1;
}

#define PROCESS_FEC_WAIT 0  /* Put back on dcache for later retry */
#define PROCESS_FEC_OK   1  /* Process FEC set */
#define PROCESS_FEC_DROP 2  /* Drop FEC set and notify rotor to start redelivery */
#define PROCESS_FEC_SKIP 3  /* Good to skip this FEC set, drop from dcache */

static int
can_process_rotor_fec( fd_replay_tile_t      * ctx,
                       fd_rotor_replay_fec_t * fec,
                       int *                   evict_banks_out ) {
  /* We can process a FEC set if a few conditions are met:
     - sched has capacity
     - banks has capacity.  Evict if we don't (see below) */

  /* Recovery redelivery re-publishes the entire ancestry path from the
     chainer root, but most of those blocks are already replayed.  Skip
     any FEC (slot, block_id) names a block we have already fully
     replayed */
  if( FD_LIKELY( fec->known_id ) ) {
    ag_block_id_t seen_key = ag_block_id( fec->slot, fec->block_id.uc );
    fd_block_id_ele_t * seen = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &seen_key, NULL, ctx->block_id_arr );
    if( FD_UNLIKELY( seen && seen->block_id_seen ) ) return PROCESS_FEC_SKIP;
  }

  if( FD_UNLIKELY( fd_sched_can_ingest_cnt( ctx->sched )==0UL ) ) {
    FD_TEST( !fd_sched_is_drained( ctx->sched ) );
    ctx->metrics.sched_full++;
    return PROCESS_FEC_WAIT;
  }

  ulong parent_bank_idx = UINT_MAX;
  fd_block_id_ele_t * parent = NULL;
  if( FD_UNLIKELY( fec->fec_set_idx==0 ) ) {
    ag_block_id_t parent_key = ag_block_id( fec->parent_slot, fec->parent_block_id.uc );
    parent = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &parent_key, NULL, ctx->block_id_arr );
    if( FD_UNLIKELY( !parent ) ) {
      FD_BASE58_ENCODE_32_BYTES( fec->parent_block_id.uc, parent_key_b58 );
      FD_LOG_INFO(( "parent bank not found for slot %lu fec set idx %u, parent slot %lu parent block_id %s", fec->slot, fec->fec_set_idx, fec->parent_slot, parent_key_b58 ));
      return PROCESS_FEC_DROP; // either pruned or bank evicted
    }
    parent_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, parent );
  } else {
    ag_block_id_t key = { .slot = fec->slot };
    if( FD_LIKELY( fec->known_id ) ) key = ag_block_id( fec->slot, fec->block_id.uc );

    parent = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key, NULL, ctx->block_id_arr );
    if( FD_UNLIKELY( !parent ) ) {
      FD_BASE58_ENCODE_32_BYTES( fec->block_id.uc, block_id_b58 );
      FD_LOG_INFO(( "parent bank not found for slot %lu fec set idx %u slot_bid %s. parent slot %lu", fec->slot, fec->fec_set_idx, block_id_b58, fec->parent_slot ));
      return PROCESS_FEC_DROP; // either pruned or bank evicted
    } else if( FD_UNLIKELY( parent->latest_fec_idx>=fec->fec_set_idx ) ) {
      /* Similar to the very first condition in can_process_rotor_fec,
         but this would hit if we were halfway through replaying a slot
         and then requested redelivery from rotor. Then we can skip
         replaying the first half of the slot. */
      FD_LOG_INFO(( "fec redelivered for slot %lu fec set idx %u, parent slot %lu. bank_idx %lu, latest_fec_idx %u", fec->slot, fec->fec_set_idx, fec->parent_slot, fd_block_id_ele_get_idx( ctx->block_id_arr, parent ), parent->latest_fec_idx ));
      return PROCESS_FEC_SKIP; // context for slot exists, but this is an earlier FEC. Safe to skip.
    } else {
      parent_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, parent );
    }
  }

  ctx->metrics.reasm_latest_slot    = fec->slot;
  ctx->metrics.reasm_latest_fec_idx = fec->fec_set_idx;

  /* If the FEC we are building off of is for a prunable bank, we must
     wait to process the FEC until the bank has been evicted. */
  fd_bank_t * parent_fec_bank = parent_bank_idx==UINT_MAX ? NULL : fd_banks_bank_query( ctx->banks, parent_bank_idx );
  if( FD_UNLIKELY( parent_fec_bank && parent_fec_bank->bank_seq==parent->bank_seq && parent_fec_bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_LOG_DEBUG(( "waiting to process FEC set (slot=%lu, fec_set_idx=%u) because parent bank is being pruned", fec->slot, fec->fec_set_idx ));
    return PROCESS_FEC_WAIT;
  }

  if( FD_UNLIKELY( ctx->is_leader && fec->fec_set_idx==0U && parent_bank_idx==ctx->leader_bank->idx ) ) {
    /* This guards against a rare race where we receive the FEC set for
       the slot right after our leader rotation before we freeze the
       bank for the last slot in our leader rotation.  Leader slot
       freezing happens only after if we've received the final PoH hash
       from the poh tile as well as the final FEC set for the leader
       slot.  So the race happens when FEC sets are delivered and
       processed sooner than the PoH hash, aka when the
       poh=>shred=>replay path for the block id beats the poh=>replay
       path for the poh hash.  To mitigate this race, we must block on
       ingesting the FEC set for the ensuing slot before the leader
       bank freezes, because that would violate ordering invariants in
       banks and sched. */
    FD_TEST( ctx->block_id_arr[ ctx->leader_bank->idx ].block_id_seen );
    FD_TEST( !ctx->recv_poh );
    ctx->metrics.leader_bid_wait++;
    return PROCESS_FEC_WAIT;
  }

  /* Should we evict banks if there are no more free banks?  The answer
     is it depends.  Eviction should only happen if we can make no
     forward replay progress.  This can only happen if:
     1. banks are full
     2. sched is drained: pending txns could complete a block and
        eventually advance the root.
     AND
     3. next reasm FEC needs a new bank.  A fec that chains off of a
        bank that is already allocated can be processed.  A FEC can
        require a new bank in three ways:
        - fec_set_idx==0: we don't have any free banks to provision a
          new bank for this FEC.
        - equivocation: a FEC may be in the middle of a block, but if
          it's the first equivocating FEC detected, we need to allocate
          a new bank for the version of the block.
        - backfill: the parent FEC's bank was never created or has been
          evicted and must be reconstructed.


     - Without reasm there is no backfill: if the parent bank was
       evicted or its bank idx was reused, this FEC can't be
       processed, so drop it and notify rotor to redeliver.
     - Rotor equivocating slots are guaranteed to be delivered starting
       from FEC 0, so even equivocations mid-slot are delivered from
       fec 0 */

  int invalid_parent = !parent_fec_bank || parent_fec_bank->bank_seq!=parent->bank_seq;
  if( FD_UNLIKELY( invalid_parent ) ) {
    FD_LOG_INFO(( "parent bank evicted for slot %lu fec set idx %u, parent slot %lu", fec->slot, fec->fec_set_idx, fec->parent_slot ));
    return PROCESS_FEC_DROP;
  }

  if( FD_UNLIKELY( !fd_banks_can_start_bank( ctx->banks ) ) ) {
    int is_new_block = fec->fec_set_idx==0U;
    if( FD_UNLIKELY( is_new_block ) ) {
      ctx->metrics.banks_full++;
      if( FD_UNLIKELY( fd_sched_is_drained( ctx->sched ) ) ) *evict_banks_out = 1;
      return PROCESS_FEC_WAIT;
    }
  }

  /* Otherwise, banks may not be full, so we can always create a new
     bank if needed.  Or, if banks are full, the current fec set's
     ancestor (idx 0) already created a bank for this slot. */
  return PROCESS_FEC_OK;
}

/* Returns 0 on successful FEC ingestion, 1 if the block got marked
   dead.  insert_fec_set assumes that all FECs that are inserted are
   directly connected to a parent FEC.  Every block that is replayed
   has initial fec set idx 0 up to and including a FEC with
   slot_complete set.  The caller is responsible for ensuring this. */
static int
insert_fec_set( fd_replay_tile_t *  ctx,
                fd_stem_context_t * stem,
                fd_reasm_fec_t *    reasm_fec ) {

  /* First, read FEC set from the store.  If it's not there that means
     that the FEC is on a minority fork which has been pruned away.
     This means we shouldn't have a bank for the corresponding block so
     we should just ignore and discard the FEC set. */

  ulong wait = (ulong)fd_clock_tile_now( ctx->clock );
  ulong work = wait;
  FD_STORE_SLOCK_BEGIN( ctx->store ) {
  ctx->metrics.store_query_acquire++;
  work = (ulong)fd_clock_tile_now( ctx->clock );
  fd_histf_sample( ctx->metrics.store_query_wait, work - wait );

  fd_store_fec_t * store_fec = fd_store_query( ctx->store, &reasm_fec->key );
  ctx->metrics.store_query_cnt++;
  if( FD_UNLIKELY( !store_fec && !reasm_fec->is_leader ) ) {
    /* The only case in which a FEC is not found in the store is either
       if the FEC is from our own leader block or after repair has
       notified is if the FEC was on a minority fork that has already
       been published away.  In this case we abandon the entire slice
       because it is no longer relevant.  If the FEC is from our own
       leader block, process the FEC so we can unbecome leader. */
    ctx->metrics.store_query_missing_cnt++;
    ctx->metrics.store_query_missing_mr = reasm_fec->key.ul[0];
    FD_BASE58_ENCODE_32_BYTES( reasm_fec->key.key, key_b58 );
    FD_LOG_WARNING(( "store fec for slot: %lu is on minority fork already pruned by publish. abandoning slice. root: %lu. pruned merkle: %s", reasm_fec->slot, ctx->consensus_root_slot, key_b58 ));
    return 1;
  }

  long now = fd_clock_tile_now( ctx->clock );

  /* A leader FEC arriving after its slot was aborted (or after a later
     leadership began) has no bank to bind to; drop it. */
  if( FD_UNLIKELY( reasm_fec->is_leader &&
                   ( !ctx->leader_bank || ctx->leader_bank->f.slot!=reasm_fec->slot ) ) ) return 0;

  /* Assign parent bank idx + seq no to the FEC */
  reasm_fec->parent_bank_idx = fd_reasm_parent( ctx->reasm, reasm_fec )->bank_idx;
  fd_bank_t * parent_bank    = fd_banks_bank_query( ctx->banks, reasm_fec->parent_bank_idx );

  if( FD_UNLIKELY( reasm_fec->fec_set_idx==0U ) ) {
    /* Provision new bank if not leader.  Assign bank idx and seq no
       to the FEC.  Remove stale block id map entry if any and update
       pool element. */
    fd_bank_t * bank = reasm_fec->is_leader ? ctx->leader_bank : fd_banks_new_bank( ctx->banks, reasm_fec->parent_bank_idx, now, 0 );

    if( FD_UNLIKELY( reasm_fec->is_leader && ctx->leader_stats.slot==reasm_fec->slot ) ) {
      ctx->leader_stats.first_fec_returned_nanos = now;
    }

    reasm_fec->bank_idx = (uint)bank->idx;
    reasm_fec->bank_seq = bank->bank_seq;

    fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ reasm_fec->bank_idx ];
    if( FD_LIKELY( fd_block_id_map_ele_query( ctx->block_id_map, &block_id_ele->latest_mr, NULL, ctx->block_id_arr )==block_id_ele ) ) {
      FD_TEST( fd_block_id_map_ele_remove( ctx->block_id_map, &block_id_ele->latest_mr, NULL, ctx->block_id_arr ) );
    }
    block_id_ele->block_id_seen  = 0;
    block_id_ele->slot           = reasm_fec->slot;
    block_id_ele->bank_seq       = bank->bank_seq;
    block_id_ele->latest_fec_idx = 0U;
    block_id_ele->latest_mr      = reasm_fec->key;
  } else { /* FEC for the middle or end of a block */
    /* Assign bank idx + seqno to the FEC.  Update block id pool ele. */
    reasm_fec->bank_idx = reasm_fec->parent_bank_idx;
    reasm_fec->bank_seq = parent_bank->bank_seq;

    FD_TEST( reasm_fec->bank_idx!=UINT_MAX );

    fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ reasm_fec->bank_idx ];
    block_id_ele->latest_fec_idx = reasm_fec->fec_set_idx;
    block_id_ele->latest_mr      = reasm_fec->key;
  }

  /* If the FEC set is a slot complete, this means we have finally seen
     the block id (block's last mr). */
  if( FD_UNLIKELY( reasm_fec->slot_complete ) ) {
    fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ reasm_fec->bank_idx ];
    block_id_ele->block_id_seen  = 1;
    block_id_ele->latest_mr      = reasm_fec->key;
    block_id_ele->latest_fec_idx = reasm_fec->fec_set_idx;
    /* If we are re-replaying a block, we want to remove the first
       version of the block that we have presumably evicted. */
    if( FD_UNLIKELY( fd_block_id_map_ele_remove( ctx->block_id_map, &block_id_ele->latest_mr, NULL, ctx->block_id_arr ) ) ) {
      FD_LOG_DEBUG(( "finished re-replaying evicted bank (slot=%lu, bank_idx=%u)", reasm_fec->slot, reasm_fec->bank_idx ));
    }
    FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );
  }

  /* For leader FECs, don't insert the FEC into the scheduler. */
  if( FD_UNLIKELY( reasm_fec->is_leader ) ) return 0;

  /* Forks form a partial ordering over FEC sets. The Repair tile
      delivers FEC sets in-order per fork, but FEC set ordering across
      forks is arbitrary */
  fd_sched_fec_t sched_fec[ 1 ];

# if DEBUG_LOGGING
  FD_BASE58_ENCODE_32_BYTES( reasm_fec->key.key, key_b58 );
  FD_BASE58_ENCODE_32_BYTES( reasm_fec->cmr.key, cmr_b58 );
  FD_LOG_INFO(( "replay processing FEC set for slot %lu fec_set_idx %u, mr %s cmr %s", reasm_fec->slot, reasm_fec->fec_set_idx, key_b58, cmr_b58 ));
# endif

  sched_fec->shred_cnt         = reasm_fec->data_cnt;
  sched_fec->is_last_in_batch  = !!reasm_fec->data_complete;
  sched_fec->is_last_in_block  = !!reasm_fec->slot_complete;
  sched_fec->bank_idx          = reasm_fec->bank_idx;
  sched_fec->parent_bank_idx   = reasm_fec->parent_bank_idx;
  sched_fec->slot              = reasm_fec->slot;
  sched_fec->parent_slot       = reasm_fec->slot - reasm_fec->parent_off;
  sched_fec->is_first_in_block = reasm_fec->fec_set_idx==0U;
  sched_fec->fec               = store_fec;
  sched_fec->data              = fd_store_fec_data( ctx->store, store_fec );
  sched_fec->completed_ns      = (long)reasm_fec->fec_completed_ts_nanos;
  sched_fec->alut_ctx->fork_id = fd_banks_bank_query( ctx->banks, ctx->published_root_bank_idx )->accdb_fork_id;
  sched_fec->alut_ctx->accdb   = ctx->accdb;
  sched_fec->alut_ctx->els     = ctx->published_root_slot;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, sched_fec->bank_idx );
  if( sched_fec->is_first_in_block ) {
    bank->refcnt++;
    FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt incremented to %lu for sched", bank->idx, sched_fec->slot, bank->refcnt ));
  }

  if( FD_UNLIKELY( !fd_sched_fec_ingest( ctx->sched, sched_fec ) ) ) {
    int dr = sched_block_dead_reason_to_event( ctx, sched_fec->bank_idx );
    int ar = dr==FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD ? FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED
                                                               : FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED;
    mark_bank_dead( ctx, stem, sched_fec->bank_idx, dr, ar );
    return 1;
  }

  } FD_STORE_SLOCK_END;

  ctx->metrics.store_query_release++;
  fd_histf_sample( ctx->metrics.store_query_work, (ulong)fd_clock_tile_now( ctx->clock ) - work );
  return 0;
}

static void
backfill_fec_sets( fd_replay_tile_t *  ctx,
                   fd_stem_context_t * stem,
                   fd_reasm_fec_t *    reasm_fec ) {
  fd_reasm_fec_t * parent = fd_reasm_parent( ctx->reasm, reasm_fec );
  FD_TEST( !!parent );

  fd_reasm_fec_t * path[ FD_FEC_BLK_MAX ];
  ulong            path_cnt = 0UL;
  ulong            path_slot = reasm_fec->slot;

  /* Walk backward from the candidate FEC until we find one with an
     associated bank that we consider 'valid'.  A FEC is considered
     valid to backfill off of if the bank matches the seq we expect and
     if its latest mr matches.  We must check the latest MR in the case
     of equivocation. */
  fd_bank_t *      base_bank = NULL;
  fd_reasm_fec_t * base_fec  = NULL;
  for( fd_reasm_fec_t * curr = reasm_fec;; ) {
    fd_bank_t *         curr_bank    = curr->bank_idx==UINT_MAX ? NULL : fd_banks_bank_query( ctx->banks, curr->bank_idx );
    fd_block_id_ele_t * block_id_ele = curr_bank ? &ctx->block_id_arr[ curr_bank->idx ] : NULL;
    if( FD_LIKELY( curr_bank &&
                   curr_bank->bank_seq==curr->bank_seq &&
                   curr_bank->state!=FD_BANK_STATE_PRUNABLE &&
                   block_id_ele->bank_seq==curr->bank_seq &&
                   fd_hash_eq( &block_id_ele->latest_mr, &curr->key ) ) ) { base_bank = curr_bank; base_fec = curr; break; }

    if( FD_UNLIKELY( curr->slot!=path_slot ) ) {
      path_cnt  = 0UL;
      path_slot = curr->slot;
    }

    FD_TEST( path_cnt<FD_FEC_BLK_MAX );
    path[ path_cnt++ ] = curr;

    curr = fd_reasm_parent( ctx->reasm, curr );
    FD_TEST( curr );
  }

  if( FD_UNLIKELY( base_bank->state==FD_BANK_STATE_DEAD ) ) {
    uchar bank_dead = fd_uchar_if( base_fec->bank_dead==2U, 2U, 1U );
    for( ulong i=0UL; i<path_cnt; i++ ) {
      path[ i ]->bank_dead     = bank_dead;
      path[ i ]->dead_reported = 0UL; /* new version: no row yet */
    }
    reasm_fec->bank_dead = bank_dead;
    if( FD_UNLIKELY( reasm_fec->slot_complete ) ) {
      publish_slot_dead( ctx, stem, reasm_fec->slot, &reasm_fec->key );
      int abandoned = bank_dead==2U;
      report_block_incomplete( ctx, reasm_fec->slot, &reasm_fec->key, NULL,
                               abandoned ? FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD    : FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_PARENT_DEAD,
                               abandoned ? FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED : FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
      reasm_fec->dead_reported = 1UL;
    }
    return;
  }

  /* Now that we have queued up the potential path of FECs to backfill,
     ingest as much as sched can allow. */
  fd_reasm_fec_t * first = path[ path_cnt-1UL ];
  fd_reasm_fec_t * last  = path[ 0 ];
  FD_LOG_DEBUG(( "backfilling FEC sets for slot %lu from fec_set_idx %u to fec_set_idx %u", first->slot, first->fec_set_idx, last->fec_set_idx ));

  ulong sched_capacity = fd_sched_can_ingest_cnt( ctx->sched );
  ulong path_idx_min   = path_cnt - fd_ulong_min( sched_capacity, path_cnt );
  for( ulong i=path_cnt; i>path_idx_min; i-- ) {
    if( FD_UNLIKELY( insert_fec_set( ctx, stem, path[ i-1UL ] ) ) ) return;
  }
}

static void
process_fec_set( fd_replay_tile_t *  ctx,
                 fd_stem_context_t * stem,
                 fd_reasm_fec_t *    reasm_fec ) {

  fd_reasm_fec_t * parent = fd_reasm_parent( ctx->reasm, reasm_fec );
  if( FD_UNLIKELY( parent->bank_dead ) ) {
    /* Inherit the dead flag from the parent (1: dead lineage, 2:
       abandoned lineage).  If a dead slot is completed, we publish the
       slot as dead.  Don't insert FECs for dead slots. */
    reasm_fec->bank_dead     = parent->bank_dead;
    reasm_fec->dead_reported = ( parent->slot==reasm_fec->slot && reasm_fec->xid_next==UINT_MAX )
                             ? parent->dead_reported : 0UL;
    if( FD_UNLIKELY( reasm_fec->slot_complete ) ) {
      publish_slot_dead( ctx, stem, reasm_fec->slot, &reasm_fec->key );
      if( !reasm_fec->dead_reported ) {
        int abandoned = reasm_fec->bank_dead==2UL;
        report_block_incomplete( ctx, reasm_fec->slot, &reasm_fec->key, NULL,
                                 abandoned ? FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD    : FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_PARENT_DEAD,
                                 abandoned ? FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED : FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
      }
    }
    FD_LOG_DEBUG(( "dropping FEC set (slot=%lu, fec_set_idx=%u) because parent bank is marked dead", reasm_fec->slot, reasm_fec->fec_set_idx ));
    return;
  }

  /* An invariant from reasm is that if we receive a FEC set that is
     both with eqvoc and confirmed set, we know that we must replay the
     slot associated with this FEC.  equivocation when fec_set_idx == 0
     gets handled cleanly. */
  int eqvoc_detected = reasm_fec->fec_set_idx!=0 && (reasm_fec->eqvoc && !parent->eqvoc);
  if( FD_UNLIKELY( eqvoc_detected ) ) FD_TEST( reasm_fec->confirmed && parent->confirmed );

  /* We can detect if a bank has not replayed if the bank index tagged
     to the FEC set is no longer valid or the bank sequence number for
     the same bank is different (the bank has been recycled).  This is
     either due to the parent bank being evicted, or in reasm, the
     parent is marked eqvoc (and not replayed), but the child gets
     confirmed and delivered. */
  fd_bank_t * parent_fec_bank = parent->bank_idx==UINT_MAX ? NULL : fd_banks_bank_query( ctx->banks, parent->bank_idx );
  int parent_bank_invalid = !parent_fec_bank || parent_fec_bank->bank_seq!=parent->bank_seq;

  /* If the upcoming FEC is either the start of an equivocating chain,
     chains off of a bank that was evicted, OR is the child of an
     equivocating chain whose parent was gated from getting replayed, we
     must backfill any FECs into the scheduler.  This backfill must
     start from a FEC with fec_set_idx==0 with a parent FEC
     corresponding to a valid bank. */
  if( FD_LIKELY( !parent_bank_invalid && !eqvoc_detected ) ) {
    insert_fec_set( ctx, stem, reasm_fec );
  } else {
    backfill_fec_sets( ctx, stem, reasm_fec );
  }
}

static int
try_notify_consensus_root( fd_replay_tile_t *  ctx,
                           fd_stem_context_t * stem ) {

  if( FD_LIKELY( ctx->notified_root_slot==ctx->consensus_root_slot &&
                 fd_hash_eq( &ctx->notified_root, &ctx->consensus_root ) ) ) return 0;

 fd_block_id_ele_t * block_id_ele = fd_block_id_ele_query( ctx, &ctx->consensus_root, ctx->consensus_root_slot );
  if( FD_UNLIKELY( !block_id_ele ) ) return 0;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
  if( FD_UNLIKELY( !bank ||
                   bank->bank_seq!=block_id_ele->bank_seq ||
                   !fd_hash_eq( &bank->f.block_id, &ctx->consensus_root ) ||
                   bank->state==FD_BANK_STATE_PRUNABLE ) ) return 0;

  fd_sched_root_notify( ctx->sched, bank->idx );
  publish_root_advanced( ctx, stem, bank );

  ctx->notified_root      = ctx->consensus_root;
  ctx->notified_root_slot = ctx->consensus_root_slot;
  ctx->notified_root_bank = bank;
  return 1;
}

/* Periodic snapshots use block height, matching Agave.  Manually
   scheduled snapshots remain slot based. */

static int
snapshot_due_for_root( fd_replay_tile_t * ctx,
                       ulong              published_root_block_height,
                       ulong              advanceable_root_slot,
                       ulong              advanceable_root_block_height,
                       ulong              consensus_root_block_height,
                       int *              out_incremental ) {
  *out_incremental = 0;
  if( FD_LIKELY( !ctx->snapmk.supported || ctx->snapmk.active ) ) return 0;

  int   caught_up   = ctx->caught_up; /* suspend periodic snaps until caught up */
  ulong full_target = ULONG_MAX;
  ulong interval    = ctx->snapmk.full_interval_blocks;
  if( FD_UNLIKELY( interval && caught_up ) ) {
    if( FD_UNLIKELY( ctx->snapmk.next_full_block_height==ULONG_MAX ) ) {
      ctx->snapmk.next_full_block_height = ((published_root_block_height/interval)+1UL)*interval;
    }

    /* If snapshot production fell behind by more than one interval,
       skip ahead to the latest due interval. */
    full_target = fd_ulong_max( ctx->snapmk.next_full_block_height,
                                (consensus_root_block_height/interval)*interval );
  }

  /* Manual slot scheduling always requests a full snapshot. */
  if( FD_UNLIKELY( advanceable_root_slot>=ctx->snapmk.scheduled_at_slot ) ) return 1;

  /* An incremental snapshot is only possible once a full snapshot
     exists to serve as its base. */
  ulong incremental_target = ULONG_MAX;
  ulong incr_interval      = ctx->snapmk.incremental_interval_blocks;
  if( FD_UNLIKELY( incr_interval && caught_up && ctx->snapmk.base_slot!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( ctx->snapmk.next_incremental_block_height==ULONG_MAX ) ) {
      ctx->snapmk.next_incremental_block_height = ((published_root_block_height/incr_interval)+1UL)*incr_interval;
    }
    incremental_target = fd_ulong_max( ctx->snapmk.next_incremental_block_height,
                                       (consensus_root_block_height/incr_interval)*incr_interval );
  }

  /* A full snapshot due at the same block height supersedes the
     incremental snapshot. */
  ulong target      = full_target;
  int   incremental = incremental_target<full_target;
  if( FD_UNLIKELY( incremental ) ) target = incremental_target;
  if( FD_LIKELY( advanceable_root_block_height<target ) ) return 0;
  *out_incremental = incremental;
  return 1;
}

static void
snapmk_start( fd_replay_tile_t *  ctx,
              fd_stem_context_t * stem,
              int                 incremental );

static int
try_advance_published_root( fd_replay_tile_t *  ctx,
                            fd_stem_context_t * stem ) {

  if( FD_LIKELY( ctx->published_root_slot==ctx->consensus_root_slot ) ) return 0;

  /* accdb pauses advance_root while producing a snapshot, so submitting
     one would stall the next wait_cmd until the snapshot completes. */
  if( FD_UNLIKELY( ctx->snapmk.active ) ) return 0;

  /* If the new root is not available because the bank is/has been
     evicted, we can't advance the root.  Try again later. */

  fd_block_id_ele_t * block_id_ele = fd_block_id_ele_query( ctx, &ctx->consensus_root, ctx->consensus_root_slot );
  if( FD_UNLIKELY( !block_id_ele ) ) return 0;
  fd_bank_t * target_bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
  if( FD_UNLIKELY( !target_bank ||
                   target_bank->bank_seq!=block_id_ele->bank_seq ||
                   !fd_hash_eq( &target_bank->f.block_id, &ctx->consensus_root ) ||
                   target_bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    return 0;
  }

  fd_bank_t * published_root_bank = fd_banks_bank_query( ctx->banks, ctx->published_root_bank_idx );
  FD_TEST( published_root_bank );
  ulong published_root_block_height = published_root_bank->f.block_height;
  ulong consensus_root_block_height = target_bank->f.block_height;

  /* If the identity vote has been seen on a bank that should be rooted,
     then we are now ready to produce blocks. */
  if( FD_UNLIKELY( !ctx->identity_vote_rooted ) ) {
    if( target_bank->f.identity_vote_idx==ctx->identity_idx ) ctx->identity_vote_rooted = 1;
  }

  ulong advanceable_root_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_banks_advance_root_prepare( ctx->banks, target_bank->idx, &advanceable_root_idx ) ) ) {
    ctx->metrics.storage_root_behind++;
    return 0;
  }

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, advanceable_root_idx );
  FD_TEST( bank );

  if( FD_UNLIKELY( advanceable_root_idx>=ctx->block_id_len ) ) {
    FD_LOG_CRIT(( "invariant violation: advanceable root ele out of bounds [0, %lu) index %lu", ctx->block_id_len, advanceable_root_idx ));
  }
  fd_block_id_ele_t * advanceable_root_ele = &ctx->block_id_arr[ advanceable_root_idx ];

  /* Telemetry: banks still mid-replay (started but never completed) on
     forks not descending from the new root are about to be cancelled by
     fd_banks_advance_root without ever emitting a block_completed row.
     Emit them as abandoned with reason `pruned`: the block was not
     invalid, it lost the fork race.  Every live bank is linked in the
     bank tree under the current root, so one preorder pass that skips
     the new root's subtree visits exactly the banks about to go. */
  if( FD_UNLIKELY( fd_event_tl ) ) {
    ulong       root_idx = fd_banks_root( ctx->banks )->idx;
    ulong       s        = root_idx;
    fd_bank_t * b        = fd_banks_root( ctx->banks );
    for(;;) {
      if( FD_LIKELY( s!=advanceable_root_idx ) ) {
        if( FD_UNLIKELY( b->state==FD_BANK_STATE_INIT || b->state==FD_BANK_STATE_REPLAYABLE ) ) {
          fd_block_id_ele_t * ele = &ctx->block_id_arr[ s ];
          report_block_incomplete( ctx, ele->slot, ctx->alpenglow && ele->block_id_seen ? &ele->dmr : &ele->latest_mr, b, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED );
        }
        if( FD_LIKELY( b->child_idx!=ULONG_MAX ) ) { s = b->child_idx; b = fd_banks_bank_query( ctx->banks, s ); continue; }
      }
      while( s!=root_idx && b->sibling_idx==ULONG_MAX ) { s = b->parent_idx; b = fd_banks_bank_query( ctx->banks, s ); }
      if( s==root_idx ) break;
      s = b->sibling_idx; b = fd_banks_bank_query( ctx->banks, s );
    }
  }

  ulong advanceable_root_slot = bank->f.slot;
  fd_txncache_advance_root( ctx->txncache, bank->txncache_fork_id );
  fd_progcache_advance_root( ctx->progcache, bank->progcache_fork_id );
  fd_accdb_advance_root( ctx->accdb, bank->accdb_fork_id );
  fd_sched_advance_root( ctx->sched, advanceable_root_idx );
  fd_banks_advance_root( ctx->banks, advanceable_root_idx );
  if( ctx->reasm ) fd_reasm_publish( ctx->reasm, &advanceable_root_ele->latest_mr, ctx->store );

  for( ulong b=0UL; b<ctx->max_live_slots; b++ ) {
    if( FD_UNLIKELY( ctx->timing_slot_of_bank[ b ]!=fd_timing_slot_pool_idx_null( ctx->timing_slot_pool ) && !fd_banks_bank_query( ctx->banks, b ) ) ) timing_slot_release( ctx, b );
  }

  int snap_incremental;
  int snap_due = snapshot_due_for_root( ctx,
                                        published_root_block_height,
                                        advanceable_root_slot,
                                        bank->f.block_height,
                                        consensus_root_block_height,
                                        &snap_incremental );

  ctx->published_root_slot     = advanceable_root_slot;
  ctx->published_root_bank_idx = advanceable_root_idx;

  if( FD_UNLIKELY( snap_due ) ) {
    snapmk_start( ctx, stem, snap_incremental );
    if( FD_UNLIKELY( !snap_incremental ) ) {
      if( FD_UNLIKELY( ctx->snapmk.full_interval_blocks &&
                       bank->f.block_height>=ctx->snapmk.next_full_block_height ) ) {
        ulong interval = ctx->snapmk.full_interval_blocks;
        ctx->snapmk.next_full_block_height = ((bank->f.block_height/interval)+1UL)*interval;
      }
      if( FD_UNLIKELY( advanceable_root_slot>=ctx->snapmk.scheduled_at_slot ) ) {
        ctx->snapmk.scheduled_at_slot = ULONG_MAX;
      }
    }
    if( FD_UNLIKELY( ctx->snapmk.incremental_interval_blocks ) ) {
      ulong interval = ctx->snapmk.incremental_interval_blocks;
      ctx->snapmk.next_incremental_block_height = ((bank->f.block_height/interval)+1UL)*interval;
    }
  }

  return 1;
}

static int
try_prune_sched( fd_replay_tile_t * ctx ) {
  ulong bank_idx;
  int   pruned = 0;
  while( (bank_idx=fd_sched_pruned_block_next( ctx->sched ) )!=ULONG_MAX ) {
    fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
    FD_TEST( bank );
    /* An evicted bank drains here with its verdict final: every
       in-flight task has resolved, so still PRUNABLE means none ruled
       it invalid (that would have converted it to DEAD and reported a
       dead row), and this is the block's only row.  A frozen victim
       already reported a completed row. */
    if( FD_UNLIKELY( bank->state==FD_BANK_STATE_PRUNABLE && !bank->block_completed_nanos ) ) {
      fd_block_id_ele_t * ele = &ctx->block_id_arr[ bank_idx ];
      report_block_incomplete( ctx, ele->slot, ctx->alpenglow && ele->block_id_seen ? &ele->dmr : &ele->latest_mr, bank,
                               FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD,
                               FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_EVICTED );
    }
    bank->refcnt--;
    FD_LOG_DEBUG(( "bank (idx=%lu) refcnt decremented to %lu for sched", bank->idx, bank->refcnt ));
    pruned = 1;
  }
  return pruned;
}

static int
try_prune_bank( fd_replay_tile_t * ctx ) {
  fd_banks_prune_cancel_info_t cancel_info[ 1 ];

  int pruned = fd_banks_prune_one_bank( ctx->banks, cancel_info );
  switch( pruned ) {
    case 2: { /* pruning bank + cancellation is needed */
      fd_txncache_cancel_fork( ctx->txncache,  cancel_info->txncache_fork_id );
      fd_progcache_cancel_fork( ctx->progcache, cancel_info->progcache_fork_id );
      fd_accdb_purge( ctx->accdb, cancel_info->accdb_fork_id );
      __attribute__((fallthrough));
    }
    case 1: { /* pruning bank + no cancellation is needed */
      /* A sched block exists, and can be marked dead, for a bank as
         soon as its first FEC has been ingested, which can happen
         before the bank ever set itself up for actual execution (e.g. a
         block that parses as bad on its very first FEC).  So always
         instruct sched to prune the block whenever banks prunes the
         bank.  The txncache/progcache/accdb forks, on the other hand,
         are only created once the bank started actual execution. */
      fd_sched_cancel( ctx->sched, cancel_info->bank_idx );
      timing_slot_release( ctx, cancel_info->bank_idx );
      return 1;
    }
    case 0: /* no bank to prune */
      return 0;
    default:
      FD_LOG_ERR(( "unreachable" ));
  }
}

static int
try_evict_reasm( fd_replay_tile_t *  ctx,
                 fd_stem_context_t * stem ) {

  /* if reasm_evicted is set, publish starting from reasm_evicted down
     to the leaf node to repair so repair can re-request for it.
     reasm_evicted gets set when reasm tries to insert a FEC and there
     is no remaining capacity. */
  if( FD_LIKELY( !ctx->reasm_evicted ) ) return 0;

  /* Publish a notification to the repair tile that the Replay tile no
     longer has the FEC that was evicted.  This will make sure that the
     repair tile will re-request the FEC if it eventually gets
     confirmed so that Replay can still make forward progress. */
  fd_replay_fec_evicted_t evicted = (fd_replay_fec_evicted_t){ .mr = ctx->reasm_evicted->key, .slot = ctx->reasm_evicted->slot, .fec_set_idx = ctx->reasm_evicted->fec_set_idx, .bank_idx = ctx->reasm_evicted->bank_idx };
  fd_memcpy( fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk ), &evicted, sizeof(fd_replay_fec_evicted_t) );
  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_REASM_EVICTED, ctx->replay_out->chunk,  sizeof(fd_replay_fec_evicted_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_fec_evicted_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  /* eviction policy only evicts chains of nodes until there is a
     fork, so guaranteed that the evict path is always the left-child
     TODO: This should be abstracted away. */
  fd_reasm_pool_release( ctx->reasm, ctx->reasm_evicted );
  ctx->reasm_evicted = fd_reasm_child( ctx->reasm, ctx->reasm_evicted ); /* indexes into pool, safe to use */
  return 1;
}

static int
try_process_fec( fd_replay_tile_t *  ctx,
                 fd_stem_context_t * stem ) {

  /* If the reassembler has a fec that is ready, we should process it
     and pass it to the scheduler.

     We would also like to pace FEC ingestion such that we keep the exec
     tiles busy.  If there's a pending frag from one of the exec tiles,
     we would like to know about that asap, because that could unblock
     dispatching.  So we ingest FEC sets only if we are sure that there
     are no more exec tile notifications to process.  This delays FEC
     ingestion just enough so as to keep the exec tiles as busy as we
     can, and prevents us from being stuck ingesting a backlog of FEC
     sets, especially when there is a pending completion notification
     about a single-transaction chokepoint in the replay dispatcher DAG.
     Except that when we are leader or the reasm buffer is getting full,
     we prioritize FEC processing.  In the leader case, this is so we
     can get to the leader FEC sets asap and freeze the leader bank on
     time.  In the reasm full case, this is so we don't prematurely
     trigger eviction. */
  int evict_banks = 0;
  if( FD_LIKELY( (ctx->execrp_idle_cnt>=2UL*ctx->in_cnt || ctx->is_leader || fd_reasm_free( ctx->reasm )<=1UL) &&
                 can_process_fec( ctx, &evict_banks ) ) ) {
    fd_reasm_fec_t * fec = fd_reasm_pop( ctx->reasm );
    process_fec_set( ctx, stem, fec );
    ctx->execrp_idle_cnt = 0UL;
    return 1;
  }

  /* If we need to evict banks, gather one evictable bank.  The bank is
     marked prunable by fd_banks_get_evictable_bank and pruned once refs
     drain. */
  if( FD_UNLIKELY( evict_banks ) ) {
    ulong evictable_bank_idx = fd_banks_get_evictable_bank( ctx->banks, ctx->notified_root_bank );
    if( FD_UNLIKELY( evictable_bank_idx==ULONG_MAX ) ) {
      FD_LOG_DEBUG(( "replay has no banks to mark as prunable, it's possible that there is one bank already marked as prunable" ));
      return 0;
    }

    FD_LOG_WARNING(( "banks full, evicting bank (idx=%lu)", evictable_bank_idx ));

    timing_slot_release( ctx, evictable_bank_idx );

    if( FD_UNLIKELY( fd_sched_block_is_discarded( ctx->sched, evictable_bank_idx ) ) ) {
      fd_block_id_ele_t * ele = &ctx->block_id_arr[ evictable_bank_idx ];
      report_block_incomplete( ctx, ele->slot, ctx->alpenglow && ele->block_id_seen ? &ele->dmr : &ele->latest_mr, fd_banks_bank_query( ctx->banks, evictable_bank_idx ),
                               FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED );
    }

    /* Send a notification to other tiles to drop a reference to the
       evictable bank.  The RPC tile is the only tile which holds onto
       non-rooted banks, non-transiently. */
    fd_replay_drop_bank_ref_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
    fd_sched_block_abandon( ctx->sched, evictable_bank_idx, FD_SCHED_ABANDON_DISCARDED );
    msg->bank_idx = evictable_bank_idx;
    fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_DROP_BANK_REF, ctx->replay_out->chunk, sizeof(fd_replay_drop_bank_ref_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_drop_bank_ref_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

    return 1;
  }

  return 0;
}

static void
after_credit( fd_replay_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_UNLIKELY( !ctx->is_booted || !ctx->wfs_complete ) ) return;

  /* The overall priority for the replay tile in order is:
     1. Make sure replay has room to progress:
        a. evicting pending FECs from the reassembler
        b. queueing up evictable banks for pruning if needed
        c. clearing any pending bank eviction victims.
     2. Drain outstanding bank references from the scheduler.  This
        happens after a block gets completed or a fork gets pruned.
     3. Notify sched and bank consumers of a new consensus root, then
        advance the storage root once old references drain.
     4. Replay.  If there is work to do for replay, do it.  This is
        more important than ingesting more FEC sets.
     5. If replay has nothing to do, ingest more FEC sets.
     WARNING: The ordering here is VERY load bearing and it should not
     be changed without extreme caution. */

  if( FD_UNLIKELY( try_evict_reasm( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( try_prune_sched( ctx ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( try_notify_consensus_root( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( try_prune_bank( ctx ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( !ctx->alpenglow && try_become_leader( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( try_fini_leader( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( try_advance_published_root( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_LIKELY( try_replay( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_LIKELY( !ctx->alpenglow && try_process_fec( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  ctx->execrp_idle_cnt++;
}

static int
before_frag( fd_replay_tile_t * ctx,
             ulong              in_idx,
             ulong              seq FD_PARAM_UNUSED,
             ulong              sig ) {

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP_OUT && sig!=FD_GOSSIP_UPDATE_TAG_WFS_DONE ) ) return 1;
  return 0;
}

static void
process_exec_task_done( fd_replay_tile_t *          ctx,
                        fd_stem_context_t *         stem,
                        fd_execrp_task_done_msg_t * msg,
                        ulong                       sig ) {

  ulong exec_tile_idx = sig&0xFFFFFFFFUL;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
  FD_TEST( bank );
  bank->refcnt--;

  switch( sig>>32 ) {
    case FD_EXECRP_TT_TXN_EXEC: {
      ulong txn_idx = msg->txn_exec->txn_idx;
      if( FD_UNLIKELY( !ctx->identity_vote_rooted ) ) {
        /* Query the txn signature against our recently generated vote
           txn signatures.  If the query is successful, then we have
           seen our own vote transaction land and this should be marked
           in the bank.  We go through this exercise until we've seen
           our vote rooted. */
        fd_txn_p_t * txn_p = fd_sched_get_txn( ctx->sched, txn_idx );

        fd_pubkey_t * identity_pubkey_out = NULL;
        if( fd_vote_tracker_query_sig( ctx->vote_tracker, fd_type_pun_const( txn_p->payload+TXN( txn_p )->signature_off ), &identity_pubkey_out ) && fd_pubkey_eq( identity_pubkey_out, ctx->identity_pubkey ) ) {
          bank->f.identity_vote_idx = ctx->identity_idx;
        }
      }
      if( FD_UNLIKELY( !msg->txn_exec->is_committable && bank->state!=FD_BANK_STATE_DEAD) ) {
        /* Every transaction in a valid block has to execute.
           Otherwise, we should mark the block as dead.  Non-committable
           means the txn failed before account loading or failed the cost
           tracker; txn_err distinguishes the cases for telemetry. */
        int dead_reason;
        switch( msg->txn_exec->txn_err ) {
          case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT:
            dead_reason = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BLOCK_COST_LIMIT;
            break;
          case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT:
            dead_reason = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ACCOUNT_COST_LIMIT;
            break;
          case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT:
            dead_reason = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_VOTE_COST_LIMIT;
            break;
          case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT:
          case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT:
            dead_reason = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_ACCOUNT_DATA_LIMIT;
            break;
          case FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE: /* exec-path duplicate, same taxonomy as the chkdup ruling */
            dead_reason = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_DUPLICATE_ACCOUNT;
            break;
          default:
            dead_reason = FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_TXN_FAILED_TO_LOAD;
        }
        mark_bank_dead( ctx, stem, bank->idx, dead_reason, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
        fd_sched_block_abandon( ctx->sched, bank->idx, FD_SCHED_ABANDON_INVALID );
      }
      int res = fd_sched_task_done( ctx->sched, FD_SCHED_TT_TXN_EXEC, txn_idx, exec_tile_idx, NULL );
      FD_TEST( res==0 );
      fd_sched_txn_info_t * txn_info = fd_sched_get_txn_info( ctx->sched, txn_idx );
      txn_info->flags |= FD_SCHED_TXN_EXEC_DONE;
      txn_info->is_simple_vote = msg->txn_exec->is_simple_vote;
      txn_info->bank_seq = msg->txn_exec->bank_seq;

      txn_info->tick_load_start        = msg->txn_exec->tick_load_start;
      txn_info->tick_check_start       = msg->txn_exec->tick_check_start;
      txn_info->tick_exec_start        = msg->txn_exec->tick_exec_start;
      txn_info->tick_commit_start      = msg->txn_exec->tick_commit_start;
      txn_info->tick_commit_end        = msg->txn_exec->tick_commit_end;

      txn_info->compute_units_consumed = msg->txn_exec->compute_units_consumed;
      if( FD_LIKELY( bank->cost_tracker_pool_idx!=ULONG_MAX ) ) {
        fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_query( bank );
        txn_info->max_compute_units = cost_tracker->block_cost_limit ? cost_tracker->block_cost_limit : ULONG_MAX;
      }
      txn_info->transaction_fee        = msg->txn_exec->transaction_fee;
      txn_info->priority_fee           = msg->txn_exec->priority_fee;
      txn_info->tips                   = msg->txn_exec->tips;
      if( FD_LIKELY( !(txn_info->flags&FD_SCHED_TXN_SIGVERIFY_DONE)||!txn_info->txn_err ) ) { /* Set execution status if sigverify hasn't happened yet or if sigverify was a success. */
        txn_info->txn_err = msg->txn_exec->txn_err;
        txn_info->flags  |= fd_ulong_if( msg->txn_exec->is_committable, FD_SCHED_TXN_IS_COMMITTABLE, 0UL );
        txn_info->flags  |= fd_ulong_if( msg->txn_exec->is_fees_only,   FD_SCHED_TXN_IS_FEES_ONLY,   0UL );
        txn_info->flags  |= fd_ulong_if( msg->txn_exec->is_noop,        FD_SCHED_TXN_IS_NOOP,        0UL );
      }
      if( FD_UNLIKELY( (txn_info->flags&FD_SCHED_TXN_REPLAY_DONE)==FD_SCHED_TXN_REPLAY_DONE ) ) { /* UNLIKELY because generally exec happens before sigverify. */
        publish_txn_executed( ctx, stem, bank->idx, txn_idx );
      }
      break;
    }
    case FD_EXECRP_TT_TXN_SIGVERIFY: {
      ulong txn_idx = msg->txn_sigverify->txn_idx;
      fd_sched_txn_info_t * txn_info = fd_sched_get_txn_info( ctx->sched, txn_idx );
      txn_info->flags |= FD_SCHED_TXN_SIGVERIFY_DONE;
      if( FD_UNLIKELY( msg->txn_sigverify->err ) ) {
        txn_info->txn_err = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
        txn_info->flags  &= ~FD_SCHED_TXN_IS_COMMITTABLE;
        txn_info->flags  &= ~FD_SCHED_TXN_IS_FEES_ONLY;
        txn_info->flags  &= ~FD_SCHED_TXN_IS_NOOP;
      }
      if( FD_UNLIKELY( msg->txn_sigverify->err && bank->state!=FD_BANK_STATE_DEAD ) ) {
        /* Every transaction in a valid block has to sigverify.
           Otherwise, we should mark the block as dead.  Also freeze the
           bank if possible. */
        mark_bank_dead( ctx, stem, bank->idx, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_SIGVERIFY_FAILED, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
        fd_sched_block_abandon( ctx->sched, bank->idx, FD_SCHED_ABANDON_INVALID );
      }
      int res = fd_sched_task_done( ctx->sched, FD_SCHED_TT_TXN_SIGVERIFY, txn_idx, exec_tile_idx, NULL );
      FD_TEST( res==0 );
      if( FD_LIKELY( (txn_info->flags&FD_SCHED_TXN_REPLAY_DONE)==FD_SCHED_TXN_REPLAY_DONE ) ) {
        publish_txn_executed( ctx, stem, bank->idx, txn_idx );
      }
      break;
    }
    case FD_EXECRP_TT_POH_HASH: {
      int res = fd_sched_task_done( ctx->sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, exec_tile_idx, msg->poh_hash );
      if( FD_UNLIKELY( res && bank->state!=FD_BANK_STATE_DEAD ) ) {
        mark_bank_dead( ctx, stem, bank->idx, sched_dead_reason_to_event( res ), FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
      }
      break;
    }
    default: FD_LOG_CRIT(( "unexpected sig 0x%lx", sig ));
  }

  /* Reference counter just decreased, and an exec tile just got freed
     up.  If there's a need to be more aggressively pruning, we could
     check here if more slots just became publishable and publish.  Not
     publishing here shouldn't bloat the fork tree too much though.  We
     mark minority forks dead as soon as we can, and execution dispatch
     stops on dead blocks.  So shortly afterwards, dead blocks should be
     eligible for pruning as in-flight transactions retire from the
     execution pipeline. */

}

static void
process_tower_slot_done( fd_replay_tile_t *           ctx,
                         fd_stem_context_t *          stem,
                         fd_tower_slot_done_t const * msg,
                         ulong                        seq ) {

  /* This frag from tower tells us to:
     - Release an outstanding refernence on the replayed bank
     - Advance the consensus root if one has been supplied
     - Update the reset block */

  fd_bank_t * replay_bank = fd_banks_bank_query( ctx->banks, msg->replay_bank_idx );
  if( FD_UNLIKELY( !replay_bank ) ) FD_LOG_CRIT(( "invariant violation: bank not found for bank index %lu", msg->replay_bank_idx ));
  replay_bank->refcnt--;
  FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt decremented to %lu for tower", replay_bank->idx, msg->replay_slot, replay_bank->refcnt ));

  if( FD_LIKELY( msg->root_slot!=ULONG_MAX ) ) {
    FD_TEST( msg->root_slot>=ctx->consensus_root_slot );
    ctx->consensus_root_slot = msg->root_slot;
    ctx->consensus_root      = msg->root_block_id;
  }

  if( FD_UNLIKELY( fd_hash_eq( &msg->reset_block_id, &ctx->reset_cmr ) ) ) return;

  fd_block_id_ele_t * block_id_ele = fd_block_id_map_ele_query( ctx->block_id_map, &msg->reset_block_id, NULL, ctx->block_id_arr );
  if( FD_UNLIKELY( !block_id_ele ) ) {
    FD_LOG_WARNING(( "ignoring reset block update from tower because block has been evicted (slot=%lu)", msg->reset_slot ));
    return;
  }
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
  if( FD_UNLIKELY( !bank || bank->bank_seq!=block_id_ele->bank_seq || bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_LOG_WARNING(( "ignoring reset block update from tower because bank has been evicted (slot=%lu)", msg->reset_slot ));
    return;
  }

  ctx->reset_cmr             = msg->reset_block_id;
  ctx->reset_slot            = msg->reset_slot;
  ctx->reset_timestamp_nanos = fd_clock_tile_now( ctx->clock );
  if( FD_LIKELY( msg->root_slot!=ULONG_MAX ) ) FD_TEST( msg->root_slot<=msg->reset_slot );

  ulong min_leader_slot = fd_ulong_max( msg->reset_slot+1UL, fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot+1UL ) );
  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, min_leader_slot, ctx->identity_pubkey );
  if( FD_LIKELY( ctx->next_leader_slot != ULONG_MAX ) ) {
    double slot_duration_ticks = (double)bank->f.slot_params.ns_per_slot_adjusted*ctx->tick_per_ns;
    ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*slot_duration_ticks) + fd_tickcount();
  } else {
    ctx->next_leader_tickcount = LONG_MAX;
  }

  if( FD_LIKELY( ctx->replay_out->idx!=ULONG_MAX ) ) {
    fd_poh_reset_t * reset = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );

    reset->bank_idx         = bank->idx;
    reset->timestamp        = ctx->reset_timestamp_nanos;
    reset->completed_slot   = ctx->reset_slot;
    reset->hashcnt_per_tick = bank->f.slot_params.hashes_per_tick;
    reset->ticks_per_slot   = bank->f.ticks_per_slot;
    reset->tick_duration_ns = bank->f.slot_params.ns_per_slot_adjusted/reset->ticks_per_slot;

    fd_memcpy( reset->completed_cmr, &block_id_ele->latest_mr, sizeof(fd_hash_t) );

    fd_blockhashes_t const * block_hash_queue = &bank->f.block_hash_queue;
    fd_hash_t const * last_hash = fd_blockhashes_peek_last_hash( block_hash_queue );
    FD_TEST( last_hash );
    fd_memcpy( reset->completed_blockhash, last_hash->uc, sizeof(fd_hash_t) );

    ulong ticks_per_slot = bank->f.ticks_per_slot;
    if( FD_UNLIKELY( reset->hashcnt_per_tick==1UL ) ) {
      /* Low power producer, maximum of one microblock per tick in the slot */
      reset->max_microblocks_in_slot = ticks_per_slot;
    } else {
      /* See the long comment in after_credit for this limit */
      reset->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ticks_per_slot*(reset->hashcnt_per_tick-1UL) );
    }
    reset->next_leader_slot = ctx->next_leader_slot;
    reset->wfs_paused       = !ctx->wfs_complete;

    fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_RESET, ctx->replay_out->chunk, sizeof(fd_poh_reset_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_reset_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
  }

  FD_LOG_INFO(( "tower_slot_done(reset_slot=%lu, next_leader_slot=%lu, vote_slot=%lu, replay_slot=%lu, root_slot=%lu, seqno=%lu)", msg->reset_slot, ctx->next_leader_slot, msg->vote_slot, msg->replay_slot, msg->root_slot, seq ));
  try_become_leader( ctx, stem );

  ulong distance = 0UL;
  fd_bank_t * parent = bank;
  while( parent ) {
    if( FD_UNLIKELY( fd_hash_eq( &parent->f.block_id, &ctx->consensus_root ) ) ) break;
    parent = fd_banks_get_parent( ctx->banks, parent );
    distance++;
  }

  FD_MGAUGE_SET( REPLAY, ROOT_DISTANCE, distance );

}

static void
process_fec_complete( fd_replay_tile_t *         ctx,
                      ulong                      sig,
                      fd_repair_fec_complete_t * complete_msg ) {
  fd_shred_t const * shred = &complete_msg->fec.last_shred_hdr;

  fd_hash_t const * merkle_root         = &complete_msg->fec.merkle_root;
  fd_hash_t const * chained_merkle_root = &complete_msg->fec.chained_merkle_root;
  int               is_leader_fec       = sig == REPAIR_SIG_FEC_LEADER;
  int               data_complete       = !!( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
  int               slot_complete       = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );

  if( FD_UNLIKELY( sig==REPAIR_SIG_FEC_INVALID ) ) {
    /* FEC set detected as invalid based on duplicate confirmations.
       Nothing to do except remove from store.  If the FEC set is not in
       reasm, we can directly remove from store.  If the FEC set is in
       reasm, then we let reasm_publish handle it. */
    if( FD_LIKELY( !fd_reasm_query( ctx->reasm, merkle_root ) ) ) {
      fd_store_remove( ctx->store, merkle_root );
    }
    return;
  }

  /* Track the cluster tip: the highest slot seen in FEC sets from the
     network (leader FECs are our own blocks, not evidence of the tip). */
  if( FD_LIKELY( !is_leader_fec && ( ctx->catch_up_max_fec_slot==ULONG_MAX || shred->slot>ctx->catch_up_max_fec_slot ) ) ) {
    ctx->catch_up_max_fec_slot = shred->slot;
    ctx->catch_up_tip_advance_cnt++;
  }

  if( FD_UNLIKELY( shred->slot - shred->data.parent_off == fd_reasm_slot0( ctx->reasm ) && shred->fec_set_idx == 0) ) {
    chained_merkle_root = &fd_reasm_root( ctx->reasm )->key;
  }

  if( FD_UNLIKELY( fd_reasm_query( ctx->reasm, merkle_root ) ) ) return;
  fd_reasm_fec_t * fec = fd_reasm_insert( ctx->reasm, merkle_root, chained_merkle_root, shred->slot, shred->fec_set_idx, shred->data.parent_off, (ushort)(shred->idx - shred->fec_set_idx + 1), data_complete, slot_complete, is_leader_fec, ctx->store, &ctx->reasm_evicted );

  if( FD_UNLIKELY( !fec ) ) {
    /* reasm failed to insert.  We don't want to just put this back on
       the returnable_frag queue because it's unclear whether this FEC
       is truly something we want to process.  Therefore our best option
       is to punt it and "go around."  Either the FEC was invalid and
       was rejected or reasm_insert populates its last pool element with
       the data of the failed insert, so we make sure to publish the
       failed insert data to repair in after_credit. */
    fd_store_remove( ctx->store, merkle_root );
    return;
  }

  fec->fec_completed_ts_nanos = complete_msg->metrics.fec_completed_ts_nanos;
  if( FD_LIKELY( complete_msg->metrics.stats_valid ) ) {
    /* Repair builds these cumulative snapshots from fd_forest_blk_t,
       which is keyed by slot rather than block identity.  Retain only
       the newest valid snapshot for that slot. */
    fd_reception_stats_t * stats = &ctx->reception_stats[ fec->slot % ctx->reception_stats_cnt ];
    stats->slot        = fec->slot;
    stats->fec_set_idx = fec->fec_set_idx;
    stats->metrics     = complete_msg->metrics;
  }
}

/* Essentially an inlined version of try_process_fec that reads off the
   dcache directly, instead of the reasm out_queue.  TODO bank eviction
   state machine.
   All FECs processed by this function must be safe to be forever
   removed from the dcache. */
static void
process_rotor_fec( fd_replay_tile_t      * ctx,
                   fd_stem_context_t     * stem,
                   fd_rotor_replay_fec_t * fec ) {
  if( FD_LIKELY( !fec->is_leader && ( ctx->catch_up_max_fec_slot==ULONG_MAX || fec->slot>ctx->catch_up_max_fec_slot ) ) ) {
    ctx->catch_up_max_fec_slot = fec->slot;
    ctx->catch_up_tip_advance_cnt++;
  }

  /* A leader FEC arriving after its slot was aborted (or after a later
     leadership began) has no bank to bind to; drop it. */
  if( FD_UNLIKELY( fec->is_leader && ( !ctx->leader_bank || ctx->leader_bank->f.slot!=fec->slot ) ) ) return;

  ulong parent_bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( fec->fec_set_idx==0 ) ) {
    ag_block_id_t parent_key = ag_block_id( fec->parent_slot, fec->parent_block_id.uc );
    fd_block_id_ele_t * parent = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &parent_key, NULL, ctx->block_id_arr );
    FD_TEST( parent ); // guaranteed by can_process_rotor_fec
    parent_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, parent );
  } else {
    /* mid-slot FEC: rotor tile promises to populate block_id
       correctly for blocks with known block id.  If we are processing
       the last FEC set of a slot received through turbine though, the
       block_id_map will still be keyed with {0}, but the block_id on
       the FEC will have the computed DMR.  We first try to replay
       this FEC on a bank keyed with the computed DMR - if it doesn't
       exist, it must belong to the original turbine version. */
    ag_block_id_t key = { .slot = fec->slot };
    if( FD_LIKELY( fec->known_id )) {
      key = ag_block_id( fec->slot, fec->block_id.uc );
    }

    fd_block_id_ele_t * parent = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key, NULL, ctx->block_id_arr );
    FD_TEST( parent );
    parent_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, parent );
  }

  fd_bank_t * parent_bank = fd_banks_bank_query( ctx->banks, parent_bank_idx );
  FD_TEST( parent_bank );

  if( FD_UNLIKELY( parent_bank->state == FD_BANK_STATE_DEAD ) ) {
    FD_LOG_WARNING(( "parent bank is dead for slot %lu, fec set idx %u, parent slot %lu, dropping", fec->slot, fec->fec_set_idx, fec->parent_slot ));
    return;
  }

  // insert_fec_set equivalent
  ulong wait = (ulong)fd_log_wallclock();
  ulong work = wait;
  FD_STORE_SLOCK_BEGIN( ctx->store ) {
  ctx->metrics.store_query_acquire++;
  work = (ulong)fd_log_wallclock();
  fd_histf_sample( ctx->metrics.store_query_wait, work - wait );

  fd_store_fec_t * store_fec = fd_store_query( ctx->store, &fec->mr );
  ctx->metrics.store_query_cnt++;
  /* A missing store entry is expected: rotor (the store publisher)
     removes FEC sets on publish, so a FEC delivered for a slice that has
     since been pruned/rooted is no longer in the store.  Abandon the
     slice rather than dereference a NULL store_fec below (fd_store_fec_data
     and the sched copy would fault on it). */
  if( FD_UNLIKELY( !store_fec ) ) {
    ctx->metrics.store_query_missing_cnt++;
    ctx->metrics.store_query_missing_mr = fec->mr.ul[0];
    FD_BASE58_ENCODE_32_BYTES( fec->mr.key, key_b58 );
    FD_LOG_INFO(( "store fec for slot: %lu not present (pruned by publish); abandoning slice. root: %lu. merkle: %s", fec->slot, ctx->consensus_root_slot, key_b58 ));
    return;
  }

  long now = fd_log_wallclock();
  fd_block_id_ele_t * block_id_ele;
  fd_bank_t * bank;
  if( FD_UNLIKELY( fec->fec_set_idx==0U ) ) {
    bank = fec->is_leader ? ctx->leader_bank : fd_banks_new_bank( ctx->banks, parent_bank_idx, now, 0 );
    if( FD_UNLIKELY( fec->is_leader && ctx->leader_stats.slot==fec->slot ) ) {
      ctx->leader_stats.first_fec_returned_nanos = now;
    }

    block_id_ele = &ctx->block_id_arr[ bank->idx ];
    /* Clear the previous occupant of this reused bank idx  */
    if( FD_LIKELY( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &block_id_ele->block_info, NULL, ctx->block_id_arr )==block_id_ele ) ) {
      FD_TEST( fd_ag_block_id_map_ele_remove( ctx->ag_block_id_map, &block_id_ele->block_info, NULL, ctx->block_id_arr ) );
    }

    block_id_ele->block_id_seen  = 0;
    block_id_ele->bank_seq       = bank->bank_seq;
    block_id_ele->slot           = fec->slot;
    block_id_ele->latest_fec_idx = 0U;
    block_id_ele->block_info     = ag_block_id( fec->slot, fec->block_id.uc );

    FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, block_id_ele, ctx->block_id_arr ) );
  } else { /* FEC for the middle or end of a block */
    /* Assign bank idx + seqno to the FEC.  Update block id pool ele.
      The block stays keyed by {slot, 0} in the compound map. */
    block_id_ele = &ctx->block_id_arr[ parent_bank_idx ];
    block_id_ele->latest_fec_idx = fec->fec_set_idx;
    bank = fd_banks_bank_query( ctx->banks, parent_bank_idx );
  }

  block_id_ele->latest_mr = fec->mr;
  if( FD_UNLIKELY( fec->slot_complete ) ) {
    FD_BASE58_ENCODE_32_BYTES( fec->block_id.uc, block_id_b58 );
    FD_LOG_INFO(( "slot %lu fec set idx %u slot_bid %s is complete, inserted to map", fec->slot, fec->fec_set_idx, block_id_b58 ));
    block_id_ele->block_id_seen = 1;
    block_id_ele->dmr           = fec->block_id;

    /* block is complete and DMR block id is now known so re-key.  The
       map does not support duplicate keys: rotor guarantees at most one
       delivery stream per block (a turbine copy of a slot with a
       votor-driven version is abandoned in the chainer, see
       fd_rotor_tile.h), so {slot, block_id} can never already be
       occupied by another bank. */
    FD_TEST( fd_ag_block_id_map_ele_remove( ctx->ag_block_id_map, &block_id_ele->block_info, NULL, ctx->block_id_arr )==block_id_ele );
    block_id_ele->block_info = ag_block_id( fec->slot, fec->block_id.uc );
    FD_TEST( !fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &block_id_ele->block_info, NULL, ctx->block_id_arr ) );
    FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, block_id_ele, ctx->block_id_arr ) );
  }

  /* For leader FECs, don't insert the FEC into the scheduler. */
  if( FD_UNLIKELY( fec->is_leader ) ) return;

  /* Forks form a partial ordering over FEC sets. The Rotor tile
     delivers FEC sets in-order per fork, but FEC set ordering across
     forks is arbitrary */
  fd_sched_fec_t sched_fec[ 1 ];
  sched_fec->shred_cnt         = FD_FEC_SHRED_CNT;
  sched_fec->is_last_in_batch  = !!fec->data_complete;
  sched_fec->is_last_in_block  = !!fec->slot_complete;
  sched_fec->bank_idx          = bank->idx;
  sched_fec->parent_bank_idx   = bank->parent_idx;
  sched_fec->slot              = fec->slot;
  sched_fec->parent_slot       = fec->parent_slot;
  sched_fec->is_first_in_block = fec->fec_set_idx==0U;
  sched_fec->fec               = store_fec;
  sched_fec->data              = fd_store_fec_data( ctx->store, store_fec );
  sched_fec->alut_ctx->fork_id = fd_banks_bank_query( ctx->banks, ctx->published_root_bank_idx )->accdb_fork_id;
  sched_fec->alut_ctx->accdb   = ctx->accdb;
  sched_fec->alut_ctx->els     = ctx->published_root_slot;
  sched_fec->completed_ns      = now; // TODO deliver data with rotor

  if( sched_fec->is_first_in_block ) {
    bank->refcnt++;
    FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt incremented to %lu for sched", bank->idx, sched_fec->slot, bank->refcnt ));
  }

  if( FD_UNLIKELY( !fd_sched_fec_ingest( ctx->sched, sched_fec ) ) ) {
    int dr = sched_block_dead_reason_to_event( ctx, sched_fec->bank_idx );
    int ar = dr==FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD ? FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED
                                                               : FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED;
    mark_bank_dead( ctx, stem, sched_fec->bank_idx, dr, ar );
    return;
  }
  } FD_STORE_SLOCK_END;

  ctx->metrics.store_query_release++;
  fd_histf_sample( ctx->metrics.store_query_work, (ulong)fd_log_wallclock() - work );
  ctx->execrp_idle_cnt = 0UL;
  return;
}

static void
process_resolv_slot_completed( fd_replay_tile_t * ctx, ulong bank_idx ) {
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  FD_TEST( bank );
  bank->refcnt--;
  FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt decremented to %lu for resolv", bank->idx, bank->f.slot, bank->refcnt ));
}

static void
process_vote_txn_sent( fd_replay_tile_t *  ctx,
                       fd_txn_m_t *        txnm ) {
  /* The send tile has signed and sent a vote.  Add this vote to the
     vote tracker.  We go through this exercise until the client has
     seen a vote corresponding to the current identity rooted. */
  if( FD_UNLIKELY( !ctx->identity_vote_rooted ) ) {
    uchar *    payload = (uchar *)txnm + sizeof(fd_txn_m_t);
    uchar      txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    fd_txn_t * txn = (fd_txn_t *)txn_mem;
    if( FD_UNLIKELY( !fd_txn_parse( payload, txnm->payload_sz, txn_mem, NULL ) ) ) {
      FD_LOG_CRIT(( "Could not parse txn from send tile" ));
    }
    /* The identity of the validator that the signed the vote will
       always be the first signer in the vote transaction. */
    fd_pubkey_t * vote_identity = fd_type_pun( payload+txn->acct_addr_off );
    fd_vote_tracker_insert( ctx->vote_tracker, vote_identity, fd_type_pun_const( payload+txn->signature_off ) );
  }
}

static inline void
maybe_verify_shred_version( fd_replay_tile_t * ctx ) {
  if( FD_LIKELY( ctx->expected_shred_version && ctx->ipecho_shred_version ) ) {
    if( FD_UNLIKELY( ctx->expected_shred_version!=ctx->ipecho_shred_version ) ) {
      FD_LOG_ERR(( "shred version mismatch: expected %u but got %u from ipecho", ctx->expected_shred_version, ctx->ipecho_shred_version ) );
    }
  }

  /* During a cluster restart, the configured shred version is the post-
     restart value advertised by gossip.  Defer comparing it against the
     snapshot's hard fork list until wait-for-supermajority completes. */
  if( FD_UNLIKELY( ctx->wfs_enabled && !ctx->wfs_complete && ctx->expected_shred_version ) ) return;

  if( FD_LIKELY( ctx->has_genesis_hash && ctx->hard_fork_cnt!=ULONG_MAX && (ctx->expected_shred_version || ctx->ipecho_shred_version) ) ) {
    ushort expected_shred_version = ctx->expected_shred_version ? ctx->expected_shred_version : ctx->ipecho_shred_version;

    ushort actual_shred_version = compute_shred_version( ctx->genesis_hash->uc, ctx->hard_forks, ctx->hard_fork_cnt );

    if( FD_UNLIKELY( expected_shred_version!=actual_shred_version ) ) {
      FD_BASE58_ENCODE_32_BYTES( ctx->genesis_hash->uc, genesis_hash_b58 );
      FD_LOG_ERR(( "Your genesis.bin file at `%s` combined with the hard_forks from the loaded snapshot have produced "
                   "a shred version of %hu but the entrypoint you connected to on boot reported a shred version of %hu. "
                   "This likely means that the genesis.bin file you have is for a different cluster than the one you "
                   "are trying to connect to, you can delete it and restart the node to download the correct genesis "
                   "file automatically.", ctx->genesis_path, actual_shred_version, expected_shred_version ));
    }
  }
}

static inline void
maybe_verify_genesis_timestamp( fd_replay_tile_t * ctx ) {
  if( FD_LIKELY( !ctx->has_expected_genesis_timestamp || !ctx->has_genesis_timestamp ) ) return;
  if( FD_LIKELY( ctx->genesis_timestamp==ctx->expected_genesis_timestamp ) ) return;

  FD_LOG_ERR(( "Your genesis.bin file at `%s` has a genesis timestamp of %lu but the snapshot you loaded has a genesis "
               "timestamp of %lu. This either means that the genesis.bin file you have is for a different cluster than "
               "the one you are trying to connect to, or you have loaded a snapshot for the wrong cluster. In either "
               "case, you can delete the problematic file and restart the node to download the correct one automatically.",
               ctx->genesis_path, ctx->genesis_timestamp, ctx->expected_genesis_timestamp ));
}

static void
update_metric_identity_balance( fd_replay_tile_t *  ctx,
                                fd_accdb_fork_id_t  fork_id,
                                fd_pubkey_t const * identity ) {
  ulong identity_balance = fd_accdb_lamports( ctx->accdb, fork_id, identity->uc );
  FD_MGAUGE_SET( REPLAY, IDENTITY_BALANCE_LAMPORTS, identity_balance );
}

static void
update_metric_epoch_credits( fd_replay_tile_t *  ctx,
                             fd_bank_t const *   bank,
                             fd_accdb_fork_id_t  fork_id,
                             fd_pubkey_t const * vote_key ) {
  ulong epoch_credits = 0UL;
  fd_acc_t ro = fd_accdb_read_one( ctx->accdb, fork_id, vote_key->uc );
  if( FD_LIKELY( ro.lamports ) ) {
    fd_vote_state_versioned_t vsv[1];
    if( FD_LIKELY( fd_vote_state_versioned_deserialize( vsv, ro.data, ro.data_len ) ) ) {
      fd_vote_epoch_credits_t const * ec = fd_vsv_get_epoch_credits( vsv );
      if( !deq_fd_vote_epoch_credits_t_empty( ec ) ) {
        fd_vote_epoch_credits_t const * last_ec = deq_fd_vote_epoch_credits_t_peek_tail_const( ec );
        if( last_ec->epoch==bank->f.epoch ) {
          epoch_credits = last_ec->credits;
        }
      }
    }
  }
  fd_accdb_unread_one( ctx->accdb, &ro );

  FD_MGAUGE_SET( REPLAY, EPOCH_CREDITS, epoch_credits );
}

static void
update_metric_active_stake( fd_bank_t const *   bank,
                            fd_pubkey_t const * vote_key ) {
  ulong my_active_stake  = 0UL;
  ulong tot_active_stake = bank->f.total_epoch_stake;

  ulong stake = 0UL;
  fd_vote_stakes_query_t_1( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, vote_key, NULL, &stake, NULL );
  my_active_stake = stake;

  FD_MGAUGE_SET( REPLAY, ACTIVE_STAKE_LAMPORTS,         my_active_stake  );
  FD_MGAUGE_SET( REPLAY, CLUSTER_ACTIVE_STAKE_LAMPORTS, tot_active_stake );
}

static void
update_metric_balances( fd_replay_tile_t * ctx,
                        fd_bank_t *        bank ) {
  fd_accdb_fork_id_t fork_id = bank->accdb_fork_id;
  fd_node_info_t node_info[1]; fd_node_info_read( node_info, ctx->node_info );
  if( !fd_pubkey_check_zero( &node_info->identity ) ) {
    update_metric_identity_balance( ctx, fork_id, &node_info->identity );
  }

  if( !fd_pubkey_check_zero( &node_info->vote_account ) ) {
    update_metric_epoch_credits( ctx, bank, fork_id, &node_info->vote_account );
    update_metric_active_stake (      bank,          &node_info->vote_account );
  }
}

static void
process_tower_optimistic_confirmed( fd_replay_tile_t *                ctx,
                                    fd_stem_context_t *               stem,
                                    fd_tower_slot_confirmed_t const * msg ) {

  fd_block_id_ele_t * block_id_ele = fd_block_id_map_ele_query( ctx->block_id_map, &msg->block_id, NULL, ctx->block_id_arr );
  if( FD_UNLIKELY( !block_id_ele ) ) {
    FD_BASE58_ENCODE_32_BYTES( msg->block_id.key, block_id_b58 );
    FD_LOG_WARNING(( "missing bank for confirmed block_id: %s level %d", block_id_b58, msg->level ));
    return;
  }

  ulong       bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele );
  fd_bank_t * bank     = fd_banks_bank_query( ctx->banks, bank_idx );

  if( FD_UNLIKELY( !bank || bank->bank_seq!=block_id_ele->bank_seq || bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_BASE58_ENCODE_32_BYTES( msg->block_id.key, block_id_cstr );
    FD_LOG_WARNING(( "failed to query optimistically confirmed bank for block id %s", block_id_cstr ));
    return;
  }

  if( ctx->rpc_enabled ) {
    bank->refcnt++;
    FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt incremented to %lu for rpc", bank->idx, bank->f.slot, bank->refcnt ));
  }

  fd_replay_oc_advanced_t * replay_msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  replay_msg->bank_idx = bank_idx;
  replay_msg->bank_seq = bank->bank_seq;
  replay_msg->slot = msg->slot;

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_OC_ADVANCED, ctx->replay_out->chunk, sizeof(fd_replay_oc_advanced_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_oc_advanced_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  update_metric_balances( ctx, bank );
}

/* snapmk_start instructs the snapmk tile to start producing a snapshot. */

static void
snapmk_start( fd_replay_tile_t *  ctx,
              fd_stem_context_t * stem,
              int                 incremental ) {

  FD_CHECK_CRIT( !ctx->snapmk.active, "snapshot creation already in progress" );

  /* pin current produced bank */
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, ctx->published_root_bank_idx );
  FD_CHECK_CRIT( bank, "invalid published_root_bank_idx" );

  if( FD_UNLIKELY( incremental ) ) {
    FD_CHECK_CRIT( ctx->snapmk.base_slot!=ULONG_MAX, "incremental snapshot without a base full snapshot" );
    FD_CHECK_CRIT( bank->f.slot>ctx->snapmk.base_slot, "incremental snapshot at or below its base slot" );
  }

  bank->refcnt++;
  ctx->snapmk.bank_idx    = bank->idx;
  ctx->snapmk.incremental = !!incremental;

  /* Send SNAP_START message to snapmk. */
  fd_replay_snap_start_t * msg = fd_chunk_to_laddr( ctx->snapmk_out->mem, ctx->snapmk_out->chunk );
  *msg = (fd_replay_snap_start_t) {
    .bank_idx  = ctx->published_root_bank_idx,
    .base_slot = incremental ? ctx->snapmk.base_slot : bank->f.slot,
    .slot      = bank->f.slot
  };
  ulong out_idx = ctx->snapmk_out->idx;
  ulong sig     = REPLAY_SIG_SNAP_START;
  ulong chunk   = ctx->snapmk_out->chunk;
  ulong tspub   = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz      = sizeof(fd_replay_snap_start_t);
  ulong seq     = fd_stem_publish( stem, out_idx, sig, chunk, sz, 0UL, 0UL, tspub );
  ctx->snapmk_out->chunk = fd_dcache_compact_next( ctx->snapmk_out->chunk, sz, ctx->snapmk_out->chunk0, ctx->snapmk_out->wmark );

  /* wake up the snapmk tile */
  fd_frag_meta_t * replay_snapmk = stem->mcaches[ out_idx ];
  ulong *          snap_sync     = fd_mcache_seq_laddr( replay_snapmk );
  fd_mcache_seq_update( snap_sync, fd_seq_inc( seq, 1UL ) );
  long ret = syscall( SYS_futex, snap_sync, FUTEX_WAKE, 1 );
  if( FD_UNLIKELY( ret<0 ) ) {
    FD_LOG_ERR(( "FUTEX_WAKE(snap_sync,seq=%u) failed (%i-%s)", (uint)seq, errno, fd_io_strerror( errno ) ));
  }

  /* update internal state */
  ctx->snapmk.active = 1;
}

/* snapmk_done reacts to the snapmk tile reporting completion. */

static void
snapmk_done( fd_replay_tile_t *  ctx,
             fd_stem_context_t * stem,
             int                 success ) {
  (void)stem;

  FD_CHECK_CRIT( ctx->snapmk.active, "spurious snap complete msg (not creating snapshot)" );

  /* release bank */
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, ctx->snapmk.bank_idx );
  FD_CHECK_CRIT( bank, "invalid snapmk.bank_idx" );
  FD_CHECK_CRIT( bank->refcnt > 0UL, "invalid snapmk.bank_idx refcnt" );

  /* A completed full snapshot becomes the base of later incrementals. */
  if( FD_LIKELY( success && !ctx->snapmk.incremental ) ) {
    ctx->snapmk.base_slot = bank->f.slot;
  }

  bank->refcnt--;
  ctx->snapmk.active = 0;
}

static void
msg_snapmk( fd_replay_tile_t *  ctx,
            fd_stem_context_t * stem,
            ulong               msg_type ) {
  switch( msg_type ) {
  case FD_SNAPMK_MSG_CREATED:
    snapmk_done( ctx, stem, 1 );
    break;
  case FD_SNAPMK_MSG_FAILED:
    snapmk_done( ctx, stem, 0 );
    break;
  default:
    break;
  }
}

/* admin command handlers
   every admin command must trigger one response frag */

static void
admin_respond( fd_replay_tile_t *  ctx,
               fd_stem_context_t * stem,
               ulong               orig,
               ulong               err ) {
  ulong ctl   = fd_frag_meta_ctl( orig, 0, 0, !!err );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, err, 0UL, 0UL, ctl, 0UL, tspub );
}

static void
admin_snap_create( fd_replay_tile_t *  ctx,
                   fd_stem_context_t * stem,
                   ulong               sig ) {
  ulong target_slot = sig;

  if( FD_UNLIKELY( !ctx->snapmk.supported ) ) {
    FD_LOG_WARNING(( "admin requested snapshot creation, but current config cannot create snapshots. increase [layout.snapzp_tile_count]?" ));
    admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

  if( FD_UNLIKELY( !ctx->is_booted ) ) {
    FD_LOG_WARNING(( "admin requested snapshot creation, but client has not yet started" ));
    admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_SNAPSHOT_CREATE_RESULT_NOT_READY );
    return;
  }

  if( FD_UNLIKELY( target_slot ) ) {
    if( FD_UNLIKELY( target_slot<=ctx->published_root_slot ) ) {
      FD_LOG_WARNING(( "admin requested snapshot creation at slot %lu, but rooting is already past it (published root slot %lu)", target_slot, ctx->published_root_slot ));
      admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_SNAPSHOT_CREATE_RESULT_SLOT_IN_PAST );
      return;
    }


    if( FD_UNLIKELY( ctx->snapmk.scheduled_at_slot!=ULONG_MAX &&
                     ctx->snapmk.scheduled_at_slot!=target_slot ) ) {
      FD_LOG_WARNING(( "admin requested snapshot creation at slot %lu, but a snapshot is already scheduled at slot %lu. ignoring ...", target_slot, ctx->snapmk.scheduled_at_slot ));
      admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_SNAPSHOT_CREATE_RESULT_BUSY );
      return;
    }

    ctx->snapmk.scheduled_at_slot = target_slot;
    FD_LOG_NOTICE(( "snapshot creation scheduled at slot %lu", target_slot ));
    admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_ADMINCTL_RESULT_SUCCESS );
    return;
  }

  if( FD_UNLIKELY( ctx->snapmk.active ) ) {
    FD_LOG_WARNING(( "admin requested snapshot creation, but currently busy creating another snapshot. ignoring ..." ));
    admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_SNAPSHOT_CREATE_RESULT_BUSY );
    return;
  }

  snapmk_start( ctx, stem, 0 );
  admin_respond( ctx, stem, FD_ADMINCTL_CMD_SNAP_CREATE, FD_ADMINCTL_RESULT_SUCCESS );
}

static void
msg_admin( fd_replay_tile_t *  ctx,
           fd_stem_context_t * stem,
           ulong               orig,
           ulong               sig ) {
  switch( orig ) {
  case FD_ADMINCTL_CMD_SNAP_CREATE:
    admin_snap_create( ctx, stem, sig );
    break;
  default:
    FD_LOG_CRIT(( "unknown admin cmd (orig=%lu, sig=%lu)", orig, sig ));
  }
}

static inline int
returnable_frag( fd_replay_tile_t *  ctx,
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
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  if( FD_UNLIKELY( sz!=0UL && (chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) )
    FD_LOG_CRIT(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[in_idx] ) {
    case IN_KIND_GENESIS: {
      fd_genesis_meta_t const * meta = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      ctx->has_genesis_hash = 1;
      ctx->has_genesis_timestamp = 1;
      ctx->genesis_timestamp = meta->creation_time_seconds;
      *ctx->genesis_hash = meta->genesis_hash;
      fd_node_info_write_begin( ctx->node_info );
      ctx->node_info->info.genesis_hash = *ctx->genesis_hash;
      fd_node_info_write_end( ctx->node_info );
      if( FD_LIKELY( meta->bootstrap ) ) {
        boot_genesis( ctx, stem, meta );
      } else {
        uchar const * genesis_blob = (uchar const *)( meta+1 );
        FD_TEST( fd_genesis_parse( ctx->genesis, genesis_blob, meta->blob_sz ) );
      }
      ctx->has_genesis_timestamp = 1;
      ctx->genesis_timestamp     = ctx->genesis->creation_time;

      maybe_verify_cluster_type( ctx );
      maybe_verify_shred_version( ctx );
      maybe_verify_genesis_timestamp( ctx );
      break;
    }
    case IN_KIND_IPECHO: {
      FD_TEST( sig && sig<=USHORT_MAX );
      ctx->ipecho_shred_version = (ushort)sig;
      maybe_verify_shred_version( ctx );
      break;
    }
    case IN_KIND_SNAP: {
      on_snapshot_message( ctx, stem, in_idx, chunk, sig );
      maybe_verify_cluster_type( ctx );
      maybe_verify_shred_version( ctx );
      maybe_verify_genesis_timestamp( ctx );
      break;
    }
    case IN_KIND_EXECRP: {
      process_exec_task_done( ctx, stem, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sig );
      ctx->execrp_idle_cnt = 0UL;
      break;
    }
    case IN_KIND_POH: {
      process_poh_message( ctx, stem, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_RESOLV: {
      fd_resolv_slot_exchanged_t * exchanged_slot = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      process_resolv_slot_completed( ctx, exchanged_slot->bank_idx );
      break;
    }
    case IN_KIND_TOWER: {
      if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_DONE ) ) {
        process_tower_slot_done( ctx, stem, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), seq );
      } else if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_CONFIRMED ) ) {
        fd_tower_slot_confirmed_t const * msg = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
        if( msg->level==FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC && !msg->fwd ) process_tower_optimistic_confirmed( ctx, stem, msg );
        if( msg->level==FD_TOWER_SLOT_CONFIRMED_DUPLICATE )               fd_reasm_confirm( ctx->reasm, &msg->block_id );
      } else if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_IGNORED ) ) {
        fd_tower_slot_ignored_t const * msg = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
        fd_tower_slot_done_t ignored = {
          .replay_slot     = msg->slot,
          .replay_bank_idx = msg->bank_idx,
          .vote_slot       = ULONG_MAX,
          .reset_slot      = ctx->reset_slot,     /* Use most recent reset slot */
          .reset_block_id  = ctx->reset_cmr,
          .root_slot       = ULONG_MAX
        };
        process_tower_slot_done( ctx, stem, &ignored, seq );
      }
      break;
    }
    case IN_KIND_VOTOR: {
      if( FD_LIKELY( sig==FD_VOTOR_SIG_ROOTED ) ) {
        fd_votor_rooted_t const * msg = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
        FD_TEST( msg->slot>ctx->consensus_root_slot );
        ctx->consensus_root_slot = msg->slot;
        ctx->consensus_root      = msg->block_id;
      } else if( FD_UNLIKELY( sig==FD_VOTOR_SIG_LEADER ) ) {
        try_become_leader_ag( ctx, stem, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      }
      break;
    }
    case IN_KIND_REPAIR: {
      /* Store and reasm follow the invariant that any FEC in the
         shred->out link, repair->out link, or reasm must be present in
         store.  If any FEC is rejected at this point, it must be
         removed from store.  See topology.c for more details. */
      if( FD_UNLIKELY( sig==REPAIR_SIG_FEC || sig==REPAIR_SIG_FEC_LEADER || sig==REPAIR_SIG_FEC_INVALID ) ) {
        process_fec_complete( ctx, sig, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      }
      if( FD_UNLIKELY( sig!=ROTOR_SIG_FEC_REPLAY ) ) break;

      /* process rotor incoming FECs. 1 to keep frag for retry, returning 0 consumes it. */

      fd_rotor_replay_fec_t * fec = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( !( ctx->execrp_idle_cnt>=2UL*ctx->in_cnt || ctx->is_leader ) ) ) return 1; /* pace behind exec notifications, retry */

      int evict_banks = 0;
      int res = can_process_rotor_fec( ctx, fec, &evict_banks );

        /* drain_rotor_fecs: a bank eviction broke the replayable chain of
           FECs delivered from rotor (we lost a parent we needed to
           replay off of).  While draining, ignore delivered FECs until
           one is replayable again (PROCESS_FEC_OK, i.e. its parent
           context is present), then resume normal processing. */
        if( FD_UNLIKELY( ctx->drain_rotor_fecs ) ) {
          if( FD_LIKELY( res==PROCESS_FEC_OK ) ) {
            ctx->drain_rotor_fecs = 0; /* chain re-established, resume */
          }
          else return 0;                  /* still broken, ignore */
        }

        switch( res ) {
          case PROCESS_FEC_OK: {
            process_rotor_fec( ctx, stem, fec );
            return 0;
          }
          case PROCESS_FEC_DROP: {
            /* enter drain state */
            ctx->drain_rotor_fecs = 1;
            fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_MISSING_FEC, ctx->replay_out->chunk, 0, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
            ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_oc_advanced_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
            return 0;
          }
          case PROCESS_FEC_SKIP: { return 0; }
          case PROCESS_FEC_WAIT: {
          /* queue an eviction, then retry the frag. */
          if( FD_UNLIKELY( evict_banks ) ) {
            ulong evictable_bank_idx = fd_banks_get_evictable_bank( ctx->banks, ctx->notified_root_bank );
            if( FD_UNLIKELY( evictable_bank_idx==ULONG_MAX ) ) {
              FD_LOG_DEBUG(( "replay has no banks to mark as prunable, it's possible that there is one bank already marked as prunable" ));
              return 1;
            }

            FD_LOG_WARNING(( "banks full, evicting bank (idx=%lu)", evictable_bank_idx ));

            timing_slot_release( ctx, evictable_bank_idx );

            if( FD_UNLIKELY( fd_sched_block_is_discarded( ctx->sched, evictable_bank_idx ) ) ) {
              fd_block_id_ele_t * ele = &ctx->block_id_arr[ evictable_bank_idx ];
              report_block_incomplete( ctx, ele->slot, ctx->alpenglow && ele->block_id_seen ? &ele->dmr : &ele->latest_mr, fd_banks_bank_query( ctx->banks, evictable_bank_idx ),
                                        FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_NOT_DEAD, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_PRUNED );
            }

            /* Send a notification to other tiles to drop a reference to the
                evictable bank.  The RPC tile is the only tile which holds onto
                non-rooted banks, non-transiently. */
            fd_replay_drop_bank_ref_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
            fd_sched_block_abandon( ctx->sched, evictable_bank_idx, FD_SCHED_ABANDON_DISCARDED );
            msg->bank_idx = evictable_bank_idx;
            fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_DROP_BANK_REF, ctx->replay_out->chunk, sizeof(fd_replay_drop_bank_ref_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
            ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_drop_bank_ref_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
          }
          return 1;
        }
        default:
          FD_LOG_CRIT(( "unhandled process_rotor_fec result: %d", res ));
      }
      break;
    }
    case IN_KIND_TXSEND: {
      process_vote_txn_sent( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_GOSSIP_OUT: {
      FD_TEST( sig==FD_GOSSIP_UPDATE_TAG_WFS_DONE );
      ctx->wfs_complete = 1;
      maybe_verify_shred_version( ctx );

      /* Recalculate next_leader_tickcount relative to now.  The
         original value was computed at boot time (in boot_genesis or
         on_snapshot_message). */
      ctx->next_leader_tickcount = LONG_MAX;
      if( FD_LIKELY( ctx->next_leader_slot!=ULONG_MAX ) ) {
        fd_block_id_ele_t * block_id_ele = fd_block_id_ele_query( ctx, ctx->alpenglow ? &ctx->reset_dmr : &ctx->reset_cmr, ctx->reset_slot );
        if( FD_LIKELY( block_id_ele ) ) {
          fd_bank_t * reset_bank = fd_banks_bank_query( ctx->banks, fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele ) );
          if( FD_LIKELY( reset_bank && reset_bank->bank_seq==block_id_ele->bank_seq && reset_bank->state!=FD_BANK_STATE_PRUNABLE ) ) {
            double slot_duration_ticks = (double)reset_bank->f.slot_params.ns_per_slot_adjusted*ctx->tick_per_ns;
            ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*slot_duration_ticks) + fd_tickcount();
          }
        }
      }

      FD_LOG_NOTICE(( "Done waiting for supermajority. More than 80 percent of cluster stake has joined." ));
      if( FD_LIKELY( ctx->replay_out->idx!=ULONG_MAX ) ) {
        fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_WFS_DONE, ctx->replay_out->chunk, 0UL, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
      }
      break;
    }
    case IN_KIND_RPC: {
      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, sig );
      FD_TEST( bank );
      bank->refcnt--;
      FD_LOG_DEBUG(( "bank (idx=%lu, slot=%lu) refcnt decremented to %lu for %s", bank->idx, bank->f.slot, bank->refcnt, ctx->in_kind[ in_idx ]==IN_KIND_RPC ? "rpc" : "gui" ));
      break;
    }
    case IN_KIND_SNAPMK:
      msg_snapmk( ctx, stem, sig );
      break;
    case IN_KIND_ADMIN:
      msg_admin( ctx, stem, fd_frag_meta_ctl_orig( ctl ), sig );
      break;
    default:
      FD_LOG_ERR(( "unhandled kind %d", ctx->in_kind[ in_idx ] ));
  }

  return 0;
}

#undef PROCESS_FEC_DROP
#undef PROCESS_FEC_WAIT
#undef PROCESS_FEC_SKIP
#undef PROCESS_FEC_OK

static inline fd_replay_out_link_t
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

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_replay_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0 };

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_replay_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t), sizeof(fd_replay_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->replay.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, /* pubkey only: */ 1 ) );
  ctx->identity_idx         = 0UL;
  ctx->identity_dirty       = 0;

  ctx->bundle.enabled = tile->replay.bundle.enabled;
  if( FD_UNLIKELY( !tile->replay.bundle.vote_account_path[0] ) ) {
    ctx->bundle.enabled = 0;
  }

  if( FD_UNLIKELY( ctx->bundle.enabled ) ) {
    if( FD_UNLIKELY( !fd_base58_decode_32( tile->replay.bundle.vote_account_path, ctx->bundle.vote_account.uc ) ) ) {
      const uchar * vote_key = fd_keyload_load( tile->replay.bundle.vote_account_path, /* pubkey only: */ 1 );
      fd_memcpy( ctx->bundle.vote_account.uc, vote_key, 32UL );
    }
  }

  FD_TEST( fd_rng_secure( &ctx->rng_seed,           sizeof(ctx->rng_seed) ) );
  FD_TEST( fd_rng_secure( &ctx->blockhash_seed,     sizeof(ulong) )         );
  FD_TEST( fd_rng_secure( &ctx->reasm_seed,         sizeof(ulong) )         );
  FD_TEST( fd_rng_secure( &ctx->vote_tracker_seed,  sizeof(ulong) )         );
  FD_TEST( fd_rng_secure( &ctx->block_id_map_seed,  sizeof(ulong) )         );
  FD_TEST( fd_rng_secure( &ctx->ag_block_id_map_seed, sizeof(ulong) )       );
  FD_TEST( fd_rng_secure( &ctx->initial_block_id,   sizeof(fd_hash_t) )     );
  FD_TEST( fd_rng_secure( &ctx->runtime_stack_seed, sizeof(ulong) )         );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  void * reasm_mem = NULL;
  void * block_id_map_mem = NULL;
  ulong chain_cnt = fd_block_id_map_chain_cnt_est( tile->replay.max_live_slots );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t),   sizeof(fd_replay_tile_t) );
  void * runtime_stack_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_runtime_stack_align(),    fd_runtime_stack_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKED_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS ) );
  void * block_id_arr_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_id_ele_t),  sizeof(fd_block_id_ele_t) * tile->replay.max_live_slots );
  if( !tile->replay.alpenglow ) {
    block_id_map_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_block_id_map_align(),     fd_block_id_map_footprint( chain_cnt ) );
  } else {
    block_id_map_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_ag_block_id_map_align(),  fd_ag_block_id_map_footprint( chain_cnt ) );
  }
  void * _txncache          = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),         fd_txncache_footprint( tile->replay.max_live_slots ) );
  void * _accdb             = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),            fd_accdb_footprint( tile->replay.max_live_slots ) );
  if( !tile->replay.alpenglow ) {
    reasm_mem               = FD_SCRATCH_ALLOC_APPEND( l, fd_reasm_align(),            fd_reasm_footprint( tile->replay.fec_max ) );
  }
  void * recp_stats_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_reception_stats_t), sizeof(fd_reception_stats_t)*tile->replay.max_live_slots );
  void * sched_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_align(),            fd_sched_footprint( tile->replay.sched_depth, tile->replay.max_live_slots ) );
  void * vote_tracker_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_tracker_align(),     fd_vote_tracker_footprint() );
  void * _capture_ctx       = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint() );
  void * dump_proto_ctx_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dump_proto_ctx_t), sizeof(fd_dump_proto_ctx_t) );
  void * block_completed_ev = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_block_completed_t), sizeof(fd_event_block_completed_t) );
  void * timing_pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_timing_slot_pool_align(),  fd_timing_slot_pool_footprint( FD_REPLAY_TXN_TIMING_SLOTS ) );
  void * timing_of_bank_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),               tile->replay.max_live_slots*sizeof(ulong) );
  void * block_dump_ctx     = NULL;
  if( FD_UNLIKELY( tile->replay.dump_block_to_pb ) ) {
    block_dump_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_block_dump_context_align(), fd_block_dump_context_footprint() );
  }

  ctx->runtime_stack = fd_runtime_stack_join( fd_runtime_stack_new( runtime_stack_mem, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKED_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS, ctx->runtime_stack_seed ) );
  FD_TEST( ctx->runtime_stack );

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  ctx->leader_txn_timing = NULL;
  ulong ldr_tt_obj_id = fd_pod_query_ulong( topo->props, "ldr_tt", ULONG_MAX );
  if( FD_LIKELY( ldr_tt_obj_id!=ULONG_MAX ) ) ctx->leader_txn_timing = fd_topo_obj_laddr( topo, ldr_tt_obj_id );

  ulong node_info_obj_id = fd_pod_query_ulong( topo->props, "node_info", ULONG_MAX );
  FD_TEST( node_info_obj_id!=ULONG_MAX );
  ctx->node_info = fd_node_info_box_join( fd_topo_obj_laddr( topo, node_info_obj_id ) );
  FD_TEST( ctx->node_info );
  fd_node_info_write_begin( ctx->node_info );
  ctx->node_info->info.identity = *ctx->identity_pubkey;
  fd_node_info_write_end( ctx->node_info );

  FD_MGAUGE_SET( REPLAY, BANK_LIVE_MAX, fd_banks_pool_max_cnt( ctx->banks ) );

  ctx->consensus_root_slot = ULONG_MAX;
  ctx->consensus_root      = ctx->initial_block_id;
  ctx->notified_root_slot  = ULONG_MAX;
  ctx->notified_root       = ctx->initial_block_id;
  ctx->notified_root_bank = NULL;
  ctx->published_root_slot = ULONG_MAX;

  ctx->expected_shred_version = tile->replay.expected_shred_version;
  ctx->ipecho_shred_version = 0;
  fd_memcpy( ctx->genesis_path, tile->replay.genesis_path, sizeof(ctx->genesis_path) );
  ctx->has_genesis_hash = 0;
  ctx->has_cluster_type = 0;
  ctx->has_genesis_timestamp          = 0;
  ctx->has_expected_genesis_timestamp = 0;
  ctx->cluster_type = FD_CLUSTER_UNKNOWN;
  ctx->hard_fork_cnt = ULONG_MAX;
  ctx->has_manifest_block_id = 0;

  if( FD_UNLIKELY( ctx->bundle.enabled ) ) {
    if( FD_UNLIKELY( !fd_bundle_crank_gen_init( ctx->bundle.gen,
             (fd_acct_addr_t const *)tile->replay.bundle.tip_distribution_program_addr,
             (fd_acct_addr_t const *)tile->replay.bundle.tip_payment_program_addr,
             (fd_acct_addr_t const *)ctx->bundle.vote_account.uc,
             (fd_acct_addr_t const *)ctx->bundle.vote_account.uc, "NAN", 0UL ) ) ) {
      FD_LOG_ERR(( "failed to initialize bundle crank gen" ));
    }
  }

  FD_TEST( tile->replay.enable_features_cnt<=sizeof(ctx->enable_features)/sizeof(ctx->enable_features[0]) );
  ctx->enable_features_cnt = tile->replay.enable_features_cnt;
  for( ulong i=0UL; i<tile->replay.enable_features_cnt; i++ ) {
    fd_memcpy( ctx->enable_features[ i ], tile->replay.enable_features[ i ], FD_BASE58_ENCODED_32_SZ );
  }

  ulong progcache_obj_id; FD_TEST( (progcache_obj_id = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX ) )!=ULONG_MAX );
  FD_TEST( fd_progcache_shmem_join( ctx->progcache, fd_topo_obj_laddr( topo, progcache_obj_id       ) ) );

  fd_wksp_t * progcache_wksp = fd_wksp_containing( ctx->progcache->shmem );
  FD_TEST( progcache_wksp );
  fd_wksp_mon_init( ctx->progcache_wksp_mon, progcache_wksp, FD_WKSP_MON_DEFAULT_RATE, fd_tickcount() );

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->replay.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->replay.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );
  ctx->accdb = fd_accdb_join( fd_accdb_new( _accdb, accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL ) );
  FD_TEST( ctx->accdb );

  ctx->capture_ctx = NULL;
  if( FD_UNLIKELY( strcmp( "", tile->replay.solcap_capture ) ) ) {
    ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
    ctx->capture_ctx->solcap_start_slot = tile->replay.capture_start_slot;
    ctx->capture_ctx->capture_solcap = 1;
  }

  ctx->block_completed_event = block_completed_ev;

  ctx->timing_slot_pool = fd_timing_slot_pool_join( fd_timing_slot_pool_new( timing_pool_mem, FD_REPLAY_TXN_TIMING_SLOTS ) );
  FD_TEST( ctx->timing_slot_pool );
  ctx->timing_slot_of_bank = timing_of_bank_mem;
  for( ulong i=0UL; i<tile->replay.max_live_slots; i++ ) ctx->timing_slot_of_bank[ i ] = fd_timing_slot_pool_idx_null( ctx->timing_slot_pool );

  ctx->dump_proto_ctx = NULL;
  if( FD_UNLIKELY( strcmp( "", tile->replay.dump_proto_dir ) ) ) {
    ctx->dump_proto_ctx                        = dump_proto_ctx_mem;
    ctx->dump_proto_ctx->dump_proto_output_dir = tile->replay.dump_proto_dir;
    if( FD_LIKELY( tile->replay.dump_block_to_pb ) ) {
      ctx->dump_proto_ctx->dump_block_to_pb = !!tile->replay.dump_block_to_pb;
    }
  }

  if( FD_UNLIKELY( tile->replay.dump_block_to_pb ) ) {
    ctx->block_dump_ctx = fd_block_dump_context_join( fd_block_dump_context_new( block_dump_ctx ) );
  } else {
    ctx->block_dump_ctx = NULL;
  }

  ctx->is_booted = 0;

  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );

  fd_clock_tile_init( ctx->clock );

  ctx->larger_max_cost_per_block = tile->replay.larger_max_cost_per_block;

  FD_TEST( fd_rng_new( ctx->rng, ctx->rng_seed, 0UL ) );

  if( !tile->replay.alpenglow ) {
    ctx->reasm = fd_reasm_join( fd_reasm_new( reasm_mem, tile->replay.fec_max, ctx->reasm_seed ) );
  } else {
    ctx->reasm = NULL;
  }
  ctx->reception_stats     = recp_stats_mem;
  ctx->reception_stats_cnt = tile->replay.max_live_slots;
  FD_TEST( ctx->reception_stats_cnt );
  for( ulong i=0UL; i<ctx->reception_stats_cnt; i++ ) ctx->reception_stats[ i ].slot = ULONG_MAX;
  ctx->reasm_evicted = NULL;

  ctx->leader_stats.slot = ULONG_MAX;
  ctx->alpenglow         = tile->replay.alpenglow;
  ctx->sched = fd_sched_join( fd_sched_new( sched_mem, ctx->rng, tile->replay.sched_depth, tile->replay.max_live_slots, fd_topo_tile_name_cnt( topo, "execrp" ), ctx->alpenglow ) );
  FD_TEST( ctx->sched );
  FD_TEST( ctx->alpenglow || ctx->reasm );

  ctx->in_cnt          = tile->in_cnt;
  ctx->execrp_idle_cnt = 0UL;

  ctx->vote_tracker = fd_vote_tracker_join( fd_vote_tracker_new( vote_tracker_mem, ctx->vote_tracker_seed ) );
  FD_TEST( ctx->vote_tracker );

  ctx->identity_vote_rooted = 0;

  ctx->wait_for_vote_to_start_leader = tile->replay.wait_for_vote_to_start_leader;

  ctx->wfs_enabled = memcmp( tile->replay.wait_for_supermajority_with_bank_hash.uc, ((fd_pubkey_t){ 0 }).uc, sizeof(fd_pubkey_t) );
  ctx->expected_bank_hash = tile->replay.wait_for_supermajority_with_bank_hash;
  ctx->wfs_complete = !ctx->wfs_enabled;

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  ctx->is_leader             = 0;
  ctx->drain_rotor_fecs      = 0;
  ctx->supports_leader       = fd_topo_find_tile( topo, "pack", 0UL )!=ULONG_MAX;
  ctx->snapmk.active                        = 0;
  ctx->snapmk.supported                     = fd_topo_find_tile( topo, "snapmk", 0UL )!=ULONG_MAX;
  ctx->snapmk.scheduled_at_slot             = ULONG_MAX;
  ctx->snapmk.full_interval_blocks          = tile->replay.full_snapshot_interval_blocks;
  ctx->snapmk.next_full_block_height        = ULONG_MAX;
  ctx->snapmk.incremental_interval_blocks   = tile->replay.incremental_snapshot_interval_blocks;
  ctx->snapmk.next_incremental_block_height = ULONG_MAX;
  ctx->snapmk.base_slot                     = ULONG_MAX;
  if( FD_UNLIKELY( !ctx->snapmk.supported ) ) {
    ctx->snapmk.full_interval_blocks        = 0UL;
    ctx->snapmk.incremental_interval_blocks = 0UL;
  }
  ctx->reset_slot            = 0UL;
  ctx->reset_cmr             = ctx->initial_block_id;
  ctx->reset_dmr             = ctx->initial_block_id;
  ctx->reset_timestamp_nanos = 0UL;
  ctx->next_leader_slot      = ULONG_MAX;
  ctx->next_leader_tickcount = LONG_MAX;
  ctx->highwater_leader_slot = ULONG_MAX;

  ctx->caught_up                = 0;
  ctx->catch_up_max_fec_slot    = ULONG_MAX;
  ctx->catch_up_tip_advance_cnt = 0UL;
  ctx->boot_timestamp_nanos     = tile->replay.boot_timestamp_nanos;
  ctx->leader_bank = NULL;

  ctx->block_id_len   = tile->replay.max_live_slots;
  ctx->max_live_slots = tile->replay.max_live_slots;
  ctx->block_id_arr = (fd_block_id_ele_t *)block_id_arr_mem;

  if( !tile->replay.alpenglow ) {
    ctx->block_id_map = fd_block_id_map_join( fd_block_id_map_new( block_id_map_mem, chain_cnt, ctx->block_id_map_seed ) );
    FD_TEST( ctx->block_id_map );
    ctx->ag_block_id_map = NULL;
  } else {
    ctx->ag_block_id_map = fd_ag_block_id_map_join( fd_ag_block_id_map_new( block_id_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
    FD_TEST( ctx->ag_block_id_map );
    ctx->block_id_map = NULL;
  }

  for( ulong i=0UL; i<tile->replay.max_live_slots; i++ ) {
    ctx->block_id_arr[ i ].block_id_seen = 0;
    memset( &ctx->block_id_arr[ i ].block_info, 0, sizeof(ag_block_id_t) );
  }

  ctx->resolv_tile_cnt = fd_topo_tile_name_cnt( topo, "resolv" );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );
  ctx->halt_leader = 0;

  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( link->dcache ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
      ctx->in[ i ].mtu    = link->mtu;
    }

    if(      !strcmp( link->name, "genesi_out"    ) ) ctx->in_kind[ i ] = IN_KIND_GENESIS;
    else if( !strcmp( link->name, "ipecho_out"    ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( !strcmp( link->name, "snapin_manif"  ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
    else if( !strcmp( link->name, "execrp_replay" ) ) ctx->in_kind[ i ] = IN_KIND_EXECRP;
    else if( !strcmp( link->name, "poh_replay"    ) ) ctx->in_kind[ i ] = IN_KIND_POH;
    else if( !strcmp( link->name, "resolv_replay" ) ) ctx->in_kind[ i ] = IN_KIND_RESOLV;
    else if( !strcmp( link->name, "shred_out"     ) ) ctx->in_kind[ i ] = IN_KIND_REPAIR;
    else if( !strcmp( link->name, "repair_out"    ) ) ctx->in_kind[ i ] = IN_KIND_REPAIR;
    else if( !strcmp( link->name, "txsend_out"    ) ) ctx->in_kind[ i ] = IN_KIND_TXSEND;
    else if( !strcmp( link->name, "rpc_replay"    ) ) ctx->in_kind[ i ] = IN_KIND_RPC;
    else if( !strcmp( link->name, "gossip_out"    ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_OUT;
    else if( !strcmp( link->name, "snapmk_out"    ) ) ctx->in_kind[ i ] = IN_KIND_SNAPMK;
    else if( !strcmp( link->name, "admin_replay"  ) ) ctx->in_kind[ i ] = IN_KIND_ADMIN;
    else if( !strcmp( link->name, "tower_out"     ) ) ctx->in_kind[ i ] = IN_KIND_TOWER;
    else if( !strcmp( link->name, "votor_out"     ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));

    if( ctx->in_kind[ i ]==IN_KIND_ADMIN ) {
      FD_TEST( ( ctx->admin_out_idx = fd_topo_find_tile_out_link( topo, tile, "replay_admin", 0UL ) )!=ULONG_MAX );
    }
  }

  *ctx->epoch_out  = out1( topo, tile, "replay_epoch" ); FD_TEST( ctx->epoch_out->idx!=ULONG_MAX );
  *ctx->replay_out = out1( topo, tile, "replay_out"   ); FD_TEST( ctx->replay_out->idx!=ULONG_MAX );
  *ctx->snapmk_out = out1( topo, tile, "replay_snapmk" ); FD_TEST( ctx->snapmk.supported == (ctx->snapmk_out->idx!=ULONG_MAX) );
  *ctx->exec_out   = out1( topo, tile, "replay_execrp"  ); FD_TEST( ctx->exec_out->idx!=ULONG_MAX );

  ctx->rpc_enabled = fd_topo_find_tile( topo, "rpc", 0UL )!=ULONG_MAX;

  if( FD_UNLIKELY( strcmp( "", tile->replay.solcap_capture ) ) ) {
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "cap_repl", 0UL );
    FD_TEST( idx!=ULONG_MAX );
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ idx ] ];


    fd_capture_link_buf_t * cap_repl_out = ctx->cap_repl_out;
    cap_repl_out->base.vt = &fd_capture_link_buf_vt;
    cap_repl_out->idx     = idx;
    cap_repl_out->mem     = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    cap_repl_out->chunk0  = fd_dcache_compact_chunk0( cap_repl_out->mem, link->dcache );
    cap_repl_out->wmark   = fd_dcache_compact_wmark( cap_repl_out->mem, link->dcache, link->mtu );
    cap_repl_out->chunk   = cap_repl_out->chunk0;
    cap_repl_out->mcache  = link->mcache;
    cap_repl_out->depth   = fd_mcache_depth( link->mcache );
    cap_repl_out->seq     = 0UL;

    ctx->capture_ctx->capctx_type.buf  = cap_repl_out;
    ctx->capture_ctx->capture_link    = &cap_repl_out->base;
    ctx->capture_ctx->current_txn_idx = 0UL;


    ulong consumer_tile_idx = fd_topo_find_tile( topo, "solcap", 0UL );
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ consumer_tile_idx ];
    cap_repl_out->fseq = NULL;
    for( ulong j = 0UL; j < consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]  == link->id ) ) {
        cap_repl_out->fseq = fd_fseq_join( fd_topo_obj_laddr( topo, consumer_tile->in_link_fseq_obj_id[ j ] ) );
        FD_TEST( cap_repl_out->fseq );
        break;
      }
    }
  }

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_histf_join( fd_histf_new( ctx->metrics.store_query_wait,   FD_MHIST_SECONDS_MIN( REPLAY, STORE_QUERY_WAIT_SECONDS ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_QUERY_WAIT_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics.store_query_work,   FD_MHIST_SECONDS_MIN( REPLAY, STORE_QUERY_WORK_SECONDS ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_QUERY_WORK_SECONDS ) ) );

  /* Ensure precompiles are available, crash fast otherwise */
  fd_precompiles();

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_FN_UNUSED,
                          fd_topo_tile_t const * tile FD_FN_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  populate_sock_filter_policy_fd_replay_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), FD_ACCDB_FD_RW );
  return sock_filter_policy_fd_replay_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_FN_UNUSED,
                      fd_topo_tile_t const * tile FD_FN_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts db */

  return out_cnt;
}

static inline void
during_housekeeping( fd_replay_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_CHECK_CRIT( ctx->halt_leader, "state machine corruption" );
    FD_LOG_DEBUG(( "keyswitch: unhalting leader" ));
    ctx->halt_leader = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: halting leader" ));
    ctx->halt_leader = 1;
    if( !ctx->is_leader ) maybe_switch_identity( ctx );
  }
}

#undef DEBUG_LOGGING

/* counting carefully, after_credit can generate at most 8 frags and
   returnable_frag boot_genesis can generate at most 7 frags, so 15 is a
   conservative bound. */
#define STEM_BURST (15UL)

/* fd_tempo_lazy_default( 16384 ) where 16384 is the minimum out-link
   depth (i.e. cr_max) but excludes replay_epoch, which is so infrequent
   credit availability is a non-issue.   */
#define STEM_LAZY ((long)36865)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_replay_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_replay_tile_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_event_block_completed_t);
}

fd_topo_run_tile_t fd_tile_replay = {
  .name                     = "replay",
  .max_event_sz             = max_event_sz,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
