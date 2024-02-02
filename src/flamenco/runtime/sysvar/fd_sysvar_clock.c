#include "fd_sysvar_clock.h"
#include "fd_sysvar.h"
#include "../fd_executor.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L14 */
#define MAX_ALLOWABLE_DRIFT_FAST ( 25 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L16 */
#define MAX_ALLOWABLE_DRIFT_SLOW ( 150 )

/* Do all intermediate calculations at nanosecond precision, to mirror Solana's behaviour. */
#define NS_IN_S ( 1000000000 )

/* The target tick duration, derived from the target tick rate.
 https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/poh_config.rs#L32
  */
#define DEFAULT_TARGET_TICK_DURATION_NS ( NS_IN_S / DEFAULT_TICKS_PER_SECOND )

/* Calculates the target duration of a slot, in nanoseconds.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/genesis_config.rs#L222

   ticks_per_slot is found in the genesis block. The default value is 64, for a target slot duration of 400ms:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L22
*/
static uint128
ns_per_slot( ulong ticks_per_slot ) {
  return DEFAULT_TARGET_TICK_DURATION_NS * ticks_per_slot;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
static long
timestamp_from_genesis( fd_exec_slot_ctx_t * slot_ctx ) {
  /* TODO: maybe make types of timestamps the same throughout the runtime codebase. as Solana uses a signed representation */
  return (long)( slot_ctx->epoch_ctx->epoch_bank.genesis_creation_time + ( ( slot_ctx->slot_bank.slot * ns_per_slot( slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot ) ) / NS_IN_S ) );
}

static void
write_clock( fd_exec_slot_ctx_t *    slot_ctx,
             fd_sol_sysvar_clock_t * clock ) {
  ulong sz = fd_sol_sysvar_clock_size( clock );
  uchar enc[sz];
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if( fd_sol_sysvar_clock_encode( clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_encode failed"));

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, (fd_pubkey_t *) &fd_sysvar_clock_id, enc, sz, slot_ctx->slot_bank.slot, NULL );
}


fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_sol_sysvar_clock_t * result,
                      fd_exec_slot_ctx_t *    slot_ctx  ) {
  FD_BORROWED_ACCOUNT_DECL(acc);
  int rc = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_clock_id, acc );
  if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t ctx =
    { .data    = acc->const_data,
      .dataend = acc->const_data + acc->const_meta->dlen,
      .valloc  = {0}  /* valloc not required */ };

  if( FD_UNLIKELY( fd_sol_sysvar_clock_decode( result, &ctx )!=FD_BINCODE_SUCCESS ) )
    return NULL;
  return result;
}

void
fd_sysvar_clock_init( fd_exec_slot_ctx_t * slot_ctx ) {
  long timestamp = timestamp_from_genesis( slot_ctx );

  fd_sol_sysvar_clock_t clock = {
    .slot = slot_ctx->slot_bank.slot,
    .epoch = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 1,
    .unix_timestamp = timestamp,
  };
  write_clock( slot_ctx, &clock );
}

/* Bounds the timestamp estimate by the max allowable drift from the expected PoH slot duration.

https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L67 */
static long
bound_timestamp_estimate( fd_exec_slot_ctx_t * slot_ctx,
                          long                 estimate,
                          long                 epoch_start_timestamp ) {

  /* Determine offsets from start of epoch */
  /* TODO: handle epoch boundary case */
  uint128 poh_estimate_offset = ns_per_slot( slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot ) * slot_ctx->slot_bank.slot;
  uint128 estimate_offset = (uint128)( ( estimate - epoch_start_timestamp ) * NS_IN_S );

  uint128 max_delta_fast = ( poh_estimate_offset * MAX_ALLOWABLE_DRIFT_FAST ) / 100;
  uint128 max_delta_slow = ( poh_estimate_offset * MAX_ALLOWABLE_DRIFT_SLOW ) / 100;

  if ( ( estimate_offset > poh_estimate_offset ) && ( ( estimate_offset - poh_estimate_offset ) > max_delta_slow ) ) {
    return epoch_start_timestamp + (long)( poh_estimate_offset / NS_IN_S ) + (long)( max_delta_slow / NS_IN_S );
  } else if ( ( estimate_offset < poh_estimate_offset ) && ( ( poh_estimate_offset - estimate_offset ) > max_delta_fast ) ) {
    return epoch_start_timestamp + (long)( poh_estimate_offset / NS_IN_S ) + (long)( max_delta_fast / NS_IN_S );
  }

  return estimate;
}

/* Estimates the current timestamp, using the stake-weighted median of the latest validator timestamp oracle votes received
   from each voting node:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2927

   Linear interpolation, using the target duration of a slot, is used to calculate the timestamp estimate for the current slot:

    timestamp = (stake-weighted median of vote timestamps) + ((target slot duration) * (slots since median timestamp vote was received))
 */
static long
estimate_timestamp( fd_exec_slot_ctx_t * slot_ctx, uint128 ns_per_slot ) {
  /* TODO: bound the estimate to ensure it stays within a certain range of the expected PoH clock:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13 */

  fd_clock_timestamp_vote_t_mapnode_t * votes = slot_ctx->slot_bank.timestamp_votes.votes_root;
  if ( NULL == votes )
    return timestamp_from_genesis( slot_ctx );

  /* TODO: actually take the stake-weighted median. For now, just use the root node. */
  fd_clock_timestamp_vote_t * head = &votes->elem;
  ulong slots = slot_ctx->slot_bank.slot - head->slot;
  uint128 ns_correction = ns_per_slot * slots;
  return head->timestamp  + (long) (ns_correction / NS_IN_S) ;
}

static void
fd_calculate_stake_weighted_timestamp(
  fd_exec_slot_ctx_t * slot_ctx,
  long * result_timestamp,
  uint fix_estimate_into_u64
 ) {
  ulong slot_duration = (ulong)ns_per_slot( slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot );
  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( &clock, slot_ctx );
  // get the unique timestamps
  /* stake per timestamp */
  treap_t _treap[1];
  void * shmem = (void *)_treap;
  void * shtreap = treap_new( shmem, 10240UL );
  treap_t * treap = treap_join( shtreap );
  ele_t * pool = pool_join( pool_new( scratch, 10240UL ) );
  ulong total_stake = 0;

  fd_clock_timestamp_vote_t_mapnode_t * timestamp_votes_root = slot_ctx->slot_bank.timestamp_votes.votes_root;
  fd_clock_timestamp_vote_t_mapnode_t * timestamp_votes_pool = slot_ctx->slot_bank.timestamp_votes.votes_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_acc_root = slot_ctx->slot_bank.epoch_stakes.vote_accounts_root;
  fd_vote_accounts_pair_t_mapnode_t * vote_acc_pool = slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool;
  for (
    fd_vote_accounts_pair_t_mapnode_t* n = fd_vote_accounts_pair_t_map_minimum(vote_acc_pool, vote_acc_root);
    n;
    n = fd_vote_accounts_pair_t_map_successor(vote_acc_pool, n)
  ) {

 
  // for (
  //   fd_clock_timestamp_vote_t_mapnode_t * n = fd_clock_timestamp_vote_t_map_minimum(timestamp_votes_pool, timestamp_votes_root);
  //   n;
  //   n = fd_clock_timestamp_vote_t_map_successor(timestamp_votes_pool, n)
  // ) {
    /* get timestamp */
    fd_pubkey_t const * vote_pubkey = &n->elem.key;
    fd_clock_timestamp_vote_t_mapnode_t query_vote_acc_node;
    query_vote_acc_node.elem.pubkey = *vote_pubkey;
    fd_clock_timestamp_vote_t_mapnode_t * vote_acc_node = fd_clock_timestamp_vote_t_map_find(timestamp_votes_pool, timestamp_votes_root, &query_vote_acc_node);
    if( vote_acc_node == NULL ) {
      // FD_LOG_WARNING(("no vote acc: %32J", vote_pubkey->key));
      continue;
    }
    // FD_BORROWED_ACCOUNT_DECL(acc);
    // int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, vote_pubkey, acc);
    // FD_TEST( err == 0 );
    // fd_bincode_decode_ctx_t decode_ctx = {
    //   .data    = acc->const_data,
    //   .dataend = acc->const_data + acc->const_meta->dlen,
    //   .valloc  = fd_scratch_virtual(),
    // };
    // ulong vote_timestamp = 0UL;
    // ulong vote_slot = 0UL;  

    // uint discriminant = 0;
    // err = fd_bincode_uint32_decode(&discriminant, &decode_ctx);
    // if ( FD_UNLIKELY(err) ) {
    //   FD_LOG_ERR(( "vote_state_versioned_decode failed" ));
    // }
    // void const * enum_inner_start = decode_ctx.data;
    // ulong last_timestamp_off = 0;
    // if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( &vote_state, &decode ) ) )
    //   FD_LOG_ERR(( "vote_state_versioned_decode failed" ));
    // switch (discriminant) {
    //   case fd_vote_state_versioned_enum_current: {
    //     fd_vote_state_off_t off;
    //     int err = fd_vote_state_decode_offsets( &off, &decode_ctx );
    //     if( FD_UNLIKELY(err) ) {
    //       FD_LOG_ERR(( "vote_state_versioned_decode failed" ));
    //     }
    //     last_timestamp_off = off.last_timestamp_off;
    //     break;
    //   }
    //   case fd_vote_state_versioned_enum_v1_14_11: {
    //     fd_vote_state_1_14_11_off_t off;
    //     int err = fd_vote_state_1_14_11_decode_offsets( &off, &decode_ctx );
    //     if( FD_UNLIKELY(err) ) {
    //       FD_LOG_ERR(( "vote_state_versioned_decode failed" ));
    //     }
    //     last_timestamp_off = off.last_timestamp_off;
    //     break;
    //   }
    //   case fd_vote_state_versioned_enum_v0_23_5: {
    //      fd_vote_state_0_23_5_off_t off;
    //     int err = fd_vote_state_0_23_5_decode_offsets( &off, &decode_ctx );
    //     if( FD_UNLIKELY(err) ) {
    //       FD_LOG_ERR(( "vote_state_versioned_decode failed" ));
    //     }
    //     last_timestamp_off = off.last_timestamp_off;
    //     break;
    //   }
    //   default:
    //     __builtin_unreachable();
    // }

    // fd_vote_block_timestamp_t last_timestamp;
    // decode_ctx.data = (uchar const *)enum_inner_start + last_timestamp_off;
    // err = fd_vote_block_timestamp_decode( &last_timestamp, &decode_ctx );
    // if( FD_UNLIKELY(err) ) {
    //   FD_LOG_ERR(( "vote_state_versioned_decode failed" ));
    // }

    ulong vote_timestamp = (ulong)vote_acc_node->elem.timestamp;
    ulong vote_slot = vote_acc_node->elem.slot;
    // if( last_timestamp.slot != vote_slot || last_timestamp.timestamp != vote_timestamp ) {
    //   FD_LOG_WARNING(("clock %32J %lu %lu, %lu %lu", vote_pubkey, vote_slot, last_timestamp.slot, vote_timestamp, last_timestamp.timestamp));
    // }

    ulong slot_delta = fd_ulong_sat_sub(slot_ctx->slot_bank.slot, vote_slot);
    if (slot_delta > slot_ctx->epoch_ctx->epoch_bank.epoch_schedule.slots_per_epoch) {
      continue;
    }

    ulong offset = fd_ulong_sat_mul(slot_duration, slot_delta);
    long estimate = (long)vote_timestamp + (long)(offset / NS_IN_S);
    /* get stake */
    total_stake += n->elem.stake;
    ulong treap_idx = treap_idx_query( treap, estimate, pool );
    if ( FD_LIKELY( treap_idx < ULONG_MAX ) ) {
      pool[ treap_idx ].stake += n->elem.stake;
    } else {
      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].timestamp = estimate;
      pool[ idx ].stake = n->elem.stake;
      treap_idx_insert( treap, idx, pool );
    }
  }

  *result_timestamp = 0;
  if (total_stake == 0) {
    return;
  }

  // FIXME: this should be a uint128
  ulong stake_accumulator = 0;
  for (treap_fwd_iter_t iter = treap_fwd_iter_init ( treap, pool);
       !treap_fwd_iter_done( iter );
       iter = treap_fwd_iter_next( iter, pool ) ) {
    ulong idx = treap_fwd_iter_idx( iter );
    stake_accumulator = fd_ulong_sat_add(stake_accumulator, pool[ idx ].stake);
    // FD_LOG_WARNING(("Ts %ld Elem stake %lu Curr stake %lu Total stake cmp %lu", pool[ idx ].timestamp, pool[ idx ].stake, stake_accumulator, total_stake/2));
    if (stake_accumulator > (total_stake / 2)) {
      *result_timestamp = pool[ idx ].timestamp;
      break;
    }
  }

  FD_LOG_DEBUG(( "stake weighted timestamp: %lu total stake %lu", *result_timestamp, total_stake ));

  // Bound estimate by `max_allowable_drift` since the start of the epoch
  fd_epoch_schedule_t schedule;
  fd_sysvar_epoch_schedule_read( &schedule, slot_ctx );
  ulong epoch_start_slot = fd_epoch_slot0( &schedule, clock.epoch );
  FD_LOG_DEBUG(("Epoch start slot %lu", epoch_start_slot));
  ulong poh_estimate_offset = fd_ulong_sat_mul(slot_duration, fd_ulong_sat_sub(slot_ctx->slot_bank.slot, epoch_start_slot));
  ulong estimate_offset = fd_ulong_sat_mul(NS_IN_S, (fix_estimate_into_u64) ? fd_ulong_sat_sub((ulong)*result_timestamp, (ulong)clock.epoch_start_timestamp) : (ulong)(*result_timestamp - clock.epoch_start_timestamp));
  ulong max_delta_fast = fd_ulong_sat_mul(poh_estimate_offset, MAX_ALLOWABLE_DRIFT_FAST) / 100;
  ulong max_delta_slow = fd_ulong_sat_mul(poh_estimate_offset, MAX_ALLOWABLE_DRIFT_SLOW) / 100;
  FD_LOG_DEBUG(("poh offset %lu estimate %lu fast %lu slow %lu", poh_estimate_offset, estimate_offset, max_delta_fast, max_delta_slow));
  if (estimate_offset > poh_estimate_offset && fd_ulong_sat_sub(estimate_offset, poh_estimate_offset) > max_delta_slow) {
    *result_timestamp = clock.epoch_start_timestamp + (long)poh_estimate_offset / NS_IN_S + (long)max_delta_slow / NS_IN_S;
  } else if (estimate_offset < poh_estimate_offset && fd_ulong_sat_sub(poh_estimate_offset, estimate_offset) > max_delta_fast) {
    *result_timestamp = clock.epoch_start_timestamp + (long)poh_estimate_offset / NS_IN_S - (long)max_delta_fast / NS_IN_S;
  }

  FD_LOG_DEBUG(( "corrected stake weighted timestamp: %lu", *result_timestamp ));

  if (*result_timestamp < clock.unix_timestamp) {
    FD_LOG_DEBUG(( "updated timestamp to ancestor" ));
    *result_timestamp = clock.unix_timestamp;
  }
  return;
}

int
fd_sysvar_clock_update( fd_exec_slot_ctx_t * slot_ctx ) {

  fd_pubkey_t const * key = &fd_sysvar_clock_id;

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, key, rec);
  if (err)
    FD_LOG_CRIT(( "fd_acc_mgr_view(clock) failed: %d", err ));

  fd_bincode_decode_ctx_t ctx;
  ctx.data    = rec->const_data;
  ctx.dataend = rec->const_data + rec->const_meta->dlen;
  ctx.valloc  = slot_ctx->valloc;
  fd_sol_sysvar_clock_t clock;
  if( fd_sol_sysvar_clock_decode( &clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_decode failed"));

  long ancestor_timestamp = clock.unix_timestamp;

  if (slot_ctx->slot_bank.slot != 0) {
    fd_calculate_stake_weighted_timestamp(slot_ctx, &clock.unix_timestamp, FD_FEATURE_ACTIVE( slot_ctx, warp_timestamp_again ) );
  } else {
    FD_LOG_DEBUG(("SLOT IS ZERO!"));
  }

  if (0 == clock.unix_timestamp) {
    /* generate timestamp for genesis */
    long timestamp_estimate         = estimate_timestamp( slot_ctx, ns_per_slot( slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot ) );
    long bounded_timestamp_estimate = bound_timestamp_estimate( slot_ctx, timestamp_estimate, clock.epoch_start_timestamp );
    if ( timestamp_estimate != bounded_timestamp_estimate ) {
      FD_LOG_INFO(( "corrected timestamp_estimate %ld to %ld", timestamp_estimate, bounded_timestamp_estimate ));
    }
    /*  if let Some(timestamp_estimate) =
            self.get_timestamp_estimate(max_allowable_drift, epoch_start_timestamp)
        {
            unix_timestamp = timestamp_estimate;
            if timestamp_estimate < ancestor_timestamp {
                unix_timestamp = ancestor_timestamp;
            }
        } */
    if( bounded_timestamp_estimate < ancestor_timestamp ) {
      FD_LOG_DEBUG(( "clock rewind detected: %ld -> %ld", ancestor_timestamp, bounded_timestamp_estimate ));
      bounded_timestamp_estimate = ancestor_timestamp;
    }
    clock.unix_timestamp = bounded_timestamp_estimate;
  }

  clock.slot  = slot_ctx->slot_bank.slot;

  ulong epoch_old = clock.epoch;
  ulong epoch_new = fd_slot_to_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, clock.slot, NULL );
  FD_LOG_DEBUG(("Epoch old %lu new %lu slot %lu", epoch_old, epoch_new, clock.slot));
  clock.epoch = epoch_new;
  if( epoch_old != epoch_new ) {
    long timestamp_estimate = 0L;
    fd_calculate_stake_weighted_timestamp( slot_ctx, &timestamp_estimate, FD_FEATURE_ACTIVE( slot_ctx, warp_timestamp_again ) );
    clock.unix_timestamp = fd_long_max( timestamp_estimate, ancestor_timestamp );
    clock.epoch_start_timestamp = clock.unix_timestamp;
    clock.leader_schedule_epoch = fd_slot_to_leader_schedule_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot );
  }

  FD_LOG_DEBUG(( "Updated clock at slot %lu", slot_ctx->slot_bank.slot ));
  FD_LOG_DEBUG(( "clock.slot: %lu", clock.slot ));
  FD_LOG_DEBUG(( "clock.epoch_start_timestamp: %ld", clock.epoch_start_timestamp ));
  FD_LOG_DEBUG(( "clock.epoch: %lu", clock.epoch ));
  FD_LOG_DEBUG(( "clock.leader_schedule_epoch: %lu", clock.leader_schedule_epoch ));
  FD_LOG_DEBUG(( "clock.unix_timestamp: %ld", clock.unix_timestamp ));

  ulong               sz       = fd_sol_sysvar_clock_size(&clock);
  FD_BORROWED_ACCOUNT_DECL(acc);
  err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, key, 1, sz, acc);
  if (err)
    FD_LOG_CRIT(( "fd_acc_mgr_modify(clock) failed: %d", err ));

  fd_bincode_encode_ctx_t e_ctx = {
    .data    = acc->data,
    .dataend = acc->data+sz,
  };
  if( fd_sol_sysvar_clock_encode( &clock, &e_ctx ) )
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  ulong lamps = (sz + 128) * ((ulong) ((double)slot_ctx->epoch_ctx->epoch_bank.rent.lamports_per_uint8_year * slot_ctx->epoch_ctx->epoch_bank.rent.exemption_threshold));
  if( acc->meta->info.lamports < lamps )
    acc->meta->info.lamports = lamps;

  acc->meta->dlen = sz;
  fd_memcpy( acc->meta->info.owner, fd_sysvar_owner_id.key, 32 );

  return fd_acc_mgr_commit( slot_ctx->acc_mgr, acc, slot_ctx );
}
