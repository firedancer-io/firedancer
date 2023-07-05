#include "fd_sysvar_clock.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"


#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L14 */
#define MAX_ALLOWABLE_DRIFT_FAST ( 25 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L16 */
#define MAX_ALLOWABLE_DRIFT_SLOW ( 150 )

/* Do all intermediate calculations at nanosecond precision, to mirror Solana's behaviour. */
#define NS_IN_S ( 1000000000 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define DEFAULT_TICKS_PER_SECOND ( 160 )

/* The target tick duration, derived from the target tick rate.
 https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/poh_config.rs#L32
  */
#define DEFAULT_TARGET_TICK_DURATION_NS ( NS_IN_S / DEFAULT_TICKS_PER_SECOND )

/* Calculates the target duration of a slot, in nanoseconds.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/genesis_config.rs#L222

   ticks_per_slot is found in the genesis block. The default value is 64, for a target slot duration of 400ms:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L22
*/
uint128 ns_per_slot( ulong ticks_per_slot ) {
  return DEFAULT_TARGET_TICK_DURATION_NS * ticks_per_slot;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
long timestamp_from_genesis( fd_global_ctx_t* global ) {
  /* TODO: maybe make types of timestamps the same throughout the runtime codebase. as Solana uses a signed representation */
  return (long)(global->bank.genesis_creation_time + ( ( global->bank.slot * ns_per_slot( global->bank.ticks_per_slot ) ) / NS_IN_S ) );
}

void write_clock( fd_global_ctx_t* global, fd_sol_sysvar_clock_t* clock ) {
  ulong          sz = fd_sol_sysvar_clock_size( clock );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_sol_sysvar_clock_encode( clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_encode failed"));

  fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_clock, enc, sz, global->bank.slot );
}

void fd_sysvar_clock_read( fd_global_ctx_t* global, fd_sol_sysvar_clock_t* result ) {
  /* Read the clock sysvar from the account */
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_clock, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_clock, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  if ( fd_sol_sysvar_clock_decode( result, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_decode failed"));
}

void fd_sysvar_clock_init( fd_global_ctx_t* global ) {
  long timestamp = timestamp_from_genesis( global );

  fd_sol_sysvar_clock_t clock = {
    .slot = global->bank.slot,
    .epoch = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 1,
    .unix_timestamp = timestamp,
  };
  write_clock( global, &clock );
}

/* Bounds the timestamp estimate by the max allowable drift from the expected PoH slot duration.

https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L67 */
long bound_timestamp_estimate( fd_global_ctx_t* global, long estimate, long epoch_start_timestamp ) {

  /* Determine offsets from start of epoch */
  /* TODO: handle epoch boundary case */
  uint128 poh_estimate_offset = ns_per_slot( global->bank.ticks_per_slot ) * global->bank.slot;
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
long estimate_timestamp( fd_global_ctx_t* global, uint128 ns_per_slot ) {
  /* TODO: bound the estimate to ensure it stays within a certain range of the expected PoH clock:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13 */

  fd_clock_timestamp_vote_t_mapnode_t * votes = global->bank.timestamp_votes.votes_root;
  if ( NULL == votes )
    return timestamp_from_genesis( global );

  /* TODO: actually take the stake-weighted median. For now, just use the root node. */
  fd_clock_timestamp_vote_t * head = &votes->elem;
  ulong slots = global->bank.slot - head->slot;
  uint128 ns_correction = ns_per_slot * slots;
  return head->timestamp  + (long) (ns_correction / NS_IN_S) ;
}

void fd_sysvar_clock_update( fd_global_ctx_t* global ) {
  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( global, &clock );

  long timestamp_estimate         = estimate_timestamp( global, ns_per_slot( global->bank.ticks_per_slot ) );
  long bounded_timestamp_estimate = bound_timestamp_estimate( global, timestamp_estimate, clock.epoch_start_timestamp );
  if ( timestamp_estimate != bounded_timestamp_estimate ) {
    FD_LOG_INFO(( "corrected timestamp_estimate %ld to %ld", timestamp_estimate, bounded_timestamp_estimate ));
  }
  clock.slot                      = global->bank.slot;
  clock.unix_timestamp            = bounded_timestamp_estimate;

  FD_LOG_INFO(( "Updated clock at slot %lu", global->bank.slot ));
  FD_LOG_INFO(( "clock.slot: %lu", clock.slot ));
  FD_LOG_INFO(( "clock.epoch_start_timestamp: %ld", clock.epoch_start_timestamp ));
  FD_LOG_INFO(( "clock.epoch: %lu", clock.epoch ));
  FD_LOG_INFO(( "clock.leader_schedule_epoch: %lu", clock.leader_schedule_epoch ));
  FD_LOG_INFO(( "clock.unix_timestamp: %ld", clock.unix_timestamp ));

  write_clock( global, &clock );
}

//ulong fd_calculate_stake_weighted_timestamp(
//  fd_global_ctx_t* global,
//  fd_clock_timestamp_votes_t *unique_timestamps,
//  ulong slot,
//  ulong epoch_time

// pub(crate) fn calculate_stake_weighted_timestamp<I, K, V, T>(
//     unique_timestamps: I,
//     stakes: &HashMap<Pubkey, (u64, T /*Account|VoteAccount*/)>,
//     slot: Slot,
//     slot_duration: Duration,
//     epoch_start_timestamp: Option<(Slot, UnixTimestamp)>,
//     max_allowable_drift: MaxAllowableDrift,
//     fix_estimate_into_u64: bool,
// ) -> Option<UnixTimestamp>
// where
//     I: IntoIterator<Item = (K, V)>,
//     K: Borrow<Pubkey>,
//     V: Borrow<(Slot, UnixTimestamp)>,
// {
//     let mut stake_per_timestamp: BTreeMap<UnixTimestamp, u128> = BTreeMap::new();
//     let mut total_stake: u128 = 0;
//     for (vote_pubkey, slot_timestamp) in unique_timestamps {
//         let (timestamp_slot, timestamp) = slot_timestamp.borrow();
//         let offset = slot_duration.saturating_mul(slot.saturating_sub(*timestamp_slot) as u32);
//         let estimate = timestamp.saturating_add(offset.as_secs() as i64);
//         let stake = stakes
//             .get(vote_pubkey.borrow())
//             .map(|(stake, _account)| stake)
//             .unwrap_or(&0);
//         stake_per_timestamp
//             .entry(estimate)
//             .and_modify(|stake_sum| *stake_sum = stake_sum.saturating_add(*stake as u128))
//             .or_insert(*stake as u128);
//         total_stake = total_stake.saturating_add(*stake as u128);
//     }
//     if total_stake == 0 {
//         return None;
//     }
//     let mut stake_accumulator: u128 = 0;
//     let mut estimate = 0;
//     // Populate `estimate` with stake-weighted median timestamp
//     for (timestamp, stake) in stake_per_timestamp.into_iter() {
//         stake_accumulator = stake_accumulator.saturating_add(stake);
//         if stake_accumulator > total_stake / 2 {
//             estimate = timestamp;
//             break;
//         }
//     }
//     // Bound estimate by `max_allowable_drift` since the start of the epoch
//     if let Some((epoch_start_slot, epoch_start_timestamp)) = epoch_start_timestamp {
//         let poh_estimate_offset =
//             slot_duration.saturating_mul(slot.saturating_sub(epoch_start_slot) as u32);
//         let estimate_offset = Duration::from_secs(if fix_estimate_into_u64 {
//             (estimate as u64).saturating_sub(epoch_start_timestamp as u64)
//         } else {
//             estimate.saturating_sub(epoch_start_timestamp) as u64
//         });
//         let max_allowable_drift_fast =
//             poh_estimate_offset.saturating_mul(max_allowable_drift.fast) / 100;
//         let max_allowable_drift_slow =
//             poh_estimate_offset.saturating_mul(max_allowable_drift.slow) / 100;
//         if estimate_offset > poh_estimate_offset
//             && estimate_offset.saturating_sub(poh_estimate_offset) > max_allowable_drift_slow
//         {
//             // estimate offset since the start of the epoch is higher than
//             // `max_allowable_drift_slow`
//             estimate = epoch_start_timestamp
//                 .saturating_add(poh_estimate_offset.as_secs() as i64)
//                 .saturating_add(max_allowable_drift_slow.as_secs() as i64);
//         } else if estimate_offset < poh_estimate_offset
//             && poh_estimate_offset.saturating_sub(estimate_offset) > max_allowable_drift_fast
//         {
//             // estimate offset since the start of the epoch is lower than
//             // `max_allowable_drift_fast`
//             estimate = epoch_start_timestamp
//                 .saturating_add(poh_estimate_offset.as_secs() as i64)
//                 .saturating_sub(max_allowable_drift_fast.as_secs() as i64);
//         }
//     }
//     Some(estimate)
// }
