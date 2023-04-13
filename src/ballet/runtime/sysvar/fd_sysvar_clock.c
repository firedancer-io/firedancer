#include "fd_sysvar_clock.h"
#include "../fd_types.h"
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
long timestamp_from_genesis( fd_genesis_solana_t* gen, ulong current_slot ) {
  /* TODO: maybe make types of timestamps the same throughout the runtime codebase. as Solana uses a signed representation */
  return (long)(gen->creation_time + ( ( current_slot * ns_per_slot( gen->ticks_per_slot ) ) / NS_IN_S ) );
}

void write_clock( fd_global_ctx_t* global, fd_sol_sysvar_clock_t* clock ) {
  ulong          sz = fd_sol_sysvar_clock_size( clock );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_sol_sysvar_clock_encode( clock, &ptr );

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_clock, enc, sz, global->current_slot );
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

  void* input = (void *)raw_acc_data;
  fd_sol_sysvar_clock_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}

void fd_sysvar_clock_init( fd_global_ctx_t* global ) {
  long timestamp = timestamp_from_genesis( &global->genesis_block, global->current_slot );

  fd_sol_sysvar_clock_t clock = {
    .slot = 0,
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
  uint128 poh_estimate_offset = ns_per_slot( global->genesis_block.ticks_per_slot ) * global->current_slot;
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

  if ( global->timestamp_votes.votes.cnt == 0 ) {
    return timestamp_from_genesis( &global->genesis_block, global->current_slot );
  }

  /* TODO: actually take the stake-weighted median. For now, just take the first vote */
  ulong slots = global->current_slot - global->timestamp_votes.votes.elems[0].slot;
  uint128 ns_correction = ns_per_slot * slots;
  return global->timestamp_votes.votes.elems[0].timestamp  + (long) (ns_correction / NS_IN_S) ;
}

void fd_sysvar_clock_update( fd_global_ctx_t* global ) {
  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( global, &clock );

  long timestamp_estimate         = estimate_timestamp( global, ns_per_slot( global->genesis_block.ticks_per_slot ) );
  long bounded_timestamp_estimate = bound_timestamp_estimate( global, timestamp_estimate, clock.epoch_start_timestamp );
  if ( timestamp_estimate != bounded_timestamp_estimate ) {
    FD_LOG_NOTICE(( "corrected timestamp_estimate %ld to %ld", timestamp_estimate, bounded_timestamp_estimate ));
  }
  clock.slot                      = global->current_slot;
  clock.unix_timestamp            = bounded_timestamp_estimate;

  FD_LOG_INFO(( "Updated clock at slot %lu", global->current_slot ));
  FD_LOG_INFO(( "clock.slot: %lu", clock.slot ));
  FD_LOG_INFO(( "clock.epoch_start_timestamp: %ld", clock.epoch_start_timestamp ));
  FD_LOG_INFO(( "clock.epoch: %lu", clock.epoch ));
  FD_LOG_INFO(( "clock.leader_schedule_epoch: %lu", clock.leader_schedule_epoch ));
  FD_LOG_INFO(( "clock.unix_timestamp: %ld", clock.unix_timestamp ));

  write_clock( global, &clock );
}
