#include "fd_sysvar_clock.h"
#include "../fd_types.h"
#include "../../base58/fd_base58.h"
#include "fd_sysvar.h"

const ulong ns_in_s = 1000000000;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
const ulong default_ticks_per_second = 160;

/* The target tick duration, derived from the target tick rate.
 https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/poh_config.rs#L32 
  */
const uint128 default_target_tick_duration_ns = ns_in_s / default_ticks_per_second;

/* Calculates the target duration of a slot, in nanoseconds.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/genesis_config.rs#L222
   
   ticks_per_slot is found in the genesis block. The default value is 64, for a target slot duration of 400ms:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L22
    */
uint128 ns_per_slot( ulong ticks_per_slot ) {
  return default_target_tick_duration_ns * ticks_per_slot;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
long timestamp_from_genesis( fd_genesis_solana_t* gen, ulong current_slot ) {
  /* TODO: check correctness */
  /* TODO: make types of timestamps the same throughout the codebase */
  return (long)(gen->creation_time + ( ( current_slot * ns_per_slot( gen->ticks_per_slot ) ) / 1000000000 ));
}

void fd_sysvar_clock_init( global_ctx_t* global ) {

  /* Calculate timestamp estimate from Genesis config */
  long timestamp = timestamp_from_genesis( &global->gen, global->current_slot );

  /* Write the data to the clock account */
  fd_sol_sysvar_clock_t clock = {
    .slot = 0,
    .epoch = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 0,
    .unix_timestamp = timestamp,
  };
  ulong sz = fd_sol_sysvar_clock_size( &clock );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_sol_sysvar_clock_encode( &clock, &ptr );

  unsigned char pubkey[32];
  unsigned char owner[32];
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (unsigned char *) owner);
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (unsigned char *) pubkey);

  fd_sysvar_set( global, owner, pubkey, enc, sz, global->current_slot );
}



/* Estimates the current timestamp, using the stake-weighted median of the latest validator timestamp oracle votes received
   from each voting node:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2927

   Linear interpolation, using the target duration of a slot, is used to calculate the timestamp estimate for the current slot:

    timestamp = (stake-weighted median of vote timestamps) + ((target slot duration) * (slots since median timestamp vote was received))
 */
long estimate_timestamp( global_ctx_t* global, uint128 ns_per_slot ) {

  /* TODO: actually take the stake-weighted median. For now, just take the first vote */
  long estimate = global->timestamp_votes.votes.elems[0].timestamp + (long)( ns_per_slot * ( global->current_slot - global->timestamp_votes.votes.elems[0].slot ) );

  /*
  TODO: bound the estimate to ensure it stays within a certain range of the expected PoH clock:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13 */

  return estimate;
}

/* TODO: make this conform to usual sysvar interface */
void fd_sysvar_clock_update( FD_FN_UNUSED global_ctx_t* global ) {

  // long timestamp_estimate = estimate_timestamp( global, ns_per_slot( global->gen.ticks_per_slot ) );

  /* Read the clock sysvar from the account */

  /* Update the values */

  /* Write the account back to disk */

  /*
  Information we need:
  - Pubkeys of all the vote accounts
    - How to get these?
  - Slot in which the vote accounts were updated.
  - PoH slot duration estimate
  */

}
