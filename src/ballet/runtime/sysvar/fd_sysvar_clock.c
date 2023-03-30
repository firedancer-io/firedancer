#include "fd_sysvar_clock.h"
#include "../fd_types.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
long timestamp_from_genesis( long genesis_creation_time, ulong slot, uint128 ns_per_slot ) {
  /* TODO: check correctness */
  return genesis_creation_time + (long)( ( slot * ns_per_slot ) / 1000000000 );
}

void fd_sysvar_clock_init( global_ctx_t* global, long genesis_creation_time, ulong slot, uint128 ns_per_slot ) {

  /* Calculate timestamp estimate from Genesis config */
  long timestamp = timestamp_from_genesis( genesis_creation_time, slot, ns_per_slot );

  /* Write the data to the clock account */
  fd_sol_sysvar_clock_t clock = {
    .slot = 0,
    .epoch = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 0,
    .unix_timestamp = timestamp,
  };

  (void)clock;
  (void)global;

  /* TODO: give the account enough lamports to make it rent exempt */

  /* TODO: write the account to the funk database */
}

void fd_sysvar_clock_update( FD_FN_UNUSED global_ctx_t* global ) {

  /*
  Information we need:
  - Pubkeys of all the vote accounts
  - PoH slot duration estimate
  */

  /* Update the clock using a stake-weighted estimate of the latest
  (timestamp, slot) values received from voting validators in vote instructions:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L24

  Linear interpolation, using the Leader's PoH estimate for the real-world duration
  of a slot, is then used to calculate the timestamp estimate for the current slot:

    timestamp = (stake-weighted votes timestamp) + ((PoH slot duration estimate) * (slots since votes were received))

  This estimate is bounded to ensure it stays within a certain range of the PoH estimate:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13 */

}
