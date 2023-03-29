#include "fd_sysvar_clock.h"
#include "../fd_types.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
long timestamp_from_genesis(ulong slot, uint128 ns_per_slot) {
  return 0;
}

void fd_sysvar_clock_init() {

  /* Calculate timestamp estimate from Genesis config */
  long timestamp = timestamp_from_genesis();

  /*  */
  fd_sol_sysvar_clock_t clock = {
    .slot = 0,
    .epoch = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 0,
    .unix_timestamp = timestamp,
  };

}

void fd_sysvar_clock_update() {



}
