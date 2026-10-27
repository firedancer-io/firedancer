#include "fd_sysvar_clock.h"
#include "fd_sysvar_epoch_schedule.h"
#include "../fd_system_ids.h"
#include "../sysvar/fd_sysvar.h"

/* Syvar Clock Possible Values:
  slot:
  [0, ULONG_MAX]

  epoch:
  [0, slot/432000UL]

  epoch_start_timestamp:
  [0, ULONG_MAX]

  leader_schedule_epoch:
  This is the value of the epoch used for the leader schedule.  It is
  computed based on the values of the epoch schedule (first_normal_slot,
  leader_schedule_slot_offset, slots_per_epoch).  It is always equal to
  ((slot - first_normal_slot) + leader_schedule_slot_offset) / schedule->slots_per_epoch
*/

/* Do all intermediate calculations at nanosecond precision, to mirror
   Solana's behavior. */
#define NS_IN_S ((long)1e9)

/* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2110-L2117 */
static inline long
unix_timestamp_from_genesis( fd_bank_t * bank ) {
  /* TODO: genesis_creation_time needs to be a long in the bank. */
  return fd_long_sat_add(
      (long)bank->f.genesis_creation_time,
      (long)( fd_uint128_sat_mul( bank->f.slot, bank->f.slot_params.ns_per_slot ) / NS_IN_S ) );
}

static void
fd_sysvar_clock_write( fd_bank_t *                   bank,
                       fd_accdb_t *                  accdb,
                       fd_capture_ctx_t *            capture_ctx,
                       fd_sol_sysvar_clock_t const * clock ) {
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_clock_id, clock, sizeof(fd_sol_sysvar_clock_t) );
}

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_accdb_t *            accdb,
                      fd_accdb_fork_id_t      fork_id,
                      fd_sol_sysvar_clock_t * clock ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, fd_sysvar_clock_id.uc );
  if( FD_UNLIKELY( !acc.lamports || acc.data_len<sizeof(fd_sol_sysvar_clock_t) ) ) {
    /* This check is needed as a quirk of the fuzzer. If a sysvar
       account exists in the accounts database, but doesn't have any
       lamports, this means that the account does not exist.  This
       wouldn't happen in a real execution environment. */
    fd_accdb_unread_one( accdb, &acc );
    return NULL;
  }

  fd_memcpy( clock, acc.data, sizeof(fd_sol_sysvar_clock_t) );
  fd_accdb_unread_one( accdb, &acc );
  return clock;
}

void
fd_sysvar_clock_init( fd_bank_t *        bank,
                      fd_accdb_t *       accdb,
                      fd_capture_ctx_t * capture_ctx ) {
  long timestamp = unix_timestamp_from_genesis( bank );

  fd_sol_sysvar_clock_t clock = {
    .slot                  = bank->f.slot,
    .epoch                 = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 1,
    .unix_timestamp        = timestamp,
  };
  fd_sysvar_clock_write( bank, accdb, capture_ctx, &clock );
}

void
fd_sysvar_clock_update_slot( fd_bank_t *        bank,
                             fd_accdb_t *       accdb,
                             fd_capture_ctx_t * capture_ctx ) {
  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t * clock = fd_sysvar_clock_read( accdb, bank->accdb_fork_id, clock_ );
  if( FD_UNLIKELY( !clock ) ) FD_LOG_ERR(( "fd_sysvar_clock_read failed" ));

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong current_epoch = fd_slot_to_epoch( epoch_schedule, bank->f.slot,        NULL );
  ulong parent_epoch  = fd_slot_to_epoch( epoch_schedule, bank->f.parent_slot, NULL );

  long epoch_start_timestamp;
  if(      FD_UNLIKELY( !bank->f.slot               ) ) epoch_start_timestamp = unix_timestamp_from_genesis( bank );
  else if( FD_UNLIKELY( parent_epoch!=current_epoch ) ) epoch_start_timestamp = clock->unix_timestamp;
  else                                                  epoch_start_timestamp = clock->epoch_start_timestamp;

  *clock = (fd_sol_sysvar_clock_t){
    .slot                  = bank->f.slot,
    .epoch_start_timestamp = epoch_start_timestamp,
    .epoch                 = current_epoch,
    .leader_schedule_epoch = fd_slot_to_leader_schedule_epoch( epoch_schedule, bank->f.slot ),
    .unix_timestamp        = clock->unix_timestamp, /* parent's footer timestamp */
  };
  fd_sysvar_clock_write( bank, accdb, capture_ctx, clock );
}
