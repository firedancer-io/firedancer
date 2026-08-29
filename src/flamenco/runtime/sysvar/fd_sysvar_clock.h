#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h

/* The clock sysvar provides an approximate measure of network time. */

#include "../../fd_flamenco_base.h"
#include "../../accdb/fd_accdb.h"
#include "fd_sysvar_base.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK (12500UL)

/* ts_est_ele_t is a temporary struct used for sorting vote accounts by
   last vote timestamp for clock sysvar calculation. */
struct ts_est_ele {
  long        timestamp;
  fd_w_u128_t stake; /* should really be fine as ulong, but we match Agave */
};
typedef struct ts_est_ele ts_est_ele_t;

/* The clock sysvar provides an approximate measure of network time. */

/* fd_sysvar_clock_init initializes the sysvar account to genesis state. */

FD_PROTOTYPES_BEGIN

void
fd_sysvar_clock_init( fd_bank_t *        bank,
                      fd_accdb_t *       accdb,
                      fd_capture_ctx_t * capture_ctx );

/* fd_sysvar_clock_read reads the current value of the clock sysvar at
   fork_id into *clock.  Returns clock on success, NULL if the account
   is missing or too small. */

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_accdb_t *            accdb,
                      fd_accdb_fork_id_t      fork_id,
                      fd_sol_sysvar_clock_t * clock );

/* fd_sysvar_clock_update updates the clock sysvar account.  Runs
   fd_calculate_stake_weighted_timestamp under the hood.  Should be
   called at the start of every slot before execution commences.  Takes
   in a pointer to the parent_epoch, where *parent_epoch is the epoch of
   the parent slot.  parent_epoch = NULL is used for genesis bootup.
   Crashes the process with FD_LOG_ERR on failure. */

void
fd_sysvar_clock_update( fd_bank_t *          bank,
                        fd_accdb_t *         accdb,
                        fd_capture_ctx_t *   capture_ctx,
                        fd_runtime_stack_t * runtime_stack,
                        ulong const *        parent_epoch );

/* fd_sysvar_clock_update_slot_for_alpenglow advances the clock sysvar's
   slot, epoch and leader_schedule_epoch at the start of an alpenglow
   block, without the stake-weighted timestamp calculation.

   https://github.com/anza-xyz/agave/blob/386cf57c45e135d8a3a8b7d16877eb896f695c64/runtime/src/bank.rs#L2507

   At an epoch boundary the parent's timestamp becomes the epoch start
   timestamp. */

void
fd_sysvar_clock_update_slot_alpenglow( fd_bank_t *        bank,
                                       fd_accdb_t *       accdb,
                                       fd_capture_ctx_t * capture_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h */
