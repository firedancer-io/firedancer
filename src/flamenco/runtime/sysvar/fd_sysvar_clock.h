#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h

/* The clock sysvar provides an approximate measure of network time. */

#include "../fd_bank.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND ( 160UL )
#define FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK  (12500UL)

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h */
