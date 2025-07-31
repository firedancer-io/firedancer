#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h

/* The clock sysvar provides an approximate measure of network time. */

#include "fd_sysvar_base.h"
#include "../../types/fd_types.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND ( 160UL )
#define FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK  (12500UL)

/* FD_SYSVAR_CLOCK_STAKE_WEIGHTS_MAX specifies the max number of stake
   weights processed in a clock update. */

#define FD_SYSVAR_CLOCK_STAKE_WEIGHTS_MAX (10240UL)

FD_PROTOTYPES_BEGIN

/* The clock sysvar provides an approximate measure of network time. */

/* fd_sysvar_clock_init initializes the sysvar account to genesis state. */

void
fd_sysvar_clock_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_clock_update updates the clock sysvar account.  Runs
   fd_calculate_stake_weighted_timestamp under the hood.  Should be
   called at the start of every slot before execution commences.
   Crashes the process with FD_LOG_ERR on failure. */

void
fd_sysvar_clock_update( fd_exec_slot_ctx_t * slot_ctx,
                        fd_spad_t *          spad );

/* Writes the current value of the clock sysvar to funk. */

void
fd_sysvar_clock_write( fd_exec_slot_ctx_t *    slot_ctx,
                       fd_sol_sysvar_clock_t * clock ) ;

/* fd_sysvar_clock_read reads the current value of the rent sysvar from
   funk. If the account doesn't exist in funk or if the account
   has zero lamports, this function returns NULL. */

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_funk_t *             funk,
                      fd_funk_txn_t *         funk_txn,
                      fd_sol_sysvar_clock_t * clock );

/* fd_calculate_stake_weighted_timestamp calculates a timestamp
   estimate.  Does not modify the slot context.  Walks all cached vote
   accounts (from the "bank") and calculates a unix timestamp estimate.
   The estimate is stored into *result_timestamp.  spad is used for
   scratch allocations (allocates a treap of size FD_SYSVAR_CLOCK_STAKE_WEIGHTS_MAX).
   Crashes the process with FD_LOG_ERR on failure (e.g. too many vote
   accounts). */

void
fd_calculate_stake_weighted_timestamp( fd_exec_slot_ctx_t * slot_ctx,
                                       long *               result_timestamp,
                                       fd_spad_t *          spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h */
