#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h

/* The clock sysvar provides an approximate measure of network time. */

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"
#include "fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND ( 160UL )
#define FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK  (12500UL)

FD_PROTOTYPES_BEGIN

/* The clock sysvar provides an approximate measure of network time. */

/* Initialize the clock sysvar account. */

void
fd_sysvar_clock_init( fd_bank_t *     bank,
                      fd_funk_t *     funk,
                      fd_funk_txn_t * funk_txn );

/* Update the clock sysvar account.  This should be called at the start
   of every slot, before execution commences. */

int
fd_sysvar_clock_update( fd_bank_t *     bank,
                        fd_funk_t *     funk,
                        fd_funk_txn_t * funk_txn,
                        fd_spad_t *     runtime_spad );

/* Writes the current value of the clock sysvar to funk. */

void
fd_sysvar_clock_write( fd_bank_t *             bank,
                       fd_funk_t *             funk,
                       fd_funk_txn_t *         funk_txn,
                       fd_sol_sysvar_clock_t * clock );

/* fd_sysvar_clok_read reads the current value of the rent sysvar from
   funk. If the account doesn't exist in funk or if the account
   has zero lamports, this function returns NULL. */

fd_sol_sysvar_clock_t const *
fd_sysvar_clock_read( fd_funk_t *     funk,
                      fd_funk_txn_t * funk_txn,
                      fd_spad_t *     spad );

/* fd_slot_cnt_2day returns the number of slots in two days.
   Used in rent collection. */

static inline ulong
fd_slot_cnt_2day( ulong ticks_per_slot ) {
  ulong seconds = (2UL * 24UL * 60UL * 60UL);
  ulong ticks   = seconds * FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK;
  return ticks / ticks_per_slot;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h */
