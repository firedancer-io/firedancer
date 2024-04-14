#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h

/* fd_sysvar_clock provides an approximate measure of network time.
   Address: SysvarC1ock11111111111111111111111111111111 */

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND ( 160UL )
#define FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK  (12500UL)

FD_PROTOTYPES_BEGIN

int
fd_sysvar_clock_read( fd_sol_sysvar_clock_t * result,
                      fd_exec_slot_ctx_t *    slot_ctx );

/* fd_slot_cnt_2day returns the number of slots in two days.
   Used in rent collection. */

static inline ulong
fd_slot_cnt_2day( ulong ticks_per_slot ) {
  ulong seconds = (2UL * 24UL * 60UL * 60UL);
  ulong ticks   = seconds * FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND;
  return ticks / ticks_per_slot;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h */
