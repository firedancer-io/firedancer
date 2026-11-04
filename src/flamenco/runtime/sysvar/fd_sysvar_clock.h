#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h

/* The clock sysvar provides an approximate measure of network time. */

#include "../../fd_flamenco_base.h"
#include "../../accdb/fd_accdb.h"
#include "fd_sysvar_base.h"

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

/* fd_sysvar_clock_update_slot advances the clock sysvar's slot, epoch
   and leader_schedule_epoch at the start of a block.  The timestamp is
   left as the parent's.

   https://github.com/anza-xyz/agave/blob/386cf57c45e135d8a3a8b7d16877eb896f695c64/runtime/src/bank.rs#L2507

   At an epoch boundary the parent's timestamp becomes the epoch start
   timestamp. */

void
fd_sysvar_clock_update_slot( fd_bank_t *        bank,
                             fd_accdb_t *       accdb,
                             fd_capture_ctx_t * capture_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_clock_h */
