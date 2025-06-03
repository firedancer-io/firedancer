#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../context/fd_exec_slot_ctx.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_last_restart_slot_init creates or updates the "last restart
   slot" sysvar account using the information in the bank's implicit
   state. */

void
fd_sysvar_last_restart_slot_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_last_restart_slot_update performs a sysvar update before
   transaction processing.  TODO not completely implemented. */

void
fd_sysvar_last_restart_slot_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad );

/* fd_sysvar_last_restart_slot_read queries the last restart slot sysvar
   from the given funk. If the account doesn't exist in funk or if the
   account has zero lamports, this function returns NULL. */

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read( fd_funk_t *     funk,
                                  fd_funk_txn_t * funk_txn,
                                  fd_spad_t *     spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h */
