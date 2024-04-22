#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h

#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_last_restart_slot_init creates or updates the "last restart
   slot" sysvar account using the information in the bank's implicit
   state. */

void
fd_sysvar_last_restart_slot_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_last_restart_slot_read queries the sysvar cache (?) for the
   slot number at which the last hard fork occurred.  This matches the
   highest slot number in the bank's "hard forks" list that is not in
   the future.  On success, returns 0 and writes *result.  On failure,
   returns an FD_ACC_MGR error code.  Reasons for error include that the
   "last restart slot sysvar" feature is not yet activated
   (FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT), or that there is a critical runtime
   error. */

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read( fd_sol_sysvar_last_restart_slot_t * result,
                                  fd_exec_slot_ctx_t const *          slot_ctx );

/* fd_sysvar_last_restart_slot_update performs a sysvar update before
   transaction processing.  TODO not completely implemented. */

void
fd_sysvar_last_restart_slot_update( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h */

