#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h

#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

void
fd_sysvar_last_restart_slot_init( fd_global_ctx_t * global );

void
fd_sysvar_last_restart_slot_read( fd_global_ctx_t *                   global,
                                  fd_sol_sysvar_last_restart_slot_t * result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_last_restart_slot_h */

