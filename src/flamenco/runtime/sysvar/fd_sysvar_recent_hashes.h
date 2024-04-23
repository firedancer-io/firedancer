#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_recent_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_recent_hashes_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

/* The recent hashes sysvar */

/* Initialize the recent hashes sysvar account. */
void
fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t * slot_ctx );

/* Update the recent hashes sysvar account. This should be called at the start of every slot, before execution commences. */
void
fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_recent_hashes_h */

