#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../context/fd_exec_slot_ctx.h"

/* The slot hashes sysvar contains the most recent hashes of the slot's parent bank hashes. */

/* Initialize the slot hashes sysvar account. */
// void fd_sysvar_slot_hashes_init( fd_exec_slot_ctx_t* global );

/* Update the slot hashes sysvar account. This should be called at the end of every slot, before execution commences. */
void fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx);

/* fd_sysvar_slot_hashes_read reads the slot hashes sysvar from the
   accounts manager.  On success, returns 0 and writes deserialized
   value into *result.  On failure, returns the bincode/acc_mgr error
   code. */
fd_slot_hashes_t *
fd_sysvar_slot_hashes_read( fd_slot_hashes_t *   result,
                            fd_exec_slot_ctx_t * slot_ctx );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h */

