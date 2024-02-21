#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_slot_ctx.h"

/* fd_sysvar_slot_hashes contains the most recent hashes of the slot's
   parent bank hashes. */

FD_PROTOTYPES_BEGIN

/* fd_sysvar_slot_hashes_read reads the slot hashes sysvar from the
   accounts manager.  On success, returns 0 and writes deserialized
   value into *result.  On failure, returns the bincode/acc_mgr error
   code. */

fd_slot_hashes_t *
fd_sysvar_slot_hashes_read( fd_slot_hashes_t *   result,
                            fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h */
