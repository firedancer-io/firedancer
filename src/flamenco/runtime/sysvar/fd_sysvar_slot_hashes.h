#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h

#include "../context/fd_exec_slot_ctx.h"

/* The slot hashes sysvar contains the most recent hashes of the slot's parent bank hashes. */

/* FD_SYSVAR_SLOT_HASHES_CAP is the max number of entries that the
   "slot hashes" sysvar will include.

   https://github.com/anza-xyz/agave/blob/6398ddf6ab8a8f81017bf675ab315a70067f0bf0/sdk/program/src/slot_hashes.rs#L19 */

#define FD_SYSVAR_SLOT_HASHES_CAP   (512UL)
#define FD_SYSVAR_SLOT_HASHES_ALIGN (FD_SLOT_HASHES_GLOBAL_ALIGN)

FD_PROTOTYPES_BEGIN

/* Write a funk entry for the slot hashes sysvar account (exposed for tests) */

void
fd_sysvar_slot_hashes_init( fd_exec_slot_ctx_t * slot_ctx,
                            fd_spad_t *          runtime_spad );

/* Update the slot hashes sysvar account. This should be called at the end of every slot, before execution commences. */
void
fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx,
                              fd_spad_t *          runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h */
