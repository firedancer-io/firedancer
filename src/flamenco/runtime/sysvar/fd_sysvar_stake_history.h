#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_stake_history_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_stake_history_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

/* FD_SYSVAR_STAKE_HISTORY_CAP is the max number of entries that the
   "stake history" sysvar will include.
   
   https://github.com/anza-xyz/agave/blob/6398ddf6ab8a8f81017bf675ab315a70067f0bf0/sdk/program/src/stake_history.rs#L12 */

#define FD_SYSVAR_STAKE_HISTORY_CAP (512UL)

FD_PROTOTYPES_BEGIN

/* The stake history sysvar contains the history of cluster-wide activations and de-activations per-epoch. Updated at the start of each epoch. */

/* Initialize the stake history sysvar account. */
void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx );

/* Update the stake history sysvar account - called during epoch boundary*/
void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *       slot_ctx,
                                fd_stake_history_entry_t * entry );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_stake_history_h */
