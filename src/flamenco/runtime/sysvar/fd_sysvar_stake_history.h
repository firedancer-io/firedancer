#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_stake_history_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_stake_history_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../../../funk/fd_funk.h"

/* FD_SYSVAR_STAKE_HISTORY_CAP is the max number of entries that the
   "stake history" sysvar will include.

   https://github.com/anza-xyz/agave/blob/6398ddf6ab8a8f81017bf675ab315a70067f0bf0/sdk/program/src/stake_history.rs#L12 */

#define FD_SYSVAR_STAKE_HISTORY_CAP (512UL)

FD_PROTOTYPES_BEGIN

/* The stake history sysvar contains the history of cluster-wide activations and de-activations per-epoch. Updated at the start of each epoch. */

/* Initialize the stake history sysvar account. */
void
fd_sysvar_stake_history_init( fd_bank_t *               bank,
                              fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx );

/* fd_sysvar_stake_history_read reads the stake history sysvar from funk.
   If the account doesn't exist in funk or if the account has zero
   lamports, this function returns NULL. */

fd_stake_history_t *
fd_sysvar_stake_history_read( fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid,
                              fd_spad_t *               spad );

/* Update the stake history sysvar account - called during epoch boundary */
void
fd_sysvar_stake_history_update( fd_bank_t *                                 bank,
                                fd_funk_t *                                 funk,
                                fd_funk_txn_xid_t const *                   xid,
                                fd_capture_ctx_t *                          capture_ctx,
                                fd_epoch_stake_history_entry_pair_t const * pair,
                                fd_spad_t *                                 runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_stake_history_h */
