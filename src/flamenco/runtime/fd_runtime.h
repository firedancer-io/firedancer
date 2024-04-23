#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

ulong
fd_runtime_calculate_fee( fd_exec_txn_ctx_t *   txn_ctx,
                          fd_txn_t const *      txn_descriptor,
                          fd_rawtxn_b_t const * txn_raw );

/* fd_features_restore loads all known feature accounts from the
   accounts database.  This is used when initializing bank from a
   snapshot. */

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_save_slot_bank( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_save_epoch_bank( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
