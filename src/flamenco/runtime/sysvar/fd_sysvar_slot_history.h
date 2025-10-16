#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../fd_bank.h"

#define FD_SLOT_HISTORY_SLOT_FOUND     (0)
#define FD_SLOT_HISTORY_SLOT_FUTURE    (-1)
#define FD_SLOT_HISTORY_SLOT_NOT_FOUND (-2)
#define FD_SLOT_HISTORY_SLOT_TOO_OLD   (-3)

/* The slot history sysvar contains a bit-vector indicating which slots
   have been processed in the current epoch. */

/* Initialize the slot history sysvar account. */
void
fd_sysvar_slot_history_init( fd_bank_t *               bank,
                             fd_funk_t *               funk,
                             fd_funk_txn_xid_t const * xid,
                             fd_capture_ctx_t *        capture_ctx );

/* Update the slot history sysvar account. This should be called at the
   end of every slot, after execution has concluded. */
int
fd_sysvar_slot_history_update( fd_bank_t *               bank,
                               fd_funk_t *               funk,
                               fd_funk_txn_xid_t const * xid,
                               fd_capture_ctx_t *        capture_ctx );

/* fd_sysvar_slot_history_read reads the slot history sysvar from funk.
   If the account doesn't exist in funk or if the account has zero
   lamports, this function returns NULL. */

fd_slot_history_global_t *
fd_sysvar_slot_history_read( fd_funk_t *               funk,
                             fd_funk_txn_xid_t const * xid,
                             uchar                     out_mem[ static FD_SYSVAR_SLOT_HISTORY_FOOTPRINT ] );

int
fd_sysvar_slot_history_find_slot( fd_slot_history_global_t const * history,
                                  ulong                            slot );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h */
