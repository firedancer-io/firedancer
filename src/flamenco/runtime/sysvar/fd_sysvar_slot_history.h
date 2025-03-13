#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_epoch_ctx.h"


#define FD_SLOT_HISTORY_SLOT_FOUND     (0)
#define FD_SLOT_HISTORY_SLOT_FUTURE    (-1)
#define FD_SLOT_HISTORY_SLOT_NOT_FOUND (-2)
#define FD_SLOT_HISTORY_SLOT_TOO_OLD   (-3)

/* The slot history sysvar contains a bit-vector indicating which slots have been processed in the current epoch. */

/* Initialize the slot history sysvar account. */
void
fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx,
                             fd_spad_t *          runtime_spad );

/* Update the slot history sysvar account. This should be called at the end of every slot, after execution has concluded. */
int
fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx,
                               fd_spad_t *          runtime_spad );

/* Reads the current value of the slot history sysvar */
fd_slot_history_t *
fd_sysvar_slot_history_read( fd_acc_mgr_t *  acc_mgr,
                             fd_funk_txn_t * funk_txn,
                             fd_spad_t *     spad );

int
fd_sysvar_slot_history_find_slot( fd_slot_history_t const * history,
                                  ulong                     slot );
#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h */
