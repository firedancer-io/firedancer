#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"

#define FD_SLOT_HISTORY_SLOT_FUTURE (-1)
#define FD_SLOT_HISTORY_SLOT_FOUND (0)
#define FD_SLOT_HISTORY_SLOT_NOTFOUND (-2)
#define FD_SLOT_HISTORY_SLOT_TOO_OLD (-3)

/* The slot history sysvar contains a bit-vector indicating which slots have been processed in the current epoch. */

/* Initialize the slot history sysvar account. */
void fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx );

/* Update the slot history sysvar account. This should be called at the end of every slot, after execution has concluded. */
int fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx );

/* Reads the current value of the slot history sysvar */
int
fd_sysvar_slot_history_read( fd_exec_slot_ctx_t * slot_ctx,
                            fd_valloc_t valloc, 
                            fd_slot_history_t * out_history );

int
fd_sysvar_slot_history_find_slot( fd_slot_history_t const * history,
                                  ulong slot );
#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_history_h */
