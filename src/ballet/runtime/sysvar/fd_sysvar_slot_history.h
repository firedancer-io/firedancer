#ifndef HEADER_fd_src_ballet_runtime_sysvar_fd_slot_history_h
#define HEADER_fd_src_ballet_runtime_sysvar_fd_slot_history_h

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"

/* The slot history sysvar contains a bit-vector indicating which slots have been processed in the current epoch. */

/* Initialize the slot history sysvar account. */
void fd_sysvar_slot_history_init( fd_global_ctx_t* global );

/* Update the slot history sysvar account. This should be called at the end of every slot, after execution has concluded. */
void fd_sysvar_slot_history_update( fd_global_ctx_t* global );

/* Reads the current value of the slot history sysvar */
void fd_sysvar_slot_history_read( fd_global_ctx_t* global, fd_slot_history_t* result );

#endif /* HEADER_fd_src_ballet_runtime_sysvar_fd_slot_history_h */

