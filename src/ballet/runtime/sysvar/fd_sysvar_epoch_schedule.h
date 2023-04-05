#ifndef HEADER_fd_src_ballet_runtime_sysvar_epoch_schedule_h
#define HEADER_fd_src_ballet_runtime_sysvar_epoch_schedule_h

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"

/* The epoch schedule sysvar contains epoch scheduling constants used to make various epoch-related calculations.
 */

/* Initialize the epoch schedule sysvar account. */
void fd_sysvar_epoch_schedule_init( fd_global_ctx_t* global );

/* Reads the current value of the epoch schedule sysvar */
void fd_sysvar_epoch_schedule_read( fd_global_ctx_t* global, fd_epoch_schedule_t* result );

#endif /* HEADER_fd_src_ballet_runtime_sysvar_epoch_schedule_h */

