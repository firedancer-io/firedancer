#ifndef HEADER_fd_src_ballet_runtime_fd_sysvar_fees_h
#define HEADER_fd_src_ballet_runtime_fd_sysvar_fees_h

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"

/* The fees sysvar contains the fee calculator for the current slot. */

/* Initialize the fees sysvar account. */
void fd_sysvar_fees_init( fd_global_ctx_t* global );

/* Reads the current value of the fees sysvar */
void fd_sysvar_fees_read( fd_global_ctx_t* global, fd_sysvar_fees_t* result );

#endif /* HEADER_fd_src_ballet_runtime_fd_sysvar_fees_h */

