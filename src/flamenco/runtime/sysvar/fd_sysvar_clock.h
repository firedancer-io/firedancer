#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

/* The clock sysvar provides an approximate measure of network time. */

/* Initialize the clock sysvar account. */
void fd_sysvar_clock_init( fd_global_ctx_t* global );

/* Update the clock sysvar account. This should be called at the start of every slot, before execution commences. */
int fd_sysvar_clock_update( fd_global_ctx_t* global );

/* Reads the current value of the clock sysvar */
int fd_sysvar_clock_read( fd_global_ctx_t* global, fd_sol_sysvar_clock_t* result );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h */
