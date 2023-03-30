#ifndef HEADER_fd_src_ballet_runtime_sysvar_fd_clock_h
#define HEADER_fd_src_ballet_runtime_sysvar_fd_clock_h

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"

/* The clock sysvar provides an approximate measure of network time. */

/* Initialize the clock sysvar account. */
void fd_sysvar_clock_init( global_ctx_t* global, long genesis_creation_time, ulong slot, uint128 ns_per_slot );

/* Update the clock sysvar account. This should be called at the start of every slot, before execution commences. */
void fd_sysvar_clock_update( global_ctx_t* global );

#endif /* HEADER_fd_src_ballet_runtime_sysvar_fd_clock_h */

