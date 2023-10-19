#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h

#include "../fd_executor.h"

/* The fees sysvar contains the fee calculator for the current slot. */

FD_PROTOTYPES_BEGIN
/* Initialize the fees sysvar account. */
void fd_sysvar_fees_init( fd_exec_slot_ctx_t * slot_ctx );

/* Reads the current value of the fees sysvar */
void fd_sysvar_fees_read( fd_exec_slot_ctx_t * slot_ctx, fd_sysvar_fees_t* result );

void fd_sysvar_fees_update( fd_exec_slot_ctx_t * slot_ctx );

void
fd_sysvar_fees_new_derived( fd_exec_slot_ctx_t * slot_ctx, fd_fee_rate_governor_t base_fee_rate_governor, ulong latest_singatures_per_slot );

/* Updates fees for every slot. */
void fd_sysvar_fees_update( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h */

