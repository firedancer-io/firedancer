#ifndef HEADER_fd_src_flamenco_runtime_sysvar_epoch_schedule_h
#define HEADER_fd_src_flamenco_runtime_sysvar_epoch_schedule_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

/* The epoch schedule sysvar contains epoch scheduling constants used to make various epoch-related calculations.
 */

/* Initialize the epoch schedule sysvar account. */
void fd_sysvar_epoch_schedule_init( fd_global_ctx_t* global );

/* Reads the current value of the epoch schedule sysvar */
void fd_sysvar_epoch_schedule_read( fd_global_ctx_t* global, fd_epoch_schedule_t* result );

/* Get the epoch and offset into the epoch for the given slot */
void get_epoch_and_slot_idx( fd_global_ctx_t* global, ulong slot, ulong* res_epoch, ulong* res_idx ) ;

/* Returns the first slot in the given epoch */
ulong get_first_slot_in_epoch( fd_global_ctx_t* global, ulong epoch ) ;

/* Returns the last slot in the given epoch */
ulong get_last_slot_in_epoch( fd_global_ctx_t* global, ulong epoch ) ;

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_epoch_schedule_h */

