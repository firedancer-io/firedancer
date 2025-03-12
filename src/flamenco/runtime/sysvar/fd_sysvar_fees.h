#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../context/fd_exec_slot_ctx.h"

/* The fees sysvar contains the fee calculator for the current slot. */

FD_PROTOTYPES_BEGIN

/* Initialize the fees sysvar account. */
void
fd_sysvar_fees_init( fd_exec_slot_ctx_t * slot_ctx );

/* Reads the current value of the fees sysvar */
fd_sysvar_fees_t *
fd_sysvar_fees_read( fd_sysvar_fees_t *        result,
                     fd_sysvar_cache_t const * sysvar_cache,
                     fd_acc_mgr_t *            acc_mgr,
                     fd_funk_txn_t *           funk_txn );

void
fd_sysvar_fees_new_derived( fd_exec_slot_ctx_t *   slot_ctx,
                            fd_fee_rate_governor_t base_fee_rate_governor,
                            ulong                  latest_singatures_per_slot );

/* Updates fees for every slot. */
void
fd_sysvar_fees_update( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h */

