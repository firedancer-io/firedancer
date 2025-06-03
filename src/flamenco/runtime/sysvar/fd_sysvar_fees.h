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

/* fd_sysvar_fees_read reads the current value of the fees sysvar from
   funk. If the account doesn't exist in funk or if the account
   has zero lamports, this function returns NULL. */

fd_sysvar_fees_t *
fd_sysvar_fees_read( fd_funk_t *     funk,
                     fd_funk_txn_t * funk_txn,
                     fd_spad_t *     spad );

void
fd_sysvar_fees_new_derived( fd_exec_slot_ctx_t *   slot_ctx,
                            fd_fee_rate_governor_t base_fee_rate_governor,
                            ulong                  latest_singatures_per_slot );

/* Updates fees for every slot. */
void
fd_sysvar_fees_update( fd_exec_slot_ctx_t * slot_ctx,
                      fd_spad_t *           runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_fees_h */

