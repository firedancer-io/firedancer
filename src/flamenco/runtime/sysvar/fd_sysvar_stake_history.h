#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h

#include "fd_sysvar_base.h"
#include "../../accdb/fd_accdb.h"

FD_PROTOTYPES_BEGIN

void
fd_sysvar_stake_history_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx );

/* Known differences:
   - Firedancer checks the account owner, Agave ignores it */

void
fd_sysvar_stake_history_update( fd_bank_t *                      bank,
                                fd_accdb_t *                     accdb,
                                fd_capture_ctx_t *               capture_ctx,
                                fd_stake_history_entry_t const * entry );

int
fd_sysvar_stake_history_validate( uchar const * data,
                                  ulong         sz );

fd_stake_history_t *
fd_sysvar_stake_history_view( fd_stake_history_t * view,
                              uchar const *        data,
                              ulong                sz );

/* https://github.com/anza-xyz/solana-sdk/blob/stake-history%40v1.0.0/stake-history/src/lib.rs#L140-L144 */
fd_stake_history_entry_t const *
fd_sysvar_stake_history_query( fd_stake_history_t const * view,
                               ulong                      epoch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h */
