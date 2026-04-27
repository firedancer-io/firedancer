#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h

#include "../../fd_flamenco_base.h"
#include "../fd_bank.h"

FD_PROTOTYPES_BEGIN

void
fd_sysvar_stake_history_init( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx );

void
fd_sysvar_stake_history_update( fd_bank_t *                      bank,
                                fd_accdb_user_t *                accdb,
                                fd_funk_txn_xid_t const *        xid,
                                fd_capture_ctx_t *               capture_ctx,
                                fd_stake_history_entry_t const * entry );

int
fd_sysvar_stake_history_validate( uchar const * data,
                                  ulong         sz );

fd_stake_history_t *
fd_sysvar_stake_history_view( fd_stake_history_t * view,
                              uchar const *        data,
                              ulong                sz );

fd_stake_history_entry_t const *
fd_sysvar_stake_history_query( fd_stake_history_t const * view,
                               ulong                      epoch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h */
