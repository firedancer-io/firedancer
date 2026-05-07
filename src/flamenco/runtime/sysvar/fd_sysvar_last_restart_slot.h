#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_last_restart_slot_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_last_restart_slot_h

#include "fd_sysvar_base.h"
#include "../../accdb/fd_accdb_user.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_last_restart_slot_init creates or updates the "last restart
   slot" sysvar account using the information in the bank's implicit
   state. */

void
fd_sysvar_last_restart_slot_init( fd_bank_t *               bank,
                                  fd_accdb_user_t *         accdb,
                                  fd_funk_txn_xid_t const * xid,
                                  fd_capture_ctx_t *        capture_ctx );

void
fd_sysvar_last_restart_slot_write( fd_bank_t *               bank,
                                   fd_accdb_user_t *         accdb,
                                   fd_funk_txn_xid_t const * xid,
                                   fd_capture_ctx_t *        capture_ctx,
                                   ulong                     slot );

/* fd_sysvar_last_restart_slot_derive returns the highest hard fork slot
   that is less than or equal to the bank slot, or 0 if no such hard
   fork exists. */

ulong
fd_sysvar_last_restart_slot_derive( fd_bank_t const * bank );

/* fd_sysvar_last_restart_slot_update ensures the "last restart slot"
   sysvar contains the restart slot implied by the bank's hard forks,
   writing to the sysvar account if necessary.
   See Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update( fd_bank_t *               bank,
                                    fd_accdb_user_t *         accdb,
                                    fd_funk_txn_xid_t const * xid,
                                    fd_capture_ctx_t *        capture_ctx );

/* fd_sysvar_last_restart_slot_read queries the last restart slot sysvar
   from the given funk. If the account doesn't exist in funk or if the
   account has zero lamports, this function returns sentinel. */

ulong
fd_sysvar_last_restart_slot_read( fd_accdb_user_t *         accdb,
                                  fd_funk_txn_xid_t const * xid,
                                  ulong                     sentinel );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_last_restart_slot_h */
