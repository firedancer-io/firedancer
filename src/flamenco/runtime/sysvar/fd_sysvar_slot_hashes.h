#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h

#include "../fd_bank.h"

/* The slot hashes sysvar contains the most recent hashes of the slot's
   parent bank hashes. */

FD_PROTOTYPES_BEGIN

/* Update the slot hashes sysvar account.  This should be called at the
   end of every slot, before execution commences. */

void
fd_sysvar_slot_hashes_update( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx );

/* fd_sysvar_slot_hashes_read reads the slot hashes sysvar from the
   accounts database.  If the account doesn't exist or if the account
   has zero lamports, this function returns NULL. */

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_read( fd_accdb_t *       accdb,
                            fd_accdb_fork_id_t fork_id,
                            uchar *            slot_hashes_mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h */
