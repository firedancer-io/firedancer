#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_last_restart_slot_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_last_restart_slot_h

#include "../fd_bank.h"

typedef struct fd_hard_forks_global fd_hard_forks_global_t;

FD_PROTOTYPES_BEGIN

/* fd_sysvar_last_restart_slot_init creates or updates the "last restart
   slot" sysvar account using the information in the bank's implicit
   state. */

void
fd_sysvar_last_restart_slot_init( fd_bank_t *        bank,
                                  fd_accdb_t *       accdb,
                                  fd_capture_ctx_t * capture_ctx );

/* fd_sysvar_last_restart_slot_update ensures the "last restart slot"
   sysvar contains the given slot number, writing to the sysvar account
   if necessary.
   See Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx,
                                    ulong              last_restart_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_last_restart_slot_h */
