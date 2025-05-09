#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_init_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_init_h

/* fd_runtime_init.h provides APIs for backing up and restoring a Solana
   runtime environment.  This file must not depend on fd_executor.h. */

#include "../fd_flamenco_base.h"
#include "../../funk/fd_funk_rec.h"

#define FD_RUNTIME_ENC_BINCODE 0xB13C0DEFU /* classic bincode encoding */
#define FD_RUNTIME_ENC_ARCHIVE 0xA3C417EAU /* archival encoding */

FD_PROTOTYPES_BEGIN

static inline fd_funk_rec_key_t
fd_runtime_epoch_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.uc[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_EPOCH_BANK;
  return id;
}

static inline fd_funk_rec_key_t
fd_runtime_slot_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.uc[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_SLOT_BANK;
  return id;
}

int
fd_runtime_save_slot_bank( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_save_epoch_bank( fd_exec_slot_ctx_t * slot_ctx );

/* fd_features_restore loads all known feature accounts from the
   accounts database.  This is used when initializing bank from a
   snapshot. */

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad );

/* Recover slot_bank and epoch_bank from funk. */

void
fd_runtime_recover_banks( fd_exec_slot_ctx_t * slot_ctx,
                          int                  delete_first,
                          int                  clear_first,
                          fd_spad_t *          runtime_spad );

void
fd_runtime_delete_banks( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_init_h */
