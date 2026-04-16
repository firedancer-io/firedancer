#ifndef HEADER_fd_src_flamenco_runtime_fd_accdb_svm_h
#define HEADER_fd_src_flamenco_runtime_fd_accdb_svm_h

/* fd_accdb_svm.h provides APIs for slot boundary account changes. */

#include "../accdb/fd_accdb_ref.h"
#include "../../funk/fd_funk_base.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

struct fd_accdb_svm_update {
  ulong lamports_before;
};
typedef struct fd_accdb_svm_update fd_accdb_svm_update_t;

/* fd_accdb_svm_open_rw starts a system account update. */

fd_accdb_rw_t *
fd_accdb_svm_open_rw( fd_accdb_user_t *         accdb,
                      fd_bank_t *               bank,
                      fd_funk_txn_xid_t const * xid,
                      fd_accdb_rw_t *           rw,
                      fd_accdb_svm_update_t *   update,
                      fd_pubkey_t const *       pubkey,
                      ulong                     data_max,
                      int                       flags );

/* fd_accdb_svm_close_rw ends a system account update.  Updates the bank
   LtHash and capitalization. */

void
fd_accdb_svm_close_rw( fd_accdb_user_t *       accdb,
                       fd_bank_t *             bank,
                       fd_capture_ctx_t *      capture_ctx,
                       fd_accdb_rw_t *         rw,
                       fd_accdb_svm_update_t * update );

/* fd_accdb_svm_credit credits an account with lamports.  Updates the
   account itself, bank LtHash, and bank capitalization.  Creates the
   account if it does not exist.  Bypasses rent-exemption rules. */

void
fd_accdb_svm_credit( fd_accdb_user_t *         accdb,
                     fd_bank_t *               bank,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx,
                     fd_pubkey_t const *       pubkey,
                     ulong                     lamports );

/* fd_accdb_svm_write replaces the contents of an account.  Replaces the
   account owner and data.  Mints lamports if account has less than
   lamports_min balance, otherwise leaves lamports untouched.  Also
   updates the bank LtHash and bank capitalization.  Bypasses rent-
   exemption rules.  The following flags are accepted (FD_ACCDB_FLAG_*):
   - CREATE: create account if it does not exist; if CREATE is not set
     and the account does not exist, this function is a no-op
   - TRUNCATE: truncate account data to sz (otherwise, if account larger
     than sz, leave tail region unchanged) */

void
fd_accdb_svm_write( fd_accdb_user_t *         accdb,
                    fd_bank_t *               bank,
                    fd_funk_txn_xid_t const * xid,
                    fd_capture_ctx_t *        capture_ctx,
                    fd_pubkey_t const *       pubkey,
                    fd_pubkey_t const *       owner,
                    void const *              data,
                    ulong                     sz,
                    ulong                     lamports_min,
                    int                       exec_bit,
                    int                       flags );

/* fd_accdb_svm_remove destroys an account and burns all lamports.
   Updates the account itself, bank LtHash, and bank capitalization.
   No-op if account does not exist.  Returns the number of lamports
   burned. */

ulong
fd_accdb_svm_remove( fd_accdb_user_t *         accdb,
                     fd_bank_t *               bank,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx,
                     fd_pubkey_t const *       pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_accdb_svm_h */
