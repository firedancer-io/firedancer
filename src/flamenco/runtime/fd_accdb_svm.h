#ifndef HEADER_fd_src_flamenco_runtime_fd_accdb_svm_h
#define HEADER_fd_src_flamenco_runtime_fd_accdb_svm_h

/* fd_accdb_svm.h provides APIs for slot boundary account changes. */

#include "../accdb/fd_accdb.h"
#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

struct fd_accdb_svm_update {
  ulong lamports_before;
  ulong data_len_before;
  uchar owner_before[ 32 ];
  int   skip_event_diff; /* cleared by open_rw; a caller sets it before
                            close_rw to keep the write out of the
                            runtime_block account diffs (e.g. the VAT
                            burn, which debits every admitted vote
                            account and is reported via runtime_epoch
                            instead) */
};
typedef struct fd_accdb_svm_update fd_accdb_svm_update_t;

/* fd_accdb_svm_open_rw starts a system account update. */

fd_acc_t
fd_accdb_svm_open_rw( fd_bank_t *             bank,
                      fd_accdb_t *            accdb,
                      fd_accdb_svm_update_t * update,
                      fd_pubkey_t const *     pubkey,
                      int                     create );

/* fd_accdb_svm_close_rw ends a system account update.  Updates the bank
   LtHash and capitalization. */

void
fd_accdb_svm_close_rw( fd_bank_t *             bank,
                       fd_accdb_t *            accdb,
                       fd_capture_ctx_t *      capture_ctx,
                       fd_acc_t *              rw,
                       fd_accdb_svm_update_t * update );

/* fd_accdb_svm_credit credits an account with lamports.  Updates the
   account itself, bank LtHash, and bank capitalization.  Creates the
   account if it does not exist.  Bypasses rent-exemption rules.
   is_vote_reward indicates the credit is an epoch vote reward (paid to
   the vote account or its inflation collector), which the runtime_reward
   telemetry event reports; the account owner cannot distinguish this
   (custom collectors are system owned). */

void
fd_accdb_svm_credit( fd_bank_t *         bank,
                     fd_accdb_t *        accdb,
                     fd_capture_ctx_t *  capture_ctx,
                     fd_pubkey_t const * pubkey,
                     ulong               lamports,
                     int                 is_vote_reward );

/* fd_accdb_svm_write replaces the contents of an account.  Replaces the
   account owner, data, and data_len (always sets data_len to sz, growing
   or shrinking as needed).  Creates the account if it does not exist.
   Mints lamports if account has less than lamports_min balance, otherwise
   leaves lamports untouched.  Also updates the bank LtHash and bank
   capitalization.  Bypasses rent-exemption rules.  skip_event_diff
   keeps the write out of the runtime_block account diffs (e.g. the
   per-block alpenglow cert-signer vote state rewrites, which would
   overflow the bounded diff array every block). */

void
fd_accdb_svm_write( fd_bank_t *         bank,
                    fd_accdb_t *        accdb,
                    fd_capture_ctx_t *  capture_ctx,
                    fd_pubkey_t const * pubkey,
                    fd_pubkey_t const * owner,
                    void const *        data,
                    ulong               sz,
                    ulong               lamports_min,
                    int                 exec_bit,
                    int                 skip_event_diff );

/* fd_accdb_svm_remove destroys an account and burns all lamports.
   Updates the account itself, bank LtHash, and bank capitalization.
   No-op if account does not exist.  Returns the number of lamports
   burned. */

ulong
fd_accdb_svm_remove( fd_bank_t *         bank,
                     fd_accdb_t *        accdb,
                     fd_capture_ctx_t *  capture_ctx,
                     fd_pubkey_t const * pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_accdb_svm_h */
