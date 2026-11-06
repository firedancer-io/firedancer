#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../fd_flamenco_base.h"
#include "../accdb/fd_accdb_base.h"
#include "../../ballet/lthash/fd_lthash.h"

/* fd_hashes.h provides functions for computing and updating the bank
   hash for a completed slot.  The bank hash is a cryptographic hash of
   the slot's state including all account modifications and transaction
   signatures.

   The bank hash is computed as: sha256( sha256( prev_bank_hash ||
     signature_count || last_blockhash ) || lthash )

   Where:
   - lthash is the cumulative lattice hash of all accounts
   - prev_bank_hash is the bank hash of the parent slot
   - last_blockhash is the last proof-of-history blockhash
   - signature_count is the number of signatures processed in the slot

   To compute the lthash, whenever any account is modified during
   transaction execution, we must remove the old version of the account
   hash from the cumulative lthash, hash the account, and add the new
   hash to the lthash. */

FD_PROTOTYPES_BEGIN

/* fd_hashes_account_lthash_simple is functionally the same as
   fd_hashes_account_lthash, but with simpler arguments that detail the
   exact parameters that go into the lthash.

   pubkey points to the account's public key (32 bytes).  owner points
   to the account's owner (32 bytes).  lamports is the account's
   lamports.  executable is the account's executable flag.  data points
   to the account data.  data_len is the length of the account data.
   lthash_out points to where the computed lthash value will be written
   (2048 bytes).

   On return, lthash_out contains the computed lthash.  This function
   assumes all pointers are valid and properly aligned.  The account
   data pointer must be readable for data_len bytes. */

void
fd_hashes_account_lthash_simple( uchar const         pubkey[ static FD_HASH_FOOTPRINT ],
                                 uchar const         owner[ static FD_HASH_FOOTPRINT ],
                                 ulong               lamports,
                                 int                 executable,
                                 uchar const *       data,
                                 ulong               data_len,
                                 fd_lthash_value_t * lthash_out );

/* fd_hashes_account_lthash_xn computes the lthashes of n accounts
   as n fd_hashes_account_lthash_simple calls would.  Outputs must not
   overlap each other or any input.  n must be at most 4. */

void
fd_hashes_account_lthash_xn( ulong                 n,
                             uchar const * const * pubkey,
                             uchar const * const * owner,
                             ulong const *         lamports,
                             int const *           executable,
                             uchar const * const * data,
                             ulong const *         data_len,
                             fd_lthash_value_t **  lthash_out );

/* fd_hashes_update_simple records an account write according to the
   bank's LtHash mode and captures it when capture_ctx requests it.  In
   INBAND mode, it computes lthash_post and replaces lthash_prev in the
   bank's LtHash.  OOB_RECORD appends pubkey to the bank's record, while
   OOB_SKIP does neither.

   lthash_prev and lthash_post are used only in INBAND mode.  The caller
   must call this for every account modification, including sysvars. */

void
fd_hashes_update_simple( fd_lthash_value_t *       lthash_post, /* out */
                         fd_lthash_value_t const * lthash_prev, /* in */
                         uchar const               pubkey[ static FD_HASH_FOOTPRINT ],
                         uchar const               owner[ static FD_HASH_FOOTPRINT ],
                         ulong                     lamports,
                         int                       executable,
                         uchar const *             data,
                         ulong                     data_len,
                         fd_bank_t               * bank,
                         fd_capture_ctx_t        * capture_ctx );

/* fd_hashes_update_pair is fd_hashes_update_simple for callers that
   have the account's previous image (prev_*) rather than its lthash.
   Both lthashes are computed at once.  The bank lthash and capture
   are updated as fd_hashes_update_simple would. */

void
fd_hashes_update_pair( uchar const        pubkey[ static FD_HASH_FOOTPRINT ],
                       uchar const        prev_owner[ static FD_HASH_FOOTPRINT ],
                       ulong              prev_lamports,
                       int                prev_executable,
                       uchar const *      prev_data,
                       ulong              prev_data_len,
                       uchar const        owner[ static FD_HASH_FOOTPRINT ],
                       ulong              lamports,
                       int                executable,
                       uchar const *      data,
                       ulong              data_len,
                       fd_bank_t *        bank,
                       fd_capture_ctx_t * capture_ctx );

/* fd_hashes_fold_lthash moves the bank's LtHash by the change of every
   account committed on the bank's accdb fork, from the account as it is
   on the parent fork to as it is now.  This settles the LtHash of a
   bank that hashed none of its writes (OOB_SKIP mode from its start).
   Nothing may commit to the bank's fork during the call. */

void
fd_hashes_fold_lthash( fd_bank_t *  bank,
                       fd_accdb_t * accdb );

/* fd_hashes_capture_account records the state of a modified account to
   the solcap capture.  It does nothing unless capture_ctx is non-NULL,
   solcap capture is enabled on it, and bank's slot is at or past the
   configured capture start slot.

   pubkey, owner, lamports, executable, data and data_len describe the
   account as it should appear in the capture, i.e. after the
   modification being recorded.

   Callers that accumulate the lthash themselves must call this
   directly.  Callers that use fd_hashes_update_simple do not. */

void
fd_hashes_capture_account( uchar const        pubkey[ static FD_HASH_FOOTPRINT ],
                           uchar const        owner[ static FD_HASH_FOOTPRINT ],
                           ulong              lamports,
                           int                executable,
                           uchar const *      data,
                           ulong              data_len,
                           fd_bank_t *        bank,
                           fd_capture_ctx_t * capture_ctx );

/* fd_hashes_hash_bank computes the bank hash for a completed slot.  The
   bank hash is a deterministic hash of the slot's state including all
   account modifications and transaction signatures.

   The hash is computed as:
     sha256( sha256( prev_bank_hash || signature_count || last_blockhash ) || lthash )

   Where:
   - lthash is the cumulative lattice hash of all accounts
   - prev_bank_hash is the bank hash of the parent slot
   - last_blockhash is the last proof-of-history blockhash
   - signature_count is the number of signatures processed in the slot

   The resulting bank hash is written to hash_out.
*/

void
fd_hashes_hash_bank( fd_lthash_value_t const * lthash,
                     fd_hash_t const *         prev_bank_hash,
                     fd_hash_t const *         last_blockhash,
                     ulong                     signature_count,
                     fd_hash_t *               hash_out );

/* fd_hashes_apply_hard_forks mixes hard-fork data into an existing bank
   hash in place, matching Agave's bank hash computation.

   For each registered hard fork i where
     parent_slot < hard_forks[i].slot <= slot,
   the fork's count is summed.  If the sum is non-zero, the hash is updated:
     hash = sha256( hash || sum_as_u64_le )

   hash is mutated in place.  slot and parent_slot are the slot and parent
   slot of the bank being finalized.  If hard_fork_cnt is zero or no
   forks are in range, hash is unchanged. */

void
fd_hashes_apply_hard_forks( fd_hash_t *            hash,
                            ulong                  slot,
                            ulong                  parent_slot,
                            fd_hard_fork_t const * hard_forks,
                            ulong                  hard_fork_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
