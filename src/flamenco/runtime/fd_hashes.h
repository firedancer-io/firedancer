#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../fd_flamenco_base.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../accdb/fd_accdb.h"

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

/* fd_hashes_fold_lthash brings bank's account lthash up to date for
   the block executed on its accdb fork: for every account committed on
   the fork it subtracts the lthash of the account's state on the
   parent fork and adds that of its state on the bank's fork.  Call
   once, after the last write to the fork and before the bank hash is
   computed.  Zero lamport and missing accounts hash to zero on either
   side.  Only for banks with fd_bank_lthash_deferred.

   Writes within the block are not hashed individually: an account
   rewritten a thousand times in a block costs two account hashes here
   instead of two thousand on the executors, and no executor touches
   the bank's 2 KiB lthash. */

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

   Every path that commits an account calls this. */

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
