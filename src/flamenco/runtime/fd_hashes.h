#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_bank.h"
#include "context/fd_capture_ctx.h"

/* fd_hashes.h provides functions for computing and updating the bank hash
   for a completed slot.  The bank hash is a cryptographic hash of the
   slot's state including all account modifications and transaction
   signatures.

   The bank hash is computed as:
     sha256( sha256( prev_bank_hash || signature_count || last_blockhash ) || lthash )

   Where:
   - lthash is the cumulative lattice hash of all accounts
   - prev_bank_hash is the bank hash of the parent slot
   - last_blockhash is the last proof-of-history blockhash
   - signature_count is the number of signatures processed in the slot

   To compute the lthash, whenever any account is modified during transaction
   execution, we must remove the old version of the account hash from the
   cumulative lthash, hash the account, and add the new hash to the lthash.
*/


FD_PROTOTYPES_BEGIN

/* fd_hashes_account_lthash computes the lattice hash (lthash) of a
   single account for use in the bank hash calculation.  The lthash is a
   cryptographic hash that supports incremental updates via addition and
   subtraction operations.

   For accounts with non-zero lamports, the hash is computed as:
     blake3( lamports || data || executable || owner || pubkey )

   For accounts with zero lamports, the hash is zero (these accounts are
   excluded from the bank hash).

   pubkey points to the account's public key (32 bytes).  account points
   to the account metadata containing lamports, data length, executable
   flag, and owner.  data points to the account data of size
   account->dlen bytes.  lthash_out points to where the computed lthash
   value will be written (FD_LTHASH_LEN_BYTES).

   On return, lthash_out contains the computed lthash.  For zero-lamport
   accounts, lthash_out will be zeroed via fd_lthash_zero.

   This function assumes all pointers are valid and properly aligned.
   The account data pointer must be readable for account->dlen bytes. */

void
fd_hashes_account_lthash( fd_pubkey_t const       * pubkey,
                          fd_account_meta_t const * account,
                          uchar const             * data,
                          fd_lthash_value_t *       lthash_out );

/* fd_hashes_update_lthash updates the bank's incremental lthash when an
   account is modified during transaction execution.  The bank lthash is
   maintained incrementally by subtracting the old account hash and
   adding the new account hash.

   account is the modified account (via fd_txn_account_t interface).
   prev_hash contains the lthash of the account before modification (or
   zero for newly created accounts).  bank is the bank whose lthash
   should be updated.  capture_ctx is an optional capture context for
   recording account changes (can be NULL).

   This function:
   - Acquires a write lock on the bank's lthash
   - Subtracts prev_hash from the bank lthash
   - Computes the new account hash
   - Adds the new hash to the bank lthash
   - Releases the lock
   - If capture_ctx is provided, writes the account state to the capture

   On capture write failure, the function will FD_LOG_ERR and terminate.
   The function assumes all non-optional pointers are valid.

   IMPORTANT: fd_hashes_update_lthash, or fd_hashes_update_lthash_from_funk,
   must be called whenever an account is modified during transaction
   execution. This includes sysvar accounts. */

void
fd_hashes_update_lthash( fd_txn_account_t const  * account,
                         fd_lthash_value_t const * prev_account_hash,
                         fd_bank_t               * bank,
                         fd_capture_ctx_t        * capture_ctx );

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

   slot_ctx contains the execution context with the bank to hash.  hash
   points to where the computed bank hash will be written (32 bytes).
*/

void
fd_hashes_hash_bank( fd_slot_lthash_t const * lthash,
                     fd_hash_t const *        prev_bank_hash,
                     fd_hash_t const *        last_blockhash,
                     ulong                    signature_count,
                     fd_hash_t *              hash_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
