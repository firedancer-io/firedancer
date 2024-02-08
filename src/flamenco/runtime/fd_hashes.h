#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../../funk/fd_funk_txn.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_capture_ctx.h"

typedef struct fd_exec_slot_ctx fd_exec_slot_ctx_t;

#define FD_PUBKEY_HASH_PAIR_ALIGN (16UL)
struct __attribute__((aligned(FD_PUBKEY_HASH_PAIR_ALIGN))) fd_pubkey_hash_pair {
  fd_pubkey_t const * pubkey;
  fd_hash_t   const * hash;
};
typedef struct fd_pubkey_hash_pair fd_pubkey_hash_pair_t;
#define FD_PUBKEY_HASH_PAIR_FOOTPRINT (sizeof(fd_pubkey_hash_pair_t))

FD_PROTOTYPES_BEGIN

void fd_hash_account_deltas( fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash, fd_exec_slot_ctx_t * slot_ctx );

int fd_update_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
                         fd_capture_ctx_t * capture_ctx,
                         fd_hash_t * hash,
                         ulong signature_cnt );
int
fd_update_hash_bank_tpool( fd_exec_slot_ctx_t * slot_ctx,
                           fd_hash_t *          hash,
                           ulong                signature_cnt,
                           fd_tpool_t *         tpool,
                           ulong                max_workers );

int
fd_print_account_hashes( fd_exec_slot_ctx_t * slot_ctx,
                         fd_tpool_t *         tpool,
                         ulong                max_workers );
/* fd_hash_account_v0 is the legacy method to compute the account
   hash.  It includes the following content:
    - lamports
    - slot
    - rent_epoch
    - data
    - executable
    - owner
    - pubkey

   Writes the resulting hash to hash, and returns hash. */

void const *
fd_hash_account_v0( uchar                     hash[ static 32 ],
                    fd_account_meta_t const * account,
                    uchar const               pubkey[ static 32 ],
                    uchar const             * data,
                    ulong                     slot );

/* fd_hash_account_v1 was introduced in Oct-2022 via
   https://github.com/solana-labs/solana/pull/28405 and is enabled via
   the "account_hash_ignore_slot" feature gate.

   It is like fd_hash_account_with_slot, but omits the slot param. */

void const *
fd_hash_account_v1( uchar                     hash  [ static 32 ],
                    fd_account_meta_t const * account,
                    uchar const               pubkey[ static 32 ],
                    uchar const             * data );

/* fd_hash_account_current chooses the correct account hash function
   based on feature activation state. */

void const *
fd_hash_account_current( uchar                      hash  [ static 32 ],
                         fd_account_meta_t const *  account,
                         uchar const                pubkey[ static 32 ],
                         uchar const *              data,
                         fd_exec_slot_ctx_t const * slot_ctx );

/* Generate a complete accounts_hash of the entire account database. */
int
fd_accounts_hash( fd_exec_slot_ctx_t * slot_ctx,
                  fd_hash_t * accounts_hash,
                  fd_funk_txn_t * child_txn,
                  ulong do_hash_verify,
                  int with_dead );

/* Generate a non-incremental hash of the entire account database. */
int
fd_snapshot_hash( fd_exec_slot_ctx_t * slot_ctx,
                  fd_hash_t * accounts_hash,
                  fd_funk_txn_t * child_txn,
                  uint check_hash,
                  int with_dead );

int
fd_accounts_init_lthash( fd_exec_slot_ctx_t * slot_ctx );

void
fd_accounts_check_lthash( fd_exec_slot_ctx_t * slot_ctx );

void
fd_calculate_epoch_accounts_hash_values(fd_exec_slot_ctx_t * slot_ctx);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
