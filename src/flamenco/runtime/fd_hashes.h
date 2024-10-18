#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk.h"

#define FD_PUBKEY_HASH_PAIR_ALIGN (16UL)
struct __attribute__((aligned(FD_PUBKEY_HASH_PAIR_ALIGN))) fd_pubkey_hash_pair {
  fd_funk_rec_t const * rec;
  fd_hash_t     const * hash;
};
typedef struct fd_pubkey_hash_pair fd_pubkey_hash_pair_t;
#define FD_PUBKEY_HASH_PAIR_FOOTPRINT (sizeof(fd_pubkey_hash_pair_t))

FD_PROTOTYPES_BEGIN

int fd_update_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
                         fd_capture_ctx_t * capture_ctx,
                         fd_hash_t * hash,
                         ulong signature_cnt );
int
fd_update_hash_bank_tpool( fd_exec_slot_ctx_t * slot_ctx,
                           fd_capture_ctx_t *   capture_ctx,
                           fd_hash_t *          hash,
                           ulong                signature_cnt,
                           fd_tpool_t *         tpool );

int
fd_print_account_hashes( fd_exec_slot_ctx_t * slot_ctx,
                         fd_tpool_t *         tpool );

/* fd_hash_account_v1 was introduced in Oct-2022 via
   https://github.com/solana-labs/solana/pull/28405 and was enabled via
   the "account_hash_ignore_slot" feature gate.  It includes the
   following content:
    - lamports
    - rent_epoch
    - data
    - executable
    - owner
    - pubkey */

void const *
fd_hash_account_v1( uchar                     hash  [ static 32 ],
                    fd_account_meta_t const * account,
                    uchar const               pubkey[ static 32 ],
                    uchar const             * data );

/* Generate a complete accounts_hash of the entire account database. */
int
fd_accounts_hash( fd_exec_slot_ctx_t * slot_ctx,
                  fd_tpool_t * tpool,
                  fd_hash_t * accounts_hash,
                  ulong do_hash_verify );

/* Special version for verifying incremental snapshot */
int
fd_accounts_hash_inc_only( fd_exec_slot_ctx_t * slot_ctx,
                           fd_hash_t * accounts_hash,
                           fd_funk_txn_t * child_txn,
                           ulong do_hash_verify );

/* Generate a non-incremental hash of the entire account database, including epoch bank hash. */
int
fd_snapshot_hash( fd_exec_slot_ctx_t * slot_ctx,
                  fd_tpool_t * tpool,
                  fd_hash_t * accounts_hash,
                  uint check_hash );

int
fd_accounts_init_lthash( fd_exec_slot_ctx_t * slot_ctx );

void
fd_accounts_check_lthash( fd_exec_slot_ctx_t * slot_ctx );

void
fd_calculate_epoch_accounts_hash_values(fd_exec_slot_ctx_t * slot_ctx);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
