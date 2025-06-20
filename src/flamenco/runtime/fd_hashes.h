#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_runtime_public.h"

#define FD_PUBKEY_HASH_PAIR_ALIGN (16UL)
struct __attribute__((aligned(FD_PUBKEY_HASH_PAIR_ALIGN))) fd_pubkey_hash_pair {
  fd_funk_rec_t const * rec;
  fd_hash_t     const * hash;
};
typedef struct fd_pubkey_hash_pair fd_pubkey_hash_pair_t;
#define FD_PUBKEY_HASH_PAIR_FOOTPRINT (sizeof(fd_pubkey_hash_pair_t))

struct fd_pubkey_hash_pair_list {
  fd_pubkey_hash_pair_t * pairs;
  ulong                   pairs_len;
};
typedef struct fd_pubkey_hash_pair_list fd_pubkey_hash_pair_list_t;

struct fd_subrange_task_info {
  fd_features_t const *        features;
  fd_funk_t *                  funk;
  ulong                        num_lists;
  fd_pubkey_hash_pair_list_t * lists;
  fd_lthash_value_t *          lthash_values;
};
typedef struct fd_subrange_task_info fd_subrange_task_info_t;

struct fd_accounts_hash_task_info {
  fd_exec_slot_ctx_t *     slot_ctx;
  fd_pubkey_t              acc_pubkey[1];
  fd_hash_t                acc_hash[1];
  uint                     should_erase;
  uint                     hash_changed;
};
typedef struct fd_accounts_hash_task_info fd_accounts_hash_task_info_t;

struct fd_accounts_hash_task_data {
  fd_accounts_hash_task_info_t * info;
  ulong                          info_sz;
  fd_lthash_value_t *            lthash_values;
  ulong                          num_recs;
};
typedef struct fd_accounts_hash_task_data fd_accounts_hash_task_data_t;

union fd_features;
typedef union fd_features fd_features_t;

FD_PROTOTYPES_BEGIN

/* These functions are used to size out and gather all of the accounts
   that are going to be hashed.
   TODO: This code can be removed when lthash is enabled. */

ulong
fd_accounts_sorted_subrange_count( fd_funk_t * funk,
                                   uint        range_idx,
                                   uint        range_cnt );

void
fd_accounts_sorted_subrange_gather( fd_funk_t *             funk,
                                    uint                    range_idx,
                                    uint                    range_cnt,
                                    ulong *                 num_pairs_out,
                                    fd_lthash_value_t *     lthash_values_out,
                                    fd_pubkey_hash_pair_t * pairs,
                                    fd_features_t const *   features );

void
fd_accounts_hash_counter_and_gather_tpool_cb( void * para_arg_1,
                                              void * para_arg_2,
                                              void * fn_arg_1,
                                              void * fn_arg_2,
                                              void * fn_arg_3,
                                              void * fn_arg_4 );

int
fd_update_hash_bank_exec_hash( fd_exec_slot_ctx_t *           slot_ctx,
                               fd_hash_t *                    hash,
                               fd_capture_ctx_t *             capture_ctx,
                               fd_accounts_hash_task_data_t * task_datas,
                               ulong                          task_datas_cnt,
                               fd_lthash_value_t *            lt_hashes,
                               ulong                          lt_hashes_cnt,
                               ulong                          signature_cnt,
                               fd_spad_t *                    runtime_spad );

void
fd_collect_modified_accounts( fd_exec_slot_ctx_t *           slot_ctx,
                              fd_accounts_hash_task_data_t * task_data,
                              fd_spad_t *                    runtime_spad );

void
fd_account_hash( fd_funk_t *                    funk,
                 fd_funk_txn_t *                funk_txn,
                 fd_accounts_hash_task_info_t * task_info,
                 fd_lthash_value_t *            lt_hash,
                 ulong                          slot,
                 fd_features_t const *          features );

int
fd_update_hash_bank_tpool( fd_exec_slot_ctx_t * slot_ctx,
                           fd_capture_ctx_t *   capture_ctx,
                           fd_hash_t *          hash,
                           ulong                signature_cnt,
                           fd_tpool_t *         tpool,
                           fd_spad_t *          runtime_spad );


/* fd_hash_account is the method to compute the account
   hash.  It includes the following content:
    - lamports
    - rent_epoch
    - data
    - executable
    - owner
    - pubkey

   Writes the resulting hash to hash, and returns hash. */

void const *
fd_hash_account( uchar                     hash  [ static 32 ],
                 fd_lthash_value_t       * lthash,
                 fd_account_meta_t const * account,
                 fd_pubkey_t const       * pubkey,
                 uchar const             * data,
                 int                       hash_needed,
                 fd_features_t const *     features
 );

/* fd_hash_account_current chooses the correct account hash function
   based on feature activation state. */

#define FD_HASH_JUST_ACCOUNT_HASH   (1)
#define FD_HASH_JUST_LTHASH         (2)
#define FD_HASH_BOTH_HASHES         (3)

void const *
fd_hash_account_current( uchar                      hash  [ static 32 ],
                         fd_lthash_value_t         *lthash,
                         fd_account_meta_t const   *account,
                         fd_pubkey_t       const   *pubkey,
                         uchar const *              data,
                         int                        hash_needed,
                         fd_features_t const *      features );

/* Generate a complete accounts_hash of the entire account database. */

int
fd_accounts_hash( fd_funk_t *             funk,
                  ulong                   slot,
                  fd_hash_t *             accounts_hash,
                  fd_spad_t *             runtime_spad,
                  fd_features_t const *   features,
                  fd_exec_para_cb_ctx_t * exec_para_ctx,
                  fd_lthash_value_t *     lt_hash );

/* Generate a non-incremental hash of the entire account database, including
   the epoch account hash. It differs from fd_snapshot_hash in that this version
   is used by the snapshot service which doesn't have access to a slot_ctx
   handle. However, it retains a copy of funk and epoch_bank.
   Do the same for the incremental hash. These functions are also
   responsible for conditionally including the epoch account hash into
   the account hash. These hashes are used by the snapshot service.
   TODO: These should be used to generate the hashes from snapshot loading. */

int
fd_snapshot_service_hash( fd_hash_t *       accounts_hash,
                          fd_hash_t *       snapshot_hash,
                          fd_funk_t *       funk,
                          fd_tpool_t *      tpool,
                          fd_spad_t *       runtime_spad,
                          fd_features_t *   features );

int
fd_snapshot_service_inc_hash( fd_hash_t *                 accounts_hash,
                              fd_hash_t *                 snapshot_hash,
                              fd_funk_t *                 funk,
                              fd_funk_rec_key_t const * * pubkeys,
                              ulong                       pubkeys_len,
                              fd_spad_t *                 spad,
                              fd_features_t *             features );

void
fd_accounts_check_lthash( fd_funk_t *      funk,
                          fd_funk_txn_t *  funk_txn,
                          fd_spad_t *      runtime_spad,
                          fd_features_t  * features );

void
fd_calculate_epoch_accounts_hash_values(fd_exec_slot_ctx_t * slot_ctx);

int
fd_accounts_hash_inc_only( fd_exec_slot_ctx_t * slot_ctx,
                           fd_hash_t *          accounts_hash,
                           fd_funk_txn_t *      child_txn,
                           ulong                do_hash_verify,
                           fd_spad_t *          spad );

void
fd_account_hash_task( void * tpool,
                      ulong t0, ulong t1,
                      void *args,
                      void *reduce, ulong stride,
                      ulong l0 , ulong l1 ,
                      ulong m0 , ulong m1 ,
                      ulong n0 , ulong n1  );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
