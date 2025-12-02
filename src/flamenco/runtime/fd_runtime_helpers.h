#include "fd_runtime_err.h"
#include "fd_rocksdb.h"
#include "fd_acc_mgr.h"
#include "fd_hashes.h"
#include "fd_txncache.h"
#include "fd_compute_budget_details.h"
#include "context/fd_capture_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "info/fd_instr_info.h"
#include "../features/fd_features.h"
#include "../../disco/pack/fd_pack.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_helpers_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_helpers_h

struct fd_exec_accounts {
  uchar rollback_nonce_account_mem[ FD_ACC_TOT_SZ_MAX ]           __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  uchar rollback_fee_payer_mem[ FD_ACC_TOT_SZ_MAX ]               __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  uchar accounts_mem[ MAX_TX_ACCOUNT_LOCKS ][ FD_ACC_TOT_SZ_MAX ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
};
typedef struct fd_exec_accounts fd_exec_accounts_t;

/* Return data for syscalls */

struct fd_txn_return_data {
  fd_pubkey_t program_id;
  ulong       len;
  uchar       data[1024];
};
typedef struct fd_txn_return_data fd_txn_return_data_t;

/* fd_exec_txn_ctx_t is the context needed to execute a transaction. */

FD_PROTOTYPES_BEGIN

/* Returns 0 on success, and non zero otherwise.  On failure, the out
   values will not be modified. */
int
fd_runtime_compute_max_tick_height( ulong   ticks_per_slot,
                                    ulong   slot,
                                    ulong * out_max_tick_height /* out */ );

void
fd_runtime_update_leaders( fd_bank_t *          bank,
                           fd_runtime_stack_t * runtime_stack );

/* Load the accounts in the address lookup tables of txn into out_accts_alt */
int
fd_runtime_load_txn_address_lookup_tables( fd_txn_t const *          txn,
                                           uchar const *             payload,
                                           fd_funk_t *               funk,
                                           fd_funk_txn_xid_t const * xid,
                                           ulong                     slot,
                                           fd_slot_hash_t const *    hashes, /* deque */
                                           fd_acct_addr_t *          out_accts_alt );

/* fd_runtime_new_fee_rate_governor_derived updates the bank's
   FeeRateGovernor to a new derived value based on the parent bank's
   FeeRateGovernor and the latest_signatures_per_slot.
   https://github.com/anza-xyz/solana-sdk/blob/badc2c40071e6e7f7a8e8452b792b66613c5164c/fee-calculator/src/lib.rs#L97-L157

   latest_signatures_per_slot is typically obtained from the parent
   slot's signature count for the bank being processed.

   The fee rate governor is deprecated in favor of FeeStructure in
   transaction fee calculations but we still need to maintain the old
   logic for recent blockhashes sysvar (and nonce logic that relies on
   it). Thus, a separate bank field, `rbh_lamports_per_sig`, tracks the
   updates to the fee rate governor derived lamports-per-second value.

   Relevant links:
   - Deprecation issue tracker:
     https://github.com/anza-xyz/agave/issues/3303
   - PR that deals with disambiguation between FeeStructure and
     FeeRateGovernor in SVM: https://github.com/anza-xyz/agave/pull/3216
  */
void
fd_runtime_new_fee_rate_governor_derived( fd_bank_t * bank,
                                          ulong       latest_signatures_per_slot );

void
fd_runtime_read_genesis( fd_banks_t *                       banks,
                         fd_bank_t *                        bank,
                         fd_accdb_user_t *                  accdb,
                         fd_funk_txn_xid_t const *          xid,
                         fd_capture_ctx_t *                 capture_ctx,
                         fd_hash_t const *                  genesis_hash,
                         fd_lthash_value_t const *          genesis_lthash,
                         fd_genesis_solana_global_t const * genesis_block,
                         fd_runtime_stack_t *               runtime_stack );

/* Error logging handholding assertions */

#ifdef FD_RUNTIME_ERR_HANDHOLDING

/* Asserts that the error and error kind are not populated (zero) */
#define FD_TXN_TEST_ERR_OVERWRITE( txn_out ) \
   FD_TEST( !txn_out->err.exec_err );        \
   FD_TEST( !txn_out->err.exec_err_kind )

/* Used prior to a FD_TXN_ERR_FOR_LOG_INSTR call to deliberately
   bypass overwrite handholding checks.
   Only use this if you know what you're doing. */
#define FD_TXN_PREPARE_ERR_OVERWRITE( txn_out ) \
   txn_out->err.exec_err = 0;                   \
   txn_out->err.exec_err_kind = 0

#else

#define FD_TXN_TEST_ERR_OVERWRITE( txn_out ) ( ( void )0 )
#define FD_TXN_PREPARE_ERR_OVERWRITE( txn_out ) ( ( void )0 )

#endif

#define FD_TXN_ERR_FOR_LOG_INSTR( txn_out, err_, idx ) (__extension__({ \
    FD_TXN_TEST_ERR_OVERWRITE( txn_out );                               \
    txn_out->err.exec_err = err_;                                       \
    txn_out->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_INSTR;            \
    txn_out->err.exec_err_idx = idx;                                    \
  }))

int
fd_runtime_find_index_of_account( fd_txn_out_t const * txn_out,
                                  fd_pubkey_t const *  pubkey );

typedef int fd_txn_account_condition_fn_t ( fd_txn_in_t const * txn_in,
                                            fd_txn_out_t *      txn_out,
                                            ushort              idx );

/* Mirrors Agave function solana_sdk::transaction_context::get_account_at_index

   Takes a function pointer to a condition function to check pre-conditions on the
   obtained account. If the condition function is NULL, the account is returned without
   any pre-condition checks.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L223-L230 */

int
fd_runtime_get_account_at_index( fd_txn_in_t const *             txn_in,
                                 fd_txn_out_t *                  txn_out,
                                 ushort                          idx,
                                 fd_txn_account_condition_fn_t * condition );

/* A wrapper around fd_exec_txn_ctx_get_account_at_index that obtains an
   account from the transaction context by its pubkey. */

int
fd_runtime_get_account_with_key( fd_txn_in_t const *             txn_in,
                                 fd_txn_out_t *                  txn_out,
                                 fd_pubkey_t const *             pubkey,
                                 int *                           index_out,
                                 fd_txn_account_condition_fn_t * condition );

/* Gets an executable (program data) account via its pubkey. */

int
fd_runtime_get_executable_account( fd_runtime_t *              runtime,
                                   fd_txn_in_t const *         txn_in,
                                   fd_txn_out_t *              txn_out,
                                   fd_pubkey_t const *         pubkey,
                                   fd_account_meta_t const * * meta );

/* Mirrors Agave function solana_sdk::transaction_context::get_key_of_account_at_index

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L212 */

int
fd_runtime_get_key_of_account_at_index( fd_txn_out_t *        txn_out,
                                        ushort                idx,
                                        fd_pubkey_t const * * key );

/* In agave, the writable accounts cache is populated by this below function.
   This cache is then referenced to determine if a transaction account is
   writable or not.

   The overall logic is as follows: an account can be passed
   in as writable based on the signature and readonly signature as they are
   passed in by the transaction message. However, the account's writable
   status will be demoted if either of the two conditions are met:
   1. If the account is in the set of reserved pubkeys
   2. If the account is the program id AND the upgradeable loader account is in
      the set of transaction accounts. */
/* https://github.com/anza-xyz/agave/blob/v2.1.1/sdk/program/src/message/versions/v0/loaded.rs#L137-L150 */

int
fd_runtime_account_is_writable_idx( fd_txn_in_t const *  txn_in,
                                    fd_txn_out_t const * txn_out,
                                    fd_bank_t *          bank,
                                    ushort               idx );

/* Account pre-condition filtering functions

   Used to filter accounts based on pre-conditions such as existence, is_writable, etc.
   when obtaining accounts from the transaction context. Passed as a function pointer. */

int
fd_runtime_account_check_exists( fd_txn_in_t const * txn_in,
                                 fd_txn_out_t *      txn_out,
                                 ushort              idx );

/* The fee payer is a valid modifiable account if it is passed in as writable
   in the message via a valid signature. We ignore if the account has been
   demoted or not (see fd_exec_txn_ctx_account_is_writable_idx) for more details.
   Agave and Firedancer will reject the fee payer if the transaction message
   doesn't have a writable signature. */

int
fd_runtime_account_check_fee_payer_writable( fd_txn_in_t const * txn_in,
                                             fd_txn_out_t *      txn_out,
                                             ushort              idx );

int
fd_account_meta_checked_sub_lamports( fd_account_meta_t * meta,
                                      ulong               lamports );

void
fd_account_meta_resize( fd_account_meta_t * meta,
                        ulong               dlen );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_helpers_h */
