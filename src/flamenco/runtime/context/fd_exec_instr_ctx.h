#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h

#include "../info/fd_instr_info.h"
#include "../fd_executor_err.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../../fd_flamenco_base.h"
#include "../../../ballet/txn/fd_txn.h"

/* Avoid circular include dependency with forward declaration */
struct fd_borrowed_account;
typedef struct fd_borrowed_account fd_borrowed_account_t;

/* fd_exec_instr_ctx_t is the context needed to execute a single
   instruction (program invocation). */

struct fd_exec_instr_ctx {
  fd_instr_info_t const *   instr;   /* The instruction info for this instruction */
  fd_runtime_t *            runtime; /* The runtime for this instruction */
  fd_txn_in_t const *       txn_in;  /* The input for this instruction */
  fd_txn_out_t *            txn_out; /* The output for this instruction */
  fd_sysvar_cache_t const * sysvar_cache;
  fd_bank_t *               bank;

  /* Most instructions log the base58 program id multiple times, so it's
     convenient to compute it once and reuse it. */
  char program_id_base58[ FD_BASE58_ENCODED_32_SZ ];
};

#define FD_EXEC_INSTR_CTX_ALIGN     (alignof(fd_exec_instr_ctx_t))
#define FD_EXEC_INSTR_CTX_FOOTPRINT (sizeof (fd_exec_instr_ctx_t))

/* Be careful when using this macro. There may be places where the error
   will need to be handled differently. */
#define FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, idx, acc ) do { \
  int err = fd_exec_instr_ctx_try_borrow_instr_account( ctx, idx, acc );    \
  if( FD_UNLIKELY( err ) ) return err;                                      \
} while (0)

FD_PROTOTYPES_BEGIN

/* Operators */

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::check_number_of_instruction_accounts

   Assert that enough accounts were supplied to this instruction. Returns
   FD_EXECUTOR_INSTR_SUCCESS if the number of accounts is as expected and
   FD_EXECUTOR_INSTR_ERR_MISSING_ACC otherwise.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L490 */

static inline int
fd_exec_instr_ctx_check_num_insn_accounts( fd_exec_instr_ctx_t const * ctx,
                                           uint                        expected_accounts ) {

  if( FD_UNLIKELY( ctx->instr->acct_cnt<expected_accounts ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::find_index_of_instruction_account.

   Returns the index of the instruction account given the account pubkey
   or -1 if the account is not found.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L524-L538 */

int
fd_exec_instr_ctx_find_idx_of_instr_account( fd_exec_instr_ctx_t const * ctx,
                                             fd_pubkey_t const *         pubkey );

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::get_index_of_instruction_account_in_transaction

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L552 */

static inline int
fd_exec_instr_ctx_get_index_of_instr_account_in_transaction( fd_exec_instr_ctx_t const * ctx,
                                                             ushort                      idx_in_instr,
                                                             ushort *                    idx_in_txn ) {
  if( FD_UNLIKELY( idx_in_instr==USHORT_MAX ) ) {
    *idx_in_txn = USHORT_MAX;
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* Return a NotEnoughAccountKeys error if the idx is out of bounds.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L559 */
  if( FD_UNLIKELY( idx_in_instr>=ctx->instr->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  *idx_in_txn = ctx->instr->accounts[ idx_in_instr ].index_in_transaction;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::get_number_of_program_accounts.

   Strictly returns 1, as we only support one program account per instruction.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L480-L482 */

static inline ushort
fd_exec_instr_ctx_get_number_of_program_accounts( fd_exec_instr_ctx_t const * ctx ) {
  (void) ctx;
  return 1U;
}

/* A helper function to get the pubkey of an account using its instruction context index */
int
fd_exec_instr_ctx_get_key_of_account_at_index( fd_exec_instr_ctx_t const * ctx,
                                               ushort                      idx_in_instr,
                                               fd_pubkey_t const * *       key );

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::get_last_program_key.

   There can only be one program per instruction, so this function simply retrieves
   that program's pubkey, despite the name implying multiple programs per instruction.
   The function exists to match semantics with Agave.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L582 */

int
fd_exec_instr_ctx_get_last_program_key( fd_exec_instr_ctx_t const * ctx,
                                        fd_pubkey_t const * *       key );

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::try_borrow_account.

   Borrows an account from the instruction context with a given account index.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L594 */

int
fd_exec_instr_ctx_try_borrow_instr_account( fd_exec_instr_ctx_t const * ctx,
                                            ushort                      idx,
                                            fd_borrowed_account_t *     account );

/* A wrapper around fd_exec_instr_ctx_try_borrow_account that accepts an account pubkey.

   Borrows an account from the instruction context with a given pubkey. */

int
fd_exec_instr_ctx_try_borrow_instr_account_with_key( fd_exec_instr_ctx_t const * ctx,
                                                     fd_pubkey_t const *         pubkey,
                                                     fd_borrowed_account_t *     account );

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::try_borrow_last_program_account

   Borrows the instruction's program account. Since there is only one program account per
   instruction, this function simply borrows the instruction's only program account, despite the name.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L616 */

int
fd_exec_instr_ctx_try_borrow_last_program_account( fd_exec_instr_ctx_t const * ctx,
                                                   fd_borrowed_account_t *     account );

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::get_signers

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L684 */

int
fd_exec_instr_ctx_get_signers( fd_exec_instr_ctx_t const * ctx,
                               fd_pubkey_t const *         signers[ static FD_TXN_SIG_MAX ] );

/* fd_exec_instr_ctx_any_signed matches
   solana_system_program::system_processor::Address::is_signer

   Scans instruction accounts for matching signer.

   Returns 1 if *any* instruction account with the given pubkey is a
   signer and 0 otherwise.  Note that the same account/pubkey can be
   specified as multiple different instruction accounts that might not
   all have the signer bit.

   https://github.com/anza-xyz/agave/blob/v2.1.14/programs/system/src/system_processor.rs#L35-L41 */

FD_FN_PURE int
fd_exec_instr_ctx_any_signed( fd_exec_instr_ctx_t const * ctx,
                              fd_pubkey_t const *         pubkey );

/* Although fd_signers_contains does not take an instruction context,
   it is included here for relevance to signer helper functions

   Loop conditions could be optimized to allow for unroll/vectorize */

static inline int
fd_signers_contains( fd_pubkey_t const * signers[ static FD_TXN_SIG_MAX ],
                     fd_pubkey_t const * pubkey ) {
  for( ulong i=0; i<FD_TXN_SIG_MAX && signers[i]; i++ )
    if( 0==memcmp( signers[i], pubkey, sizeof( fd_pubkey_t ) ) ) return 1;
  return 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h */
