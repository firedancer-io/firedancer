#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h

#include "../info/fd_instr_info.h"
#include "../fd_executor_err.h"
#include "../../../funk/fd_funk.h"

/* Avoid circular include dependency with forward declaration */
struct fd_borrowed_account;
typedef struct fd_borrowed_account fd_borrowed_account_t;

/* fd_exec_instr_ctx_t is the context needed to execute a single
   instruction (program invocation). */

struct __attribute__((aligned(8UL))) fd_exec_instr_ctx {
  ulong magic; /* ==FD_EXEC_INSTR_CTX_MAGIC */

  fd_exec_txn_ctx_t *         txn_ctx;  /* The transaction context for this instruction */

  fd_exec_instr_ctx_t const * parent;

  uint depth;      /* starts at 0 */
  uint index;      /* number of preceding instructions with same parent */
  uint child_cnt;  /* number of child instructions */
  uint instr_err;  /* TODO: this is kind of redundant wrt instr_exec */

  fd_funk_txn_t * funk_txn;
  fd_acc_mgr_t *  acc_mgr;

  /* Most instructions log the base58 program id multiple times, so it's
     convenient to compute it once and reuse it. */
  char program_id_base58[ FD_BASE58_ENCODED_32_SZ ];

  fd_instr_info_t const * instr;
};

#define FD_EXEC_INSTR_CTX_ALIGN     (alignof(fd_exec_instr_ctx_t))
#define FD_EXEC_INSTR_CTX_FOOTPRINT (sizeof (fd_exec_instr_ctx_t))
#define FD_EXEC_INSTR_CTX_MAGIC     (0x18964FC6EDAAC5A8UL) /* random */

/* Be careful when using this macro. There may be places where the error
   will need to be handled differently. */
#define FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, idx, acc ) do { \
  int err = fd_exec_instr_ctx_try_borrow_account( ctx, idx, acc );          \
  if( FD_UNLIKELY( err ) ) return err;                                      \
} while (0)

FD_PROTOTYPES_BEGIN

/* Constructors */

void *
fd_exec_instr_ctx_new( void * mem );

fd_exec_instr_ctx_t *
fd_exec_instr_ctx_join( void * mem );

void *
fd_exec_instr_ctx_leave( fd_exec_instr_ctx_t * ctx );

void *
fd_exec_instr_ctx_delete( void * mem );

/* Operators */

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::check_number_of_instruction_accounts

   Assert that enough accounts were supplied to this instruction. Returns
   FD_EXECUTOR_INSTR_SUCCESS if the number of accounts is as expected and
   FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS otherwise.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L490 */
static inline int
fd_exec_instr_ctx_check_num_insn_accounts( fd_exec_instr_ctx_t * ctx,
                                           uint                  expected_accounts ) {

  if( FD_UNLIKELY( ctx->instr->acct_cnt<expected_accounts ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::try_borrow_account.

   Borrows an account from the instruction context with a given account index.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L594 */

int
fd_exec_instr_ctx_try_borrow_account( fd_exec_instr_ctx_t const * ctx,
                                      ulong                       idx,
                                      fd_borrowed_account_t *     account );

/* A wrapper around fd_exec_instr_ctx_try_borrow_account that accepts an account pubkey.

   Borrows an account from the instruction context with a given pubkey. */

int
fd_exec_instr_ctx_try_borrow_account_with_key( fd_exec_instr_ctx_t *   ctx,
                                               fd_pubkey_t const *     pubkey,
                                               fd_borrowed_account_t * account );

/* Mirrors Agave function solana_sdk::transaction_context::InstructionContext::find_index_of_instruction_account.

   Returns the index of the the instruction account given the account pubkey
   or -1 if the account is not found.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L524-L538 */

int
fd_exec_instr_ctx_find_idx_of_instr_account( fd_exec_instr_ctx_t const * ctx,
                                             fd_pubkey_t const *         pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h */
