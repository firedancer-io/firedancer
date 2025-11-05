#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h

#include "fd_exec_instr_ctx.h"
#include "../../log_collector/fd_log_collector_base.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../features/fd_features.h"
#include "../fd_txncache.h"
#include "../../progcache/fd_progcache_user.h"
#include "../fd_compute_budget_details.h"
#include "../../../disco/pack/fd_microblock.h"
#include "../../../disco/pack/fd_pack.h"

/* Return data for syscalls */

struct fd_txn_return_data {
  fd_pubkey_t program_id;
  ulong       len;
  uchar       data[1024];
};

typedef struct fd_txn_return_data fd_txn_return_data_t;

/* fd_exec_txn_ctx_t is the context needed to execute a transaction. */

/* An entry in the instruction trace */
struct fd_exec_instr_trace_entry {
  /* Metadata about the instruction */
  fd_instr_info_t * instr_info;
  /* Stack height when this instruction was pushed onto the stack (including itself)
     https://github.com/anza-xyz/agave/blob/d87e23d8d91c32d5f2be2bb3557c730bee1e9434/sdk/src/transaction_context.rs#L475-L480 */
  ulong stack_height;
};
typedef struct fd_exec_instr_trace_entry fd_exec_instr_trace_entry_t;

/* https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139 */
#define FD_MAX_INSTRUCTION_TRACE_LENGTH (64UL)
/* https://github.com/anza-xyz/agave/blob/f70ab5598ccd86b216c3928e4397bf4a5b58d723/compute-budget/src/compute_budget.rs#L13 */
#define FD_MAX_INSTRUCTION_STACK_DEPTH  (5UL)

struct fd_exec_txn_ctx {
  /* Input fields: memory, bank, acc db, funk, prog cache, and txn */
  fd_bank_t *          bank;
  fd_txncache_t *      status_cache;
  fd_funk_t            funk[1];
  fd_funk_txn_xid_t    xid[1];
  fd_progcache_t *     progcache;
  fd_progcache_t       _progcache[1];
  fd_txn_p_t           txn;
  fd_exec_stack_t *    exec_stack;
  fd_exec_accounts_t * exec_accounts;

  /* During sanitization, v0 transactions are allowed to have up to 256 accounts:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/sdk/program/src/message/versions/v0/mod.rs#L139
     Nonetheless, when Agave prepares a sanitized batch for execution and tries to lock accounts, a lower limit is enforced:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118
     That is the limit we are going to use here. */
  struct {
    ulong                           accounts_cnt;                                /* Number of account pubkeys accessed by this transaction. */
    fd_pubkey_t                     account_keys[ MAX_TX_ACCOUNT_LOCKS ];        /* Array of account pubkeys accessed by this transaction. */
    fd_txn_account_t                accounts[ MAX_TX_ACCOUNT_LOCKS ];            /* Array of borrowed accounts accessed by this transaction. */
    ulong                           executable_cnt;                              /* Number of BPF upgradeable loader accounts. */
    fd_txn_account_t                executable_accounts[ MAX_TX_ACCOUNT_LOCKS ]; /* Array of BPF upgradeable loader program data accounts */
  /* The next three fields describe Agave's "rollback" accounts, which
     are copies of the fee payer and (if applicable) nonce account.  If
     the transaction fails to load, the fee payer is still debited the
     transaction fee, and the nonce account is advanced.  The fee payer
     must also be rolled back to its state pre-transaction, plus
     debited any transaction fees.
     This is a bit of a misnomer but Agave calls it "rollback".
     This is the account state that the nonce account should be in when
     the txn fails. It will advance the nonce account, rather than "roll
     back". */
    fd_txn_account_t                rollback_nonce[ 1 ];
    /* If the transaction has a nonce account that must be advanced,
       this would be !=ULONG_MAX. */
    ulong                           nonce_idx_in_txn;
    fd_txn_account_t                rollback_fee_payer[ 1 ];

  } accounts;

  struct {
    uchar                       stack_sz;                              /* Current depth of the instruction execution stack. */
    fd_exec_instr_ctx_t         stack[FD_MAX_INSTRUCTION_STACK_DEPTH]; /* Instruction execution stack. */
    /* The memory for all of the instructions in the transaction
       (including CPI instructions) are preallocated.  However, the order
       in which the instructions are executed does not match the order in
       which they are allocated.  The instr_trace will instead be used to
       track the order in which the instructions are executed.  We leave
       space for an extra instruction to account for the case where the
       transaction has too many instructions leading to
       FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED.
       TODO: In reality, we should just be allocating instr_infos per
       instruction and not up front.  The dependency on using instr_info
       for the sysvar instruction setup is not needed and should be
       removed.  At this point, instr_info snad instr_trace should be
       combined. */
    fd_instr_info_t             infos[FD_MAX_INSTRUCTION_TRACE_LENGTH * 2UL];
    ulong                       info_cnt;
    fd_exec_instr_trace_entry_t trace[FD_MAX_INSTRUCTION_TRACE_LENGTH]; /* Instruction trace */
    ulong                       trace_length;                           /* Number of instructions in the trace */
    /* The current instruction index being executed */
    int current_idx;
  } instr;

  struct {
    int                 is_bundle;
    fd_exec_txn_ctx_t * prev_txn_ctxs[ FD_PACK_MAX_TXN_PER_BUNDLE ];
    ulong               prev_txn_ctxs_cnt;
  } bundle;

  struct {
    int is_committable;
    int is_fees_only;
    int txn_err;
    /* These are error fields produced by instruction execution
       when txn_err == FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR (-9). */
    int  exec_err;
    int  exec_err_kind;
    int  exec_err_idx;
    uint custom_err;
  } err;

  struct {
    fd_compute_budget_details_t compute_budget;                 /* Compute budget details */
    ulong                       loaded_accounts_data_size;      /* The actual transaction loaded data size */
    ulong                       loaded_accounts_data_size_cost; /* The cost of the loaded accounts data size in CUs */
    ulong                       accounts_resize_delta;          /* Transaction level tracking for account resizing */
    fd_txn_return_data_t        return_data;                    /* Data returned from `return_data` syscalls */
    fd_hash_t                   blake_txn_msg_hash;             /* Hash of raw transaction message used by the status cache */
    ulong                       execution_fee;                  /* Execution fee paid by the fee payer in the transaction */
    ulong                       priority_fee;                   /* Priority fee paid by the fee payer in the transaction */
    /* When a program is deployed or upgraded, we must queue it to be
       updated in the program cache (if it exists already) so that
       the cache entry's ELF / sBPF information can be updated for
       future executions.  We keep an array of pubkeys for the
       transaction to track which programs need to be reverified.  The
       actual queueing for reverification is done in the transaction
       finalization step. */
    uchar                       programs_to_reverify_cnt;
    fd_pubkey_t                 programs_to_reverify[ MAX_TX_ACCOUNT_LOCKS ];
  } details;

  struct {
    int                enable_exec_recording;
    fd_log_collector_t log_collector; /* Log collector instance */
    fd_capture_ctx_t * capture_ctx;
    /* Pointer to buffer used for dumping instructions and transactions
       into protobuf files. */
    uchar *            dumping_mem;
    /* Pointer to buffer used for tracing instructions and transactions
       into protobuf files. */
    int                enable_vm_tracing;
    uchar *            tracing_mem;
  } log;
};

#define FD_EXEC_TXN_CTX_ALIGN     (alignof(fd_exec_txn_ctx_t))
#define FD_EXEC_TXN_CTX_FOOTPRINT ( sizeof(fd_exec_txn_ctx_t))

FD_PROTOTYPES_BEGIN

/* Error logging handholding assertions */

#ifdef FD_RUNTIME_ERR_HANDHOLDING

/* Asserts that the error and error kind are not populated (zero) */
#define FD_TXN_TEST_ERR_OVERWRITE( txn_ctx ) \
   FD_TEST( !txn_ctx->err.exec_err );        \
   FD_TEST( !txn_ctx->err.exec_err_kind )

/* Used prior to a FD_TXN_ERR_FOR_LOG_INSTR call to deliberately
   bypass overwrite handholding checks.
   Only use this if you know what you're doing. */
#define FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx ) \
   txn_ctx->err.exec_err = 0;                   \
   txn_ctx->err.exec_err_kind = 0

#else

#define FD_TXN_TEST_ERR_OVERWRITE( txn_ctx ) ( ( void )0 )
#define FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx ) ( ( void )0 )

#endif

#define FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err_, idx ) (__extension__({ \
    FD_TXN_TEST_ERR_OVERWRITE( txn_ctx );                               \
    txn_ctx->err.exec_err = err_;                                       \
    txn_ctx->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_INSTR;            \
    txn_ctx->err.exec_err_idx = idx;                                    \
  }))

void *
fd_exec_txn_ctx_new( void * mem );

fd_exec_txn_ctx_t *
fd_exec_txn_ctx_join( void * mem );

void *
fd_exec_txn_ctx_leave( fd_exec_txn_ctx_t * ctx );

void *
fd_exec_txn_ctx_delete( void * mem );

/* Mirrors Agave function solana_sdk::transaction_context::find_index_of_account

   Backward scan over transaction accounts.
   Returns -1 if not found.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L233-L238 */

static inline int
fd_exec_txn_ctx_find_index_of_account( fd_exec_txn_ctx_t const * ctx,
                                       fd_pubkey_t const *       pubkey ) {
  for( ulong i=ctx->accounts.accounts_cnt; i>0UL; i-- ) {
    if( 0==memcmp( pubkey, &ctx->accounts.account_keys[ i-1UL ], sizeof(fd_pubkey_t) ) ) {
      return (int)(i-1UL);
    }
  }
  return -1;
}

typedef int fd_txn_account_condition_fn_t ( fd_txn_account_t *        acc,
                                            fd_exec_txn_ctx_t const * ctx,
                                            ushort                    idx );

/* Mirrors Agave function solana_sdk::transaction_context::get_account_at_index

   Takes a function pointer to a condition function to check pre-conditions on the
   obtained account. If the condition function is NULL, the account is returned without
   any pre-condition checks.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L223-L230 */

int
fd_exec_txn_ctx_get_account_at_index( fd_exec_txn_ctx_t *             ctx,
                                      ushort                          idx,
                                      fd_txn_account_t * *            account,
                                      fd_txn_account_condition_fn_t * condition );

/* A wrapper around fd_exec_txn_ctx_get_account_at_index that obtains an
   account from the transaction context by its pubkey. */

int
fd_exec_txn_ctx_get_account_with_key( fd_exec_txn_ctx_t *             ctx,
                                      fd_pubkey_t const *             pubkey,
                                      fd_txn_account_t * *            account,
                                      fd_txn_account_condition_fn_t * condition );

/* Gets an executable (program data) account via its pubkey. */

int
fd_exec_txn_ctx_get_executable_account( fd_exec_txn_ctx_t *             ctx,
                                        fd_pubkey_t const *             pubkey,
                                        fd_txn_account_t * *            account,
                                        fd_txn_account_condition_fn_t * condition );

/* Mirrors Agave function solana_sdk::transaction_context::get_key_of_account_at_index

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L212 */

int
fd_exec_txn_ctx_get_key_of_account_at_index( fd_exec_txn_ctx_t *  ctx,
                                             ushort               idx,
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
fd_exec_txn_ctx_account_is_writable_idx( fd_exec_txn_ctx_t const * txn_ctx, ushort idx );

/* This flat function does the same as the function above, but uses the
   exact arguments needed instead of the full fd_exec_txn_ctx_t */

int
fd_exec_txn_account_is_writable_idx_flat( const ulong           slot,
                                          const ushort          idx,
                                          const fd_pubkey_t *   addr_at_idx,
                                          const fd_txn_t *      txn_descriptor,
                                          const fd_features_t * features,
                                          const uint            bpf_upgradeable_in_txn );

/* The bpf_upgradeable_in_txn argument of the above function can be
   obtained by the function below */
uint
fd_txn_account_has_bpf_loader_upgradeable( const fd_pubkey_t * account_keys,
                                           const ulong         accounts_cnt );


/* Account pre-condition filtering functions

   Used to filter accounts based on pre-conditions such as existence, is_writable, etc.
   when obtaining accounts from the transaction context. Passed as a function pointer. */

int
fd_txn_account_check_exists( fd_txn_account_t *        acc,
                             fd_exec_txn_ctx_t const * ctx,
                             ushort                    idx );

int
fd_txn_account_check_is_writable( fd_txn_account_t *        acc,
                                  fd_exec_txn_ctx_t const * ctx,
                                  ushort                    idx );

/* The fee payer is a valid modifiable account if it is passed in as writable
   in the message via a valid signature. We ignore if the account has been
   demoted or not (see fd_exec_txn_ctx_account_is_writable_idx) for more details.
   Agave and Firedancer will reject the fee payer if the transaction message
   doesn't have a writable signature. */

int
fd_txn_account_check_fee_payer_writable( fd_txn_account_t *        acc,
                                         fd_exec_txn_ctx_t const * ctx,
                                         ushort                    idx );

/* Checks if the account is mutable and borrows the account mutably.

   The borrow is an acquired write on the account object.
   The caller is responsible for releasing the write via
   fd_txn_account_release_write.

   TODO: Agave doesn't need to check if the account is mutable
   because it uses Writable/Readable traits for accounts. We
   should have a similar concept to abstract away fd_txn_account_t's
   const_meta and meta fields. */

int
fd_txn_account_check_borrow_mut( fd_txn_account_t *        acc,
                                 fd_exec_txn_ctx_t const * ctx,
                                 ushort                    idx );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h */
