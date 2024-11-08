#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h

#include "fd_exec_instr_ctx.h"
#include "../../../util/fd_util_base.h"
#include "../../log_collector/fd_log_collector_base.h"

#include "../fd_borrowed_account.h"

#include "../../../ballet/txn/fd_txn.h"

/* Return data for syscalls */

struct fd_txn_return_data {
  fd_pubkey_t program_id;
  ulong       len;
  uchar       data[1024];
};

typedef struct fd_txn_return_data fd_txn_return_data_t;

/* fd_exec_txn_ctx_t is the context needed to execute a transaction. */

/* Cache of deserialized vote accounts to support iteration after replaying a slot (required for fork choice) */
struct fd_vote_account_cache_entry {
  fd_pubkey_t pubkey;
  ulong next;
  fd_vote_state_t vote_account;
};
typedef struct fd_vote_account_cache_entry fd_vote_account_cache_entry_t;

#define POOL_NAME fd_vote_account_pool
#define POOL_T fd_vote_account_cache_entry_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME          fd_vote_account_cache
#define MAP_ELE_T         fd_vote_account_cache_entry_t
#define MAP_KEY           pubkey
#define MAP_KEY_T         fd_pubkey_t
#define MAP_KEY_EQ(k0,k1) (!(memcmp((k0)->key,(k1)->key,sizeof(fd_hash_t))))
#define MAP_KEY_HASH(key,seed) ( ((key)->ui[0]) ^ (seed) )
#include "../../../util/tmpl/fd_map_chain.c"

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

struct __attribute__((aligned(8UL))) fd_exec_txn_ctx {
  ulong magic; /* ==FD_EXEC_TXN_CTX_MAGIC */

  fd_exec_epoch_ctx_t const * epoch_ctx;
  fd_exec_slot_ctx_t const *  slot_ctx;

  fd_funk_txn_t *       funk_txn;
  fd_acc_mgr_t *        acc_mgr;
  fd_valloc_t           valloc;

  ulong                 paid_fees;
  ulong                 compute_unit_limit;                          /* Compute unit limit for this transaction. */
  ulong                 compute_unit_price;                          /* Compute unit price for this transaction. */
  ulong                 compute_meter;                               /* Remaining compute units */
  ulong                 heap_size;                                   /* Heap size for VMs for this transaction. */
  ulong                 loaded_accounts_data_size_limit;             /* Loaded accounts data size limit for this transaction. */
  uint                  prioritization_fee_type;                     /* The type of prioritization fee to use. */
  fd_txn_t const *      txn_descriptor;                              /* Descriptor of the transaction. */
  fd_rawtxn_b_t         _txn_raw[1];                                 /* Raw bytes of the transaction. */
  uint                  custom_err;                                  /* When a custom error is returned, this is where the numeric value gets stashed */
  uchar                 instr_stack_sz;                              /* Current depth of the instruction execution stack. */
  fd_exec_instr_ctx_t   instr_stack[FD_MAX_INSTRUCTION_STACK_DEPTH]; /* Instruction execution stack. */
  fd_exec_instr_ctx_t * failed_instr;
  int                   instr_err_idx;
  /* During sanitization, v0 transactions are allowed to have up to 256 accounts:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/sdk/program/src/message/versions/v0/mod.rs#L139
     Nonetheless, when Agave prepares a sanitized batch for execution and tries to lock accounts, a lower limit is enforced:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118
     That is the limit we are going to use here. */
  ulong                 accounts_cnt;                                /* Number of account pubkeys accessed by this transaction. */
  fd_pubkey_t           accounts[ MAX_TX_ACCOUNT_LOCKS ];            /* Array of account pubkeys accessed by this transaction. */
  ulong                 executable_cnt;                              /* Number of BPF upgradeable loader accounts. */
  fd_borrowed_account_t executable_accounts[ MAX_TX_ACCOUNT_LOCKS ]; /* Array of BPF upgradeable loader program data accounts */
  fd_borrowed_account_t borrowed_accounts[ MAX_TX_ACCOUNT_LOCKS ];   /* Array of borrowed accounts accessed by this transaction. */
  uchar                 nonce_accounts[ MAX_TX_ACCOUNT_LOCKS ];      /* Nonce accounts in the txn to be saved */
  uint                  num_instructions;                            /* Counter for number of instructions in txn */
  fd_txn_return_data_t  return_data;                                 /* Data returned from `return_data` syscalls */
  fd_vote_account_cache_t * vote_accounts_map;                       /* Cache of bank's deserialized vote accounts to support fork choice */
  fd_vote_account_cache_entry_t * vote_accounts_pool;                /* Memory pool for deserialized vote account cache */
  ulong                 accounts_resize_delta;                       /* Transaction level tracking for account resizing */
  fd_hash_t             blake_txn_msg_hash;                          /* Hash of raw transaction message used by the status cache */
  ulong                 execution_fee;                               /* Execution fee paid by the fee payer in the transaction */
  ulong                 priority_fee;                                /* Priority fee paid by the fee payer in the transaction */
  ulong                 collected_rent;                              /* Rent collected from accounts in this transaction */

  uchar dirty_vote_acc  : 1;                                         /* 1 if this transaction maybe modified a vote account */
  uchar dirty_stake_acc : 1;                                         /* 1 if this transaction maybe modified a stake account */

  fd_capture_ctx_t * capture_ctx;

  /* The instr_infos for the entire transaction are allocated at the start of
     the transaction. However, this must preserve a different counter because
     the top level instructions must get set up at once. The instruction 
     error check on a maximum instruction size can be done on the
     instr_info_cnt instead of the instr_trace_length because it is a proxy
     for the trace_length: the instr_info_cnt gets incremented faster than
     the instr_trace_length because it counts all of the top level instructions
     first. */
  fd_instr_info_t             instr_infos[FD_MAX_INSTRUCTION_TRACE_LENGTH];
  ulong                       instr_info_cnt;

  fd_exec_instr_trace_entry_t instr_trace[FD_MAX_INSTRUCTION_TRACE_LENGTH]; /* Instruction trace */
  ulong                       instr_trace_length;                           /* Number of instructions in the trace */

  fd_log_collector_t          log_collector;             /* Log collector instance */

  /* Execution error and type, to match Agave. */
  int exec_err;
  int exec_err_kind;

  fd_spad_t * spad;
};

#define FD_EXEC_TXN_CTX_ALIGN     (alignof(fd_exec_txn_ctx_t))
#define FD_EXEC_TXN_CTX_FOOTPRINT ( sizeof(fd_exec_txn_ctx_t))
#define FD_EXEC_TXN_CTX_MAGIC     (0x9AD93EE71469F4D7UL      ) /* random */

FD_PROTOTYPES_BEGIN

#define FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, idx ) (__extension__({ \
    txn_ctx->exec_err = err;                                           \
    txn_ctx->exec_err_kind = FD_EXECUTOR_ERR_KIND_INSTR;               \
    txn_ctx->instr_err_idx = idx;                                      \
  }))

void *
fd_exec_txn_ctx_new( void * mem );

fd_exec_txn_ctx_t *
fd_exec_txn_ctx_join( void * mem );

void *
fd_exec_txn_ctx_leave( fd_exec_txn_ctx_t * ctx );

void *
fd_exec_txn_ctx_delete( void * mem );

void
fd_exec_txn_ctx_setup( fd_exec_txn_ctx_t * txn_ctx,
                       fd_txn_t const * txn_descriptor,
                       fd_rawtxn_b_t const * txn_raw );
void
fd_exec_txn_ctx_from_exec_slot_ctx( fd_exec_slot_ctx_t * slot_ctx,
                                    fd_exec_txn_ctx_t * txn_ctx );

void
fd_exec_txn_ctx_teardown( fd_exec_txn_ctx_t * txn_ctx );

int
fd_txn_borrowed_account_view_idx( fd_exec_txn_ctx_t * ctx,
                                  uchar idx,
                                  fd_borrowed_account_t * * account );

/* Same as above, except that this function doesn't check if the account
   is dead (0 balance, 0 data, etc.) or not. When agave obtains a
   borrowed account, it doesn't always check if the account is dead or
   not. For example
   https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/program-runtime/src/invoke_context.rs#L453
   This function allows us to more closely emulate that behavior. */
int
fd_txn_borrowed_account_view_idx_allow_dead( fd_exec_txn_ctx_t * ctx,
                                             uchar idx,
                                             fd_borrowed_account_t * * account );

int
fd_txn_borrowed_account_view( fd_exec_txn_ctx_t * ctx,
                              fd_pubkey_t const *      pubkey,
                              fd_borrowed_account_t * * account );

int
fd_txn_borrowed_account_executable_view( fd_exec_txn_ctx_t * ctx,
                              fd_pubkey_t const *      pubkey,
                              fd_borrowed_account_t * * account );

int
fd_txn_borrowed_account_modify_idx( fd_exec_txn_ctx_t * ctx,
                                    uchar idx,
                                    ulong min_data_sz,
                                    fd_borrowed_account_t * * account );
int
fd_txn_borrowed_account_modify( fd_exec_txn_ctx_t * ctx,
                                fd_pubkey_t const * pubkey,
                                ulong min_data_sz,
                                fd_borrowed_account_t * * account );
void
fd_exec_txn_ctx_reset_return_data( fd_exec_txn_ctx_t * txn_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h */
