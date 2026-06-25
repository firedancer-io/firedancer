#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "fd_runtime_const.h"
#include "fd_runtime_stack.h"
#include "fd_compute_budget_details.h"
#include "fd_runtime_helpers.h"
#include "fd_txncache.h"
#include "program/vote/fd_vote_codec.h"
#include "program/fd_system_program.h"
#include "context/fd_exec_instr_ctx.h"
#include "../fd_flamenco_base.h"
#include "../accdb/fd_accdb.h"

/* The general structure for executing transactions in Firedancer can
   be thought as a state maching where transaction execution is a
   deterministic state transition over various data structures.

   The starting and ending state before a transaction is executed is
   represented by the bank, accounts database, and status cache.  The
   bank holds Solana state not represented by accounts (see fd_bank.c/h
   for more details) and each bank is per-slot.  The latter two data
   structures are contained by the runtime.

   The runtime also owns valid joins to important data structures which
   are non-deterministically transitioned through execution such as the
   program cache which is a pure cache on top of the accounts database.
   The runtime also owns bounded out temporary memory regions used for
   transaction execution and valid joins to other scratch memory regions
   (e.g. acc_pool).

   So we expect the state of the runtime and the bank to change as a
   result of execution.

   The transaction, or the input to said state machine is represented by
   a fd_txn_in_t.  The fd_txn_in_t is just a parsed transaction message
   and any state that may have accrued as a result of bundle execution.

   Executing a transaction produces a set of results.  This is
   represented by a fd_txn_out_t.  The fd_txn_out_t consists of any
   information that needs to be applied to the bank and runtime.

   We can execute a fd_txn_in_t against a given fd_runtime_t and a
   fd_bank_t and expect to produce a fd_txn_out_t.  Then a fd_txn_out_t
   can be applied/committed on top of a fd_runtime_t and fd_bank_t.
   Execution is done via fd_runtime_prepare_and_execute_txn.  If a
   transaction is committable, it should be committed via
   fd_runtime_commit_txn.  If a transaction is not committable, it
   should be canceled via fd_runtime_cancel_txn.

   TLDR: The runtime is a state machine that executes transactions and
   produces results that are applied to various data structures
   including the bank, account database, and status cache.  The
   transaction is executed via a call to
   fd_runtime_prepare_and_execute_txn.  If the transaction is
   committable, it should be committed via fd_runtime_commit_txn.  If
   the transaction is not committable (txn_out->err.is_committable is 0),
   it should be canceled via fd_runtime_cancel_txn.  Two calls to
   fd_runtime_prepare_and_execute_txn without a call to
   fd_runtime_commit_txn or fd_runtime_cancel_txn in between are not
   allowed.

               input                                  output
   fd_runtime_t ->
   fd_txn_in_t  -> fd_runtime_prepare_and_execute_txn() -> fd_txn_out_t
   fd_bank_t    ->

   fd_txn_out_t is the state transition output of a transaction.

   txn_out (committable)     --> fd_runtime_commit_txn()
   txn_out (not committable) --> fd_runtime_cancel_txn()
*/

struct fd_runtime {
  fd_accdb_t *     accdb;
  fd_txncache_t *  status_cache;
  fd_progcache_t * progcache;

  struct {
    uchar               stack_sz;                                /* Current depth of the instruction execution stack. */
    fd_exec_instr_ctx_t stack[ FD_MAX_INSTRUCTION_STACK_DEPTH ]; /* Instruction execution stack. */
    /* The memory for all of the instructions in the transaction
       (including CPI instructions) are preallocated.  However, the
       order in which the instructions are executed does not match the
       order in which they are allocated.  The instr_trace will instead
       be used to track the order in which the instructions are
       executed. We add a +1 to allow any instructions past the max
       instr trace limit to be safely allocated, so that we can fail
       out like Agave does later at the stack push step within
       fd_execute_instr.

       The caller is responsible for updating the trace_length for the
       callee. For CPI, the trace length is updated when preparing a
       new instruction within cpi_common. For top-level instructions,
       the trace length is updated within fd_execute_txn when preparing
       an instruction for execution. */
    fd_instr_info_t trace[ FD_MAX_INSTRUCTION_TRACE_LENGTH+1UL ];
    ulong           trace_length;
    /* The current instruction index being executed */
    int             current_idx;
  } instr;

  struct {
    /* fd_txn_out_t only stores pointers into this runtime-owned memory.
       Bundle txns execute before any txn_out is committed/canceled, so
       the whole bundle's accounts are kept opened (deduplicated) in
       these flat arrays until commit/cancel. */

    /* The executable accounts are derived from the accounts in the
       transaction and are used by the bpf loader program to validate
       the program data account. */
    ulong    executable_cnt;
    fd_acc_t executable[ FD_PACK_MAX_TXN_PER_BUNDLE * MAX_TX_ACCOUNT_LOCKS ];

    ulong    account_cnt;
    ulong    refcnt[ FD_PACK_MAX_TXN_PER_BUNDLE * MAX_TX_ACCOUNT_LOCKS ];
    fd_acc_t account[ FD_PACK_MAX_TXN_PER_BUNDLE * MAX_TX_ACCOUNT_LOCKS ];
  } accounts;

  struct {
    int                   enable_log_collector;
    fd_log_collector_t *  log_collector; /* Log collector instance */
    fd_capture_ctx_t *    capture_ctx;
    fd_dump_proto_ctx_t * dump_proto_ctx;
    fd_txn_dump_ctx_t *   txn_dump_ctx;

    /* Pointer to buffer used for dumping instructions and transactions
       into protobuf files. */
    uchar *               dumping_mem;
    /* Pointer to buffer used for tracing instructions and transactions
       into protobuf files. */
    int                   enable_vm_tracing;
    uchar *               tracing_mem;
  } log;

  struct {
    uchar serialization_mem[ FD_MAX_INSTRUCTION_STACK_DEPTH ][ BPF_LOADER_SERIALIZATION_FOOTPRINT ] __attribute__((aligned(FD_RUNTIME_EBPF_HOST_ALIGN)));
  } bpf_loader_serialization;

  struct {
    uchar rodata        [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_SBPF_PROG_RODATA_ALIGN)));
    uchar sbpf_footprint[ FD_SBPF_PROGRAM_FOOTPRINT ] __attribute__((aligned(alignof(fd_sbpf_program_t))));
    uchar programdata   [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  } bpf_loader_program;

  union {
    struct {
      fd_vote_state_versioned_t vote_state;
    } authorize;

    struct {
      fd_vote_state_versioned_t vote_state;
    } update_validator_identity;

    struct {
      fd_vote_state_versioned_t vote_state;
    } update_commission;

    struct {
      fd_vote_state_versioned_t vote_state;
    } update_commission_bps;

    struct {
      fd_vote_state_versioned_t vote_state;
    } withdraw;

    struct {
      fd_vote_state_versioned_t vote_state;
    } init_account;

    struct {
      fd_vote_state_versioned_t vote_state;
      uchar                     tower_sync_landed_votes_mem[ FD_VOTE_INSTR_LANDED_VOTES_FOOTPRINT ] __attribute__((aligned(FD_VOTE_INSTR_LANDED_VOTES_ALIGN)));
    } tower_sync;

    struct {
      /* Deprecated instructions */
      fd_vote_state_versioned_t vote_state;
      uchar                     compact_vs_lockout_mem    [ FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT     ] __attribute__((aligned(FD_VOTE_INSTR_LOCKOUTS_ALIGN)));
      uchar                     vs_update_landed_votes_mem[ FD_VOTE_INSTR_LANDED_VOTES_FOOTPRINT ] __attribute__((aligned(FD_VOTE_INSTR_LANDED_VOTES_ALIGN)));
    } process_vote;

  } vote_program;

  struct {

    /* Ticks spent spent preparing a txn-level VM (zeroing memory,
       copying account data, etc) */
    ulong vm_setup_cum_ticks;

    /* Ticks spent committing txn-level VM results (copying account
       data, etc) */
    ulong vm_commit_cum_ticks;

    /* Ticks spent in top-levl VM interpreter (includes CPI setup/commit
       ticks) */
    ulong vm_exec_cum_ticks;

    /* Ticks spent preparing/committing a cross-program invocation) */
    ulong cpi_setup_cum_ticks;
    ulong cpi_commit_cum_ticks;

    ulong cu_cum;
  } metrics;

  struct {
    int enabled;
    int reclaim_accounts;
  } fuzz;
};
typedef struct fd_runtime fd_runtime_t;

struct fd_txn_in {
  fd_txn_p_t const * txn;

  /* FEC-set merkle root at dispatch time. */
  uchar fec_merkle_root[ 32 ];

  /* 0-indexed position of this txn within its block. */
  ulong index_in_slot;

  struct {
    int            is_bundle;
    fd_txn_out_t * prev_txn_outs[ FD_PACK_MAX_TXN_PER_BUNDLE ];
    ulong          prev_txn_cnt;
  } bundle;
};
typedef struct fd_txn_in fd_txn_in_t;

struct fd_txn_out {
  struct {
    int  is_committable;
    int  is_fees_only;
    int  txn_err;
    /* These are error fields produced by instruction execution
       when txn_err == FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR (-9). */
    int  exec_err;
    int  exec_err_kind;
    uint exec_err_idx;
    uint custom_err;
  } err;

  struct {
    long                        load_start_ticks;
    long                        check_start_ticks;
    long                        exec_start_ticks;
    long                        commit_start_ticks;

    fd_compute_budget_details_t compute_budget;            /* Compute budget details */
    fd_transaction_cost_t       txn_cost;                  /* Transaction cost */
    ulong                       loaded_accounts_data_size; /* The actual transaction loaded data size */
    long                        accounts_resize_delta;     /* Transaction level tracking for account resizing */

    fd_txn_return_data_t        return_data;               /* Data returned from `return_data` syscalls */

    fd_hash_t                   blake_txn_msg_hash;        /* Hash of raw transaction message used by the status cache */
    fd_hash_t                   blockhash;                 /* Blockhash of the block that the transaction is being executed in */

    ulong                       execution_fee;             /* Execution fee paid by the fee payer in the transaction */
    ulong                       priority_fee;              /* Priority fee paid by the fee payer in the transaction */
    ulong                       tips;                      /* Jito tips paid during execution */

    ulong                       signature_count;           /* Number of signatures in the transaction */
    fd_signature_t              signature;                 /* First transaction signature */
    int                         is_simple_vote;            /* Whether the transaction is a simple vote */
    ulong                       commit_index_in_slot;      /* 0-indexed commit-completion order within this slot */
  } details;

  /* During sanitization, v0 transactions are allowed to have up to 256 accounts:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/sdk/program/src/message/versions/v0/mod.rs#L139
     Nonetheless, when Agave prepares a sanitized batch for execution and tries to lock accounts, a lower limit is enforced:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118
     That is the limit we are going to use here. */
  struct {
    /* is_setup is set to 1 if account data buffer resources have been
       acquired for the transaction and 0 if they have not.  If the flag
       has been set, memory resources must be released. */
    int         is_setup;
    /* is_bundle is set to 1 if this txn is part of a bundle.  For bundle
       txns the accounts are acquired once for the whole bundle (see
       fd_runtime_prepare_bundle_accounts) and released once via
       fd_runtime_fini_bundle, so commit/cancel must NOT release
       per-txn. */
    int         is_bundle;
    ulong       cnt;
    fd_pubkey_t keys[ MAX_TX_ACCOUNT_LOCKS ];
    fd_acc_t *  account[ MAX_TX_ACCOUNT_LOCKS ];
    uchar       is_writable[ MAX_TX_ACCOUNT_LOCKS ];
    uchar       account_acquired[ MAX_TX_ACCOUNT_LOCKS ];
    ulong       starting_lamports[ MAX_TX_ACCOUNT_LOCKS ];
    ulong       starting_data_len[ MAX_TX_ACCOUNT_LOCKS ];
    fd_pubkey_t starting_owner[ MAX_TX_ACCOUNT_LOCKS ];

    ulong      executable_cnt;                          /* Number of BPF upgradeable loader accounts for the active txn. */
    fd_acc_t * executable[ MAX_TX_ACCOUNT_LOCKS ];      /* Active txn's BPF upgradeable loader program data accounts. */
    int        executable_from_parent[ MAX_TX_ACCOUNT_LOCKS ]; /* 1 => read-only copy from the parent fork (loader gates on pd_write); 0 => current-fork copy (loader keeps the slot check) */
    int        executable_pd_write[ MAX_TX_ACCOUNT_LOCKS ];    /* probe result: deploy-status-changing write committed on the current fork this slot */
    ulong      executable_cur_len[ MAX_TX_ACCOUNT_LOCKS ];     /* current-fork committed data length, ULONG_MAX if none; for loaded-account-size accounting */

    /* Programdata deployed this slot has no executable[] entry, but
       Agave still counts its size toward loaded-accounts-data-size
       before the invoke fails; recorded here at setup. */
    ushort      executable_skipped_cnt;
    fd_pubkey_t executable_skipped_key[ MAX_TX_ACCOUNT_LOCKS ];
    ulong       executable_skipped_len[ MAX_TX_ACCOUNT_LOCKS ];

    /* Flags to demarcate if an account is queued up to update the vote
       or stakes caches in the commit stage of a transaction. */
    uchar stake_update[ MAX_TX_ACCOUNT_LOCKS ];
    uchar vote_update [ MAX_TX_ACCOUNT_LOCKS ];
    uchar new_vote    [ MAX_TX_ACCOUNT_LOCKS ];
    uchar rm_vote     [ MAX_TX_ACCOUNT_LOCKS ];

    ulong nonce_idx_in_txn; /* !=ULONG_MAX if exists */
    ulong nonce_rollback_data_len;
    uchar nonce_rollback_data[ FD_RUNTIME_ACC_SZ_MAX ];
    ulong fee_payer_rollback_lamports;

    /* Backing buffer for the sysvar instructions account.  This account
       is constructed on-the-fly by the SVM and never persisted to the
       accounts database, so the accdb returns data=NULL for it. */
    uchar sysvar_instructions_data[ FD_SYSVAR_INSTRUCTIONS_FOOTPRINT ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  } accounts;
};
typedef struct fd_txn_out fd_txn_out_t;

FD_PROTOTYPES_BEGIN

/* fd_runtime_block_execute_prepare kicks off the execution of a block.
   After this function is called, transactions can be executed and
   committed against the block.  This function handles epoch boundary
   and rewards updates if needed and updates sysvars.  It assumes that
   the bank and accounts database have been setup to execute against
   the bank: the bank has already been cloned from the parent bank and
   that the database has a transaction that is linked to the parent
   block's xid. */

void
fd_runtime_block_execute_prepare( fd_banks_t *         banks,
                                  fd_bank_t *          bank,
                                  fd_accdb_t  *        accdb,
                                  fd_runtime_stack_t * runtime_stack,
                                  fd_capture_ctx_t *   capture_ctx,
                                  int *                is_epoch_boundary );

/* fd_runtime_block_execute_finalize finishes the execution of the block
   by paying a fee out to the block leader, updating any sysvars, and
   updating the bank hash.  The required updates are made to the bank
   and the accounts database. */

void
fd_runtime_block_execute_finalize( fd_bank_t *        bank,
                                   fd_accdb_t  *      accdb,
                                   fd_capture_ctx_t * capture_ctx );

/* fd_runtime_prepare_and_execute_txn is responsible for executing a
   fd_txn_in_t against a fd_runtime_t and a fd_bank_t.  The results of
   the transaction execution are set in the fd_txn_out_t.  The caller
   is responisble for correctly setting up the fd_txn_in_t and the
   fd_runtime_t handles.

   TODO: fd_runtime_t and fd_bank_t should be const here. */

void
fd_runtime_prepare_and_execute_txn( fd_runtime_t *      runtime,
                                    fd_bank_t *         bank,
                                    fd_txn_in_t const * txn_in,
                                    fd_txn_out_t *      txn_out );

/* fd_runtime_commit_txn commits the results of a transaction execution
   as represented by the fd_txn_out_t to the bank and the accounts
   database. */

void
fd_runtime_commit_txn( fd_runtime_t *      runtime,
                       fd_bank_t *         bank,
                       fd_txn_in_t const * txn_in,
                       fd_txn_out_t *      txn_out,
                       int                 report_transaction_diffs );

/* fd_runtime_cancel_txn cancels the result of a transaction execution
   and frees any resources that may have been acquired.  A transaction
   should only be canceled when the transaction is not committable.
   1. An invalid transaction that causes a block to be rejected/
      considered invalid/'bad'.
   2. All transactions in a bundle with a failed transaction should be
      canceled as they will not be included in the block. */

void
fd_runtime_cancel_txn( fd_runtime_t *      runtime,
                       fd_bank_t *         bank,
                       fd_txn_in_t const * txn_in,
                       fd_txn_out_t *      txn_out,
                       int                 report_transaction_diffs );

/* fd_runtime_prepare_bundle_accounts is called before executing a
   bundle.  It is responsible for acquiring the union of all accounts
   referenced by all transactions in the bundle.  This is required
   to make sure account acquisition does not get torn across tiles and
   cause a resource acquisition deadlock. */

int
fd_runtime_prepare_bundle_accounts( fd_runtime_t *      runtime,
                                    fd_bank_t *         bank,
                                    fd_txn_in_t const * txn_ins,
                                    fd_txn_out_t *      txn_outs,
                                    ulong               txn_cnt );

/* fd_runtime_fini_bundle must be called unconditionally after
   attempting to execute a bundle regardless of success or failure.
   Under the hood it is responsible for freeing any account references
   that were acquired for the bundle. */

void
fd_runtime_fini_bundle( fd_runtime_t * runtime );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
