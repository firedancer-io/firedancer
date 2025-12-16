#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "fd_runtime_helpers.h"

/* The general structure for executing transactions in Firedancer is as
   follows if we think about transaction execution as part of a state
   machine:

   the starting and ending state are represented by the bank and the
   runtime.  The bank holds all Solana state not represented by an
   account (see fd_bank.c/h for more details) and each bank is per-slot.
   The runtime holds valid joins to other important data structures such
   as the accounts database, accounts mem pool. status cache, and
   program cache.  The runtime also owns bounded out temporary memory
   regions used for transaction execution.  So we expect the state of
   the runtime and the bank to change as a result of execution.

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
   should be canceled via fd_runtime_cancel_txn.  */

struct fd_runtime {
  fd_accdb_user_t * accdb;
  fd_funk_t *       funk;
  fd_txncache_t *   status_cache;
  fd_progcache_t *  progcache;
  fd_acc_pool_t *   acc_pool;

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
    /* The sysvar instructions account is a special account that is
       modified through the course of transaction execution, but its
       results are not committed to the bank or accounts database. */
    uchar                     sysvar_instructions_mem[ FD_ACC_TOT_SZ_MAX ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));

    /* The executable accounts are derived from the accounts in the
       transaction and are used by the bpf loader program to validate
       the program data account. */
    ulong                     executable_cnt;                             /* Number of BPF upgradeable loader accounts. */
    fd_account_meta_t const * executables_meta[ MAX_TX_ACCOUNT_LOCKS ];   /* Array of BPF upgradeable loader program data accounts */
    fd_pubkey_t               executable_pubkeys[ MAX_TX_ACCOUNT_LOCKS ]; /* Array of BPF upgradeable loader program data accounts */

    ulong                     starting_lamports[ MAX_TX_ACCOUNT_LOCKS ]; /* Starting lamports for each account */
    ulong                     starting_dlen[ MAX_TX_ACCOUNT_LOCKS ];     /* Starting data length for each account */
    ulong                     refcnt[ MAX_TX_ACCOUNT_LOCKS ];            /* Reference count for each account */
  } accounts;

  struct {
    int                  enable_log_collector;
    fd_log_collector_t * log_collector; /* Log collector instance */
    fd_capture_ctx_t *   capture_ctx;
    /* Pointer to buffer used for dumping instructions and transactions
       into protobuf files. */
    uchar *              dumping_mem;
    /* Pointer to buffer used for tracing instructions and transactions
       into protobuf files. */
    int                  enable_vm_tracing;
    uchar *              tracing_mem;
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
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } authorize;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } update_validator_identity;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } update_commission;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } withdraw;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } init_account;

    struct {
      uchar vote_state_mem             [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem      [ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar vote_state_landed_votes_mem[ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar tower_sync_landed_votes_mem[ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
    } tower_sync;

    struct {
      /* Deprecated instructions */
      uchar vote_state_mem            [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem     [ FD_AUTHORIZED_VOTERS_FOOTPRINT    ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem          [ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem          [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
      uchar compact_vs_lockout_mem    [ FD_VOTE_LOCKOUTS_FOOTPRINT        ] __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
      uchar vs_update_landed_votes_mem[ FD_LANDED_VOTES_FOOTPRINT         ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
    } process_vote;

  } vote_program;

  union {
    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
      uchar landed_votes_mem     [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
    } delegate;
    struct {
      uchar delinquent_vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar delinquent_authorized_voters_mem[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
      uchar delinquent_landed_votes_mem     [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));

      uchar reference_vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar reference_authorized_voters_mem[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
      uchar reference_landed_votes_mem     [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
    } deactivate_delinquent;
  } stake_program;
};
typedef struct fd_runtime fd_runtime_t;

struct fd_txn_in {
  fd_txn_p_t const * txn;

  struct {
    int                  is_bundle;
    fd_txn_out_t const * prev_txn_outs[ FD_PACK_MAX_TXN_PER_BUNDLE ];
    ulong                prev_txn_cnt;
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
    int  exec_err_idx;
    uint custom_err;
  } err;

  struct {
    long                        prep_start_timestamp;
    long                        load_start_timestamp;
    long                        exec_start_timestamp;
    long                        commit_start_timestamp;

    fd_compute_budget_details_t compute_budget;            /* Compute budget details */
    fd_transaction_cost_t       txn_cost;                  /* Transaction cost */
    ulong                       loaded_accounts_data_size; /* The actual transaction loaded data size */
    ulong                       accounts_resize_delta;     /* Transaction level tracking for account resizing */

    fd_txn_return_data_t        return_data;               /* Data returned from `return_data` syscalls */

    fd_hash_t                   blake_txn_msg_hash;        /* Hash of raw transaction message used by the status cache */
    fd_hash_t                   blockhash;                 /* Blockhash of the block that the transaction is being executed in */

    ulong                       execution_fee;             /* Execution fee paid by the fee payer in the transaction */
    ulong                       priority_fee;              /* Priority fee paid by the fee payer in the transaction */
    ulong                       tips;                      /* Jito tips paid during execution */

    ulong                       signature_count;           /* Number of signatures in the transaction */
    int                         is_simple_vote;            /* Whether the transaction is a simple vote */
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

  /* During sanitization, v0 transactions are allowed to have up to 256 accounts:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/sdk/program/src/message/versions/v0/mod.rs#L139
     Nonetheless, when Agave prepares a sanitized batch for execution and tries to lock accounts, a lower limit is enforced:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118
     That is the limit we are going to use here. */
  struct {
    int                 is_setup;
    ulong               cnt;
    fd_pubkey_t         keys       [ MAX_TX_ACCOUNT_LOCKS ];
    fd_account_meta_t * metas      [ MAX_TX_ACCOUNT_LOCKS ];
    ushort              is_writable[ MAX_TX_ACCOUNT_LOCKS ];

    /* The fee payer and nonce accounts are treated differently than
       other accounts: if an on-transaction fails they are still
       committed to the accounts database.  However, they are saved at
       the point right after a fee is debited or the nonce is advanced
       respectively.  The rollback accounts store this state because a
       failed transaction could have potentially modified the state of
       these two accounts.

       The memory for the nonce and fee payer is always provisioned when
       the transaction is prepared, but isn't necessarily used. */
    uchar *             rollback_fee_payer_mem;
    uchar *             rollback_nonce_mem;

    ulong               nonce_idx_in_txn; /* !=ULONG_MAX if exists */
    fd_account_meta_t * rollback_nonce;
    fd_account_meta_t * rollback_fee_payer;
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
                                  fd_accdb_user_t  *   accdb,
                                  fd_runtime_stack_t * runtime_stack,
                                  fd_capture_ctx_t *   capture_ctx,
                                  int *                is_epoch_boundary );

/* fd_runtime_block_execute_finalize finishes the execution of the block
   by paying a fee out to the block leader, updating any sysvars, and
   updating the bank hash.  The required updates are made to the bank
   and the accounts database. */

void
fd_runtime_block_execute_finalize( fd_bank_t *        bank,
                                   fd_accdb_user_t  * accdb,
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
fd_runtime_commit_txn( fd_runtime_t * runtime,
                       fd_bank_t *    bank,
                       fd_txn_out_t * txn_out );

/* fd_runtime_cancel_txn cancels the result of a transaction execution
   and frees any resources that may have been acquired.  A transaction
   should only be canceled when the transaction is not committable.
   1. An invalid transaction that causes a block to be rejected/
      considered invalid/'bad'.
   2. All transactions in a bundle with a failed transaction should be
      canceled as they will not be included in the block. */

void
fd_runtime_cancel_txn( fd_runtime_t * runtime,
                       fd_txn_out_t * txn_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
