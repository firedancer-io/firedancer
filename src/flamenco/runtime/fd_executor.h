#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_h

#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/block/fd_microblock.h"
#include "fd_banks_solana.h"
#include "fd_acc_mgr.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/poh/fd_poh.h"
#include "fd_borrowed_account.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"
#include "fd_rent_lists.h"
#include "../capture/fd_solcap_writer.h"

FD_PROTOTYPES_BEGIN

/* TODO make sure these are serialized consistently with solana_program::InstructionError */
/* TODO FD_EXECUTOR_INSTR_SUCCESS is used like Ok(()) in Rust. But this is both overloaded and a
 * misnomer, because the instruction hasn't necessarily been executed succesfully yet */
/* Instruction error codes */
#define FD_EXECUTOR_INSTR_SUCCESS                                ( 0 )  /* Instruction executed successfully */
#define FD_EXECUTOR_INSTR_ERR_GENERIC_ERR                        ( -1 ) /* The program instruction returned an error */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ARG                        ( -2 ) /* The arguments provided to a program were invalid */
#define FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA                 ( -3 ) /* An instruction's data contents were invalid */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA                   ( -4 ) /* An account's data contents was invalid */
#define FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL                 ( -5 ) /* An account's data was too small */
#define FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS                 ( -6 ) /* An account's balance was too small to complete the instruction */
#define FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID               ( -7 ) /* The account did not have the expected program id */
#define FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE         ( -8 ) /* A signature was required but not found */
#define FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED            ( -9  ) /* An initialize instruction was sent to an account that has already been initialized. */
#define FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT              ( -10 ) /* An attempt to operate on an account that hasn't been initialized. */
#define FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR                   ( -11 ) /* Program's instruction lamport balance does not equal the balance after the instruction */
#define FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID                ( -12 ) /* Program illegally modified an account's program id */
#define FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND     ( -13 ) /* Program spent the lamports of an account that doesn't belong to it */
#define FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED             ( -14 ) /* Program modified the data of an account that doesn't belong to it */
#define FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE            ( -15 ) /* Read-only account's lamports modified */
#define FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED             ( -16 ) /* Read-only account's data was modified */
#define FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX              ( -17 ) /* An account was referenced more than once in a single instruction. Deprecated. */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED                ( -18 ) /* Executable bit on account changed, but shouldn't have */
#define FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED                ( -19 ) /* Rent_epoch account changed, but shouldn't have */
#define FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS                ( -20 ) /* The instruction expected additional account keys */
#define FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED              ( -21 ) /* Program other than the account's owner changed the size of the account data */
#define FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE                 ( -22 ) /* The instruction expected an executable account */
#define FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED                  ( -23 ) /* Failed to borrow a reference to account data, already borrowed */
#define FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING             ( -24 ) /* Account data has an outstanding reference after a program's execution */
#define FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC      ( -25 ) /* The same account was multiply passed to an on-chain program's entrypoint, but the program modified them differently. */
#define FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         ( -26 ) /* Allows on-chain programs to implement program-specific error types and see them returned by the runtime. */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ERR                        ( -27 ) /* The return value from the program was invalid.  */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED           ( -28 ) /* Executable account's data was modified */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE          ( -29 ) /* Executable account's lamports modified */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT ( -30 ) /* Executable accounts must be rent exempt */
#define FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID             ( -31 ) /* Unsupported program id */
#define FD_EXECUTOR_INSTR_ERR_CALL_DEPTH                         ( -32 ) /* Cross-program invocation call depth too deep */
#define FD_EXECUTOR_INSTR_ERR_MISSING_ACC                        ( -33 ) /* An account required by the instruction is missing */
#define FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED             ( -34 ) /* Cross-program invocation reentrancy not allowed for this instruction */
#define FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED           ( -35 ) /* Length of the seed is too long for address generation */
#define FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS                      ( -36 ) /* Provided seeds do not result in a valid address */
#define FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC                    ( -37 ) /* Failed to reallocate account data of this length */
#define FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED            ( -38 ) /* Computational budget exceeded */
#define FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION               ( -39 ) /* Cross-program invocation with unauthorized signer or writable account */
#define FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE  ( -40 ) /* Failed to create program execution environment */
#define FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE         ( -41 ) /* Program failed to complete */
#define FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE          ( -42 ) /* Program failed to compile */
#define FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE                      ( -43 ) /* Account is immutable */
#define FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY                ( -44 ) /* Incorrect authority provided */
#define FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR                     ( -45 ) /* Failed to serialize or deserialize account data */
#define FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT                ( -46 ) /* An account does not have enough lamports to be rent-exempt */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER                  ( -47 ) /* Invalid account owner */
#define FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW                ( -48 ) /* Program arithmetic overflowed */
#define FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR                 ( -49 ) /* Unsupported sysvar */
#define FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER                      ( -50 ) /* Provided owner is not allowed */
#define FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED        ( -51 ) /* Account data allocation exceeded the maximum accounts data size limit */
#define FD_EXECUTOR_INSTR_ERR_ACTIVE_VOTE_ACC_CLOSE              ( -52 ) /* Active vote account close */

#define FD_EXECUTOR_SYSTEM_ERR_ACCOUNT_ALREADY_IN_USE            ( -1 ) /* an account with the same address already exists */
#define FD_EXECUTOR_SYSTEM_ERR_RESULTS_WITH_NEGATIVE_LAMPORTS    ( -2 ) /* account does not have enough SOL to perform the operation */
#define FD_EXECUTOR_SYSTEM_ERR_INVALID_PROGRAM_ID                ( -3 ) /* cannot assign account to this program id */
#define FD_EXECUTOR_SYSTEM_ERR_INVALID_ACCOUNT_DATA_LENGTH       ( -4 ) /* cannot allocate account data of this length */
#define FD_EXECUTOR_SYSTEM_ERR_MAX_SEED_LENGTH_EXCEEDED          ( -5 ) /* length of requested seed is too long */
#define FD_EXECUTOR_SYSTEM_ERR_ADDRESS_WITH_SEED_MISMATCH        ( -6 ) /* provided address does not match addressed derived from seed */
#define FD_EXECUTOR_SYSTEM_ERR_NONCE_NO_RECENT_BLOCKHASHES       ( -7 ) /* advancing stored nonce requires a populated RecentBlockhashes sysvar */
#define FD_EXECUTOR_SYSTEM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED       ( -8 ) /* stored nonce is still in recent_blockhashes */
#define FD_EXECUTOR_SYSTEM_ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE  ( -9 ) /* specified nonce does not match stored nonce */

#define FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS                        (-100)
#define FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE               (-101)
#define FD_EXECUTOR_SIGN_ERR_SIGNATURE                           (-102)

struct fd_rawtxn_b {
  /* Pointer to txn in local wksp */
  void * raw;

  /* Size of txn */
  ushort txn_sz;
};
typedef struct fd_rawtxn_b fd_rawtxn_b_t;


#define FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE (0)
#define FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED         (1)

#define FD_INSTR_ACCT_FLAGS_IS_SIGNER   (0x01)
#define FD_INSTR_ACCT_FLAGS_IS_WRITABLE (0x02)


#define VECT_NAME fd_stake_rewards
#define VECT_ELEMENT fd_stake_reward_t*
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

#define VECT_NAME fd_stake_rewards_vector
#define VECT_ELEMENT fd_stake_rewards_t
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

struct fd_epoch_reward_status {
  uint is_active;
  ulong start_block_height;
  fd_stake_rewards_vector_t * stake_rewards_by_partition;
};
typedef struct fd_epoch_reward_status fd_epoch_reward_status_t;

struct fd_instr_info {
  uchar                 program_id;
  ushort                data_sz;
  ushort                acct_cnt;

  uchar *               data;
  fd_pubkey_t           program_id_pubkey;

  uchar                 acct_txn_idxs[128];
  uchar                 acct_flags[128];
  fd_pubkey_t           acct_pubkeys[128];

  fd_borrowed_account_t * borrowed_accounts[128];
};
typedef struct fd_instr_info fd_instr_info_t;

struct fd_exec_txn_ctx;
typedef struct fd_exec_txn_ctx fd_exec_txn_ctx_t;

/* Context needed to execute a single epoch. */
#define FD_EXEC_EPOCH_CTX_ALIGN (8UL)
struct __attribute__((aligned(FD_EXEC_EPOCH_CTX_ALIGN))) fd_exec_epoch_ctx {
  ulong magic; /* ==FD_EXEC_EPOCH_CTX_MAGIC */

  fd_epoch_leaders_t * leaders;  /* Current epoch only */
  fd_features_t        features;
  fd_rent_lists_t *    rentlists;
  ulong                rent_epoch;
};
typedef struct fd_exec_epoch_ctx fd_exec_epoch_ctx_t;
#define FD_EXEC_EPOCH_CTX_FOOTPRINT ( sizeof(fd_exec_epoch_ctx_t) )
#define FD_EXEC_EPOCH_CTX_MAGIC (0x3E64F44C9F44366AUL) /* random */

/* Context needed to execute a single microblock. */
struct fd_exec_mircoblock_ctx {
  int x;
};
typedef struct fd_exec_microblock_ctx fd_exec_microblock_ctx_t;

/* Context needed to execute a single block. */
struct fd_exec_block_ctx {
  int x;
};
typedef struct fd_exec_block_ctx fd_exec_block_ctx_t;

#define FD_EXEC_SLOT_CTX_ALIGN (8UL)
struct __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN))) fd_exec_slot_ctx {
  ulong magic; /* ==FD_EXEC_SLOT_CTX_MAGIC */

  fd_exec_epoch_ctx_t * epoch_ctx;
  
  // TODO: needs to move out
  fd_funk_txn_t * funk_txn_tower[32];
  ushort          funk_txn_index;
  fd_wksp_t *     funk_wksp; // Workspace dedicated to funk, KEEP YOUR GRUBBY MITS OFF!
  fd_wksp_t *     local_wksp; // Workspace for allocs local to this process

  fd_funk_txn_t *      funk_txn;
  fd_acc_mgr_t *       acc_mgr;
  fd_valloc_t          valloc;
  fd_solcap_writer_t * capture;
  int                  trace_dirfd;
  int                  trace_mode;
  fd_rng_t             rnd_mem;
  fd_rng_t *           rng;

  fd_epoch_reward_status_t epoch_reward_status;
  ulong                    signature_cnt;
  fd_hash_t                account_delta_hash;
  fd_hash_t                prev_banks_hash;
  
  fd_pubkey_t const * leader;   /* Current leader */
  fd_firedancer_banks_t bank;
};
typedef struct fd_exec_slot_ctx fd_exec_slot_ctx_t;
#define FD_EXEC_SLOT_CTX_FOOTPRINT ( sizeof(fd_exec_slot_ctx_t) )
#define FD_EXEC_SLOT_CTX_MAGIC (0xC2287BA2A5E6FC3DUL) /* random */

/* Context needed to execute a single instruction. TODO: split into a hierarchy of layered contexts.  */
struct fd_exec_instr_ctx {
  fd_exec_epoch_ctx_t const * epoch_ctx;
  fd_exec_block_ctx_t const * block_ctx;
  fd_exec_slot_ctx_t *        slot_ctx; // TOOD: needs to be made const to be thread safe.
  fd_exec_txn_ctx_t *         txn_ctx;  /* The transaction context for this instruction */

  fd_funk_txn_t * funk_txn;
  fd_acc_mgr_t *  acc_mgr;
  fd_valloc_t     valloc;
  
  fd_instr_info_t const *     instr;    /* The instruction */
};
typedef struct fd_exec_instr_ctx fd_exec_instr_ctx_t;

/* Context needed to execute a single transaction. */
struct fd_exec_txn_ctx {
  fd_exec_epoch_ctx_t const * epoch_ctx;
  fd_exec_slot_ctx_t *        slot_ctx;

  fd_funk_txn_t * funk_txn;
  fd_acc_mgr_t *  acc_mgr;
  fd_valloc_t     valloc;

  ulong                 compute_unit_limit;       /* Compute unit limit for this transaction. */
  ulong                 compute_unit_price;       /* Compute unit price for this transaction. */
  ulong                 heap_size;                /* Heap size for VMs for this transaction. */
  uint                  prioritization_fee_type;  /* The type of prioritization fee to use. */
  fd_txn_t *            txn_descriptor;           /* Descriptor of the transaction. */
  fd_rawtxn_b_t const * _txn_raw;                 /* Raw bytes of the transaction. */
  uint                  custom_err;               /* When a custom error is returned, this is where the numeric value gets stashed */
  uchar                 instr_stack_sz;           /* Current depth of the instruction execution stack. */
  fd_exec_instr_ctx_t   instr_stack[6];           /* Instruction execution stack. */
  ulong                 accounts_cnt;             /* Number of account pubkeys accessed by this transaction. */
  fd_pubkey_t           accounts[128];            /* Array of account pubkeys accessed by this transaction. */
  fd_borrowed_account_t borrowed_accounts[128];   /* Array of borrowed accounts accessed by this transaction. */
};
typedef struct fd_exec_txn_ctx fd_exec_txn_ctx_t;

/* Type definition for native programs, akin to an interface for native programs.
   The executor will execute instructions designated for a given native program by invoking a function of this type. */
typedef int(*execute_instruction_func_t) ( fd_exec_instr_ctx_t ctx );

execute_instruction_func_t
fd_executor_lookup_native_program( fd_pubkey_t const * pubkey ) ;

int
fd_execute_instr( fd_instr_info_t * instr, fd_exec_txn_ctx_t * txn_ctx );

/*
  Execute the given transaction.

  Makes changes to the Funk accounts DB. */
int
fd_execute_txn( fd_exec_slot_ctx_t *  slot_ctx,
                fd_txn_t *            txn_descriptor,
                fd_rawtxn_b_t const * txn_raw );

void
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx,
                                             fd_rawtxn_b_t const * txn_raw,
                                             uint * use_sysvar_instructions  );

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

void
fd_convert_txn_instr_to_instr( fd_txn_t const *        txn_descriptor,
                               fd_rawtxn_b_t const *   txn_raw,
                               fd_txn_instr_t const *  txn_instr,
                               fd_pubkey_t const *     accounts,
                               fd_borrowed_account_t * borrowed_accounts,
                               fd_instr_info_t *       instr );

static inline uint
fd_instr_acc_is_writable_idx(fd_instr_info_t const * instr, uchar idx) {
  return !!(instr->acct_flags[idx] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
}

static inline uint
fd_instr_acc_is_writable(fd_instr_info_t const * instr, fd_pubkey_t const * acc) {
  for( uchar i = 0; i < instr->acct_cnt; i++ ) {
    if( memcmp( &instr->acct_pubkeys[i], acc, sizeof( fd_pubkey_t ) )==0 ) {
      return fd_instr_acc_is_writable_idx( instr, i );
    }
  }

  return 0;
}

static inline uint
fd_instr_acc_is_signer_idx(fd_instr_info_t const * instr, uchar idx) {
  return !!(instr->acct_flags[idx] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
}

static inline uint
fd_instr_acc_is_signer(fd_instr_info_t const * instr, fd_pubkey_t const * acc) {
  for( uchar i = 0; i < instr->acct_cnt; i++ ) {
    if( memcmp( &instr->acct_pubkeys[i], acc, sizeof( fd_pubkey_t ) )==0 ) {
      return fd_instr_acc_is_signer_idx( instr, i );
    }
  }

  return 0;
}

int
fd_instr_borrowed_account_view_idx( fd_exec_instr_ctx_t * ctx,
                                    uchar idx,
                                    fd_borrowed_account_t * * account );
int
fd_instr_borrowed_account_view( fd_exec_instr_ctx_t * ctx,
                                fd_pubkey_t const *      pubkey,
                                fd_borrowed_account_t * * account );
int
fd_instr_borrowed_account_modify_idx( fd_exec_instr_ctx_t * ctx,
                                uchar idx,
                                int do_create,
                                ulong min_data_sz,
                                fd_borrowed_account_t * *  account );
int
fd_instr_borrowed_account_modify( fd_exec_instr_ctx_t * ctx,
                                  fd_pubkey_t const * pubkey,
                                  int do_create,
                                  ulong min_data_sz,
                                  fd_borrowed_account_t * * account );


/* fd_executor_get_signers returns the instruction accounts that are signers. Corresponds to
   https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L718

   Returns the number of signers, and `signers` will contain the account pubkeys that are signers.

   The caller is responsible for ensuring signers is sufficiently sized. */
ulong
fd_executor_get_signers( fd_exec_instr_ctx_t * ctx, fd_pubkey_t ** signers );

void *
fd_exec_slot_ctx_new( void * mem );

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_join( void * mem );

void *
fd_exec_slot_ctx_leave( fd_exec_slot_ctx_t * ctx );

void *
fd_exec_slot_ctx_delete( void * mem );

void *
fd_exec_epoch_ctx_new( void * mem );

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem );

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx );

void *
fd_exec_epoch_ctx_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_h */
