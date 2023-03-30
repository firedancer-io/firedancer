#ifndef HEADER_fd_src_ballet_runtime_fd_executor_h
#define HEADER_fd_src_ballet_runtime_fd_executor_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "../block/fd_microblock.h"
#include "fd_banks_solana.h"
#include "fd_acc_mgr.h"
#include "../../funk/fd_funk.h"
#include "../poh/fd_poh.h"

FD_PROTOTYPES_BEGIN

struct global_ctx {
  fd_alloc_fun_t      allocf;
  void *              allocf_arg;
  fd_free_fun_t       freef;
  void *              freef_arg;
  fd_acc_mgr_t*       acc_mgr;

  fd_genesis_solana_t gen;
  uchar               genesis_hash[FD_SHA256_HASH_SZ];

  fd_poh_state_t      poh;
  fd_wksp_t *         wksp;
  fd_funk_t*          funk;
};
typedef struct global_ctx global_ctx_t;

struct fd_executor {
  global_ctx_t* global;
};
typedef struct fd_executor fd_executor_t;

#define FD_EXECUTOR_FOOTPRINT ( sizeof(fd_executor_t) )

void* fd_executor_new( void* mem, global_ctx_t* global, ulong footprint );

fd_executor_t *fd_executor_join( void* mem );

void *fd_executor_leave( fd_executor_t* executor );

void* fd_executor_delete( void* mem );

/* Instruction error codes */
/* TODO: make sure these are serialized consistently with solana_program::InstructionError */
#define FD_EXECUTOR_INSTR_SUCCESS                                ( 0 )  /* Instruction executed successfully */
#define FD_EXECUTOR_INSTR_ERR_GENERIC_ERR                        ( -1 ) /* The program instruction returned an error */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ARG                        ( -2 ) /* The arguments provided to a program were invalid */
#define FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA                 ( -3 ) /* An instruction's data contents were invalid */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA                   ( -4 ) /* An account's data contents was invalid */
#define FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL                 ( -5 ) /* An account's data was too small */
#define FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS                 ( -6 ) /* An account's balance was too small to complete the instruction */
#define FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID               ( -7 ) /* The account did not have the expected program id */
#define FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE         ( -9 ) /* A signature was required but not found */
#define FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED            ( -10 ) /* An initialize instruction was sent to an account that has already been initialized. */
#define FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT              ( -11 ) /* An attempt to operate on an account that hasn't been initialized. */
#define FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR                   ( -12 ) /* Program's instruction lamport balance does not equal the balance after the instruction */
#define FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID                ( -13 ) /* Program illegally modified an account's program id */
#define FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND     ( -14 ) /* Program spent the lamports of an account that doesn't belong to it */
#define FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED             ( -15 ) /* Program modified the data of an account that doesn't belong to it */
#define FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE            ( -16 ) /* Read-only account's lamports modified */
#define FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED             ( -17 ) /* Read-only account's data was modified */
#define FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX              ( -18 ) /* An account was referenced more than once in a single instruction. Deprecated. */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED                ( -19 ) /* Executable bit on account changed, but shouldn't have */
#define FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED                ( -20 ) /* Rent_epoch account changed, but shouldn't have */
#define FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS                ( -21 ) /* The instruction expected additional account keys */
#define FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED              ( -22 ) /* Program other than the account's owner changed the size of the account data */
#define FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE                 ( -23 ) /* The instruction expected an executable account */
#define FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED                  ( -24 ) /* Failed to borrow a reference to account data, already borrowed */
#define FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING             ( -25 ) /* Account data has an outstanding reference after a program's execution */
#define FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC      ( -26 ) /* The same account was multiply passed to an on-chain program's entrypoint, but the program modified them differently. */
#define FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         ( -27 ) /* Allows on-chain programs to implement program-specific error types and see them returned by the runtime. */
#define FD_EXECUTOR_INSTR_ERR_INVALID_ERR                        ( -28 ) /* The return value from the program was invalid.  */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MOTIFIED           ( -29 ) /* Executable account's data was modified */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE          ( -30 ) /* Executable account's lamports modified */
#define FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT ( -31 ) /* Executable accounts must be rent exempt */
#define FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID             ( -32 ) /* Unsupported program id */
#define FD_EXECUTOR_INSTR_ERR_CALL_DEPTH                         ( -33 ) /* Cross-program invocation call depth too deep */
#define FD_EXECUTOR_INSTR_ERR_MISSING_ACC                        ( -34 ) /* An account required by the instruction is missing */
#define FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED             ( -35 ) /* Cross-program invocation reentrancy not allowed for this instruction */
#define FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED           ( -36 ) /* Length of the seed is too long for address generation */
#define FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS                      ( -37 ) /* Provided seeds do not result in a valid address */
#define FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC                    ( -38 ) /* Failed to reallocate account data of this length */
#define FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED            ( -39 ) /* Computational budget exceeded */
#define FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION               ( -40 ) /* Cross-program invocation with unauthorized signer or writable account */
#define FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE  ( -41 ) /* Failed to create program execution environment */
#define FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE         ( -42 ) /* Program failed to complete */
#define FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE          ( -43 ) /* Program failed to compile */
#define FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE                      ( -44 ) /* Account is immutable */
#define FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY                ( -45 ) /* Incorrect authority provided */

/*
  Execute the given transaction.

  Makes changes to the Funk accounts DB. */
void
fd_execute_txn( fd_executor_t* executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) ;

/* Context needed to execute a single instruction. TODO: split into a hierarchy of layered contexts.  */
struct instruction_ctx {
  global_ctx_t*   global;
  fd_txn_instr_t* instr;                      /* The instruction */
  fd_txn_t*       txn_descriptor;             /* Descriptor of the transaction this instruction was part of */
  fd_rawtxn_b_t*  txn_raw;                    /* Raw bytes of the transaction this instruction was part of */
};
typedef struct instruction_ctx instruction_ctx_t;

/* Type definition for native programs, akin to an interface for native programs.
   The executor will execute instructions designated for a given native program by invoking a function of this type. */
typedef int(*execute_instruction_func_t) ( instruction_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_executor_h */
