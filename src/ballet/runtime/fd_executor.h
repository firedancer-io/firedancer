#ifndef HEADER_fd_src_ballet_runtime_fd_executor_h
#define HEADER_fd_src_ballet_runtime_fd_executor_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"

FD_PROTOTYPES_BEGIN

#define FD_EXECUTOR_LOOKUP_TABLE_CAPACITY 5

/* Context needed to execute a single instruction */
struct instruction_ctx {
    fd_txn_instr_t* instr; /* The instruction */
    fd_txn_t*       txn;   /* Transaction this instruction was part of */
};
typedef struct instruction_ctx instruction_ctx_t;

/* Function definition for native programs */
typedef void(*instruction_invocation_func_t)(instruction_ctx_t ctx);

/* Key pair used in the native program lookup table */
struct fd_native_program_lookup_pair {
    fd_txn_acct_addr_t            key;
    instruction_invocation_func_t instruction_invocation_func;
};
typedef struct fd_native_program_lookup_pair fd_native_program_lookup_pair_t;
#define FD_NATIVE_PROGRAM_LOOKUP_PAIR_FOOTPRINT sizeof(fd_slot_meta_t)

FD_FN_CONST static inline ulong
fd_executor_footprint( ) {
    return FD_NATIVE_PROGRAM_LOOKUP_PAIR_FOOTPRINT * FD_EXECUTOR_LOOKUP_TABLE_CAPACITY;
}

/* Lookup a native program by it's public key */
instruction_invocation_func_t
fd_executor_lookup_native_program(
    fd_txn_acct_addr_t key
) ;

/* Execute the given transaction */
void
fd_execute_txn( fd_txn_t * txn ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_executor_h */
