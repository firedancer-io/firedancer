#ifndef HEADER_fd_src_ballet_runtime_fd_executor_h
#define HEADER_fd_src_ballet_runtime_fd_executor_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "../block/fd_microblock.h"
#include "fd_banks_solana.h"
#include "fd_acc_mgr.h"
#include "../../funk/fd_funk.h"

FD_PROTOTYPES_BEGIN

struct fd_executor {
    fd_acc_mgr_t* acc_mgr;
};
typedef struct fd_executor fd_executor_t;

#define FD_EXECUTOR_FOOTPRINT ( sizeof(fd_executor_t) )

void* fd_executor_new( void* mem, fd_acc_mgr_t* acc_mgr, ulong footprint );

fd_executor_t *fd_executor_join( void* mem );

void *fd_executor_leave( fd_executor_t* executor );

void* fd_executor_delete( void* mem );

/* Execute the given transaction */
void
fd_execute_txn( fd_executor_t* executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) ;

/* Context needed to execute a single instruction. TODO: split into a hierarchy of layered contexts.  */
struct instruction_ctx {
    fd_txn_instr_t* instr;                      /* The instruction */
    fd_txn_t*       txn_descriptor;             /* Descriptor of the transaction this instruction was part of */
    fd_rawtxn_b_t*  txn_raw;                    /* Raw bytes of the transaction this instruction was part of */
    fd_acc_mgr_t*   acc_mgr;                    /* Account manager */
};
typedef struct instruction_ctx instruction_ctx_t;

/* Type definition for native programs, akin to an interface for native programs.
   The executor will execute instructions designated for a given native program by invoking a function of this type. */
/* TODO: execution return codes */
typedef void(*execute_instruction_func_t) ( instruction_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_executor_h */
