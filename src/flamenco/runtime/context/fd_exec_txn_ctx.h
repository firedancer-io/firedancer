
#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h

#include "../../../ballet/txn/fd_txn.h"
#include "../../../util/fd_util_base.h"

#include "../fd_borrowed_account.h"
#include "../fd_rawtxn.h"

#include "fd_exec_epoch_ctx.h"
#include "fd_exec_instr_ctx.h"

/* Return data for syscalls */
struct transaction_return_data {
  fd_pubkey_t program_id;
  uchar * data;
  ulong len;
};
typedef struct transaction_return_data fd_transaction_return_data_t;

/* Context needed to execute a single transaction. */
#define FD_EXEC_TXN_CTX_ALIGN (8UL)
struct __attribute__((aligned(FD_EXEC_TXN_CTX_ALIGN))) fd_exec_txn_ctx {
  ulong magic; /* ==FD_EXEC_TXN_CTX_MAGIC */

  fd_exec_epoch_ctx_t const * epoch_ctx;
  fd_exec_slot_ctx_t *        slot_ctx;

  fd_funk_txn_t * funk_txn;
  fd_acc_mgr_t *  acc_mgr;
  fd_valloc_t     valloc;

  ulong                 compute_unit_limit;       /* Compute unit limit for this transaction. */
  ulong                 compute_unit_price;       /* Compute unit price for this transaction. */
  ulong                 compute_meter;            /* Remaining compute units */
  fd_transaction_return_data_t return_data;       /* Data returned from `return_data` syscalls */
  ulong                 heap_size;                /* Heap size for VMs for this transaction. */
  uint                  prioritization_fee_type;  /* The type of prioritization fee to use. */
  fd_txn_t const *      txn_descriptor;           /* Descriptor of the transaction. */
  fd_rawtxn_b_t const * _txn_raw;                 /* Raw bytes of the transaction. */
  uint                  custom_err;               /* When a custom error is returned, this is where the numeric value gets stashed */
  uchar                 instr_stack_sz;           /* Current depth of the instruction execution stack. */
  fd_exec_instr_ctx_t   instr_stack[6];           /* Instruction execution stack. */
  ulong                 accounts_cnt;             /* Number of account pubkeys accessed by this transaction. */
  fd_pubkey_t           accounts[128];            /* Array of account pubkeys accessed by this transaction. */
  fd_borrowed_account_t borrowed_accounts[128];   /* Array of borrowed accounts accessed by this transaction. */
};
typedef struct fd_exec_txn_ctx fd_exec_txn_ctx_t;
#define FD_EXEC_TXN_CTX_FOOTPRINT ( sizeof(fd_exec_txn_ctx_t) )
#define FD_EXEC_TXN_CTX_MAGIC (0x9AD93EE71469F4D7UL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_txn_ctx_new( void * mem );

fd_exec_txn_ctx_t *
fd_exec_txn_ctx_join( void * mem );

void *
fd_exec_txn_ctx_leave( fd_exec_txn_ctx_t * ctx );

void *
fd_exec_txn_ctx_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h */
