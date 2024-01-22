#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h

#include "fd_exec_instr_ctx.h"
#include "../../../util/fd_util_base.h"

#include "../fd_borrowed_account.h"

/* Return data for syscalls */

struct fd_txn_return_data {
  fd_pubkey_t program_id;
  ulong       len;
  uchar       data[1024];
};

typedef struct fd_txn_return_data fd_txn_return_data_t;

/* fd_exec_txn_ctx_t is the context needed to execute a transaction. */

struct __attribute__((aligned(8UL))) fd_exec_txn_ctx {
  ulong magic; /* ==FD_EXEC_TXN_CTX_MAGIC */

  fd_exec_epoch_ctx_t const * epoch_ctx;
  fd_exec_slot_ctx_t *        slot_ctx;

  fd_funk_txn_t *       funk_txn;
  fd_acc_mgr_t *        acc_mgr;
  fd_valloc_t           valloc;

  ulong                 paid_fees;
  ulong                 compute_unit_limit;              /* Compute unit limit for this transaction. */
  ulong                 compute_unit_price;              /* Compute unit price for this transaction. */
  ulong                 compute_meter;                   /* Remaining compute units */
  ulong                 heap_size;                       /* Heap size for VMs for this transaction. */
  ulong                 loaded_accounts_data_size_limit; /* Loaded accounts data size limit for this transaction. */
  uint                  prioritization_fee_type;         /* The type of prioritization fee to use. */
  fd_txn_t const *      txn_descriptor;                  /* Descriptor of the transaction. */
  fd_rawtxn_b_t const * _txn_raw;                        /* Raw bytes of the transaction. */
  uint                  custom_err;                      /* When a custom error is returned, this is where the numeric value gets stashed */
  uchar                 instr_stack_sz;                  /* Current depth of the instruction execution stack. */
  fd_exec_instr_ctx_t   instr_stack[6];                  /* Instruction execution stack. */
  ulong                 accounts_cnt;                    /* Number of account pubkeys accessed by this transaction. */
  fd_pubkey_t           accounts[128];                   /* Array of account pubkeys accessed by this transaction. */
  ulong                 executable_cnt;                  /* Number of BPF upgradeable loader accounts. */
  fd_borrowed_account_t executable_accounts[128];        /* Array of BPF upgradeable loader program data accounts */
  fd_borrowed_account_t borrowed_accounts[128];          /* Array of borrowed accounts accessed by this transaction. */
  uchar                 unknown_accounts[128];           /* Array of boolean values to denote if an account is unknown */
  fd_txn_return_data_t  return_data;                     /* Data returned from `return_data` syscalls */
};

#define FD_EXEC_TXN_CTX_ALIGN     (alignof(fd_exec_txn_ctx_t))
#define FD_EXEC_TXN_CTX_FOOTPRINT ( sizeof(fd_exec_txn_ctx_t))
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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h */
