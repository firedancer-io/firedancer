#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_h

#include "fd_executor_err.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/poh/fd_poh.h"
#include "../types/fd_types_yaml.h"
#include "../log_collector/fd_log_collector.h"
#include "tests/harness/generated/invoke.pb.h"
#include "tests/harness/generated/txn.pb.h"
#include "../features/fd_features.h"
#include "fd_runtime.h"

#define FD_FEE_PAYER_TXN_IDX (0UL)

/* FD_EXEC_CU_UPDATE consumes CUs from the current instr ctx
   and fails in case of error. */
#define FD_EXEC_CU_UPDATE( ctx, cost ) do {               \
  fd_exec_instr_ctx_t * _ctx = (ctx);                     \
  int err = fd_exec_consume_cus( _ctx->txn_ctx, (cost) ); \
  if( FD_UNLIKELY( err ) ) return err;                    \
  } while(0)

// https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L82
#define FD_ACCOUNT_DATA_COST_PAGE_SIZE ( 32UL * 1024UL )

FD_PROTOTYPES_BEGIN

/* https://github.com/anza-xyz/agave/blob/v2.0.9/runtime/src/bank.rs#L3239-L3251 */
static inline ulong
get_transaction_account_lock_limit( fd_exec_txn_ctx_t const * txn_ctx ) {
  return fd_ulong_if( FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, increase_tx_account_lock_limit ), MAX_TX_ACCOUNT_LOCKS, 64UL );
}

/* fd_exec_instr_fn_t processes an instruction.  Returns an error code
   in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}. */

typedef int (* fd_exec_instr_fn_t)( fd_exec_instr_ctx_t * ctx );

fd_exec_instr_fn_t
fd_executor_lookup_native_precompile_program( fd_txn_account_t const * prog_acc );

/* Returns 1 if the given pubkey matches one of the BPF loader v1/v2/v3/v4
   program IDs, and 0 otherwise. */
uchar
fd_executor_pubkey_is_bpf_loader( fd_pubkey_t const * pubkey );

int
fd_executor_verify_transaction( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_check_transactions( fd_exec_txn_ctx_t * txn_ctx );

/* fd_execute_instr creates a new fd_exec_instr_ctx_t and performs
   instruction processing.  Does fd_spad_t allocations.  Returns an
   error code in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}.

   IMPORTANT: instr_info must have the same lifetime as txn_ctx. This can
   be achieved by using fd_executor_acquire_instr_info_elem( txn_ctx ) to
   acquire an fd_instr_info_t element with the same lifetime as the txn_ctx */
int
fd_executor_txn_verify( fd_exec_txn_ctx_t * txn_ctx );

int
fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                  fd_instr_info_t *   instr_info );

int
fd_execute_txn_prepare_start( fd_exec_slot_ctx_t const * slot_ctx,
                              fd_exec_txn_ctx_t *        txn_ctx,
                              fd_txn_t const *           txn_descriptor,
                              fd_rawtxn_b_t const *      txn_raw );

/*
  Execute the given transaction.

  Makes changes to the Funk accounts DB. */
int
fd_execute_txn( fd_execute_txn_task_info_t * task_info );

int
fd_executor_validate_transaction_fee_payer( fd_exec_txn_ctx_t * txn_ctx );

void
fd_executor_setup_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

void
fd_executor_setup_txn_account_keys( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_setup_txn_alut_account_keys( fd_exec_txn_ctx_t * txn_ctx );

/*
  Validate the txn after execution for violations of various lamport balance and size rules
 */

int
fd_executor_txn_check( fd_exec_txn_ctx_t * txn_ctx );

void
fd_txn_reclaim_accounts( fd_exec_txn_ctx_t * txn_ctx );

/* fd_io_strerror converts an FD_EXECUTOR_INSTR_ERR_{...} code into a
   human readable cstr.  The lifetime of the returned pointer is
   infinite and the call itself is thread safe.  The returned pointer is
   always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_executor_instr_strerror( int err );

int
fd_executor_load_transaction_accounts( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_validate_account_locks( fd_exec_txn_ctx_t const * txn_ctx );

static inline int
fd_exec_consume_cus( fd_exec_txn_ctx_t * txn_ctx,
                     ulong               cus ) {
  ulong new_cus   =  txn_ctx->compute_budget_details.compute_meter - cus;
  int   underflow = (txn_ctx->compute_budget_details.compute_meter < cus);
  if( FD_UNLIKELY( underflow ) ) {
    txn_ctx->compute_budget_details.compute_meter = 0UL;
    return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
  }
  txn_ctx->compute_budget_details.compute_meter = new_cus;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* We expose these only for the fuzzing harness.
   Normally you shouldn't be invoking these manually. */
int
fd_instr_stack_push( fd_exec_txn_ctx_t *     txn_ctx,
                     fd_instr_info_t *       instr );

int
fd_instr_stack_pop( fd_exec_txn_ctx_t *       txn_ctx,
                    fd_instr_info_t const *   instr );

void
fd_exec_txn_ctx_from_exec_slot_ctx( fd_exec_slot_ctx_t const * slot_ctx,
                                    fd_exec_txn_ctx_t *        ctx,
                                    fd_wksp_t const *          funk_wksp,
                                    fd_wksp_t const *          runtime_pub_wksp,
                                    ulong                      funk_txn_gaddr,
                                    ulong                      funk_gaddr,
                                    fd_bank_hash_cmp_t *       bank_hash_cmp );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_h */
