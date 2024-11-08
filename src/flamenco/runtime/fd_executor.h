#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_h

#include "fd_executor_err.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/pack/fd_microblock.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/poh/fd_poh.h"
#include "../types/fd_types_yaml.h"
#include "../log_collector/fd_log_collector.h"
#include "tests/generated/invoke.pb.h"
#include "tests/generated/txn.pb.h"
#include "../features/fd_features.h"
#include "fd_runtime.h"

/* FD_EXEC_CU_UPDATE consumes CUs from the current instr ctx
   and fails in case of error. */
#define FD_EXEC_CU_UPDATE( ctx, cost ) do {               \
  fd_exec_instr_ctx_t * _ctx = (ctx);                     \
  int err = fd_exec_consume_cus( _ctx->txn_ctx, (cost) ); \
  if( FD_UNLIKELY( err ) ) return err;                    \
  } while(0)

FD_PROTOTYPES_BEGIN

/* https://github.com/anza-xyz/agave/blob/v2.0.9/runtime/src/bank.rs#L3239-L3251 */
static inline ulong
get_transaction_account_lock_limit( fd_exec_slot_ctx_t const * slot_ctx ) {
  return fd_ulong_if( FD_FEATURE_ACTIVE( slot_ctx, increase_tx_account_lock_limit ), MAX_TX_ACCOUNT_LOCKS, 64UL );
}

/* Create an InstrContext protobuf struct from a given 
   transaction context and instr info. 

   NOTE: Calling this function requires the caller to have a scratch 
   frame ready and pushed (see dump_instr_to_protobuf) */
void
fd_create_instr_context_protobuf_from_instructions( fd_exec_test_instr_context_t       * instr_context,
                                                    fd_exec_txn_ctx_t            const * txn_ctx,
                                                    fd_instr_info_t              const * instr );

/* fd_exec_instr_fn_t processes an instruction.  Returns an error code
   in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}. */

typedef int (* fd_exec_instr_fn_t)( fd_exec_instr_ctx_t * ctx );

/* fd_executor_lookup_native_program returns the appropriate instruction
   processor for the given native program ID.  Returns NULL if given ID
   is not a recognized native program. */

fd_exec_instr_fn_t
fd_executor_lookup_native_program( fd_borrowed_account_t const * account );

/* TODO:FIXME: add documentation here */

int
fd_validate_fee_payer( fd_borrowed_account_t * account, fd_rent_t const * rent, ulong fee );

int
fd_executor_check_transactions( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_verify_precompiles( fd_exec_txn_ctx_t * txn_ctx );

/* fd_execute_instr creates a new fd_exec_instr_ctx_t and performs
   instruction processing.  Does fd_scratch allocations.  Returns an
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
fd_execute_txn_prepare_start( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx,
                               fd_txn_t const * txn_descriptor,
                               fd_rawtxn_b_t const * txn_raw );

int
fd_execute_txn_prepare_phase3( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx,
                               fd_txn_p_t * txn );

int
fd_execute_txn_finalize( fd_exec_txn_ctx_t * txn_ctx,
                         int exec_txn_err );

/*
  Execute the given transaction.

  Makes changes to the Funk accounts DB. */
int
fd_execute_txn( fd_exec_txn_ctx_t * txn_ctx );

uint
fd_executor_txn_uses_sysvar_instructions( fd_exec_txn_ctx_t const * txn_ctx );

int
fd_executor_validate_transaction_fee_payer( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_is_system_nonce_account( fd_borrowed_account_t * account );

/*
  Validate the txn after execution for violations of various lamport balance and size rules
 */

int
fd_executor_txn_check( fd_exec_slot_ctx_t const * slot_ctx, 
                       fd_exec_txn_ctx_t *        txn );

void
fd_txn_reclaim_accounts( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_is_blockhash_valid_for_age( fd_block_hash_queue_t const * block_hash_queue,
                                        fd_hash_t const *             blockhash,
                                        ulong                         max_age );

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
  ulong new_cus   =  txn_ctx->compute_meter - cus;
  int   underflow = (txn_ctx->compute_meter < cus);
  if( FD_UNLIKELY( underflow ) ) {
    txn_ctx->compute_meter = 0UL;
    return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
  }
  txn_ctx->compute_meter = new_cus;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
dump_txn_to_protobuf( fd_exec_txn_ctx_t *txn_ctx, fd_spad_t * spad );

/* We expose these only for the fuzzing harness.
   Normally you shouldn't be invoking these manually. */
int
fd_instr_stack_push( fd_exec_txn_ctx_t *     txn_ctx,
                     fd_instr_info_t *       instr );

int
fd_instr_stack_pop( fd_exec_txn_ctx_t *       txn_ctx,
                    fd_instr_info_t const *   instr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_h */
