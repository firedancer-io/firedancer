#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_h

#include "info/fd_instr_info.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../disco/fd_txn_p.h"

/* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L40-L47 */
#define FD_TRANSACTION_ACCOUNT_BASE_SIZE  (64UL)
#define FD_ADDRESS_LOOKUP_TABLE_BASE_SIZE (8248UL)

#define FD_FEE_PAYER_TXN_IDX (0UL)

/* FD_EXEC_CU_UPDATE consumes CUs from the current instr ctx
   and fails in case of error. */
#define FD_EXEC_CU_UPDATE( ctx, cost ) do {                   \
  fd_exec_instr_ctx_t * _ctx = (ctx);                         \
  int err = fd_executor_consume_cus( _ctx->txn_out, (cost) ); \
  if( FD_UNLIKELY( err ) ) return err;                        \
  } while(0)

// https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L82
#define FD_ACCOUNT_DATA_COST_PAGE_SIZE ( 32UL * 1024UL )

FD_PROTOTYPES_BEGIN

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
fd_executor_verify_transaction( fd_bank_t *         bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out );

int
fd_executor_check_transactions( fd_runtime_t *      runtime,
                                fd_bank_t *         bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out );

/* fd_execute_instr creates a new fd_exec_instr_ctx_t and performs
   instruction processing.  Does fd_spad_t allocations.  Returns an
   error code in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}.

   IMPORTANT: instr_info must have the same lifetime as txn_ctx. This can
   be achieved by using fd_executor_acquire_instr_info_elem( txn_ctx ) to
   acquire an fd_instr_info_t element with the same lifetime as the txn_ctx */
int
fd_executor_txn_verify( fd_txn_p_t *  txn_p,
                        fd_sha512_t * shas[ FD_TXN_ACTUAL_SIG_MAX ] );

int
fd_execute_instr( fd_runtime_t *      runtime,
                  fd_bank_t *         bank,
                  fd_txn_in_t const * txn_in,
                  fd_txn_out_t *      txn_out,
                  fd_instr_info_t *   instr_info );

/*
  Execute the given transaction.

  Makes changes to the Funk accounts DB. */
int
fd_execute_txn( fd_runtime_t *      runtime,
                fd_bank_t *         bank,
                fd_txn_in_t const * txn_in,
                fd_txn_out_t *      txn_out );

int
fd_executor_validate_transaction_fee_payer( fd_runtime_t *      runtime,
                                            fd_bank_t *         bank,
                                            fd_txn_in_t const * txn_in,
                                            fd_txn_out_t *      txn_out );

void
fd_executor_setup_accounts_for_txn( fd_runtime_t *      runtime,
                                    fd_bank_t *         bank,
                                    fd_txn_in_t const * txn_in,
                                    fd_txn_out_t *      txn_out );

void
fd_executor_setup_txn_account_keys( fd_txn_in_t const * txn_in,
                                    fd_txn_out_t *      txn_out );

int
fd_executor_setup_txn_alut_account_keys( fd_runtime_t *      runtime,
                                         fd_bank_t *         bank,
                                         fd_txn_in_t const * txn_in,
                                         fd_txn_out_t *      txn_out );

/*
  Validate the txn after execution for violations of various lamport balance and size rules
 */

int
fd_executor_txn_check( fd_bank_t *    bank,
                       fd_txn_out_t * txn_out );

void
fd_executor_reclaim_account( fd_txn_account_t * account,
                             ulong              slot );

/* fd_io_strerror converts an FD_EXECUTOR_INSTR_ERR_{...} code into a
   human readable cstr.  The lifetime of the returned pointer is
   infinite and the call itself is thread safe.  The returned pointer is
   always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_executor_instr_strerror( int err );

int
fd_executor_load_transaction_accounts( fd_runtime_t *      runtime,
                                       fd_bank_t *         bank,
                                       fd_txn_in_t const * txn_in,
                                       fd_txn_out_t *      txn_out );

int
fd_executor_validate_account_locks( fd_bank_t *          bank,
                                    fd_txn_out_t const * txn_out );

int
fd_executor_consume_cus( fd_txn_out_t * txn_out,
                         ulong          cus );

/* We expose these only for the fuzzing harness.
   Normally you shouldn't be invoking these manually. */
int
fd_instr_stack_push( fd_runtime_t *      runtime,
                     fd_txn_in_t const * txn_in,
                     fd_txn_out_t *      txn_out,
                     fd_instr_info_t *   instr );

int
fd_instr_stack_pop( fd_runtime_t *          runtime,
                    fd_txn_out_t *          txn_out,
                    fd_instr_info_t const * instr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_h */
