#include "test_vm_util.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_runtime.h"

/* Generates a minimal instruction context to supply to fd_vm_t.
   For now, we just need to setup feature flags. */
void
test_vm_minimal_exec_instr_ctx( fd_exec_instr_ctx_t * instr_ctx,
                                fd_runtime_t *        runtime,
                                fd_bank_t *           bank,
                                fd_bank_data_t *      bank_data,
                                fd_txn_out_t *        txn_out ) {
  memset( instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  bank->data = bank_data;

  /* Setup feature flags */
  fd_features_disable_all( fd_bank_features_modify( bank ) );
  fd_features_set( fd_bank_features_modify( bank ), fd_feature_id_query( TEST_VM_REJECT_CALLX_R10_FEATURE_PREFIX ), 0UL );

  fd_bank_slot_set( bank, 1UL );

  instr_ctx->txn_out = txn_out;
  instr_ctx->bank    = bank;
  instr_ctx->runtime = runtime;
}

void
test_vm_clear_txn_ctx_err( fd_txn_out_t * txn_out ) {
  txn_out->err.exec_err      = 0;
  txn_out->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_NONE;
  return;
}
