#include "test_vm_util.h"
#include "../runtime/context/fd_exec_txn_ctx.h"
#include "../runtime/fd_bank.h"

/* Generates a minimal instruction context to supply to fd_vm_t.
   For now, we just need to setup feature flags. */
void
test_vm_minimal_exec_instr_ctx( fd_exec_instr_ctx_t * instr_ctx,
                                fd_exec_txn_ctx_t *   txn_ctx,
                                fd_bank_t *           bank ) {
  memset( instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  memset( txn_ctx,   0, sizeof(fd_exec_txn_ctx_t)   );

  txn_ctx->bank = bank;

  /* Setup feature flags */
  fd_features_disable_all( fd_bank_features_modify( txn_ctx->bank ) );
  fd_features_set( fd_bank_features_modify( txn_ctx->bank ), fd_feature_id_query( TEST_VM_REJECT_CALLX_R10_FEATURE_PREFIX ), 0UL );

  fd_bank_slot_set( bank, 1UL );

  instr_ctx->txn_ctx = txn_ctx;
}

void
test_vm_clear_txn_ctx_err( fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->err.exec_err      = 0;
  txn_ctx->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_NONE;
  return;
}
