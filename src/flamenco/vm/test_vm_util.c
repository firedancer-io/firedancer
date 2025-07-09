#include "test_vm_util.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/context/fd_exec_txn_ctx.h"

/* Generates a minimal instruction context to supply to fd_vm_t.
   For now, we just need to setup feature flags. */
fd_exec_instr_ctx_t *
test_vm_minimal_exec_instr_ctx( fd_valloc_t valloc, fd_exec_slot_ctx_t * slot_ctx ) {
  (void)slot_ctx;

  void * _ctx = fd_exec_instr_ctx_new( fd_valloc_malloc( valloc, FD_EXEC_INSTR_CTX_ALIGN, FD_EXEC_INSTR_CTX_FOOTPRINT ) );

  fd_exec_instr_ctx_t * ctx = fd_exec_instr_ctx_join( _ctx );

  if ( !ctx ) {
    return NULL;
  }

  /* Keep slot_ctx initialization simple. We only want features ATM.
     Feel free to change this to use actual init semantics (*_new and *_join),
     but remember to update the cleanup function below :) */
  fd_exec_txn_ctx_t * txn_ctx = fd_valloc_malloc( valloc, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );

  if( !txn_ctx ) {
    return NULL;
  }

  /* Setup feature flags */
  fd_features_disable_all( &txn_ctx->features );
  fd_features_set( &txn_ctx->features, fd_feature_id_query(TEST_VM_REJECT_CALLX_R10_FEATURE_PREFIX), 0UL );

  txn_ctx->slot = 1UL;

  ctx->txn_ctx = txn_ctx;

  return ctx;
}

void
test_vm_exec_instr_ctx_delete( fd_exec_instr_ctx_t * ctx,
                               fd_valloc_t           valloc ) {

  fd_exec_txn_ctx_t * txn_ctx = ctx->txn_ctx;

  fd_exec_instr_ctx_delete( fd_exec_instr_ctx_leave( ctx ) );

  fd_valloc_free( valloc, txn_ctx );
  fd_valloc_free( valloc, ctx );

  return;
}

void
test_vm_clear_txn_ctx_err( fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->exec_err      = 0;
  txn_ctx->exec_err_kind = FD_EXECUTOR_ERR_KIND_NONE;
  return;
}
