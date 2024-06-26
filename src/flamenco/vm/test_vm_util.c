#include "test_vm_util.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

/* Generates a minimal instruction context to supply to fd_vm_t.
   For now, we just need to setup feature flags. */
fd_exec_instr_ctx_t *
test_vm_minimal_exec_instr_ctx( 
    fd_valloc_t valloc,
    bool reject_callx_r10 ) {

  void * _ctx = fd_exec_instr_ctx_new( fd_valloc_malloc( valloc, FD_EXEC_INSTR_CTX_ALIGN, FD_EXEC_INSTR_CTX_FOOTPRINT ) );

  fd_exec_instr_ctx_t * ctx = fd_exec_instr_ctx_join( _ctx );

  if ( !ctx ) {
    return NULL;
  }

  ctx->valloc = valloc;

  /* Keep slot_ctx and epoch_ctx initialization simple. We only want features ATM.
     Feel free to change this to use actual init semantics (*_new and *_join),
     but remember to update the cleanup function below :) */
  void *    _slot_ctx  = fd_valloc_malloc( valloc, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT );
  fd_exec_slot_ctx_t  * slot_ctx  = (fd_exec_slot_ctx_t *)( _slot_ctx );

  void *    _epoch_ctx = fd_valloc_malloc( valloc, fd_exec_epoch_ctx_align() , sizeof(fd_exec_epoch_ctx_t) );
  fd_exec_epoch_ctx_t * epoch_ctx = (fd_exec_epoch_ctx_t *) _epoch_ctx;

  if ( !epoch_ctx || !slot_ctx ) {
    return NULL;
  }

  ctx->epoch_ctx = epoch_ctx; /* technically not necessary, given how FEATURE_ACTIVE macro works */
  ctx->slot_ctx  = slot_ctx;

  slot_ctx->epoch_ctx = epoch_ctx;

  /* Setup feature flags */
  fd_features_disable_all( &epoch_ctx->features );
  if ( reject_callx_r10 ) {
    fd_features_set( &epoch_ctx->features, fd_feature_id_query(TEST_VM_REJECT_CALLX_R10_FEATURE_PREFIX), 0UL );
  }

  return ctx;
}

void
test_vm_exec_instr_ctx_delete(
    fd_exec_instr_ctx_t * ctx ) {
  
  fd_valloc_t valloc = ctx->valloc;
  fd_exec_slot_ctx_t  * slot_ctx  = ctx->slot_ctx;
  fd_exec_epoch_ctx_t * epoch_ctx = slot_ctx->epoch_ctx;

  fd_exec_instr_ctx_delete( fd_exec_instr_ctx_leave( ctx ) );

  fd_valloc_free( valloc, epoch_ctx );
  fd_valloc_free( valloc, slot_ctx );
  fd_valloc_free( valloc, ctx );

  return;
}
