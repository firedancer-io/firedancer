#include "fd_sysvar_slot_hashes.h"
#include "../fd_executor.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

fd_slot_hashes_t *
fd_sysvar_slot_hashes_read( fd_slot_hashes_t *   result,
                            fd_exec_slot_ctx_t * slot_ctx ) {

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_slot_hashes_id, rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t decode = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen,
    .valloc  = slot_ctx->valloc /* !!! There is no reason to place this on the slot_ctx heap.  Use scratch instead. */
  };

  if( FD_UNLIKELY( fd_slot_hashes_decode( result, &decode )!=FD_BINCODE_SUCCESS ) )
    return NULL;
  return result;
}
