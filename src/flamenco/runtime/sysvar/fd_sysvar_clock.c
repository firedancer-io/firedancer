#include "fd_sysvar_clock.h"
#include "../fd_executor.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

int
fd_sysvar_clock_read( fd_sol_sysvar_clock_t * result,
                      fd_exec_slot_ctx_t *    slot_ctx ) {
  FD_BORROWED_ACCOUNT_DECL(acc);
  int rc = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_clock_id, acc );

  switch( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  default:
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  fd_bincode_decode_ctx_t ctx =
    { .data    = acc->const_data,
      .dataend = acc->const_data + acc->const_meta->dlen,
      .valloc  = {0}  /* valloc not required */ };

  return fd_sol_sysvar_clock_decode( result, &ctx );
}
