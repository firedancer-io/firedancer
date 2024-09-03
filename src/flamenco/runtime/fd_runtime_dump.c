#include "fd_runtime_dump.h"

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "../runtime/tests/generated/instr_v2.pb.h"
#include "../runtime/tests/generated/txn_v2.pb.h"
#include "../runtime/tests/generated/slot_v2.pb.h"
#include "../runtime/tests/generated/exec_v2.pb.h"

int
fd_runtime_dump_instr( fd_exec_instr_ctx_t * instr_ctx ) {
  fd_v2_exec_env_t     exec_env   = {0};
  fd_v2_acct_state_t * acct_state = fd_valloc_malloc( instr_ctx->valloc, 
                                                      alignof(fd_v2_acct_state_t), 
                                                      sizeof(fd_v2_acct_state_t) * instr_ctx->instr->acct_cnt );

  (void)exec_env;
  (void)acct_state;
  (void)instr_ctx;
  return 0;
}

int
fd_runtime_dump_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  (void)txn_ctx;
  return 0;
}

int
fd_runtime_dump_slot( fd_exec_slot_ctx_t * slot_ctx ) {
  (void)slot_ctx;
  return 0;
}

int
fd_runtime_dump_runtime( fd_exec_epoch_ctx_t * epoch_ctx ) {
  (void)epoch_ctx;
  return 0;
}
