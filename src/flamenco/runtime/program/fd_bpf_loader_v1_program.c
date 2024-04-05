#include "fd_bpf_loader_v1_program.h"
#include "../context/fd_exec_txn_ctx.h"

int
fd_bpf_loader_v1_program_execute( fd_exec_instr_ctx_t ctx ) {
  do {
    int err = fd_exec_consume_cus( ctx.txn_ctx, 1140UL );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}
