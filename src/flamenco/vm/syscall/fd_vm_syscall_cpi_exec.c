#include "fd_vm_syscall.h"
#include "../../runtime/fd_executor.h"

/* Need this to be in a separate translation unit to use the --wrap
   functionality provided by linkers. See  */
int
fd_vm_cpi_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                         fd_instr_info_t *   instr_info){
  return fd_execute_instr(txn_ctx, instr_info);
}
