#include "fd_vm_alt_bn128.h"

int
fd_vm_syscall_sol_alt_bn128_group_op( FD_PARAM_UNUSED void *  _ctx,
                                      FD_PARAM_UNUSED ulong   params,
                                      FD_PARAM_UNUSED ulong   endianness,
                                      FD_PARAM_UNUSED ulong   vals_addr,
                                      FD_PARAM_UNUSED ulong   vals_len,
                                      FD_PARAM_UNUSED ulong   result_addr,
                                      FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_SYSCALL_ERR_INVAL;
}

int
fd_vm_syscall_sol_alt_bn128_compression( FD_PARAM_UNUSED void *  _ctx,
                                         FD_PARAM_UNUSED ulong   params,
                                         FD_PARAM_UNUSED ulong   endianness,
                                         FD_PARAM_UNUSED ulong   vals_addr,
                                         FD_PARAM_UNUSED ulong   vals_len,
                                         FD_PARAM_UNUSED ulong   result_addr,
                                         FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_SYSCALL_ERR_INVAL;
}
