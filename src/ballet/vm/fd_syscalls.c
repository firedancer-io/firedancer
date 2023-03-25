#include "fd_syscalls.h"
#include "fd_syscalls.h"

#define FD_VM_SYSCALL_DEFN(name, ctx_attr, mem_map_attr, arg0, arg1, arg2, arg3, arg4) \
ulong \
fd_vm_syscall_##name##( \
    ctx_attr fd_vm_exec_context_t * ctx, \
    mem_map_attr fd_vm_mem_map_t *  mem_map, \
    arg0, arg1, arg2, arg3, arg4, \
    ulong * ret_val )

#define FD_VM_SYSCALL_DEFN0_NO_CTX_NO_MEM(name) FD_VM_SYSCALL_DEFN( \
    name, FD_FN_UNUSED, FD_FN_UNUSED, \
    FD_FN_UNUSED ulong _arg0, \
    FD_FN_UNUSED ulong _arg1, \
    FD_FN_UNUSED ulong _arg2, \
    FD_FN_UNUSED ulong _arg3, \
    FD_FN_UNUSED ulong _arg4 )

#define FD_VM_SYSCALL_DEFN4(name, arg0, arg1, arg2, arg3) FD_VM_SYSCALL_DEFN( \
    name, , , \
    ulong arg0, \
    ulong arg1, \
    ulong arg2, \
    ulong arg3, \
    FD_FN_UNUSED ulong _arg4 )

#define FD_VM_SYSCALL_DEFN4_NO_MEM(name, arg0, arg1, arg2, arg3, arg4) FD_VM_SYSCALL_DEFN( \
    name, , FD_UNUSED, \
    ulong arg0, \
    ulong arg1, \
    ulong arg2, \
    ulong arg3, \
    ulong arg4 )

FD_VM_SYSCALL_DEFN0_NO_CTX_NO_MEM(abort) {
  return FD_VM_SYSCALL_ERR_ABORT;
}

FD_VM_SYSCALL_DEFN4(sol_panic_, file, len, line, column) { 
}

FD_VM_SYSCALL_DEFN5_NO_MEM(sol_log_64_, arg0, arg1, arg2, arg3, arg4) {
  uchar buf[1000];
  ulong len = sprintf(buf, "%016x %016x %016x %016x %016x", arg0, arg1, arg2, arg3, arg4);

  fd_vm_log_collector_log(ctx->log_collector, buf, len);

  *ret_val = 0;
  return FD_VM_SYSCALL_SUCCESS;
}
