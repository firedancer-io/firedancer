#ifndef HEADER_fd_src_ballet_runtime_vm_fd_call_stack_h
#define HEADER_fd_src_ballet_runtime_vm_fd_call_stack_h

#include "../util/fd_util.h"

#define FD_VM_STACK_MAX_DEPTH (64)
#define FD_VM_STACK_FRAME_SZ  (0x1000)

#define FD_VM_STACK_OP_SUCCESS            (0)
#define FD_VM_STACK_OP_ERR_POP_EMPTY      (1)
#define FD_VM_STACK_OP_ERR_PUSH_OVERFLOW  (2)

struct fd_vm_shadow_stack {
  ulong ret_instr_ptr;
  ulong saved_registers[4];
};
typedef struct fd_vm_shadow_stack fd_vm_shadow_stack_t;

struct fd_vm_stack {
  ulong stack_pointer;
  ulong frames_used; 
  fd_vm_shadow_stack_t frames[64];
  uchar data[FD_VM_STACK_MAX_DEPTH * FD_VM_STACK_FRAME_SZ];
};
typedef struct fd_vm_stack fd_vm_stack_t;

fd_vm_stack_t * fd_vm_stack_init( fd_vm_stack_t * stack );

ulong fd_vm_stack_push( fd_vm_stack_t * stack, ulong saved_regs[4] );

ulong fd_vm_stack_pop( fd_vm_stack_t * stack, ulong saved_regs[4] );

#endif // HEADER_fd_src_ballet_runtime_vm_fd_call_stack_h
