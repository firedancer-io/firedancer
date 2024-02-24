#ifndef HEADER_fd_src_flamenco_vm_fd_vm_stack_h
#define HEADER_fd_src_flamenco_vm_fd_vm_stack_h

#include "fd_vm_base.h"

/* FIXME: The max depth of the stack is configurable by the compute budget */
#define FD_VM_STACK_MAX_DEPTH           (64)
#define FD_VM_STACK_FRAME_SZ            (0x1000)
#define FD_VM_STACK_FRAME_WITH_GUARD_SZ (0x2000)

#define FD_VM_STACK_OP_SUCCESS            (0)
#define FD_VM_STACK_OP_ERR_POP_EMPTY      (1)
#define FD_VM_STACK_OP_ERR_PUSH_OVERFLOW  (2)
#define FD_VM_STACK_OP_ERR_POP_UNDERFLOW  (3)

/* The shadow stack frames have information which is hidden from the program execution. */
struct fd_vm_shadow_stack_frame {
  ulong ret_instr_ptr;
  ulong saved_registers[4];
};
typedef struct fd_vm_shadow_stack_frame fd_vm_shadow_stack_frame_t;

/* The VM stack holds scratch space for each function call in a VM execution. */
struct fd_vm_stack {
  ulong                       stack_pointer;
  ulong                       frames_used;
  fd_vm_shadow_stack_frame_t  frames[FD_VM_STACK_MAX_DEPTH];
  uchar                       data[FD_VM_STACK_MAX_DEPTH * FD_VM_STACK_FRAME_WITH_GUARD_SZ];
};
typedef struct fd_vm_stack fd_vm_stack_t;


FD_PROTOTYPES_BEGIN

/* Initializes a VM stack. */
fd_vm_stack_t * fd_vm_stack_init( fd_vm_stack_t * stack );

/* Pushes a new frame onto the VM stack. Returns a non-zero status code on failure. */
ulong fd_vm_stack_push( fd_vm_stack_t * stack, ulong ret_instr_ptr, ulong saved_regs[4] );

/* Pops a frame off of the VM stack. Returns a non-zero status code on failure. */
ulong fd_vm_stack_pop( fd_vm_stack_t * stack, ulong * ret_instr_ptr, ulong saved_regs[4] );

/* TODO: add strerror function */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_stack_h */
