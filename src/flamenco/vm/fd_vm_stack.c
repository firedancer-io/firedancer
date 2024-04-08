#include "fd_vm_stack.h"


fd_vm_stack_t *
fd_vm_stack_init( fd_vm_stack_t * stack ) {
  stack->stack_pointer = 0;
  stack->frames_used = 0;
  fd_memset(stack->frames, 0, sizeof(stack->frames));
  fd_memset(stack->data, 0, sizeof(stack->data));
  
  return stack;
}

ulong 
fd_vm_stack_push( fd_vm_stack_t * stack, 
                  ulong           ret_instr_ptr, 
                  ulong           saved_regs[4] ) {
  if( stack->frames_used >= FD_VM_STACK_MAX_DEPTH ) {
    return FD_VM_STACK_OP_ERR_PUSH_OVERFLOW;
  }

  ulong cur_frame_idx = stack->frames_used;
  stack->frames[cur_frame_idx].ret_instr_ptr = ret_instr_ptr;
  fd_memcpy( stack->frames[cur_frame_idx].saved_registers, saved_regs, 4*sizeof(ulong) );

  stack->frames_used++;

  return FD_VM_STACK_OP_SUCCESS;
}

ulong 
fd_vm_stack_pop( fd_vm_stack_t * stack, ulong * ret_instr_ptr, ulong saved_regs[4] ) {
  if( FD_UNLIKELY( stack->frames_used == 0 ) ) {
    return FD_VM_STACK_OP_ERR_POP_UNDERFLOW;
  }
  
  ulong cur_frame_idx = stack->frames_used-1;
  *ret_instr_ptr = stack->frames[cur_frame_idx].ret_instr_ptr;
  fd_memcpy( saved_regs, stack->frames[cur_frame_idx].saved_registers, 4*sizeof(ulong) );
  stack->frames_used--;
  
  return FD_VM_STACK_OP_SUCCESS;
}
