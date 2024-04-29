#include "fd_vm_private.h"

/* FIXME: MAKE DIFFERENT VERSIONS FOR EACH COMBO OF CHECK_ALIGN/TRACE? */

int
fd_vm_exec_private( fd_vm_t * vm ) {

  if( FD_UNLIKELY( !vm ) ) return FD_VM_ERR_INVAL;

  /* Unpack the configuration */
  /* FIXME: move this into fd_vm_init */
  int err = fd_vm_setup_state_for_execution( vm );
  if ( FD_UNLIKELY( err != FD_VM_SUCCESS ) ) {
    return err;
  }

  /* Pull out variables needed for the fd_vm_interp_core template */
  int   check_align = vm->check_align;
  ulong frame_max   = FD_VM_STACK_FRAME_MAX; /* FIXME: vm->frame_max to make this run-time configured */
  ulong heap_max    = vm->heap_max;

  ulong const * FD_RESTRICT text          = vm->text;
  ulong                     text_cnt      = vm->text_cnt;
  ulong                     text_word_off = vm->text_off / 8UL;
  ulong                     entry_pc      = vm->entry_pc;
  ulong const * FD_RESTRICT calldests     = vm->calldests;

  fd_sbpf_syscalls_t const * FD_RESTRICT syscalls = vm->syscalls;

  ulong const * FD_RESTRICT region_haddr = vm->region_haddr;
  uint  const * FD_RESTRICT region_ld_sz = vm->region_ld_sz;
  uint  const * FD_RESTRICT region_st_sz = vm->region_st_sz;

  ulong * FD_RESTRICT reg = vm->reg;

  fd_vm_shadow_t * FD_RESTRICT shadow = vm->shadow;

  /* Run the VM */
# include "fd_vm_interp_core.c"

  return err;

}

int
fd_vm_exec_notrace( fd_vm_t * vm ) {

# undef FD_VM_INTERP_EXE_TRACING_ENABLED
# undef FD_VM_INTERP_MEM_TRACING_ENABLED

  return fd_vm_exec_private( vm );
}

int
fd_vm_exec_trace( fd_vm_t * vm ) {

# define FD_VM_INTERP_EXE_TRACING_ENABLED 1
# define FD_VM_INTERP_MEM_TRACING_ENABLED 1

  int err = fd_vm_exec_private( vm );

# undef FD_VM_INTERP_EXE_TRACING_ENABLED
# undef FD_VM_INTERP_MEM_TRACING_ENABLED

  return err;
}
