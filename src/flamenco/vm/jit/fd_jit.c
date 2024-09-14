#include "fd_jit_private.h"

/* Runtime thread locals **********************************************/

FD_TL fd_vm_t *                  fd_jit_vm;        /* current VM being executed */
FD_TL fd_sbpf_syscalls_t const * fd_jit_syscalls;  /* current syscall table */

FD_TL uint  fd_jit_segment_cnt;
FD_TL uint  fd_jit_mem_ro_sz[ FD_VM_JIT_SEGMENT_MAX ];
FD_TL uint  fd_jit_mem_rw_sz[ FD_VM_JIT_SEGMENT_MAX ];
FD_TL ulong fd_jit_mem_base [ FD_VM_JIT_SEGMENT_MAX ];
FD_TL ulong fd_jit_jmp_buf[8];
FD_TL ulong fd_jit_segfault_vaddr;
FD_TL ulong fd_jit_segfault_rip;

ulong
fd_jit_est_code_sz( ulong bpf_sz ) {
  (void)bpf_sz;
  return 0; // FIXME
}

ulong
fd_jit_est_scratch_sz( ulong bpf_sz ) {
  (void)bpf_sz;
  return 0; // FIXME
}

fd_jit_prog_t *
fd_jit_prog_join( void * prog ) {
  return prog;
}

void *
fd_jit_prog_leave( fd_jit_prog_t * prog ) {
  return prog;
}

void *
fd_jit_prog_delete( void * prog ) {
  (void)prog;
  return NULL;
}

int
fd_jit_exec( fd_jit_prog_t * jit_prog,
             fd_vm_t *       vm ) {
  fd_jit_vm_attach( vm );
  int err = jit_prog->entrypoint( jit_prog->first_rip );
  fd_jit_vm_detach();
  return err;
}

int
fd_jit_vm_attach( fd_vm_t * vm ) {
  fd_jit_vm       = vm;
  fd_jit_syscalls = vm->syscalls;

  ulong region_cnt = vm->input_mem_regions_cnt;
  if( FD_UNLIKELY( region_cnt > FD_VM_JIT_SEGMENT_MAX ) ) return FD_VM_ERR_UNSUP;
  for( ulong j=0UL; j<region_cnt; j++ ) {
    fd_vm_input_region_t const * region = vm->input_mem_regions + j;
    if( FD_UNLIKELY( region->haddr != j<<32 ) ) return FD_VM_ERR_UNSUP;

    fd_jit_mem_base [j] = region->haddr;
    fd_jit_mem_rw_sz[j] = fd_uint_if( !!region->is_writable, region->region_sz, 0 );
    fd_jit_mem_ro_sz[j] = region->region_sz;
  }
  fd_jit_segment_cnt = (uint)region_cnt;

  fd_jit_segfault_vaddr = 0UL;
  fd_jit_segfault_rip   = 0UL;

  return FD_VM_SUCCESS;
}

void
fd_jit_vm_detach( void ) {
  fd_jit_segment_cnt    = 0U;
  fd_jit_segfault_vaddr = 0UL;
  fd_jit_segfault_rip   = 0UL;
}
