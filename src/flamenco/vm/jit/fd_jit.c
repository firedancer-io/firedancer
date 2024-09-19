#include "fd_jit_private.h"
#include <math.h>

FD_TL fd_vm_t *                  fd_jit_vm;        /* current VM being executed */
FD_TL fd_sbpf_syscalls_t const * fd_jit_syscalls;  /* current syscall table */

FD_TL uint  fd_jit_segment_cnt;
FD_TL uint  fd_jit_mem_ro_sz[ FD_VM_JIT_SEGMENT_MAX ];
FD_TL uint  fd_jit_mem_rw_sz[ FD_VM_JIT_SEGMENT_MAX ];
FD_TL ulong fd_jit_mem_base [ FD_VM_JIT_SEGMENT_MAX ];
FD_TL ulong fd_jit_jmp_buf[8];
FD_TL ulong fd_jit_segfault_vaddr;
FD_TL ulong fd_jit_segfault_rip;

FD_TL jmp_buf fd_jit_compile_abort;

FD_TL void * fd_jit_code_section_base;
FD_TL ulong  fd_jit_code_section_sz;

ulong
fd_jit_est_code_sz( ulong bpf_sz ) {
  if( FD_UNLIKELY( bpf_sz > (1UL<<24) ) ) return 0UL; /* float32 representation limit */
  return FD_JIT_BLOAT_BASE + (ulong)ceilf( (float)bpf_sz * FD_JIT_BLOAT_MAX );
}

ulong
fd_jit_est_scratch_sz( ulong bpf_sz ) {
  fd_jit_scratch_layout_t layout[1];
  if( FD_UNLIKELY( !fd_jit_scratch_layout( layout, bpf_sz ) ) ) return 0UL;
  return layout->sz;
}

fd_jit_prog_t *
fd_jit_prog_new( fd_jit_prog_t *            jit_prog,
                 fd_sbpf_program_t const *  prog,
                 fd_sbpf_syscalls_t const * syscalls,
                 void *                     code_buf,
                 ulong                      code_bufsz,
                 void *                     scratch,
                 ulong                      scratch_sz,
                 int *                      out_err ) {

  *out_err = FD_VM_ERR_INVAL;

  if( FD_UNLIKELY( setjmp( fd_jit_compile_abort ) ) ) {
    /* DASM_M_GROW longjmp() here in case of alloc failure */
    *out_err = FD_VM_ERR_FULL;
    return NULL;
  }
  fd_jit_code_section_base = (void *)1; /* an invalid non-NULL pointer */
  fd_jit_code_section_sz   = 0UL;

  uint  text_cnt = (uint)prog->text_cnt;
  ulong bpf_sz   = text_cnt * 8UL;

  /* Prepare custom scratch allocator for DynASM.
     Constructors provided by dasm_x86.h heavily rely on realloc() like
     semantics.  The code below replaces these with pre-allocated
     regions out of code_buf and uses the redefined DASM_M_GROW to
     detect out-of-memory conditions. */

  fd_jit_scratch_layout_t layout[1];
  if( FD_UNLIKELY( !fd_jit_scratch_layout( layout, bpf_sz ) ) ) {
    *out_err = FD_VM_ERR_FULL;
    return NULL;
  }
  if( FD_UNLIKELY( layout->sz > scratch_sz ) ) {
    *out_err = FD_VM_ERR_FULL;
    return NULL;
  }

  dasm_State * d = fd_jit_prepare( scratch, layout, code_buf, code_bufsz );

  fd_jit_compile( &d, prog, syscalls );

  ulong code_sz;
  dasm_link( &d, &code_sz );
  if( FD_UNLIKELY( code_sz > code_bufsz ) ) {
    *out_err = FD_VM_ERR_FULL;
    return NULL;
  }

  dasm_encode( &d, code_buf );
  jit_prog->first_rip = (ulong)code_buf + (ulong)dasm_getpclabel( &d, (uint)prog->entry_pc );

  /* Would ordinarily call dasm_free here, but no need, since all
     memory was allocated in scratch and is released on function return.  */
  //dasm_free( &d );

  *out_err = FD_VM_SUCCESS;
  return jit_prog;
}

void *
fd_jit_prog_delete( fd_jit_prog_t * prog ) {
  (void)prog;
  return NULL;
}

int
fd_jit_vm_attach( fd_vm_t * vm ) {
  fd_jit_vm       = vm;
  fd_jit_syscalls = vm->syscalls;

  /* 6UL is a magic hardcoded constant in fd_vm_t -- Needs to change */
  fd_jit_segment_cnt = 6UL;
  for( ulong j=0UL; j<fd_jit_segment_cnt; j++ ) {
    /* FIXME i accidentally created exactly the same data structure
             through separate work, but now it has different names */
    fd_jit_mem_base [j] = vm->region_haddr[j];
    fd_jit_mem_rw_sz[j] = vm->region_st_sz[j];
    fd_jit_mem_ro_sz[j] = vm->region_ld_sz[j];
  }

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

int
fd_jit_exec( fd_jit_prog_t * jit_prog,
             fd_vm_t *       vm ) {
  fd_jit_vm_attach( vm );
  int err = jit_prog->entrypoint( jit_prog->first_rip );
  fd_jit_vm_detach();
  return err;
}

/* fd_dasm_grow_check gets called when DynASM tries to grow a buffer
   using realloc().  We stubbed out realloc(), so we just check if the
   requested buffer is sufficiently large.  If it's not, we abort via
   longjmp(). */

void
fd_dasm_grow_check( void * ptr,
                    ulong  min_sz ) {
  if( FD_UNLIKELY( ptr!=fd_jit_code_section_base ) ) goto fail;
  if( FD_UNLIKELY( min_sz>fd_jit_code_section_sz ) ) goto fail;
  return;
fail:
  FD_LOG_WARNING(( "Aborting JIT compile" ));
  longjmp( fd_jit_compile_abort, 1 );
}
