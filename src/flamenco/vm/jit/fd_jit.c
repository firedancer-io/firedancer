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

void *
fd_jit_prog_new( fd_jit_prog_t *            jit_prog,
                 fd_sbpf_program_t const *  prog,
                 fd_sbpf_syscalls_t const * syscalls,
                 void *                     code_buf,
                 ulong                      code_bufsz,
                 void *                     scratch,
                 ulong                      scratch_sz,
                 int *                      out_err ) {

  if( FD_UNLIKELY( setjmp( fd_jit_compile_abort ) ) ) {
    /* DASM_M_GROW longjmp() here in case of alloc failure */
    *out_err = FD_VM_ERR_FULL;
    return NULL;
  }

  uint text_cnt = (uint)prog->text_cnt;

  /* Prepare custom scratch allocator for DynASM.
     Constructors provided by dasm_x86.h heavily rely on realloc() like
     semantics.  The code below replaces these with pre-allocated
     regions out of code_buf and uses the redefined DASM_M_GROW to
     detect out-of-memory conditions. */

  ulong dasm_sz     = DASM_PSZ( DASM_MAXSECTION );
  ulong lglabels_sz = (10+fd_jit_lbl__MAX)*sizeof(int);
  ulong pclabels_sz = text_cnt*sizeof(int);
  ulong code_sz     = fd_jit_est_scratch_sz( (ulong)text_cnt * 8UL );

  fd_jit_scratch_layout_t layout = fd_jit_scratch_layout( bpf_sz );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  void * dasm_mem = FD_SCRATCH_ALLOC_APPEND( l, 16UL, dasm_sz     );
  void * lglabels = FD_SCRATCH_ALLOC_APPEND( l, 16UL, lglabels_sz );
  void * pclabels = FD_SCRATCH_ALLOC_APPEND( l, 16UL, pclabels_sz );
  void * section  = FD_SCRATCH_ALLOC_APPEND( l, 16UL, code_sz     );

  /* Custom dasm_init */
  dasm_State * d = (dasm_State *)dasm_mem;
  fd_memset( d, 0, dasm_sz );
  d->psize      = dasm_sz;
  d->maxsection = DASM_MAXSECTION;

  /* Custom dasm_setupglobal */
  d->globals  = fd_jit_labels;
  d->lglabels = lglabels;

  /* Custom dasm_growpc */
  d->pcsize   = text_cnt*sizeof(int);
  d->pclabels = pclabels;

  /* Setup encoder. Zeros lglabels and pclabels. */
  dasm_setup( &d, actions );

  /* Preallocate space for .code section */
  dasm_Section * code = d->sections + 0;
  sec->buf   = code_buf;
  sec->bsize = code_bufsz;
  sec->pos   = DASM_SEC2POS( 0 );
  sec->rbuf  = sec->buf - DASM_POS2BIAS( sec->pos );
  sec->epos  = (int)sec->bsize/sizeof(int) - DASM_MAXSECPOS+DASM_POS2BIAS(pos);
  sec->ofs   = 0;

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
     memory was allocated in scratch and is releasd on function return.  */
  //dasm_free( &d );

  return jit_prog;
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

fd_jit_scratch_layout_t *
fd_jit_scratch_layout( fd_jit_scratch_layout_t * layout,
                       ulong                     bpf_sz ) {

  if( FD_UNLIKELY( bpf_sz > (1UL<<24) ) ) return NULL;

  /* These "magic" values are taken from dasm_x86.h */

  ulong dasm_sz     = DASM_PSZ( DASM_MAXSECTION );       /* dasm_x86.h(89) */
  ulong lglabels_sz = (10+fd_jit_lbl__MAX)*sizeof(int);  /* dasm_x86.h(119) */
  ulong pclabels_sz = text_cnt*sizeof(int);              /* dasm_x86.h(127) */
  ulong code_sz     = fd_jit_est_code_sz( bpf_sz );

  memset( layout, 0, sizeof(fd_jit_scratch_layout_t) );
  FD_SCRATCH_ALLOC_INIT( l, 0 );
  layout->dasm_off     = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, dasm_sz     );
  layout->lglabels_off = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, lglabels_sz );
  layout->pclabels_off = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, pclabels_sz );
  layout->code_off     = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, code_sz     );
  layout->sz           = (ulong)FD_SCRATCH_ALLOC_FINI( l );
  return layout;
}

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
