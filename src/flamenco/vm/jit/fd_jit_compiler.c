/*
** This file has been pre-processed with DynASM.
** https://luajit.org/dynasm.html
** DynASM version 1.5.0, DynASM x64 version 1.5.0
** DO NOT EDIT! The original file is in "fd_jit_compiler.dasc".
*/

#line 1 "fd_jit_compiler.dasc"
/* WARNING: WORK IN PROGRESS!
   This is an experimental version of the Firedancer JIT compiler.
   It is disabled in production.  There are known security issues in
   this code.  It is not covered by the Firedancer bug bounty policy. */

#include "../../../util/fd_util_base.h"

/* Include dynasm headers.  These fail to compile when some strict
   checks are enabled. */

void fd_dasm_grow_check( void * ptr, ulong min_sz );
#define DASM_M_GROW(ctx, t, p, sz, need) (fd_dasm_grow_check( (p), (need) ))
#define DASM_M_FREE(ctx, p, sz) do{}while(0)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#include "dasm_proto.h"
#include "dasm_x86.h"
#pragma GCC diagnostic pop

#include "fd_jit_private.h"
#include "../fd_vm_private.h"

//| .arch x64
#if DASM_VERSION != 10500
#error "Version mismatch between DynASM and included encoding engine"
#endif
#line 27 "fd_jit_compiler.dasc"
//| .actionlist actions
static const unsigned char actions[1609] = {
  254,0,248,10,72,193,231,32,72,9,215,100,72,137,60,37,237,72,139,60,36,100,
  72,137,60,37,237,252,233,244,11,255,248,12,137,252,250,72,193,252,239,32,
  100,59,60,37,237,15,131,244,10,137,208,33,232,133,192,15,133,244,10,1,213,
  15,130,244,10,100,59,44,189,237,15,131,244,10,100,72,3,20,252,253,237,195,
  248,13,137,252,250,72,193,252,239,32,100,59,60,37,237,15,131,244,10,137,208,
  33,232,133,192,15,133,244,10,1,213,15,130,244,10,255,100,59,44,189,237,15,
  131,244,10,100,72,3,20,252,253,237,195,255,248,14,100,72,139,4,37,237,72,
  137,176,233,76,137,152,233,76,137,160,233,76,137,168,233,76,137,176,233,76,
  137,184,233,72,137,152,233,72,137,136,233,76,137,128,233,76,137,136,233,76,
  137,144,233,195,255,248,15,100,72,139,4,37,237,72,139,176,233,76,139,152,
  233,76,139,160,233,76,139,168,233,76,139,176,233,76,139,184,233,72,139,152,
  233,72,139,136,233,76,139,128,233,76,139,136,233,76,139,144,233,195,255,248,
  16,73,187,237,237,73,137,155,233,73,137,171,233,77,137,99,16,77,137,107,24,
  77,137,115,32,77,137,123,40,72,141,84,36,8,73,137,83,48,72,139,20,36,73,137,
  83,56,49,192,49,210,195,255,248,17,72,137,252,248,186,1,0,0,0,72,191,237,
  237,72,139,159,233,72,139,175,233,76,139,103,16,76,139,111,24,76,139,119,
  32,76,139,127,40,72,139,103,48,252,255,119,56,195,255,248,18,232,244,14,72,
  137,229,72,131,228,252,240,72,131,252,236,16,100,76,139,28,37,237,100,76,
  139,151,233,76,137,223,72,139,176,233,72,139,144,233,72,139,136,233,76,139,
  128,233,76,139,136,233,76,141,152,233,65,83,65,252,255,210,72,137,252,236,
  232,244,15,133,252,255,15,133,244,11,195,255,248,19,100,72,139,60,37,237,
  72,252,255,135,233,95,83,81,65,80,65,81,73,129,194,0,32,0,0,252,255,231,255,
  248,20,100,72,139,60,37,237,72,252,255,143,233,95,65,89,65,88,89,91,73,129,
  252,234,0,32,0,0,252,255,231,255,248,11,191,237,252,233,244,17,255,248,21,
  255,232,244,16,133,210,15,133,244,247,255,232,244,15,72,131,252,236,32,252,
  255,215,72,137,252,247,232,244,17,248,1,195,255,249,255,64,129,192,240,43,
  239,255,252,233,245,255,72,129,192,240,35,239,255,64,1,192,240,131,240,51,
  255,72,1,192,240,131,240,35,255,64,129,232,240,43,239,255,72,129,252,248,
  240,35,239,255,15,132,245,255,72,129,232,240,35,239,255,64,49,192,240,131,
  240,51,255,72,199,192,240,35,237,255,64,41,192,240,131,240,51,255,72,57,192,
  240,131,240,35,15,132,245,255,72,41,192,240,131,240,35,255,64,105,192,240,
  131,240,51,239,255,72,129,252,248,240,35,239,15,135,245,255,72,105,192,240,
  131,240,35,239,255,64,15,175,192,240,132,240,52,255,72,57,192,240,131,240,
  35,15,135,245,255,72,15,175,192,240,132,240,36,255,64,144,240,42,49,210,191,
  237,252,247,252,247,64,144,240,42,255,72,129,252,248,240,35,239,15,131,245,
  255,72,144,240,34,49,210,72,199,199,237,72,252,247,252,247,72,144,240,34,
  255,64,133,192,240,131,240,51,15,132,244,11,255,64,184,240,42,1,0,0,0,255,
  64,144,240,42,49,210,64,252,247,252,240,240,43,64,144,240,42,255,72,57,192,
  240,131,240,35,15,131,245,255,72,133,192,240,131,240,35,15,132,244,11,255,
  72,144,240,34,49,210,72,252,247,252,240,240,35,72,144,240,34,255,64,129,200,
  240,43,239,255,72,252,247,192,240,35,237,15,133,245,255,72,129,200,240,35,
  239,255,64,9,192,240,131,240,51,255,72,133,192,240,131,240,35,15,133,245,
  255,72,9,192,240,131,240,35,255,64,129,224,240,43,239,255,72,129,252,248,
  240,35,239,15,133,245,255,72,129,224,240,35,239,255,64,33,192,240,131,240,
  51,255,72,57,192,240,131,240,35,15,133,245,255,72,33,192,240,131,240,35,255,
  72,141,184,253,240,3,233,189,3,0,0,0,232,244,13,64,139,2,240,139,255,72,141,
  184,253,240,3,233,189,3,0,0,0,232,244,12,199,2,237,255,72,141,184,253,240,
  3,233,189,3,0,0,0,232,244,12,64,137,2,240,139,255,64,193,224,240,43,235,255,
  72,129,252,248,240,35,239,15,143,245,255,72,193,224,240,35,235,255,72,141,
  184,253,240,3,233,189,1,0,0,0,232,244,13,64,49,192,240,131,240,51,102,64,
  139,2,240,139,255,72,141,184,253,240,3,233,189,1,0,0,0,232,244,12,102,199,
  2,236,255,72,141,184,253,240,3,233,189,1,0,0,0,232,244,12,64,137,2,240,139,
  255,64,136,193,240,131,64,211,224,240,43,255,72,57,192,240,131,240,35,15,
  143,245,255,64,136,193,240,131,72,211,224,240,35,255,72,141,184,253,240,3,
  233,49,252,237,232,244,13,255,64,49,192,240,131,240,51,64,138,2,240,131,255,
  72,141,184,253,240,3,233,49,252,237,232,244,12,198,2,235,255,72,141,184,253,
  240,3,233,49,252,237,232,244,12,64,136,2,240,131,255,64,193,232,240,43,235,
  255,72,129,252,248,240,35,239,15,141,245,255,72,193,232,240,35,235,255,72,
  141,184,253,240,3,233,189,7,0,0,0,232,244,13,72,139,2,240,131,255,72,141,
  184,253,240,3,233,189,7,0,0,0,232,244,12,72,199,192,237,72,137,2,255,72,141,
  184,253,240,3,233,189,7,0,0,0,232,244,12,72,137,2,240,131,255,64,136,193,
  240,131,64,211,232,240,43,255,72,57,192,240,131,240,35,15,141,245,255,64,
  136,193,240,131,72,211,232,240,35,255,64,252,247,216,240,43,255,232,244,19,
  232,245,255,72,199,199,237,232,244,18,255,72,252,247,216,240,35,255,64,144,
  240,42,49,210,191,237,252,247,252,247,64,135,208,240,43,255,232,244,20,195,
  255,64,184,240,42,0,0,0,0,255,64,144,240,42,49,210,64,252,247,252,240,240,
  43,64,135,208,240,43,255,72,144,240,34,49,210,72,252,247,252,240,240,35,72,
  135,208,240,35,255,64,129,252,240,240,43,239,255,72,129,252,248,240,35,239,
  15,130,245,255,72,129,252,240,240,35,239,255,72,57,192,240,131,240,35,15,
  130,245,255,72,49,192,240,131,240,35,255,64,184,240,42,237,255,72,129,252,
  248,240,35,239,15,134,245,255,64,137,192,240,131,240,51,255,72,57,192,240,
  131,240,35,15,134,245,255,72,137,192,240,131,240,35,255,64,193,252,248,240,
  43,235,255,72,129,252,248,240,35,239,15,140,245,255,72,193,252,248,240,35,
  235,255,64,136,193,240,131,64,211,252,248,240,43,255,72,57,192,240,131,240,
  35,15,140,245,255,64,136,193,240,131,72,211,252,248,240,35,255,72,129,252,
  248,240,35,239,15,142,245,255,64,15,183,192,240,132,240,52,102,64,193,200,
  240,43,8,255,64,15,200,240,43,255,72,15,200,240,35,255,72,57,192,240,131,
  240,35,15,142,245,255,248,22,252,233,244,11,255
};

#line 28 "fd_jit_compiler.dasc"
//| .globals fd_jit_lbl_
enum {
  fd_jit_lbl_translate_fail,
  fd_jit_lbl_vm_fault,
  fd_jit_lbl_fd_jit_vm_translate_rw,
  fd_jit_lbl_fd_jit_vm_translate_ro,
  fd_jit_lbl_save_regs,
  fd_jit_lbl_restore_regs,
  fd_jit_lbl_setjmp,
  fd_jit_lbl_longjmp,
  fd_jit_lbl_emulate_syscall,
  fd_jit_lbl_call_stack_push,
  fd_jit_lbl_call_stack_pop,
  fd_jit_lbl_entrypoint,
  fd_jit_lbl_overrun,
  fd_jit_lbl__MAX
};
#line 29 "fd_jit_compiler.dasc"
//| .section code
#define DASM_SECTION_CODE	0
#define DASM_MAXSECTION		1
#line 30 "fd_jit_compiler.dasc"

fd_jit_scratch_layout_t *
fd_jit_scratch_layout( fd_jit_scratch_layout_t * layout,
                       ulong                     bpf_sz ) {

  if( FD_UNLIKELY( bpf_sz > (1UL<<24) ) ) return NULL;
  ulong text_cnt = bpf_sz / 8UL;

  /* These "magic" values are taken from dasm_x86.h */

  ulong dasm_sz     = DASM_PSZ( DASM_MAXSECTION );       /* dasm_x86.h(89) */
  ulong lglabels_sz = (10+fd_jit_lbl__MAX)*sizeof(int);  /* dasm_x86.h(119) */
  ulong pclabels_sz = text_cnt*sizeof(int);              /* dasm_x86.h(127) */
  ulong code_sz     = fd_jit_est_code_sz( bpf_sz );

  memset( layout, 0, sizeof(fd_jit_scratch_layout_t) );
  FD_SCRATCH_ALLOC_INIT( l, 0 );
  layout->dasm_off     = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, dasm_sz     );
  layout->dasm_sz      = dasm_sz;
  layout->lglabels_off = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, lglabels_sz );
  layout->lglabels_sz  = lglabels_sz;
  layout->pclabels_off = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, pclabels_sz );
  layout->pclabels_sz  = pclabels_sz;
  layout->code_off     = (ulong)FD_SCRATCH_ALLOC_APPEND( l, 16UL, code_sz     );
  layout->code_sz      = code_sz;
  layout->sz           = (ulong)FD_SCRATCH_ALLOC_FINI( l, 16UL );
  return layout;
}

dasm_State *
fd_jit_prepare( void *                          scratch,
                fd_jit_scratch_layout_t const * layout ) {

  /* Custom dasm_init */
  dasm_State * d = (void *)( (ulong)scratch + layout->dasm_off );
  fd_memset( d, 0, layout->dasm_sz );
  d->psize      = layout->dasm_sz;
  d->maxsection = DASM_MAXSECTION;

  /* Custom dasm_setupglobal */
  d->globals  = fd_jit_labels;
  d->lglabels = (void *)( (ulong)scratch + layout->lglabels_off );
  d->lgsize   = layout->lglabels_sz;

  /* Custom dasm_growpc */
  d->pcsize   = layout->pclabels_sz;
  d->pclabels = (void *)( (ulong)scratch + layout->pclabels_off );

  /* Setup encoder. Zeros lglabels and pclabels. */
  dasm_setup( &d, actions );

  /* Preallocate space for .code section
     See dasm_x86.h(172) */
  dasm_Section * code = d->sections + 0;
  code->buf   = (void *)( (ulong)scratch + layout->code_off );
  code->bsize = layout->code_sz;
  code->pos   = 0;
  code->rbuf  = code->buf;
  code->epos  = (int)( ((ulong)code->bsize / sizeof(int)) - DASM_MAXSECPOS );
  code->ofs   = 0;

  return d;
}

/* Compile time thread locals */

FD_TL void * fd_jit_labels[ FD_JIT_LABEL_CNT ];
FD_STATIC_ASSERT( sizeof(fd_jit_labels)==fd_jit_lbl__MAX*8, label_cnt );

/* Mapping between sBPF registers and x86_64 registers *****************

   This mapping is valid just before a translated sBPF instruction is
   about to be executed.  (At the `=>next_label` token in the code gen
   loop)

   BPF | r0  | r1  | r2  | r3  | r4  | r5  | r6  | r7  | r8  | r9  | r10
   X86 | rsi | r11 | r12 | r13 | r14 | r15 | rbx | rcx | r8  | r9  | r10

   x86_64 GPRs rax, rdi, rdx, rbp do not map to sBPF registers.  Those can
   be used as scratch registers for complex opcodes.

   Note that this mapping cannot be trivially changed.  Certain x86
   instructions (like div) have hardcoded register accesses which the
   JIT code works around.

   dynasm macros bpf_r{...} resolve to 64-bit register names.

   reg_bpf2x86 is indexed by sBPF register numbers and resolves to the
   x86_64 dynasm register index. */

static uchar const reg_bpf2x86[11] = {
  [ 0] =     FD_DASM_RSI,
  //| .define bpf_r0,  rsi
  [ 1] =     FD_DASM_R11,
  //| .define bpf_r1,  r11
  [ 2] =     FD_DASM_R12,
  //| .define bpf_r2,  r12
  [ 3] =     FD_DASM_R13,
  //| .define bpf_r3,  r13
  [ 4] =     FD_DASM_R14,
  //| .define bpf_r4,  r14
  [ 5] =     FD_DASM_R15,
  //| .define bpf_r5,  r15
  [ 6] =     FD_DASM_RBX,
  //| .define bpf_r6,  rbx
  [ 7] =     FD_DASM_RCX,
  //| .define bpf_r7,  rcx
  [ 8] =     FD_DASM_R8,
  //| .define bpf_r8,  r8
  [ 9] =     FD_DASM_R9,
  //| .define bpf_r9,  r9
  [10] =     FD_DASM_R10
  //| .define bpf_r10, r10
};


/* JIT compiler *******************************************************/

void
fd_jit_compile( struct dasm_State **       Dst,
                fd_sbpf_program_t const *  prog,
                fd_sbpf_syscalls_t const * syscalls ) {

  //| .code
  dasm_put(Dst, 0);
#line 154 "fd_jit_compiler.dasc"

  /* Derive offsets of thread locals in FS "segment" */

# if defined(__FSGSBASE__)
  ulong fs_base; __asm__( "mov %%fs:0, %0" : "=r"(fs_base) );
# else
  ulong fs_base = __builtin_ia32_rdfsbase64();
# endif
# define FS_RELATIVE(ptr) ((uint)( (ulong)(ptr) - fs_base ))
  uint  fd_jit_vm_tpoff             = FS_RELATIVE( &fd_jit_vm             );
  uint  fd_jit_syscalls_tpoff       = FS_RELATIVE( &fd_jit_syscalls       );
  uint  fd_jit_segment_cnt_tpoff    = FS_RELATIVE( &fd_jit_segment_cnt    );
  uint  fd_jit_mem_ro_sz_tpoff      = FS_RELATIVE( fd_jit_mem_ro_sz       );
  uint  fd_jit_mem_rw_sz_tpoff      = FS_RELATIVE( fd_jit_mem_rw_sz       );
  uint  fd_jit_mem_base_tpoff       = FS_RELATIVE( fd_jit_mem_base        );
  uint  fd_jit_segfault_vaddr_tpoff = FS_RELATIVE( &fd_jit_segfault_vaddr );
  uint  fd_jit_segfault_rip_tpoff   = FS_RELATIVE( &fd_jit_segfault_rip   );
# undef FD_RELATIVE

  /* Address translation macros

     The translate_{rw,ro}_{1,2,4,8} macros perform address translation
     and access permission checks for {read-write,read-only} accesses of
     {1,2,4,8} bytes.  The compiler may inline this macro for each
     translated sBPF instruction, so these should be optimized for small
     size.

     Prior to the macro, rdi holds an address in the virtual address
     space (untrusted in [0,2^64)).  If translation and permission
     checks succeed, rdx holds the translated address in the host
     address space.  On failure jumps to sigsegv.  Reasons for failure
     include access to out-of-bounds memory, unaligned address, access
     permission error. */

  //| .define translate_in,  rdi
  //| .define translate_out, rdx
  //|.macro gen_scalar_translate, sz_table_tpoff
  //| // rdi := virtual address
  //| // ebp := size of the access minus 1
  //|
  //| // edx := segment offset
  //| mov edx, edi
  //|
  //| // edi := segment index
  //| shr rdi, 32
  //|
  //| // segment index in bounds?
  //| fs
  //| cmp edi, [fd_jit_segment_cnt_tpoff]
  //| jae ->translate_fail
  //|
  //| // aligned access?
  //| mov eax, edx
  //| and eax, ebp
  //| test eax, eax
  //| jnz ->translate_fail
  //|
  //| // no multi segment overlap?
  //| add ebp, edx
  //| jc ->translate_fail
  //|
  //| // segment offset in bounds?
  //| fs
  //| cmp ebp, [rdi*4 + sz_table_tpoff]
  //| jae ->translate_fail
  //|
  //| // rdx := host address
  //| fs
  //| add rdx, [rdi*8 + fd_jit_mem_base_tpoff]
  //| ret
  //|.endmacro

  //|->translate_fail:
  //| shl rdi, 32
  //| or rdi, rdx
  //| fs
  //| mov [fd_jit_segfault_vaddr_tpoff], rdi
  //| mov rdi, [rsp]
  //| fs
  //| mov [fd_jit_segfault_rip_tpoff], rdi
  //| jmp ->vm_fault
  dasm_put(Dst, 2, fd_jit_segfault_vaddr_tpoff, fd_jit_segfault_rip_tpoff);
#line 235 "fd_jit_compiler.dasc"

  //|->fd_jit_vm_translate_rw:
  //| gen_scalar_translate, fd_jit_mem_rw_sz_tpoff
  //|->fd_jit_vm_translate_ro:
  //| gen_scalar_translate, fd_jit_mem_ro_sz_tpoff
  dasm_put(Dst, 32, fd_jit_segment_cnt_tpoff, fd_jit_mem_rw_sz_tpoff, fd_jit_mem_base_tpoff, fd_jit_segment_cnt_tpoff);
  dasm_put(Dst, 120, fd_jit_mem_ro_sz_tpoff, fd_jit_mem_base_tpoff);
#line 240 "fd_jit_compiler.dasc"

  //|.macro translate_rw_1
  //| xor ebp, ebp
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_rw_2
  //| mov ebp, 1
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_rw_4
  //| mov ebp, 3
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_rw_8
  //| mov ebp, 7
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_ro_1
  //| xor ebp, ebp
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|.macro translate_ro_2
  //| mov ebp, 1
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|.macro translate_ro_4
  //| mov ebp, 3
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|.macro translate_ro_8
  //| mov ebp, 7
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|->save_regs:
  //| fs
  //| mov rax, [fd_jit_vm_tpoff]
  //| mov [rax + offsetof(fd_vm_t, reg[ 0])], bpf_r0
  //| mov [rax + offsetof(fd_vm_t, reg[ 1])], bpf_r1
  //| mov [rax + offsetof(fd_vm_t, reg[ 2])], bpf_r2
  //| mov [rax + offsetof(fd_vm_t, reg[ 3])], bpf_r3
  //| mov [rax + offsetof(fd_vm_t, reg[ 4])], bpf_r4
  //| mov [rax + offsetof(fd_vm_t, reg[ 5])], bpf_r5
  //| mov [rax + offsetof(fd_vm_t, reg[ 6])], bpf_r6
  //| mov [rax + offsetof(fd_vm_t, reg[ 7])], bpf_r7
  //| mov [rax + offsetof(fd_vm_t, reg[ 8])], bpf_r8
  //| mov [rax + offsetof(fd_vm_t, reg[ 9])], bpf_r9
  //| mov [rax + offsetof(fd_vm_t, reg[10])], bpf_r10
  //| ret
  dasm_put(Dst, 138, fd_jit_vm_tpoff, offsetof(fd_vm_t, reg[ 0]), offsetof(fd_vm_t, reg[ 1]), offsetof(fd_vm_t, reg[ 2]), offsetof(fd_vm_t, reg[ 3]), offsetof(fd_vm_t, reg[ 4]), offsetof(fd_vm_t, reg[ 5]), offsetof(fd_vm_t, reg[ 6]), offsetof(fd_vm_t, reg[ 7]), offsetof(fd_vm_t, reg[ 8]), offsetof(fd_vm_t, reg[ 9]), offsetof(fd_vm_t, reg[10]));
#line 296 "fd_jit_compiler.dasc"

  //|->restore_regs:
  //| fs
  //| mov rax, [fd_jit_vm_tpoff]
  //| mov bpf_r0,  [rax + offsetof(fd_vm_t, reg[ 0])]
  //| mov bpf_r1,  [rax + offsetof(fd_vm_t, reg[ 1])]
  //| mov bpf_r2,  [rax + offsetof(fd_vm_t, reg[ 2])]
  //| mov bpf_r3,  [rax + offsetof(fd_vm_t, reg[ 3])]
  //| mov bpf_r4,  [rax + offsetof(fd_vm_t, reg[ 4])]
  //| mov bpf_r5,  [rax + offsetof(fd_vm_t, reg[ 5])]
  //| mov bpf_r6,  [rax + offsetof(fd_vm_t, reg[ 6])]
  //| mov bpf_r7,  [rax + offsetof(fd_vm_t, reg[ 7])]
  //| mov bpf_r8,  [rax + offsetof(fd_vm_t, reg[ 8])]
  //| mov bpf_r9,  [rax + offsetof(fd_vm_t, reg[ 9])]
  //| mov bpf_r10, [rax + offsetof(fd_vm_t, reg[10])]
  //| ret
  dasm_put(Dst, 192, fd_jit_vm_tpoff, offsetof(fd_vm_t, reg[ 0]), offsetof(fd_vm_t, reg[ 1]), offsetof(fd_vm_t, reg[ 2]), offsetof(fd_vm_t, reg[ 3]), offsetof(fd_vm_t, reg[ 4]), offsetof(fd_vm_t, reg[ 5]), offsetof(fd_vm_t, reg[ 6]), offsetof(fd_vm_t, reg[ 7]), offsetof(fd_vm_t, reg[ 8]), offsetof(fd_vm_t, reg[ 9]), offsetof(fd_vm_t, reg[10]));
#line 312 "fd_jit_compiler.dasc"

  /* Generate setjmp/longjmp subroutines.  These can be called from any
     execution state with a valid stack.  The JIT uses them to restore a
     sane SystemV-ABI context when exiting JIT code.

     These are based on musl libc's setjmp/longjmp implementation.
     Copyright 2011-2012 Nicholas J. Kain, licensed under standard MIT license

     setjmp takes no arguments.  longjmp takes a 64-bit value in rdi.
     When setjmp returns from setjmp, sets rax=0 and rdx=0.  When setjmp
     returns from longjmp, sets rax to the rdi argument of longjmp, and
     sets rdx=1.  setjmp preserves rdi. */

  //|->setjmp:
  //| mov64 r11, (ulong)fd_jit_jmp_buf
  //| mov [r11+ 0], rbx
  //| mov [r11+ 8], rbp
  //| mov [r11+16], r12
  //| mov [r11+24], r13
  //| mov [r11+32], r14
  //| mov [r11+40], r15
  //| // save callee's stack pointer
  //| // derived by removing our 8 byte stack frame (only return address)
  //| lea rdx, [rsp+8]
  //| mov [r11+48], rdx
  //| // save return address
  //| mov rdx, [rsp]
  //| mov [r11+56], rdx
  //| // normal return
  //| xor eax, eax
  //| xor edx, edx
  //| ret
  dasm_put(Dst, 246, (unsigned int)((ulong)fd_jit_jmp_buf), (unsigned int)(((ulong)fd_jit_jmp_buf)>>32), 0, 8);
#line 344 "fd_jit_compiler.dasc"

  //|->longjmp:
  //| mov rax, rdi // move first argument to first output register
  //| mov edx, 1   // set second output register to 1
  //| mov64 rdi, (ulong)fd_jit_jmp_buf
  //| // restore execution state to callee of setjmp
  //| mov rbx, [rdi+ 0]
  //| mov rbp, [rdi+ 8]
  //| mov r12, [rdi+16]
  //| mov r13, [rdi+24]
  //| mov r14, [rdi+32]
  //| mov r15, [rdi+40]
  //| mov rsp, [rdi+48]
  //| push qword [rdi+56]
  //| ret // retpoline
  dasm_put(Dst, 299, (unsigned int)((ulong)fd_jit_jmp_buf), (unsigned int)(((ulong)fd_jit_jmp_buf)>>32), 0, 8);
#line 359 "fd_jit_compiler.dasc"

  /* The emulate_syscall function switches from a JIT to an interpreter (C)
     execution context and invokes a syscall handler.  Register edi is
     assumed to hold the byte offset into the vm->syscalls table of the
     fd_sbpf_syscalls_t entry to invoke.
     On syscall return, switches back to the JIT execution context and
     resumes execution after the syscall instruction. */

  //|->emulate_syscall:
  //| call ->save_regs
  //| // rax points to the BPF register file
  //| mov rbp, rsp
  //| // Reserve 16 aligned bytes on the stack
  //| and rsp, -16
  //| sub rsp, 16
  //| fs
  //| mov r11, [fd_jit_vm_tpoff]
  //| fs
  //| mov r10, [rdi + fd_jit_syscalls_tpoff + offsetof(fd_sbpf_syscalls_t, func)]
  //| mov rdi, r11
  //| // load BPF r1 through r5 into function arguments
  //| // FIXME could avoid spill to memory by shuffling registers
  //| mov rsi, [rax + offsetof(fd_vm_t, reg[1])]
  //| mov rdx, [rax + offsetof(fd_vm_t, reg[2])]
  //| mov rcx, [rax + offsetof(fd_vm_t, reg[3])]
  //| mov r8,  [rax + offsetof(fd_vm_t, reg[4])]
  //| mov r9,  [rax + offsetof(fd_vm_t, reg[5])]
  //| lea r11, [rax + offsetof(fd_vm_t, reg[0])]
  //| push r11
  //| call r10
  //| mov rsp, rbp
  //| call ->restore_regs
  //| test edi, edi
  //| jnz ->vm_fault
  //| ret
  dasm_put(Dst, 348, fd_jit_vm_tpoff, fd_jit_syscalls_tpoff + offsetof(fd_sbpf_syscalls_t, func), offsetof(fd_vm_t, reg[1]), offsetof(fd_vm_t, reg[2]), offsetof(fd_vm_t, reg[3]), offsetof(fd_vm_t, reg[4]), offsetof(fd_vm_t, reg[5]), offsetof(fd_vm_t, reg[0]));
#line 394 "fd_jit_compiler.dasc"

  /* The call_stack_push function pushes the current program counter and
     eBPF registers r6, r7, r8, r9 to the shadow stack.  The frame register
     (r10) grows upwards.  FIXME implement shadow stack overflow. */

# define REG(n) (offsetof(fd_vm_t, shadow[0].r##n))

  //|->call_stack_push:
  //| fs
  //| mov rdi, [fd_jit_vm_tpoff]
  //| // vm->frame_cnt++
  //| inc qword [rdi + offsetof(fd_vm_t, frame_cnt)]
  //| // save registers
  //| pop rdi
  //| push bpf_r6
  //| push bpf_r7
  //| push bpf_r8
  //| push bpf_r9
  //| add bpf_r10, 0x2000
  //| jmp rdi
  dasm_put(Dst, 426, fd_jit_vm_tpoff, offsetof(fd_vm_t, frame_cnt));
#line 414 "fd_jit_compiler.dasc"

  /* The call_stack_pop function undoes the effects of call_stack_push. */

  //|->call_stack_pop:
  //| fs
  //| mov rdi, [fd_jit_vm_tpoff]
  //| // vm->frame_cnt--
  //| dec qword [rdi + offsetof(fd_vm_t, frame_cnt)]
  //| // restore registers
  //| pop rdi
  //| pop bpf_r9
  //| pop bpf_r8
  //| pop bpf_r7
  //| pop bpf_r6
  //| sub bpf_r10, 0x2000
  //| jmp rdi
  dasm_put(Dst, 457, fd_jit_vm_tpoff, offsetof(fd_vm_t, frame_cnt));
#line 430 "fd_jit_compiler.dasc"

# undef REG
  /* Exception handlers */

  //|->vm_fault:
  //| mov edi, FD_VM_ERR_ABORT
  //| jmp ->longjmp
  dasm_put(Dst, 489, FD_VM_ERR_ABORT);
#line 437 "fd_jit_compiler.dasc"

  /* JIT entrypoint from C code */

  //|->entrypoint:
  dasm_put(Dst, 498);
#line 441 "fd_jit_compiler.dasc"

  /* Create setjmp anchor used to return from JIT */

  //| call ->setjmp // preserves rdi
  //| test edx, edx
  //| jnz >1
  dasm_put(Dst, 501);
#line 447 "fd_jit_compiler.dasc"

  /* Enter JIT execution context */

  //| call ->restore_regs
  //| sub rsp, 0x20 // balance call_stack_push
  //| call rdi
  //| mov rdi, bpf_r0
  //| call ->longjmp
  //|1:
  //| ret
  dasm_put(Dst, 511);
#line 457 "fd_jit_compiler.dasc"

  /* Start translating user code */

  ulong * const text_start = prog->text;
  ulong *       text_end   = prog->text + prog->text_cnt;

  for( ulong * cur=text_start; cur<text_end; cur++ ) {
    ulong instr = *cur;

    ulong opcode  = fd_vm_instr_opcode( instr ); /* in [0,256) even if malformed */
    ulong dst     = fd_vm_instr_dst   ( instr ); /* in [0, 16) even if malformed */
    ulong src     = fd_vm_instr_src   ( instr ); /* in [0, 16) even if malformed */
    short offset  = fd_vm_instr_offset( instr ); /* in [-2^15,2^15) even if malformed */
    uint  imm     = fd_vm_instr_imm   ( instr ); /* in [0,2^32) even if malformed */

    /* Macros for translating register accesses */

    uint x86_dst = reg_bpf2x86[ dst ];
    uint x86_src = reg_bpf2x86[ src ];

    //| .define dst64, Rq(x86_dst)
    //| .define src64, Rq(x86_src)
    //| .define dst32, Rd(x86_dst)
    //| .define src32, Rd(x86_src)
    //| .define src8,  Rb(x86_src)

    /* Macro for translating jumps */

    ulong * jmp_dst       = cur + 1 + offset; /* may be OOB, FIXME validate */
    int     jmp_dst_lbl   = (int)( jmp_dst - text_start );
    //int     jmp_bounds_ok = jmp_dst>=text_start && jmp<text_end;
    /* FIXME do a bounds check */
    /* FIXME what happens if the label is not set? */

    /* FIXME CU accounting */

    /* Create a dynamic label for each instruction */

    uint cur_pc = (uint)( cur - text_start );
    int next_label = (int)cur_pc;
    //|=>next_label:
    dasm_put(Dst, 533, next_label);
#line 498 "fd_jit_compiler.dasc"

    /* Translate instruction */

    switch( opcode ) {

    /* 0x00 - 0x0f ******************************************************/

    case 0x04:  /* FD_SBPF_OP_ADD_IMM */
      //| add dst32, imm
      dasm_put(Dst, 535, (x86_dst), imm);
#line 507 "fd_jit_compiler.dasc"
      break;

    case 0x05:  /* FD_SBPF_OP_JA */
      //| jmp =>jmp_dst_lbl
      dasm_put(Dst, 542, jmp_dst_lbl);
#line 511 "fd_jit_compiler.dasc"
      break;

    case 0x07:  /* FD_SBPF_OP_ADD64_IMM */
      //| add dst64, imm
      dasm_put(Dst, 546, (x86_dst), imm);
#line 515 "fd_jit_compiler.dasc"
      break;

    case 0x0c:  /* FD_SBPF_OP_ADD_REG */
      //| add dst32, src32
      dasm_put(Dst, 553, (x86_src), (x86_dst));
#line 519 "fd_jit_compiler.dasc"
      break;

    case 0x0f:  /* FD_SBPF_OP_ADD64_REG */
      //| add dst64, src64
      dasm_put(Dst, 561, (x86_src), (x86_dst));
#line 523 "fd_jit_compiler.dasc"
      break;

    /* 0x10 - 0x1f ******************************************************/

    case 0x14:  /* FD_SBPF_OP_SUB_IMM */
      //| sub dst32, imm
      dasm_put(Dst, 569, (x86_dst), imm);
#line 529 "fd_jit_compiler.dasc"
      break;

    case 0x15:  /* FD_SBPF_OP_JEQ_IMM */
      //| cmp dst64, imm
      dasm_put(Dst, 576, (x86_dst), imm);
#line 533 "fd_jit_compiler.dasc"
      /* pre branch check here ... branchless cu update? */
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 584, jmp_dst_lbl);
#line 535 "fd_jit_compiler.dasc"
      break;

    case 0x17:  /* FD_SBPF_OP_SUB64_IMM */
      //| sub dst64, imm
      dasm_put(Dst, 588, (x86_dst), imm);
#line 539 "fd_jit_compiler.dasc"
      break;

    case 0x18:  /* FD_SBPF_OP_LDQ */
      cur++; {
      ulong imm64 = (ulong)imm | ( (ulong)fd_vm_instr_imm( *cur ) << 32 );
      if( imm64==0 ) {
        //| xor dst32, dst32
        dasm_put(Dst, 595, (x86_dst), (x86_dst));
#line 546 "fd_jit_compiler.dasc"
      } else {
        //| mov dst64, imm64
        dasm_put(Dst, 603, (x86_dst), imm64);
#line 548 "fd_jit_compiler.dasc"
      }
      break;
    }

    case 0x1c:  /* FD_SBPF_OP_SUB_REG */
      //| sub dst32, src32
      dasm_put(Dst, 610, (x86_src), (x86_dst));
#line 554 "fd_jit_compiler.dasc"
      break;

    case 0x1d:  /* FD_SBPF_OP_JEQ_REG */
      //| cmp dst64, src64
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 618, (x86_src), (x86_dst), jmp_dst_lbl);
#line 559 "fd_jit_compiler.dasc"
      break;

    case 0x1f:  /* FD_SBPF_OP_SUB64_REG */
      //| sub dst64, src64
      dasm_put(Dst, 629, (x86_src), (x86_dst));
#line 563 "fd_jit_compiler.dasc"
      break;

    /* 0x20 - 0x2f ******************************************************/

    case 0x24:  /* FD_SBPF_OP_MUL_IMM */
      /* TODO strength reduction? */
      //| imul dst32, imm
      dasm_put(Dst, 637, (x86_dst), (x86_dst), imm);
#line 570 "fd_jit_compiler.dasc"
      break;

    case 0x25:  /* FD_SBPF_OP_JGT_IMM */
      //| cmp dst64, imm
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 646, (x86_dst), imm, jmp_dst_lbl);
#line 575 "fd_jit_compiler.dasc"
      break;

    case 0x27:  /* FD_SBPF_OP_MUL64_IMM */
      /* TODO strength reduction? */
      //| imul dst64, imm
      dasm_put(Dst, 657, (x86_dst), (x86_dst), imm);
#line 580 "fd_jit_compiler.dasc"
      break;

    case 0x2c:  /* FD_SBPF_OP_MUL_REG */
      //| imul dst32, src32
      dasm_put(Dst, 666, (x86_dst), (x86_src));
#line 584 "fd_jit_compiler.dasc"
      break;

    case 0x2d:  /* FD_SBPF_OP_JGT_REG */
      //| cmp dst64, src64
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 675, (x86_src), (x86_dst), jmp_dst_lbl);
#line 589 "fd_jit_compiler.dasc"
      break;

    case 0x2f:  /* FD_SBPF_OP_MUL64_REG */
      //| imul dst64, src64
      dasm_put(Dst, 686, (x86_dst), (x86_src));
#line 593 "fd_jit_compiler.dasc"
      break;

    /* 0x30 - 0x3f ******************************************************/

    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 27);
#line 600 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg eax, dst32
      dasm_put(Dst, 695, (x86_dst), imm, (x86_dst));
#line 607 "fd_jit_compiler.dasc"
      break;

    case 0x35:  /* FD_SBPF_OP_JGE_IMM */
      //| cmp dst64, imm
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 712, (x86_dst), imm, jmp_dst_lbl);
#line 612 "fd_jit_compiler.dasc"
      break;

    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 27);
#line 617 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 723, (x86_dst), imm, (x86_dst));
#line 624 "fd_jit_compiler.dasc"
      break;

    case 0x3c:  /* FD_SBPF_OP_DIV_REG */
      //| test src32, src32
      //| jz ->vm_fault
      dasm_put(Dst, 743, (x86_src), (x86_src));
#line 629 "fd_jit_compiler.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 755, (x86_dst));
#line 631 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg eax, dst32
      dasm_put(Dst, 764, (x86_dst), (x86_src), (x86_dst));
#line 637 "fd_jit_compiler.dasc"
      break;

    case 0x3d:  /* FD_SBPF_OP_JGE_REG */
      //| cmp dst64, src64
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 782, (x86_src), (x86_dst), jmp_dst_lbl);
#line 642 "fd_jit_compiler.dasc"
      break;

    case 0x3f:  /* FD_SBPF_OP_DIV64_REG */
      //| test src64, src64
      //| jz ->vm_fault
      dasm_put(Dst, 793, (x86_src), (x86_src));
#line 647 "fd_jit_compiler.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 755, (x86_dst));
#line 649 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rax, dst64
      dasm_put(Dst, 805, (x86_dst), (x86_src), (x86_dst));
#line 655 "fd_jit_compiler.dasc"
      break;

    /* 0x40 - 0x4f ******************************************************/

    case 0x44:  /* FD_SBPF_OP_OR_IMM */
      //| or dst32, imm
      dasm_put(Dst, 823, (x86_dst), imm);
#line 661 "fd_jit_compiler.dasc"
      break;

    case 0x45:  /* FD_SBPF_OP_JSET_IMM */
      //| test dst64, imm
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 830, (x86_dst), imm, jmp_dst_lbl);
#line 666 "fd_jit_compiler.dasc"
      break;

    case 0x47:  /* FD_SBPF_OP_OR64_IMM */
      //| or dst64, imm
      dasm_put(Dst, 841, (x86_dst), imm);
#line 670 "fd_jit_compiler.dasc"
      break;

    case 0x4c:  /* FD_SBPF_OP_OR_REG */
      //| or dst32, src32
      dasm_put(Dst, 848, (x86_src), (x86_dst));
#line 674 "fd_jit_compiler.dasc"
      break;

    case 0x4d:  /* FD_SBPF_OP_JSET_REG */
      //| test dst64, src64
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 856, (x86_src), (x86_dst), jmp_dst_lbl);
#line 679 "fd_jit_compiler.dasc"
      break;

    case 0x4f:  /* FD_SBPF_OP_OR64_REG */
      //| or dst64, src64
      dasm_put(Dst, 867, (x86_src), (x86_dst));
#line 683 "fd_jit_compiler.dasc"
      break;

    /* 0x50 - 0x5f ******************************************************/

    case 0x54:  /* FD_SBPF_OP_AND_IMM */
      //| and dst32, imm
      dasm_put(Dst, 875, (x86_dst), imm);
#line 689 "fd_jit_compiler.dasc"
      break;

    case 0x55:  /* FD_SBPF_OP_JNE_IMM */
      //| cmp dst64, imm
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 882, (x86_dst), imm, jmp_dst_lbl);
#line 694 "fd_jit_compiler.dasc"
      break;

    case 0x57:  /* FD_SBPF_OP_AND64_IMM */
      //| and dst64, imm
      dasm_put(Dst, 893, (x86_dst), imm);
#line 698 "fd_jit_compiler.dasc"
      break;

    case 0x5c:  /* FD_SBPF_OP_AND_REG */
      //| and dst32, src32
      dasm_put(Dst, 900, (x86_src), (x86_dst));
#line 702 "fd_jit_compiler.dasc"
      break;

    case 0x5d:  /* FD_SBPF_OP_JNE_REG */
      //| cmp dst64, src64
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 908, (x86_src), (x86_dst), jmp_dst_lbl);
#line 707 "fd_jit_compiler.dasc"
      break;

    case 0x5f:  /* FD_SBPF_OP_AND64_REG */
      //| and dst64, src64
      dasm_put(Dst, 919, (x86_src), (x86_dst));
#line 711 "fd_jit_compiler.dasc"
      break;

    /* 0x60 - 0x6f ******************************************************/

    case 0x61:  /* FD_SBPF_OP_LDXW */
      //| lea translate_in, [src64+offset]
      //| translate_ro_4
      //| mov dst32, [translate_out]
      dasm_put(Dst, 927, (x86_src), offset, (x86_dst));
#line 719 "fd_jit_compiler.dasc"
      break;

    case 0x62:  /* FD_SBPF_OP_STW */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_4
      //| mov dword [translate_out], imm
      dasm_put(Dst, 948, (x86_dst), offset, imm);
#line 725 "fd_jit_compiler.dasc"
      break;

    case 0x63:  /* FD_SBPF_OP_STXW */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_4
      //| mov [translate_out], src32
      dasm_put(Dst, 967, (x86_dst), offset, (x86_src));
#line 731 "fd_jit_compiler.dasc"
      break;

    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
      //| shl dst32, imm
      dasm_put(Dst, 988, (x86_dst), imm);
#line 735 "fd_jit_compiler.dasc"
      break;

    case 0x65:  /* FD_SBPF_OP_JSGT_IMM */
      //| cmp dst64, imm
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 995, (x86_dst), imm, jmp_dst_lbl);
#line 740 "fd_jit_compiler.dasc"
      break;

    case 0x67:  /* FD_SBPF_OP_LSH64_IMM */
      //| shl dst64, imm
      dasm_put(Dst, 1006, (x86_dst), imm);
#line 744 "fd_jit_compiler.dasc"
      break;

    case 0x69:  /* FD_SBPF_OP_LDXH */
      //| lea translate_in, [src64+offset]
      //| translate_ro_2
      //| xor dst32, dst32
      //| mov Rw(x86_dst), [translate_out]
      dasm_put(Dst, 1013, (x86_src), offset, (x86_dst), (x86_dst), (x86_dst));
#line 751 "fd_jit_compiler.dasc"
      break;

    case 0x6a:  /* FD_SBPF_OP_STH */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_2
      //| mov word [translate_out], imm
      dasm_put(Dst, 1042, (x86_dst), offset, imm);
#line 757 "fd_jit_compiler.dasc"
      break;

    case 0x6b:  /* FD_SBPF_OP_STXH */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_2
      //| mov [translate_out], src32
      dasm_put(Dst, 1062, (x86_dst), offset, (x86_src));
#line 763 "fd_jit_compiler.dasc"
      break;

    case 0x6c:  /* FD_SBPF_OP_LSH_REG */
      //| mov cl, src8
      //| shl dst32, cl
      dasm_put(Dst, 1083, (x86_src), (x86_dst));
#line 768 "fd_jit_compiler.dasc"
      break;

    case 0x6d:  /* FD_SBPF_OP_JSGT_REG */
      //| cmp dst64, src64
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 1094, (x86_src), (x86_dst), jmp_dst_lbl);
#line 773 "fd_jit_compiler.dasc"
      break;

    case 0x6f:  /* FD_SBPF_OP_LSH64_REG */
      //| mov cl, src8
      //| shl dst64, cl
      dasm_put(Dst, 1105, (x86_src), (x86_dst));
#line 778 "fd_jit_compiler.dasc"
      break;

    /* 0x70 - 0x7f ******************************************************/

    case 0x71:  /* FD_SBPF_OP_LDXB */
      //| lea translate_in, [src64+offset]
      //| translate_ro_1
      dasm_put(Dst, 1116, (x86_src), offset);
#line 785 "fd_jit_compiler.dasc"
      /* TODO is there a better way to zero upper and mov byte? */
      //| xor dst32, dst32
      //| mov Rb(x86_dst), [translate_out]
      dasm_put(Dst, 1130, (x86_dst), (x86_dst), (x86_dst));
#line 788 "fd_jit_compiler.dasc"
      break;

    case 0x72:  /* FD_SBPF_OP_STB */
      //| lea translate_in, [src64+offset]
      //| translate_rw_1
      //| mov byte [translate_out], imm
      dasm_put(Dst, 1143, (x86_src), offset, imm);
#line 794 "fd_jit_compiler.dasc"
      break;

    case 0x73:  /* FD_SBPF_OP_STXB */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_1
      //| mov byte [translate_out], Rb(x86_src)
      dasm_put(Dst, 1160, (x86_dst), offset, (x86_src));
#line 800 "fd_jit_compiler.dasc"
      break;

    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
      //| shr dst32, imm
      dasm_put(Dst, 1179, (x86_dst), imm);
#line 804 "fd_jit_compiler.dasc"
      break;

    case 0x75:  /* FD_SBPF_OP_JSGE_IMM */
      //| cmp dst64, imm
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 1186, (x86_dst), imm, jmp_dst_lbl);
#line 809 "fd_jit_compiler.dasc"
      break;

    case 0x77:  /* FD_SBPF_OP_RSH64_IMM */
      //| shr dst64, imm
      dasm_put(Dst, 1197, (x86_dst), imm);
#line 813 "fd_jit_compiler.dasc"
      break;

    case 0x79:  /* FD_SBPF_OP_LDXQ */
      //| lea translate_in, [src64+offset]
      //| translate_ro_8
      //| mov dst64, [translate_out]
      dasm_put(Dst, 1204, (x86_src), offset, (x86_dst));
#line 819 "fd_jit_compiler.dasc"
      break;

    case 0x7a:  /* FD_SBPF_OP_STQ */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_8
      //| mov rax, imm
      //| mov [translate_out], rax
      dasm_put(Dst, 1225, (x86_dst), offset, imm);
#line 826 "fd_jit_compiler.dasc"
      break;

    case 0x7b:  /* FD_SBPF_OP_STXQ */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_8
      //| mov [translate_out], src64
      dasm_put(Dst, 1248, (x86_dst), offset, (x86_src));
#line 832 "fd_jit_compiler.dasc"
      break;

    case 0x7c:  /* FD_SBPF_OP_RSH_REG */
      //| mov cl, src8
      //| shr dst32, cl
      dasm_put(Dst, 1269, (x86_src), (x86_dst));
#line 837 "fd_jit_compiler.dasc"
      break;

    case 0x7d:  /* FD_SBPF_OP_JSGE_REG */
      //| cmp dst64, src64
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 1280, (x86_src), (x86_dst), jmp_dst_lbl);
#line 842 "fd_jit_compiler.dasc"
      break;

    case 0x7f:  /* FD_SBPF_OP_RSH64_REG */
      //| mov cl, src8
      //| shr dst64, cl
      dasm_put(Dst, 1291, (x86_src), (x86_dst));
#line 847 "fd_jit_compiler.dasc"
      break;

    /* 0x80-0x8f ********************************************************/

    case 0x84:  /* FD_SBPF_OP_NEG */
      //| neg dst32
      dasm_put(Dst, 1302, (x86_dst));
#line 853 "fd_jit_compiler.dasc"
      break;

    case 0x85: { /* FD_SBPF_OP_CALL_IMM */
      fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( syscalls, imm, NULL );
      if( !syscall ) {
        ulong target_pc = (ulong)fd_pchash_inverse( imm );
        //| call ->call_stack_push
        //| call =>target_pc
        dasm_put(Dst, 1309, target_pc);
#line 861 "fd_jit_compiler.dasc"
      } else {
        /* Optimize for code footprint: Generate an offset into the
           syscall table (32-bit) instead of the syscall address (64-bit) */
        //| mov rdi, (uint)( (ulong)syscall - (ulong)syscalls );
        //| call ->emulate_syscall
        dasm_put(Dst, 1315, (uint)( (ulong)syscall - (ulong)syscalls ));
#line 866 "fd_jit_compiler.dasc"
      }
      break;
    }

    case 0x87:  /* FD_SBPF_OP_NEG64 */
      //| neg dst64
      dasm_put(Dst, 1323, (x86_dst));
#line 872 "fd_jit_compiler.dasc"
      break;

    case 0x8d:  /* FD_SBPF_OP_CALL_REG */
      FD_LOG_WARNING(( "TODO: CALLX" ));
      break;

    /* 0x90 - 0x9f ******************************************************/

    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 27);
#line 883 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg edx, dst32
      dasm_put(Dst, 1330, (x86_dst), imm, (x86_dst));
#line 890 "fd_jit_compiler.dasc"
      break;

    case 0x95:  /* FD_SBPF_OP_EXIT */
      //| call ->call_stack_pop
      //| ret
      dasm_put(Dst, 1348);
#line 895 "fd_jit_compiler.dasc"
      break;

    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 27);
#line 900 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 723, (x86_dst), imm, (x86_dst));
#line 907 "fd_jit_compiler.dasc"
      break;

    case 0x9c:  /* FD_SBPF_OP_MOD_REG */
      //| test src32, src32
      //| jz ->vm_fault
      dasm_put(Dst, 743, (x86_src), (x86_src));
#line 912 "fd_jit_compiler.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 1353, (x86_dst));
#line 914 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg edx, dst32
      dasm_put(Dst, 1362, (x86_dst), (x86_src), (x86_dst));
#line 920 "fd_jit_compiler.dasc"
      break;

    case 0x9f:  /* FD_SBPF_OP_MOD64_REG */
      //| test src64, src64
      //| jz ->vm_fault
      dasm_put(Dst, 793, (x86_src), (x86_src));
#line 925 "fd_jit_compiler.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 1353, (x86_dst));
#line 927 "fd_jit_compiler.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rdx, dst64
      dasm_put(Dst, 1381, (x86_dst), (x86_src), (x86_dst));
#line 933 "fd_jit_compiler.dasc"
      break;

    /* 0xa0 - 0xaf ******************************************************/

    case 0xa4:  /* FD_SBPF_OP_XOR_IMM */
      //| xor dst32, imm
      dasm_put(Dst, 1400, (x86_dst), imm);
#line 939 "fd_jit_compiler.dasc"
      break;

    case 0xa5:  /* FD_SBPF_OP_JLT_IMM */
      //| cmp dst64, imm
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 1408, (x86_dst), imm, jmp_dst_lbl);
#line 944 "fd_jit_compiler.dasc"
      break;

    case 0xa7:  /* FD_SBPF_OP_XOR64_IMM */
      // TODO sign extension
      //| xor dst64, imm
      dasm_put(Dst, 1419, (x86_dst), imm);
#line 949 "fd_jit_compiler.dasc"
      break;

    case 0xac:  /* FD_SBPF_OP_XOR_REG */
      //| xor dst32, src32
      dasm_put(Dst, 595, (x86_src), (x86_dst));
#line 953 "fd_jit_compiler.dasc"
      break;

    case 0xad:  /* FD_SBPF_OP_JLT_REG */
      //| cmp dst64, src64
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 1427, (x86_src), (x86_dst), jmp_dst_lbl);
#line 958 "fd_jit_compiler.dasc"
      break;

    case 0xaf:  /* FD_SBPF_OP_XOR64_REG */
      //| xor dst64, src64
      dasm_put(Dst, 1438, (x86_src), (x86_dst));
#line 962 "fd_jit_compiler.dasc"
      break;

    /* 0xb0 - 0xbf ******************************************************/

    case 0xb4:  /* FD_SBPF_OP_MOV_IMM */
      //| mov dst32, imm
      dasm_put(Dst, 1446, (x86_dst), imm);
#line 968 "fd_jit_compiler.dasc"
      break;

    case 0xb5:  /* FD_SBPF_OP_JLE_IMM */
      //| cmp dst64, imm
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 1452, (x86_dst), imm, jmp_dst_lbl);
#line 973 "fd_jit_compiler.dasc"
      break;

    case 0xb7:  /* FD_SBPF_OP_MOV64_IMM */
      if( imm==0 ) {
        //| xor dst32, dst32
        dasm_put(Dst, 595, (x86_dst), (x86_dst));
#line 978 "fd_jit_compiler.dasc"
      } else {
        //| mov dst64, imm
        dasm_put(Dst, 603, (x86_dst), imm);
#line 980 "fd_jit_compiler.dasc"
      }
      break;

    case 0xbc:  /* FD_SBPF_OP_MOV_REG */
      //| mov dst32, src32
      dasm_put(Dst, 1463, (x86_src), (x86_dst));
#line 985 "fd_jit_compiler.dasc"
      break;

    case 0xbd:  /* FD_SBPF_OP_JLE_REG */
      //| cmp dst64, src64
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 1471, (x86_src), (x86_dst), jmp_dst_lbl);
#line 990 "fd_jit_compiler.dasc"
      break;

    case 0xbf:  /* FD_SBPF_OP_MOV64_REG */
      //| mov dst64, src64
      dasm_put(Dst, 1482, (x86_src), (x86_dst));
#line 994 "fd_jit_compiler.dasc"
      break;

    /* 0xc0 - 0xcf ******************************************************/

    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      //| sar dst32, imm
      dasm_put(Dst, 1490, (x86_dst), imm);
#line 1000 "fd_jit_compiler.dasc"
      break;

    case 0xc5:  /* FD_SBPF_OP_JSLT_IMM */
      //| cmp dst64, imm
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 1498, (x86_dst), imm, jmp_dst_lbl);
#line 1005 "fd_jit_compiler.dasc"
      break;

    case 0xc7:  /* FD_SBPF_OP_ARSH64_IMM */
      //| sar dst64, imm
      dasm_put(Dst, 1509, (x86_dst), imm);
#line 1009 "fd_jit_compiler.dasc"
      break;

    case 0xcc:  /* FD_SBPF_OP_ARSH_REG */
      //| mov cl, src8
      //| sar dst32, cl
      dasm_put(Dst, 1517, (x86_src), (x86_dst));
#line 1014 "fd_jit_compiler.dasc"
      break;

    case 0xcd:  /* FD_SBPF_OP_JSLT_REG */
      //| cmp dst64, src64
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 1529, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1019 "fd_jit_compiler.dasc"
      break;

    case 0xcf:  /* FD_SBPF_OP_ARSH64_REG */
      //| mov cl, src8
      //| sar dst64, cl
      dasm_put(Dst, 1540, (x86_src), (x86_dst));
#line 1024 "fd_jit_compiler.dasc"
      break;

    /* 0xd0 - 0xdf ******************************************************/

    case 0xd4:  /* FD_SBPF_OP_END_LE */
      /* nop */
      break;

    case 0xd5:  /* FD_SBPF_OP_JSLE_IMM */
      //| cmp dst64, imm
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 1552, (x86_dst), imm, jmp_dst_lbl);
#line 1035 "fd_jit_compiler.dasc"
      break;

    case 0xdc:  /* FD_SBPF_OP_END_BE */
      switch( imm ) {
      case 16U:
        //| movzx dst32, Rw(x86_dst)
        //| ror Rw(x86_dst), 8
        dasm_put(Dst, 1563, (x86_dst), (x86_dst), (x86_dst));
#line 1042 "fd_jit_compiler.dasc"
        break;
      case 32U:
        //| bswap dst32
        dasm_put(Dst, 1579, (x86_dst));
#line 1045 "fd_jit_compiler.dasc"
        break;
      case 64U:
        //| bswap dst64
        dasm_put(Dst, 1585, (x86_dst));
#line 1048 "fd_jit_compiler.dasc"
        break;
      default:
        break;
        // TODO sigill
      }
      break;

    case 0xdd:  /* FD_SBPF_OP_JSLE_REG */
      //| cmp dst64, src64
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 1591, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1058 "fd_jit_compiler.dasc"
      break;

    default:
      FD_LOG_WARNING(( "Unsupported opcode %x", opcode ));
      cur = text_end;
      break;

    }

  }

  //|->overrun:
  //| jmp ->vm_fault
  dasm_put(Dst, 1602);
#line 1071 "fd_jit_compiler.dasc"

}

fd_jit_entrypoint_t
fd_jit_get_entrypoint( void ) {
  return (fd_jit_entrypoint_t)(ulong)fd_jit_labels[ fd_jit_lbl_entrypoint ];
}
