#ifndef HEADER_fd_src_flamenco_vm_jit_fd_jit_private_h
#define HEADER_fd_src_flamenco_vm_jit_fd_jit_private_h

#include "fd_jit.h"
#include <setjmp.h>

/* DynASM code uses realloc.  fd_jit can estimate the number of bytes
   needed, so we can do better and allocate once on startup.

   DynASM calls realloc in 4 places:  On initialization in dasm_init,
   dasm_setupglobal, and dasm_growpc.  Then, for every block of code
   in dasm_put.

   Checks that enough memory was allocated on initialization are moved
   to test_vm_jit.  Checks during code generation (dasm_put) are moved
   to the fd_dasm_grow_check function call.  Calls to 'realloc' and
   'free' are removed. */

#include "dasm_proto.h"

/* FD_DASM_R{...} specify the dynasm register index of x86_64 registers. */

#define FD_DASM_RAX  (0)
#define FD_DASM_RCX  (1)
#define FD_DASM_RDX  (2)
#define FD_DASM_RBX  (3)
#define FD_DASM_RSP  (4)
#define FD_DASM_RBP  (5)
#define FD_DASM_RSI  (6)
#define FD_DASM_RDI  (7)
#define FD_DASM_R8   (8)
#define FD_DASM_R9   (9)
#define FD_DASM_R10 (10)
#define FD_DASM_R11 (11)
#define FD_DASM_R12 (12)
#define FD_DASM_R13 (13)
#define FD_DASM_R14 (14)
#define FD_DASM_R15 (15)

/* FD_VM_JIT_SEGMENT_MAX is the max number of segments. */

#define FD_VM_JIT_SEGMENT_MAX (64)

/* Thread-local storage ************************************************

   For now, these are assumed to be absolute-addressed using the fs
   segment selector.  Practically, this means that fd_jit only supports
   targets with FD_HAS_THREADS.  (Other targets might use absolute
   addressing without a segment selector or rip-relative) */

FD_PROTOTYPES_BEGIN

extern FD_TL fd_vm_t *                  fd_jit_vm;        /* current VM being executed */
extern FD_TL fd_sbpf_syscalls_t const * fd_jit_syscalls;  /* current syscall table */

/* Thread-local storage for address translation

   fd_jit_segment_cnt is number of memory regions mapped in by the VM.
   For each region i, fd_jit_mem_sz[2*i] is the number of readable bytes
   and fd_jit_mem_sz[2*i+1] is the number of writable bytes.
   fd_jit_mem_haddr points to the first byte of a region in host address
   space. */

extern FD_TL uint  fd_jit_segment_cnt;
extern FD_TL uint  fd_jit_mem_sz   [ 2*FD_VM_JIT_SEGMENT_MAX ];
extern FD_TL ulong fd_jit_mem_haddr[   FD_VM_JIT_SEGMENT_MAX ];

/* Thread-local storage for fast return to JIT entrypoint
   These are a setjmp()-like anchor for quickly exiting out of a VM
   execution, e.g. in case of a VM fault.
   Slots: 0=rbx 1=rbp 2=r12 3=r13 4=r14 5=r15 6=rsp 7=rip */

extern FD_TL ulong fd_jit_jmp_buf[8];

/* Thread-local storage for exception handling */

extern FD_TL ulong fd_jit_segfault_vaddr;
extern FD_TL ulong fd_jit_segfault_rip;

/* Thread-local storage for compile time */

/* fd_jit_compile_abort is a setjmp buffer to quickly abort a JIT
   compile operation without unwinding. */

extern FD_TL jmp_buf fd_jit_compile_abort;

/* fd_jit_code_section points to the code buffer managed by
   dasm_Section.  This thread-local is used to detect when this
   area is about to run out of space. */

extern FD_TL void * fd_jit_code_section_base;
extern FD_TL ulong  fd_jit_code_section_sz;

/* fd_jit_labels is a table of function pointers to 'static' labels in the
   JIT code.  They are indexed by fd_jit_lbl_{...}.  Only used at
   compile time. */

#define FD_JIT_LABEL_CNT 16
extern FD_TL void * fd_jit_labels[ FD_JIT_LABEL_CNT ];

/* FD_JIT_BLOAT_BASE approximates the number of code bytes that the JIT
   compiler generates regardless of the BPF instruction count. */

#define FD_JIT_BLOAT_BASE (10000UL)

/* FD_JIT_BLOAT_MAX is the max acceptable JIT code bloat factor
   (Ratio jit_code_sz / bpf_sz) */

#define FD_JIT_BLOAT_MAX (3.0f) /* FIXME choose value based on mainnet contracts */

FD_PROTOTYPES_END

/* fd_jit_scratch_layout_t describes the layout of the scratch region.
   The scratch region contains preallocated objects used by DynASM. */

struct fd_jit_scratch_layout {
  ulong dasm_off;
  ulong dasm_sz;

  ulong lglabels_off;
  ulong lglabels_sz;

  ulong pclabels_off;
  ulong pclabels_sz;

  ulong code_off;
  ulong code_sz;

  ulong sz;
};

typedef struct fd_jit_scratch_layout fd_jit_scratch_layout_t;

FD_PROTOTYPES_BEGIN

/* fd_jit_scratch_layout proposes a memory layout for

   The size of the scratch region is assumed to be
   fd_jit_est_scratch_sz. */

fd_jit_scratch_layout_t *
fd_jit_scratch_layout( fd_jit_scratch_layout_t * scratch,
                       ulong                     bpf_sz );

/* fd_jit_prepare constructs a dasm_State object in the given scratch
   memory region.  Calls dasm_init and dasm_setup. */

dasm_State *
fd_jit_prepare( void *                          scratch,
                fd_jit_scratch_layout_t const * layout );

/* FIXME documentation for fd_jit_compile. */

void
fd_jit_compile( struct dasm_State **       Dst,
                fd_sbpf_program_t const *  prog,
                fd_sbpf_syscalls_t const * syscalls );

/* fd_jit_vm_compatible checks whether a VM instance is compatible with
   fd_jit.  Returns FD_VM_SUCCESS or FD_VM_ERR_UNSUP. */

FD_FN_PURE int
fd_jit_vm_compatible( fd_vm_t const * vm );

fd_jit_entrypoint_t
fd_jit_get_entrypoint( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_jit_fd_jit_private_h */
