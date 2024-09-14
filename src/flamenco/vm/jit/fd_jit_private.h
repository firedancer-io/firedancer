#ifndef HEADER_fd_src_flamenco_vm_jit_fd_jit_private_h
#define HEADER_fd_src_flamenco_vm_jit_fd_jit_private_h

#include "fd_jit.h"

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
   segment selector.  Practically, this means that fd_vm_jitproto only
   supports targets with FD_HAS_THREADS.  (Other targets might use
   absolute addressing without a segment selector or rip-relative) */

FD_PROTOTYPES_BEGIN

extern FD_TL fd_vm_t *                  fd_jit_vm;        /* current VM being executed */
extern FD_TL fd_sbpf_syscalls_t const * fd_jit_syscalls;  /* current syscall table */

/* Thread-local storage for address translation

   fd_jit_segment_cnt is number of memory regions mapped in by the VM.
   fd_jit_mem_{ro,rw}_sz are the number of read- and write-addressable
   bytes in each region.  fd_jit_mem_base points to the first byte of a
   region in host address space. */

extern FD_TL uint  fd_jit_segment_cnt;
extern FD_TL uint  fd_jit_mem_ro_sz[ FD_VM_JIT_SEGMENT_MAX ];
extern FD_TL uint  fd_jit_mem_rw_sz[ FD_VM_JIT_SEGMENT_MAX ];
extern FD_TL ulong fd_jit_mem_base [ FD_VM_JIT_SEGMENT_MAX ];

/* Thread-local storage for fast return to JIT entrypoint
   These are a setjmp()-like anchor for quickly exiting out of a VM
   execution, e.g. in case of a VM fault.
   Slots: 0=rbx 1=rbp 2=r12 3=r13 4=r14 5=r15 6=rsp 7=rip */

extern FD_TL ulong fd_jit_jmp_buf[8];

/* Thread-local storage for exception handling */

extern FD_TL ulong fd_jit_segfault_vaddr;
extern FD_TL ulong fd_jit_segfault_rip;


/* fd_jit_labels is a table of function pointers to 'static' labels in the
   JIT code.  They are indexed by fd_jit_lbl_{...}.  Only used at
   compile time. */

#define FD_JIT_LABEL_CNT 13
extern FD_TL void * fd_jit_labels[ FD_JIT_LABEL_CNT ];

FD_PROTOTYPES_END

/* JIT steps **********************************************************/

struct dasm_State;

FD_PROTOTYPES_BEGIN

void
fd_jit_compile( struct dasm_State **       dasm,
                fd_sbpf_program_t const *  prog,
                fd_sbpf_syscalls_t const * syscalls );

int
fd_jit_vm_attach( fd_vm_t * vm );

void
fd_jit_vm_detach( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_jit_fd_jit_private_h */
