#ifndef HEADER_fd_src_flamenco_vm_jit_fd_jit_h
#define HEADER_fd_src_flamenco_vm_jit_fd_jit_h

/* fd_vm_jit.h provides an API to transpile sBPF programs to native
   machine code.  Currently only supports x86 with threads.

   WARNING: WORK IN PROGRESS!
   This is an experimental version of the Firedancer JIT compiler.
   It is disabled in production.  There are known security issues in
   this code.  It is not covered by the Firedancer bug bounty policy. */

#include "../fd_vm.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"

/* fd_jit_entrypoint is the entrypoint function of JIT compiled code.
   first_rip is a pointer to the x86 instruction in the host address space
   that corresponds to the BPF entrypoint. */

typedef int (* fd_jit_entrypoint_t)( ulong first_rip );

struct fd_jit_prog {
  void *              host_code;
  ulong               host_code_sz;
  fd_jit_entrypoint_t entrypoint;
  ulong               first_rip;
};

typedef struct fd_jit_prog fd_jit_prog_t;

#if FD_HAS_X86 && FD_HAS_THREADS

FD_FN_CONST static inline ulong
fd_jit_prog_align( void ) {
  return 16UL;
}

FD_FN_CONST static inline ulong
fd_jit_prog_footprint( void ) {
  return sizeof(fd_jit_prog_t);
}

ulong
fd_jit_est_code_sz( ulong bpf_sz );

ulong
fd_jit_est_scratch_sz( ulong bpf_sz );

/* fd_jit_compile attempts to transpile sBPF bytecode in prog to native
   machine code.  Compile results are written into the memory region at
   out_buf.  Returns FD_VM_SUCCESS on success.  On failure, returns
   FD_VM_ERR_{...}.  Reasons for failure include:
     FULL   Not enough output or scratch space to JIT compile
     UNSUP  JIT compiler does not support the given executable. */

void *
fd_jit_prog_new( fd_jit_prog_t *            jit_prog,
                 fd_sbpf_program_t const *  prog,
                 fd_sbpf_syscalls_t const * syscalls,
                 void *                     code_buf,
                 ulong                      code_bufsz,
                 void *                     scratch,
                 ulong                      scratch_sz,
                 int *                      out_err );

fd_jit_prog_t *
fd_jit_prog_join( void * prog );

void *
fd_jit_prog_leave( fd_jit_prog_t * prog );

void *
fd_jit_prog_delete( void * prog );

/* fd_jit_exec executes a compiled program from entrypoint to halt or
   fault.  */

int
fd_jit_exec( fd_jit_prog_t * jit_prog,
             fd_vm_t *       vm );

#endif /* FD_HAS_X86 && FD_HAS_THREADS */

#endif /* HEADER_fd_src_flamenco_vm_jit_fd_jit_h */
