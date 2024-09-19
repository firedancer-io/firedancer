#ifndef HEADER_fd_src_flamenco_vm_jit_fd_jit_h
#define HEADER_fd_src_flamenco_vm_jit_fd_jit_h

/* fd_vm_jit.h provides an API to transpile sBPF programs to native
   machine code.  Currently only supports x86 with threads.

   FIXME This is not a "JIT" compiler.  Fix the naming ...

   WARNING: WORK IN PROGRESS!
   This is an experimental version of the Firedancer JIT compiler.
   It is disabled in production.  There are known security issues in
   this code.  It is not covered by the Firedancer bug bounty program. */

#include "../fd_vm.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"

/* fd_jit_entrypoint is the entrypoint function of JIT compiled code.
   first_rip is a pointer to the x86 instruction in the host address
   space that corresponds to the BPF entrypoint. */

typedef int (* fd_jit_entrypoint_t)( ulong first_rip );

/* fd_jit_prog_t is an instance of a JIT compiled program.  It is not
   relocatable since the generated code effectively contains absolute
   addresses.

   fd_jit_prog_t references an external "code" buffer (the memory region
   storing executable code).  During the lifetime of a fd_jit_prog_t
   object, the backing "code" buffer may not be moved, freed, or written
   to */

struct fd_jit_prog {
  ulong               magic;
  void *              code_buf;
  ulong               code_sz;
  fd_jit_entrypoint_t entrypoint;
  ulong               first_rip;
};

typedef struct fd_jit_prog fd_jit_prog_t;

#define FD_JIT_PROG_MAGIC (0x2c19d91e7ca38c6bUL)

#if FD_HAS_X86 && FD_HAS_THREADS

/* fd_jit_est_code_sz returns the estimated x86 code footprint for a
   BPF program with bpf_sz .text size.  Returns zero if bpf_sz is too
   large.

   fd_jit_est_scratch_sz returns the estimated scratch memory size
   required to JIT compile a bpf program with bpf_sz .text size.
   Returns zero if bpf_sz is too large.

   This estimation is a "best guess", some programs will exceed this
   size requirement. */

ulong
fd_jit_est_code_sz( ulong bpf_sz );

/* fd_jit_est_scratch_sz returns the estimated scratch buffer size
   required to call fd_jit_prog_new.  This buffer is used to store
   intermediate results during compilation. */

ulong
fd_jit_est_scratch_sz( ulong bpf_sz );

/* fd_jit_prog_new transpiles an sBPF program into native machine code.

   @param jit_prog    Output JIT program -- Fully initialized on success
   @param prog        sBPF program to compile
   @param syscalls    fd_map_dynamic of enabled syscalls
   @param code_buf    Buffer to place machine code in
   @param code_bufsz  Size of code_buf buffer
   @param scratch     Temporary buffer (released on return)
   @param scratch_sz  Size of scratch buffer
   @param out_err     *out_err set to FD_VM_{SUCCESS,ERR_{...}}

   Writes up to scratch_sz bytes for arbitrary use to scratch.  This
   memory is always released back to the caller on return.

   Writes up to code_bufsz bytes of x86 bytecode to code_buf.  The
   number of bytes written is set to jit_prog->code_sz.  A read interest
   remains for the lifetime of the jit_prog object.

   On success, initializes and returns jit_prog.

   On failure, returns NULL and releases any memory back to the caller.
   Reasons include FD_VM_ERR_{...}:

     FULL   Not enough output or scratch space to compile
            FIXME introduce separate error codes for scratch and code sz
     UNSUP  JIT compiler does not support the given executable. */

fd_jit_prog_t *
fd_jit_prog_new( fd_jit_prog_t *            jit_prog,
                 fd_sbpf_program_t const *  prog,
                 fd_sbpf_syscalls_t const * syscalls,
                 void *                     code_buf,
                 ulong                      code_bufsz,
                 void *                     scratch,
                 ulong                      scratch_sz,
                 int *                      out_err );

/* fd_jit_prog_delete releases the memory backing prog and code_buf back
   to the caller. */

void *
fd_jit_prog_delete( fd_jit_prog_t * prog );

/* fd_jit_exec executes a compiled program from entrypoint to halt or
   fault.

   On failure, returns NULL and releases any memory back to the caller.
   Reasons include FD_VM_ERR_{...}:

     UNSUP  JIT compiler does not support the given execution context
            (e.g. complex memory map) */

int
fd_jit_exec( fd_jit_prog_t * jit_prog,
             fd_vm_t *       vm );

#endif /* FD_HAS_X86 && FD_HAS_THREADS */

#endif /* HEADER_fd_src_flamenco_vm_jit_fd_jit_h */
