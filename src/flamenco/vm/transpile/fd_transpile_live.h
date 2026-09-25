#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_live_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_live_h

/* fd_transpile_live.h provides an API for transpiling and executing
   programs on the fly (using mmap()).  This is dangerous and is only
   used for testing. */

#include "fd_transpile.h"

#if defined(__linux__) && FD_HAS_X86

/* fd_transpiled_live_t is a transpiled sBPF program loaded into the
   current process.  It is backed by two anonymous mappings at kernel
   chosen (ASLR) addresses: .text (r-x) and .rodata (r--).  .text is
   placed at a random distance (up to 1 GiB) from .rodata.  No mapping
   is ever writable and executable at the same time.  The
   fd_transpiled_live_t itself lives at the start of .rodata and is
   therefore read-only.

   text_haddr is the entrypoint (an fd_vm_transpiled_exec_func_t). */

struct fd_transpiled_live {
  ulong text_haddr;
  ulong text_map_sz;
  ulong rodata_haddr;
  ulong rodata_map_sz;
};

typedef struct fd_transpiled_live fd_transpiled_live_t;

FD_PROTOTYPES_BEGIN

/* fd_transpiled_live_create transpiles prog and loads it into memory.
   CALL_IMM instructions naming a syscall registered in syscalls bind
   to its handler.  prog and syscalls are not referenced after this
   function returns.  Returns
   NULL on failure (logs reason). */

fd_transpiled_live_t *
fd_transpiled_live_create( fd_sbpf_program_t const * prog,
                           fd_sbpf_syscalls_t const * syscalls );

/* fd_transpiled_live_destroy unmaps a program created by
   fd_transpiled_live_create.  live is invalid after return.  No-op if
   live is NULL. */

void
fd_transpiled_live_destroy( fd_transpiled_live_t * live );

FD_PROTOTYPES_END

#endif /* defined(__linux__) && FD_HAS_X86 */

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_live_h */
