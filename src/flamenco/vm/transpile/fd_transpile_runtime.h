#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_runtime_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_runtime_h

/* fd_transpile_runtime.h provides run-time support for transpiled
   programs.  This is a public ABI that transpiled programs call during
   execution. */

#include "../fd_vm.h"

/* a fd_vm_transpiled_exec_func_t function executes a transpiled
   program.  This is a drop-in replacement for fd_vm_exec.

   This function gains one special return code, FD_VM_ERR_EBPF_BAIL.
   This means that execution stopped because the program attempted odd
   behavior that is not allowed in a transpiled context.  The caller
   should resume with fd_vm_exec in this case. */

typedef int
(* fd_vm_transpiled_exec_func_t)( fd_vm_t * vm );

struct fd_transpile_meta {
  uchar prog_id[ 32 ];       /* program address */
  uchar elf_hash[ 32 ];      /* BLAKE3 of the sBPF ELF file the program was transpiled from */
  ulong text_cnt;
  ulong text_sz;
  ulong entry_pc;
  ulong sbpf_version;
};

typedef struct fd_transpile_meta fd_transpile_meta_t;

/* fd_transpile_export_t is the only global symbol of a transpiled
   program's object file. */

struct fd_transpile_export {
  ulong                        abi_version;
  ulong                        struct_size;
  fd_vm_transpiled_exec_func_t exec;
  fd_transpile_meta_t          meta;
};

typedef struct fd_transpile_export fd_transpile_export_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_transpiled_mmu_translate maps a memory access at guest virtual
   address vaddr to a host address, and runs access checks.
   access_width is in {1,2,4,8} (only scalar accesses supported), and
   is_write is 0 or 1.  Returns a host address (>=0) on success, or a
   negative FD_VM_ERR_EBPF error on translation failure, e.g. access
   violation.  */

long
fd_vm_transpiled_mmu_translate( fd_vm_t * vm,
                                ulong     vaddr,
                                ulong     access_width,
                                uchar     is_write );

/* fd_vm_transpiled_frame_init zero-initializes the stack memory backing
   call frame vm->frame_cnt and refreshes vm->transpiled.frame_clean_cnt.
   Called by transpiled code after pushing a frame that reaches into
   uninitialized stack memory. */

void
fd_vm_transpiled_frame_init( fd_vm_t * vm );

/* fd_transpiled_ext is a NULL-terminated array of transpiled programs
   linked in via the archive produced by fd_transpiler_export_archive. */

extern fd_transpile_export_t const * const fd_transpiled_ext[];

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_runtime_h */
