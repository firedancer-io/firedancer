#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_obj_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_obj_h

/* fd_transpile_obj.h is a high-level API to create static object files
   containing sBPF-to-x86 transpiled programs. */

#include "fd_transpile.h"

FD_PROTOTYPES_BEGIN

/* fd_transpiler_export_obj creates a relocatable ELF object file from a
   transpiled program.  Such object files can be linked into Linux -fPIC
   x86 builds.  Object files depend on symbols provided in
   fd_transpile_runtime.  t is a transpiler state previously populated
   using fd_vm_transpile_code.  syscalls is the syscall table that was
   passed to fd_vm_transpile_code (relocations reference its slots).

   The ELF file content is written into [elf,elf+elf_max).  Returns 0 on
   failure (e.g. transpile failed or buffer space exceeded) and logs
   warning.  On success, returns ELF size.

   This ELF gains a single global symbol of fd_transpile_export with
   name 'fd_transpiled_ext_<base58(prog_id)>'. */

ulong
fd_transpiler_export_obj( fd_transpiler_t *          t,
                          fd_sbpf_syscalls_t const * syscalls,
                          uchar *                    elf,
                          ulong                      elf_max );

#if FD_HAS_HOSTED

/* fd_transpiler_export_archive creates a thin archive (.a) of
   transpiled object files.  obj_dir is the cstr path to a directory
   containing 'fd_transpiled_<base58(prog_id)>.o' files.  Produces a
   'fd_transpiled_export.o' object file and a 'libfd_transpiled.a'
   archive file. */

int
fd_transpiler_export_archive( char const * obj_dir );

int
fd_transpile_export_ar( char const *         dir,
                        char const *         ar_name,
                        char const * const * names,
                        char const * const * syms,
                        ulong                cnt );

#endif /* FD_HAS_HOSTED */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_obj_h */
