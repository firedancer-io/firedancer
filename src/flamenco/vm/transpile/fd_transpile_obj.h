#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_obj_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_obj_h

/* fd_transpile_obj.h is a high-level API to create static object files
   containing sBPF-to-x86 transpiled programs. */

#include "../../../ballet/sbpf/fd_sbpf_loader.h"

/* fd_vm_transpile_obj creates a position-independent relocatable ELF
   object file.  It contains a sBPF program transpiled to x86.
   Such object files can be linked into native Linux x86 builds.
   Object files depend on symbols provided in fd_transpile_runtime.

   elf points a buffer of capacity *elf_sz into which the ELF content is
   written.  prog the loaded and verified sBPF program to be translated.
   entrypoint_name_cstr is used as the symbol name of the only global
   symbol in .text (the entrypoint function of the transpiled program).

   This function uses malloc()/free().

   On failure, logs warning and returns NULL.  There is an arbitrary
   number of reasons why transpiling can fail.  Only an unspecified
   subset of programs can be transpiled (the rest can be executed via
   the interpreter).

   On success, sets *elf_sz to the final size of the binary file. */

FD_PROTOTYPES_BEGIN

uchar *
fd_vm_transpile_obj( uchar *                   elf,
                     ulong *                   elf_sz,
                     fd_sbpf_program_t const * prog,
                     char const *              entrypoint_name_cstr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_obj_h */
