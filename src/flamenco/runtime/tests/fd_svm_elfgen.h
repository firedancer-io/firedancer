#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_svm_elfgen_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_svm_elfgen_h

/* fd_svm_elfgen.h crafts minimal loadable programs from assembly blobs.
   Useful for injecting test programs in end-to-end tests. */

#include "../../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_svm_elfgen_sz returns the byte size required to host an ELF file
   with text_sz bytes of sBPF instructions and rodata_sz read-only
   bytes. */

ulong
fd_svm_elfgen_sz( ulong text_sz,
                  ulong rodata_sz );

/* fd_svm_elfgen writes an sBPF ELF file to the byte array at elf (with
   elf_max capacity).  text points to sBPF instructions, and rodata
   points to read-only data.

   The generated ELF is Loader v2-compatible.  CALL_IMM instructions
   must be in pc-relative (not hashed) format. */

void
fd_svm_elfgen( uchar *       elf,
               ulong         elf_max,
               uchar const * text,
               ulong         text_sz,
               uchar const * rodata,
               ulong         rodata_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_svm_elfgen_h */
