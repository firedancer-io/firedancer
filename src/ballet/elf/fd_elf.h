#ifndef HEADER_fd_src_ballet_elf_fd_elf_h
#define HEADER_fd_src_ballet_elf_fd_elf_h

#include "../../util/fd_util_base.h"

#define FD_ELF_EI_MAG0        0
#define FD_ELF_EI_MAG1        1
#define FD_ELF_EI_MAG2        2
#define FD_ELF_EI_MAG3        3
#define FD_ELF_EI_CLASS       4
#define FD_ELF_EI_DATA        5
#define FD_ELF_EI_VERSION     6
#define FD_ELF_EI_OSABI       7
#define FD_ELF_EI_ABIVERSION  8
#define FD_ELF_EI_NIDENT     16

#define FD_ELF_CLASS_NONE 0
#define FD_ELF_CLASS_32   1
#define FD_ELF_CLASS_64   2

#define FD_ELF_DATA_NONE  0
#define FD_ELF_DATA_LE    1
#define FD_ELF_DATA_BE    2

#define FD_ELF_ET_NONE 0
#define FD_ELF_ET_REL  1
#define FD_ELF_ET_EXEC 2
#define FD_ELF_ET_DYN  3
#define FD_ELF_ET_CORE 4

#define FD_ELF_EM_NONE   0
#define FD_ELF_EM_BPF  247

#define FD_ELF_R_BPF_64_64 1

FD_PROTOTYPES_BEGIN

FD_FN_PURE char const *
fd_elf_read_cstr( void const * buf,
                  ulong        buf_sz,
                  ulong        off,
                  ulong        max_len );

FD_PROTOTYPES_END

/* Re-export sibling headers for convenience */

#include "fd_elf64.h"

#endif /* HEADER_fd_src_ballet_elf_fd_elf_h */
