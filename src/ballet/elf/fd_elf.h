#ifndef HEADER_fd_src_ballet_elf_fd_elf_h
#define HEADER_fd_src_ballet_elf_fd_elf_h

/* Executable and Linking Format (ELF) */

#include "../../util/fd_util.h"
#include <string.h>

/* FD_ELF_EI: File type related */

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

/* FD_ELF_CLASS: 32-bit/64-bit architecture */

#define FD_ELF_CLASS_NONE 0
#define FD_ELF_CLASS_32   1
#define FD_ELF_CLASS_64   2

/* FD_ELF_DATA: Endianness */

#define FD_ELF_DATA_NONE  0
#define FD_ELF_DATA_LE    1
#define FD_ELF_DATA_BE    2

/* FD_ELF_OSABI */

#define FD_ELF_OSABI_NONE 0

/* FD_ELF_ET: ELF file type */

#define FD_ELF_ET_NONE 0
#define FD_ELF_ET_REL  1 /* relocatable static object */
#define FD_ELF_ET_EXEC 2 /* executable */
#define FD_ELF_ET_DYN  3 /* shared object */
#define FD_ELF_ET_CORE 4 /* core dump */

/* FD_ELF_EM: Machine type */

#define FD_ELF_EM_NONE   0
#define FD_ELF_EM_BPF  247
#define FD_ELF_EM_SBPF 263

/* FD_ELF_EF: ELF flags */

#define FD_ELF_EF_SBPF_V2 32

/* FD_ELF_PT: Program header type */

#define FD_ELF_PT_NULL    0
#define FD_ELF_PT_LOAD    1
#define FD_ELF_PT_DYNAMIC 2

/* FD_ELF_SHT: Section header type */

#define FD_ELF_SHT_NULL      0
#define FD_ELF_SHT_PROGBITS  1
#define FD_ELF_SHT_SYMTAB    2
#define FD_ELF_SHT_STRTAB    3
#define FD_ELF_SHT_RELA      4
#define FD_ELF_SHT_HASH      5
#define FD_ELF_SHT_DYNAMIC   6
#define FD_ELF_SHT_NOBITS    8
#define FD_ELF_SHT_REL       9
#define FD_ELF_SHT_DYNSYM   11

/* FD_ELF_SHF: Section header flags */

#define FD_ELF_SHF_WRITE     0x1
#define FD_ELF_SHF_ALLOC     0x2
#define FD_ELF_SHF_EXECINSTR 0x4

/* FD_ELF_DT: Dynamic entry type */

#define FD_ELF_DT_NULL     0
#define FD_ELF_DT_SYMTAB   6
#define FD_ELF_DT_REL     17
#define FD_ELF_DT_RELSZ   18
#define FD_ELF_DT_RELENT  19

/* FD_ELF64_ST_TYPE extracts the symbol type from symbol st_info */

#define FD_ELF64_ST_TYPE(i) ((i)&0xF)

/* FD_ELF_STT: Symbol type */

#define FD_ELF_STT_NOTYPE  0
#define FD_ELF_STT_FUNC    2

/* FD_ELF64_R_SYM extracts the symbol index from reloc r_info.
   FD_ELF64_R_TYPE extracts the relocation type from reloc r_info. */

#define FD_ELF64_R_SYM(i)  ((uint)((ulong)(i) >> 32))
#define FD_ELF64_R_TYPE(i) ((uint)((ulong)(i) & 0xFFFFFFFF))

/* FD_ELF_R_BPF: BPF relocation types */

#define FD_ELF_R_BPF_64_64        1 /* 64-bit immediate (lddw form) */
#define FD_ELF_R_BPF_64_RELATIVE  8
#define FD_ELF_R_BPF_64_32       10

FD_PROTOTYPES_BEGIN

/* fd_elf_read_cstr: Validate cstr and return pointer.  Given memory
   region buf of size buf_sz, attempt to read cstr at offset off in
   [0,buf_sz)  If buf_sz is 0, buf may be an invalid pointer.  Returns
   pointer to first byte of cstr in buf on success, and NULL on failure.
   Reasons for failure include: off or cstr is out-of-bounds, footprint
   of cstr (including NUL) greater than max_sz. */

FD_FN_PURE static inline char const *
fd_elf_read_cstr( void const * buf,
                  ulong        buf_sz,
                  ulong        off,
                  ulong        max_sz ) {

  if( FD_UNLIKELY( off>=buf_sz ) )
    return NULL;

  char const * str    = (char const *)( (ulong)buf + off );
  ulong        str_sz = buf_sz - off;

  ulong n = fd_ulong_min( str_sz, max_sz );
  if( FD_UNLIKELY( fd_cstr_nlen( str, n )==max_sz ) )
    return NULL;

  return str;
}

FD_PROTOTYPES_END

/* Re-export sibling headers for convenience */

#include "fd_elf64.h"

#endif /* HEADER_fd_src_ballet_elf_fd_elf_h */

