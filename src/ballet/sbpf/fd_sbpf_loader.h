#ifndef HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h
#define HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h

#include "../../util/fd_util_base.h"

/* ELF data types *****************************************************/

#include <elf.h>

typedef Elf64_Ehdr fd_elf64_ehdr;
typedef Elf64_Phdr fd_elf64_phdr;
typedef Elf64_Shdr fd_elf64_shdr;
typedef Elf64_Dyn  fd_elf64_dyn;
typedef Elf64_Rel  fd_elf64_rel;
typedef Elf64_Sym  fd_elf64_sym;

/* FD_SBPF_PHNDX_UNDEF: placeholder for undefined program header index */
#define FD_SBPF_PHNDX_UNDEF (ULONG_MAX)

/* Error types ********************************************************/

#define FD_SBPF_ERR_INVALID_ELF (1)

/* Program struct *****************************************************/

struct fd_sbpf_program {
  /* File header */
  fd_elf64_ehdr ehdr;

  /* Segments */
  fd_elf64_phdr * phdrs;
  ulong phndx_load;
  ulong phndx_dyn;

  /* Sections */
  fd_elf64_shdr * shdrs;
  ulong shndx_dyn;
  ulong shndx_bss;
  ulong shndx_text;
  ulong shndx_symtab;
  ulong shndx_strtab;
  ulong shndx_dynstr;

  /* Dynamic */
  ulong dt_rel;
  ulong dt_relent;
  ulong dt_relsz;
  ulong dt_symtab;
};
typedef struct fd_sbpf_program fd_sbpf_program_t;

/* Prototypes *********************************************************/

FD_PROTOTYPES_BEGIN

int
fd_sbpf_program_load( fd_sbpf_program_t * program,
                      uchar * bin,
                      ulong   bin_sz );

/* fd_csv_strerror: Returns a cstr describing the source line and error
   kind after the last call to `fd_sbpf_program_load` from the same
   thread returned non-zero.
   Always returns a valid cstr, though the content is undefined in case
   the last call to `fd_sbpf_program_load` returned zero (success). */
char const *
fd_sbpf_strerror( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h */
