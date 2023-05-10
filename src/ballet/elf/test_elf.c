#include "fd_elf64.h"

#include <stddef.h>

/* Sanity checks for ELF */

#if defined(__linux__)

#include <elf.h>

/* Assert that ELF defines are binary compatible. */

FD_STATIC_ASSERT( FD_ELF_EI_MAG0      ==EI_MAG0,       compat );
FD_STATIC_ASSERT( FD_ELF_EI_MAG1      ==EI_MAG1,       compat );
FD_STATIC_ASSERT( FD_ELF_EI_MAG2      ==EI_MAG2,       compat );
FD_STATIC_ASSERT( FD_ELF_EI_MAG3      ==EI_MAG3,       compat );
FD_STATIC_ASSERT( FD_ELF_EI_CLASS     ==EI_CLASS,      compat );
FD_STATIC_ASSERT( FD_ELF_EI_DATA      ==EI_DATA,       compat );
FD_STATIC_ASSERT( FD_ELF_EI_VERSION   ==EI_VERSION,    compat );
FD_STATIC_ASSERT( FD_ELF_EI_OSABI     ==EI_OSABI,      compat );
FD_STATIC_ASSERT( FD_ELF_EI_ABIVERSION==EI_ABIVERSION, compat );
FD_STATIC_ASSERT( FD_ELF_EI_NIDENT    ==EI_NIDENT,     compat );

FD_STATIC_ASSERT( FD_ELF_CLASS_NONE==ELFCLASSNONE, compat );
FD_STATIC_ASSERT( FD_ELF_CLASS_32  ==ELFCLASS32,   compat );
FD_STATIC_ASSERT( FD_ELF_CLASS_64  ==ELFCLASS64,   compat );

FD_STATIC_ASSERT( FD_ELF_DATA_NONE==ELFDATANONE, compat );
FD_STATIC_ASSERT( FD_ELF_DATA_LE  ==ELFDATA2LSB, compat );
FD_STATIC_ASSERT( FD_ELF_DATA_BE  ==ELFDATA2MSB, compat );

FD_STATIC_ASSERT( FD_ELF_OSABI_NONE==ELFOSABI_NONE, compat );

FD_STATIC_ASSERT( FD_ELF_ET_NONE==ET_NONE, compat );
FD_STATIC_ASSERT( FD_ELF_ET_REL ==ET_REL,  compat );
FD_STATIC_ASSERT( FD_ELF_ET_EXEC==ET_EXEC, compat );
FD_STATIC_ASSERT( FD_ELF_ET_DYN ==ET_DYN,  compat );
FD_STATIC_ASSERT( FD_ELF_ET_CORE==ET_CORE, compat );

FD_STATIC_ASSERT( FD_ELF_PT_NULL   ==PT_NULL,    compat );
FD_STATIC_ASSERT( FD_ELF_PT_LOAD   ==PT_LOAD,    compat );
FD_STATIC_ASSERT( FD_ELF_PT_DYNAMIC==PT_DYNAMIC, compat );

FD_STATIC_ASSERT( FD_ELF_SHT_NULL    ==SHT_NULL,     compat );
FD_STATIC_ASSERT( FD_ELF_SHT_PROGBITS==SHT_PROGBITS, compat );
FD_STATIC_ASSERT( FD_ELF_SHT_SYMTAB  ==SHT_SYMTAB,   compat );
FD_STATIC_ASSERT( FD_ELF_SHT_STRTAB  ==SHT_STRTAB,   compat );
FD_STATIC_ASSERT( FD_ELF_SHT_RELA    ==SHT_RELA,     compat );
FD_STATIC_ASSERT( FD_ELF_SHT_HASH    ==SHT_HASH,     compat );
FD_STATIC_ASSERT( FD_ELF_SHT_DYNAMIC ==SHT_DYNAMIC,  compat );
FD_STATIC_ASSERT( FD_ELF_SHT_REL     ==SHT_REL,      compat );
FD_STATIC_ASSERT( FD_ELF_SHT_DYNSYM  ==SHT_DYNSYM,   compat );

FD_STATIC_ASSERT( FD_ELF_SHF_WRITE    ==SHF_WRITE,     compat );
FD_STATIC_ASSERT( FD_ELF_SHF_ALLOC    ==SHF_ALLOC,     compat );
FD_STATIC_ASSERT( FD_ELF_SHF_EXECINSTR==SHF_EXECINSTR, compat );

FD_STATIC_ASSERT( FD_ELF_DT_NULL  ==DT_NULL,     compat );
FD_STATIC_ASSERT( FD_ELF_DT_SYMTAB==DT_SYMTAB,   compat );
FD_STATIC_ASSERT( FD_ELF_DT_REL   ==DT_REL,      compat );
FD_STATIC_ASSERT( FD_ELF_DT_RELSZ ==DT_RELSZ,    compat );
FD_STATIC_ASSERT( FD_ELF_DT_RELENT==DT_RELENT,   compat );

FD_STATIC_ASSERT( FD_ELF_STT_NOTYPE==STT_NOTYPE, compat );
FD_STATIC_ASSERT( FD_ELF_STT_FUNC  ==STT_FUNC,   compat );

/* Assert that our ELF structs are binary compatible with the system ELF
   headers. */

FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_ident     )==offsetof( Elf64_Ehdr, e_ident     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_type      )==offsetof( Elf64_Ehdr, e_type      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_machine   )==offsetof( Elf64_Ehdr, e_machine   ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_version   )==offsetof( Elf64_Ehdr, e_version   ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_entry     )==offsetof( Elf64_Ehdr, e_entry     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_phoff     )==offsetof( Elf64_Ehdr, e_phoff     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_shoff     )==offsetof( Elf64_Ehdr, e_shoff     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_flags     )==offsetof( Elf64_Ehdr, e_flags     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_ehsize    )==offsetof( Elf64_Ehdr, e_ehsize    ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_phentsize )==offsetof( Elf64_Ehdr, e_phentsize ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_phnum     )==offsetof( Elf64_Ehdr, e_phnum     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_shentsize )==offsetof( Elf64_Ehdr, e_shentsize ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_shnum     )==offsetof( Elf64_Ehdr, e_shnum     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_ehdr, e_shstrndx  )==offsetof( Elf64_Ehdr, e_shstrndx  ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_ehdr              )==sizeof  ( Elf64_Ehdr              ), compat );

FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_type   )==offsetof( Elf64_Phdr, p_type   ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_flags  )==offsetof( Elf64_Phdr, p_flags  ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_offset )==offsetof( Elf64_Phdr, p_offset ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_vaddr  )==offsetof( Elf64_Phdr, p_vaddr  ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_paddr  )==offsetof( Elf64_Phdr, p_paddr  ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_filesz )==offsetof( Elf64_Phdr, p_filesz ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_memsz  )==offsetof( Elf64_Phdr, p_memsz  ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_phdr, p_align  )==offsetof( Elf64_Phdr, p_align  ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_phdr           )==sizeof  ( Elf64_Phdr           ), compat );

FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_name      )==offsetof( Elf64_Shdr, sh_name      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_type      )==offsetof( Elf64_Shdr, sh_type      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_flags     )==offsetof( Elf64_Shdr, sh_flags     ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_addr      )==offsetof( Elf64_Shdr, sh_addr      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_offset    )==offsetof( Elf64_Shdr, sh_offset    ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_size      )==offsetof( Elf64_Shdr, sh_size      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_link      )==offsetof( Elf64_Shdr, sh_link      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_info      )==offsetof( Elf64_Shdr, sh_info      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_addralign )==offsetof( Elf64_Shdr, sh_addralign ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_shdr, sh_entsize   )==offsetof( Elf64_Shdr, sh_entsize   ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_shdr               )==sizeof  ( Elf64_Shdr               ), compat );

FD_STATIC_ASSERT( offsetof( fd_elf64_sym, st_name  )==offsetof( Elf64_Sym, st_name  ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_sym, st_info  )==offsetof( Elf64_Sym, st_info  ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_sym, st_other )==offsetof( Elf64_Sym, st_other ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_sym, st_shndx )==offsetof( Elf64_Sym, st_shndx ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_sym, st_value )==offsetof( Elf64_Sym, st_value ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_sym, st_size  )==offsetof( Elf64_Sym, st_size  ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_sym           )==sizeof  ( Elf64_Sym           ), compat );

FD_STATIC_ASSERT( offsetof( fd_elf64_rel, r_offset )==offsetof( Elf64_Rel, r_offset ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_rel, r_info   )==offsetof( Elf64_Rel, r_info   ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_rel           )==sizeof  ( Elf64_Rel           ), compat );

FD_STATIC_ASSERT( offsetof( fd_elf64_rela, r_offset )==offsetof( Elf64_Rela, r_offset ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_rela, r_info   )==offsetof( Elf64_Rela, r_info   ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_rela, r_addend )==offsetof( Elf64_Rela, r_addend ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_rela           )==sizeof  ( Elf64_Rela           ), compat );

FD_STATIC_ASSERT( offsetof( fd_elf64_dyn, d_tag      )==offsetof( Elf64_Dyn, d_tag      ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_dyn, d_un       )==offsetof( Elf64_Dyn, d_un       ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_dyn, d_un.d_val )==offsetof( Elf64_Dyn, d_un.d_val ), compat );
FD_STATIC_ASSERT( offsetof( fd_elf64_dyn, d_un.d_ptr )==offsetof( Elf64_Dyn, d_un.d_ptr ), compat );
FD_STATIC_ASSERT( sizeof  ( fd_elf64_dyn             )==sizeof  ( Elf64_Dyn             ), compat );

#endif /* defined(__linux__) */


int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );

  /* TODO */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
