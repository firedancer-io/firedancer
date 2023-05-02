#ifndef HEADER_fd_src_vm_elf_fd_elf_types_h
#define HEADER_fd_src_vm_elf_fd_elf_types_h

#include "../../util/fd_util.h"
#include "../../ballet/fd_ballet_base.h"

/* ELF_MAGIC is the magic value which must be the first for bytes of the 
 * ELF object. They are the characters '\x7F', 'E', 'L', 'F'.
 */
#define ELF_MAGIC (0x7F454C46) 

#define ELFCLASS_32 (1)
#define ELFCLASS_64 (2)

#define ELFDATA_2LSB (1)
#define ELFDATA_2MSB (2)

#define EV_CURRENT (1)

#define ELFOSABI_SYSV       (1)
#define ELFOSABI_HPUX       (2)
#define ELFOSABI_STANDALONE (3)

#define ET_NONE   (0x0000)
#define ET_REL    (0x0001)
#define ET_EXEC   (0x0002)
#define ET_DYN    (0x0003)
#define ET_CORE   (0x0004)
#define ET_LOOS   (0xFE00)
#define ET_HIOS   (0xFEFF)
#define ET_LOPROC (0xFF00)
#define ET_HIPROC (0xFFFF)

#define EM_BPF    (0x7F00)

struct fd_elf64_elf_hdr_ident {
  uint  ei_magic;
  uchar ei_class;
  uchar ei_data;
  uchar ei_version;
  uchar ei_osabi;
  uchar ei_abiversion;
  uchar ei_pad;
  
  uchar ei_reserved_10;
  uchar ei_reserved_11;
  uchar ei_reserved_12;
  uchar ei_reserved_13;
  uchar ei_reserved_14;

  uchar ei_nident;
};
typedef struct fd_elf64_elf_hdr_ident fd_elf64_elf_hdr_ident_t;

struct fd_elf64_elf_hdr {
  fd_elf64_elf_hdr_ident_t  e_ident;
  ushort                    e_type;
  ushort                    e_machine;
  uint                      e_version;
  ulong                     e_entry;
  ulong                     e_phoff;
  ulong                     e_shoff;
  uint                      e_flags;
  ushort                    e_ehsize;
  ushort                    e_phentsize;
  ushort                    e_phnum;
  ushort                    e_shentsize;
  ushort                    e_shnum;
  ushort                    e_shstrndx;
};
typedef struct fd_elf64_elf_hdr fd_elf64_elf_hdr_t;

#define SHN_UNDEF   (0x0000)
#define SHN_LOPROC  (0xFF00)
#define SHN_HIPROC  (0xFF1F)
#define SHN_LOOS    (0xFF20)
#define SHN_HIOS    (0xFF3F)
#define SHN_ABS     (0xFFF1)
#define SHN_COMMON  (0xFFF2)

#define SHT_NULL      (0x00000000)
#define SHT_PROGBITS  (0x00000001)
#define SHT_SYMTAB    (0x00000002)
#define SHT_STRTAB    (0x00000003)
#define SHT_RELA      (0x00000004)
#define SHT_HASH      (0x00000005)
#define SHT_DYNAMIC   (0x00000006)
#define SHT_NOTE      (0x00000007)
#define SHT_NOBITS    (0x00000008)
#define SHT_REL       (0x00000009)
#define SHT_SHLIB     (0x0000000A)
#define SHT_DYNSYM    (0x0000000B)
#define SHT_LOOS      (0x60000000)
#define SHT_HIOS      (0x6FFFFFFF)
#define SHT_LOPROC    (0x70000000)
#define SHT_HIPROC    (0x7FFFFFFF)

#define SHF_WRITE     (0x00000001)
#define SHF_ALLOC     (0x00000002)
#define SHF_EXECINSTR (0x00000004)
#define SHF_MASKOS    (0x0F000000)
#define SHF_MASKPROC  (0xF0000000)

/* Common ELF sections */
#define ELF_SECTION_TEXT    (".text")
#define ELF_SECTION_RODATA  (".rodata")
#define ELF_SECTION_REL_DYN (".rel.dyn")
#define ELF_SECTION_DYNSYM  (".dynsym")
#define ELF_SECTION_DYNSTR  (".dynstr")

struct fd_elf64_section_hdr {
  uint  sh_name;
  uint  sh_type;
  ulong sh_flags;
  ulong sh_addr;
  ulong sh_offset;
  ulong sh_size;
  uint  sh_link;
  uint  sh_info;
  ulong sh_addralign;
  ulong sh_entsize;
};
typedef struct fd_elf64_section_hdr fd_elf64_section_hdr_t;

#define STB_LOCAL   (0x0)
#define STB_GLOBAL  (0x1)
#define STB_WEAK    (0x2)
#define STB_LOOS    (0xA)
#define STB_HIOS    (0xB)
#define STB_LOPROC  (0xC)
#define STB_HIPROC  (0xF)

#define STT_NOTYPE  (0x0)
#define STT_OBJECT  (0x1)
#define STT_FUNC    (0x2)
#define STT_SECTION (0x3)
#define STT_FILE    (0x4)
#define STT_LOOS    (0xA)
#define STT_HIOS    (0xB)
#define STT_LOPROC  (0xC)
#define STT_HIPROC  (0xF)

struct fd_elf64_sym_tab_ent {
  uint    st_name;
  uchar   st_info;
  uchar   st_other;
  ushort  st_shndx;
  ulong   st_value;
  ulong   st_size;
};
typedef struct fd_elf64_sym_tab_ent fd_elf64_sym_tab_ent_t;

#define PT_NULL     (0x00000000)
#define PT_LOAD     (0x00000001)
#define PT_DYNAMIC  (0x00000002)
#define PT_INTERP   (0x00000003)
#define PT_NOTE     (0x00000004)
#define PT_SHLIB    (0x00000005)
#define PT_PHDR     (0x00000006)
#define PT_LOOS     (0x60000000)
#define PT_HIOS     (0x6FFFFFFF)
#define PT_LOPROC   (0x70000000)
#define PT_HIPROC   (0x7FFFFFFF)

#define PF_X        (0x00000001)
#define PF_W        (0x00000002)
#define PF_R        (0x00000004)
#define PF_MASKOS   (0x00FF0000)
#define PF_MASKPROC (0xFF000000)

struct fd_elf64_program_hdr {
  uint  p_type;
  uint  p_flags;
  ulong p_offset;
  ulong p_vaddr;
  ulong p_paddr;
  ulong p_filesz;
  ulong p_memsz;
  ulong p_align;
};
typedef struct fd_elf64_program_hdr fd_elf64_program_hdr_t;

#define R_BPF_NONE        (0)
#define R_BPF_64_64       (1)
#define R_BPF_64_RELATIVE (8)
#define R_BPF_64_32       (10)

struct fd_elf64_relocation_rel {
  ulong r_offset;
  ulong r_info;
};
typedef struct fd_elf64_relocation_rel fd_elf64_relocation_rel_t;

struct fd_elf64_relocated_sbfp_program {
  ulong   entrypoint;

  uchar * text_section;
  ulong   text_section_len;
  uchar * rodata_section;
  ulong   rodata_section_len;
};
typedef struct fd_elf64_relocated_sbfp_program fd_elf64_relocated_sbfp_program_t;

#endif /* HEADER_fd_src_vm_elf_fd_elf_types_h */
