#ifndef HEADER_fd_src_ballet_elf_fd_elf64_h
#define HEADER_fd_src_ballet_elf_fd_elf64_h

#include "fd_elf.h"

#define FD_ELF64_R_SYM(i)  ((ulong)(i) >> 32)
#define FD_ELF64_R_TYPE(i) ((ulong)(i) & 0xFFFFFFFF)

struct __attribute__((packed)) fd_elf64_ehdr_ {
  uchar  e_ident[ FD_ELF_EI_NIDENT ];
  ushort e_type;
  ushort e_machine;
  uint   e_version;
  ulong  e_entry;
  ulong  e_phoff;
  ulong  e_shoff;
  uint   e_flags;
  ushort e_ehsize;
  ushort e_phentsize;
  ushort e_phnum;
  ushort e_shentsize;
  ushort e_shnum;
  ushort e_shstrndx;
};
typedef struct fd_elf64_ehdr_ fd_elf64_ehdr;

struct __attribute__((packed)) fd_elf64_phdr_ {
  uint  p_type;
  uint  p_flags;
  ulong p_offset;
  ulong p_vaddr;
  ulong p_paddr;
  ulong p_filesz;
  ulong p_memsz;
  ulong p_align;
};
typedef struct fd_elf64_phdr_ fd_elf64_phdr;

#define FD_ELF_SHT_NULL      0
#define FD_ELF_SHT_PROGBITS  1
#define FD_ELF_SHT_SYMTAB    2
#define FD_ELF_SHT_STRTAB    3
#define FD_ELF_SHT_RELA      4
#define FD_ELF_SHT_HASH      5
#define FD_ELF_SHT_DYNAMIC   6
#define FD_ELF_SHT_REL       9
#define FD_ELF_SHT_DYNSYM   11

struct __attribute__((packed)) fd_elf64_shdr_ {
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
typedef struct fd_elf64_shdr_ fd_elf64_shdr;

struct __attribute__((packed)) fd_elf64_sym_ {
  uint   st_name;
  uchar  st_info;
  uchar  st_other;
  ushort st_shndx;
  ulong  st_value;
  ulong  st_size;
};
typedef struct fd_elf64_sym_ fd_elf64_sym;

struct __attribute__((packed)) fd_elf64_rel_ {
  ulong r_offset;
  ulong r_info;
};
typedef struct fd_elf64_rel_ fd_elf64_rel;

struct __attribute__((packed)) fd_elf64_rela_ {
  ulong r_offset;
  ulong r_info;
  long  r_addend;
};
typedef struct fd_elf64_rela_ fd_elf64_rela;

struct __attribute__((packed)) fd_elf64_dyn_ {
  long d_tag;
  union {
    ulong d_val;
    ulong d_ptr;
  } d_un;
};
typedef struct fd_elf64_dyn_ fd_elf64_dyn;

#endif /* HEADER_fd_src_ballet_elf_fd_elf64_h */

