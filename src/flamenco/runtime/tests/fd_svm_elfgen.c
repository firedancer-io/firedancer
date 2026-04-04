#include "fd_svm_elfgen.h"
#include "../../../ballet/elf/fd_elf64.h"

static char const shstrtab[] = "\0.text\0.rodata\0.shstrtab\0";
#define SHSTRTAB_OFF_TEXT    1  /* byte offset of ".text"     in shstrtab */
#define SHSTRTAB_OFF_RODATA  7  /* byte offset of ".rodata"   in shstrtab */
#define SHSTRTAB_OFF_SHSTR  15  /* byte offset of ".shstrtab" in shstrtab */

ulong
fd_svm_elfgen_sz( ulong text_sz,
                  ulong rodata_sz ) {
  ulong phdr_file_off     = sizeof(fd_elf64_ehdr);
  ulong text_file_off     = fd_ulong_align_up( phdr_file_off + sizeof(fd_elf64_phdr), 8UL );
  ulong rodata_file_off   = text_file_off + text_sz;
  ulong shstrtab_file_off = rodata_file_off + rodata_sz;
  ulong shdr_file_off     = fd_ulong_align_up( shstrtab_file_off + sizeof(shstrtab), 8UL );
  ulong total_sz          = shdr_file_off + 4UL * sizeof(fd_elf64_shdr);
  return total_sz;
}

void
fd_svm_elfgen( uchar *       buf,
               ulong         buf_sz,
               uchar const * text_data,
               ulong         text_sz,
               uchar const * rodata,
               ulong         rodata_sz ) {
  ulong phdr_file_off     = sizeof(fd_elf64_ehdr);
  ulong text_file_off     = fd_ulong_align_up( phdr_file_off + sizeof(fd_elf64_phdr), 8UL );
  ulong rodata_file_off   = text_file_off + text_sz;
  ulong segment_sz        = text_sz + rodata_sz;
  ulong shstrtab_file_off = rodata_file_off + rodata_sz;
  ulong shdr_file_off     = fd_ulong_align_up( shstrtab_file_off + sizeof(shstrtab), 8UL );
  ulong total_sz          = shdr_file_off + 4UL * sizeof(fd_elf64_shdr);

  FD_TEST( total_sz <= buf_sz );
  memset( buf, 0, total_sz );

  FD_STORE( fd_elf64_ehdr, buf, ((fd_elf64_ehdr) {
    .e_ident = { 0x7f,'E','L','F', FD_ELF_CLASS_64, FD_ELF_DATA_LE, 1, FD_ELF_OSABI_NONE },
    .e_type  = FD_ELF_ET_DYN,
    .e_machine   = FD_ELF_EM_BPF,
    .e_version   = 1,
    .e_entry     = text_file_off,
    .e_phoff     = phdr_file_off,
    .e_shoff     = shdr_file_off,
    .e_flags     = 0,
    .e_ehsize    = sizeof(fd_elf64_ehdr),
    .e_phentsize = sizeof(fd_elf64_phdr),
    .e_phnum     = 1,
    .e_shentsize = sizeof(fd_elf64_shdr),
    .e_shnum     = 4,
    .e_shstrndx  = 3
  }) );

  /* Single PT_LOAD segment covering .text and .rodata */
  fd_elf64_phdr * phdr = (fd_elf64_phdr *)(buf + phdr_file_off);
  phdr->p_type   = FD_ELF_PT_LOAD;
  phdr->p_flags  = 5;
  phdr->p_offset = text_file_off;
  phdr->p_vaddr  = text_file_off;
  phdr->p_paddr  = text_file_off;
  phdr->p_filesz = segment_sz;
  phdr->p_memsz  = segment_sz;
  phdr->p_align  = 8;

  /* Section 1: .text (sh_addr must equal sh_offset for the loader) */
  fd_elf64_shdr * shdr_text = (fd_elf64_shdr *)(buf + shdr_file_off + sizeof(fd_elf64_shdr));
  shdr_text->sh_name      = SHSTRTAB_OFF_TEXT;
  shdr_text->sh_type      = FD_ELF_SHT_PROGBITS;
  shdr_text->sh_flags     = 0x6;
  shdr_text->sh_addr      = text_file_off;
  shdr_text->sh_offset    = text_file_off;
  shdr_text->sh_size      = text_sz;
  shdr_text->sh_addralign = 8;

  /* Section 2: .rodata */
  fd_elf64_shdr * shdr_ro = (fd_elf64_shdr *)(buf + shdr_file_off + 2UL * sizeof(fd_elf64_shdr));
  shdr_ro->sh_name      = SHSTRTAB_OFF_RODATA;
  shdr_ro->sh_type      = FD_ELF_SHT_PROGBITS;
  shdr_ro->sh_flags     = 0x2;
  shdr_ro->sh_addr      = rodata_file_off;
  shdr_ro->sh_offset    = rodata_file_off;
  shdr_ro->sh_size      = rodata_sz;
  shdr_ro->sh_addralign = 1;

  /* Section 3: .shstrtab */
  fd_elf64_shdr * shdr_strtab = (fd_elf64_shdr *)(buf + shdr_file_off + 3UL * sizeof(fd_elf64_shdr));
  shdr_strtab->sh_name      = SHSTRTAB_OFF_SHSTR;
  shdr_strtab->sh_type      = FD_ELF_SHT_STRTAB;
  shdr_strtab->sh_offset    = shstrtab_file_off;
  shdr_strtab->sh_size      = sizeof(shstrtab);
  shdr_strtab->sh_addralign = 1;

  memcpy( buf + text_file_off, text_data, text_sz );
  if( rodata_sz ) memcpy( buf + rodata_file_off, rodata, rodata_sz );
  memcpy( buf + shstrtab_file_off, shstrtab, sizeof(shstrtab) );
}
