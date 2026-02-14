#include "fdos_env.h"
#include "../kern/fdos_kern_def.h"
#include "../../ballet/elf/fd_elf64.h"

/* Kernel loader */

struct fdos_kern_img_off {
  fd_elf64_ehdr ehdr;
  fd_elf64_phdr phdr_rom;
  fd_elf64_phdr phdr_code;
  fd_elf64_phdr phdr_ram;
};

typedef struct fdos_kern_img_off fdos_kern_img_off_t;

static fdos_kern_img_off_t *
fdos_kern_img_off_load( fdos_kern_img_off_t * img_off,
                        uchar const *         bin,
                        ulong                 bin_sz ) {
  memset( img_off, 0, sizeof(fdos_kern_img_off_t) );

  img_off->ehdr = FD_LOAD( fd_elf64_ehdr, bin );
  FD_TEST( FD_LOAD( uint, img_off->ehdr.e_ident )==fd_uint_bswap( 0x7f454c46 ) );
  /* FIXME More validation */
  FD_TEST( img_off->ehdr.e_phnum==3 );
  FD_TEST( img_off->ehdr.e_phentsize==sizeof(fd_elf64_phdr) );

  ulong phdr_off0 = img_off->ehdr.e_phoff;
  ulong phdr_off1 = img_off->ehdr.e_phoff + img_off->ehdr.e_phnum*sizeof(fd_elf64_phdr);
  FD_TEST( phdr_off1<=bin_sz );

  uchar const * phdr_i = bin + phdr_off0;
  img_off->phdr_rom  = FD_LOAD( fd_elf64_phdr, phdr_i ); phdr_i += sizeof(fd_elf64_phdr);
  img_off->phdr_code = FD_LOAD( fd_elf64_phdr, phdr_i ); phdr_i += sizeof(fd_elf64_phdr);
  img_off->phdr_ram  = FD_LOAD( fd_elf64_phdr, phdr_i ); phdr_i += sizeof(fd_elf64_phdr);

  FD_TEST( img_off->phdr_rom.p_type   == FD_ELF_PT_LOAD );
  FD_TEST( img_off->phdr_rom.p_flags  == 4 );
  FD_TEST( img_off->phdr_code.p_type  == FD_ELF_PT_LOAD );
  FD_TEST( img_off->phdr_code.p_flags == 5 );
  FD_TEST( img_off->phdr_ram.p_type   == FD_ELF_PT_LOAD );
  FD_TEST( img_off->phdr_ram.p_flags  == 6 );

  ulong off1;
  FD_TEST( !__builtin_uaddl_overflow( img_off->phdr_rom.p_offset,  img_off->phdr_rom.p_filesz,  &off1 ) && off1<=bin_sz );
  FD_TEST( !__builtin_uaddl_overflow( img_off->phdr_code.p_offset, img_off->phdr_code.p_filesz, &off1 ) && off1<=bin_sz );
  FD_TEST( !__builtin_uaddl_overflow( img_off->phdr_ram.p_offset,  img_off->phdr_ram.p_filesz,  &off1 ) && off1<=bin_sz );

  return img_off;
}

void
fdos_env_img_load( fdos_env_t *  env,
                   uchar const * bin,
                   ulong         bin_sz ) {
  fdos_kern_img_off_t img_off[1];
  FD_TEST( fdos_kern_img_off_load( img_off, bin, bin_sz ) );

  ulong rodata_gaddr = fd_wksp_alloc( env->wksp_kern_rodata, FD_SHMEM_NORMAL_PAGE_SZ, img_off->phdr_rom.p_memsz, 1UL );
  FD_TEST( rodata_gaddr==FD_SHMEM_NORMAL_PAGE_SZ );
  uchar * rodata = fd_wksp_laddr_fast( env->wksp_kern_rodata, rodata_gaddr );
  fd_memcpy( rodata, bin + img_off->phdr_rom.p_offset, img_off->phdr_rom.p_filesz );
  env->rodata        = rodata;
  env->rodata_gvaddr = FDOS_GPADDR_KERN_RODATA + rodata_gaddr;
  env->rodata_sz     = img_off->phdr_rom.p_filesz;

  ulong text_gaddr = fd_wksp_alloc( env->wksp_kern_code, FD_SHMEM_NORMAL_PAGE_SZ, img_off->phdr_code.p_memsz, 1UL );
  FD_TEST( text_gaddr==FD_SHMEM_NORMAL_PAGE_SZ );
  uchar * text = fd_wksp_laddr_fast( env->wksp_kern_code, text_gaddr );
  fd_memcpy( text, bin + img_off->phdr_code.p_offset, img_off->phdr_code.p_filesz );
  env->text         = text;
  env->text_gvaddr  = FDOS_GPADDR_KERN_CODE + text_gaddr;
  env->text_sz      = img_off->phdr_code.p_filesz;
  env->entry_gvaddr = img_off->ehdr.e_entry;

  ulong data_gaddr = fd_wksp_alloc( env->wksp_kern_data, FD_SHMEM_NORMAL_PAGE_SZ, img_off->phdr_ram.p_memsz, 1UL );
  FD_TEST( data_gaddr==FD_SHMEM_NORMAL_PAGE_SZ );
  uchar * data = fd_wksp_laddr_fast( env->wksp_kern_data, data_gaddr );
  fd_memcpy( data, bin + img_off->phdr_ram.p_offset, img_off->phdr_ram.p_filesz );
  env->data        = data;
  env->data_gvaddr = FDOS_GPADDR_KERN_DATA + data_gaddr;
  env->data_sz     = img_off->phdr_ram.p_filesz;
}
