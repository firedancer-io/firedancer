#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

uint const _syscalls[] = {
  0xb6fc1a11, 0x686093bb, 0x207559bd, 0x5c2a3178, 0x52ba5096,
  0x7ef088ca, 0x9377323c, 0x48504a38, 0x11f49d86, 0xd7793abb,
  0x17e40350, 0x174c5122, 0xaa2607ca, 0xdd1c41a6, 0xd56b5fe9,
  0x23a29a61, 0x3b97b73c, 0xbf7188f6, 0x717cc4a3, 0x434371f8,
  0x5fdcde31, 0x3770fb22, 0xa22b9c85, 0xd7449092, 0x83f00e8f,
  0xa226d3eb, 0x5d2245e4, 0x7317b434, 0xadb8efc8, 0x85532d94,
  0U
};

#define LOAD_ELF(id) \
  FD_IMPORT_BINARY( id##_elf, "src/ballet/sbpf/fixtures/" #id ".elf" );

LOAD_ELF( duplicate_entrypoint_entry )
LOAD_ELF( zero_text_cnt )

/* Properties of duplicate_entrypoint_entry.elf we are testing:
  * Two symbol entries with the "entrypoint" as st_name:
    Num:    Value          Size Type    Bind   Vis      Ndx Name
    21: 0000000000001380  1264 FUNC    GLOBAL DEFAULT    1 entrypoint
    30: 0000000000007b68  1392 FUNC    GLOBAL DEFAULT    1 entrypoint

    - Second entry is the actual entrypoint
    - First entry is a bad dynsym entry
    - First entry would be PC 595
    - This entry should not be registered in calldests
    - So in a call to fd_sbpf_calldests_test( prog->calldests, 595 ), we should get 0

  * Entrypoint is not referenced in text section or relocation table
    - Yet it must be in calldests, since we register it by default
    - So in a call to fd_sbpf_calldests_test( prog->calldests, 3920 ), we should still get 1

*/

void test_duplicate_entrypoint_entry( void ) {
  fd_scratch_push();
  fd_sbpf_elf_info_t info;

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 1;
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  fd_sbpf_elf_peek( &info, duplicate_entrypoint_entry_elf, duplicate_entrypoint_entry_elf_sz, &config );

  void * rodata = fd_scratch_alloc( FD_SBPF_PROG_RODATA_ALIGN, info.bin_sz );
  FD_TEST( rodata );

  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_scratch_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );

  for( uint const * x = _syscalls; *x; x++ )
      fd_sbpf_syscalls_insert( syscalls, (ulong)*x );

  void * scratch = fd_scratch_alloc( 1UL, duplicate_entrypoint_entry_elf_sz );
  int res = fd_sbpf_program_load( prog, duplicate_entrypoint_entry_elf, duplicate_entrypoint_entry_elf_sz, syscalls, &config, scratch, duplicate_entrypoint_entry_elf_sz );

  FD_TEST( res == 0 );
  FD_TEST( fd_sbpf_calldests_test( prog->calldests, 595UL )==0 );
  FD_TEST( fd_sbpf_calldests_test( prog->calldests, 3920UL )==0 );
  FD_TEST( prog->entry_pc==3920UL );
}

void test_zero_text_cnt( void ) {
  fd_scratch_push();
  fd_sbpf_elf_info_t info;

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 0;
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  fd_sbpf_elf_peek( &info, zero_text_cnt_elf, zero_text_cnt_elf_sz, &config );

  void * rodata = fd_scratch_alloc( FD_SBPF_PROG_RODATA_ALIGN, info.bin_sz );
  FD_TEST( rodata );

  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_scratch_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );

  for( uint const * x = _syscalls; *x; x++ )
      fd_sbpf_syscalls_insert( syscalls, (ulong)*x );

  void * scratch = fd_scratch_alloc( 1UL, zero_text_cnt_elf_sz );
  int res = fd_sbpf_program_load( prog, zero_text_cnt_elf, zero_text_cnt_elf_sz, syscalls, &config, scratch, zero_text_cnt_elf_sz );

  FD_TEST( res == 0 );
  FD_TEST( prog->entry_pc==0UL );
}

/* .text at an odd sh_addr.  The lenient path takes text_off straight
   from sh_addr, so prog->text lands misaligned; Agave accepts these,
   so this must load. */

#define TEXT_ADDR (321UL)  /* == sh_offset, deliberately odd */
#define TEXT_SZ    (16UL)  /* mov64 r0, 1 ; exit */
#define SHOFF     (128UL)
#define SHSTRTAB  "\0.text\0.shstrtab"

static ulong
build_unaligned_text_elf( uchar bin[ 512 ] ) {
  ulong shstrtab_off = TEXT_ADDR + TEXT_SZ;
  fd_memset( bin, 0, 512UL );

  fd_elf64_ehdr ehdr = {
    .e_ident     = { 0x7f, 'E', 'L', 'F', FD_ELF_CLASS_64, FD_ELF_DATA_LE, 1, FD_ELF_OSABI_NONE },
    .e_type      = FD_ELF_ET_DYN,
    .e_machine   = FD_ELF_EM_BPF,
    .e_version   = 1,
    .e_entry     = TEXT_ADDR,
    .e_shoff     = SHOFF,
    .e_flags     = FD_SBPF_V0,
    .e_ehsize    = sizeof(fd_elf64_ehdr),
    .e_phentsize = sizeof(fd_elf64_phdr),
    .e_shentsize = sizeof(fd_elf64_shdr),
    .e_shnum     = 3,
    .e_shstrndx  = 2
  };
  fd_elf64_shdr shdr[3] = {
    { 0 },
    { .sh_name = 1U, .sh_type = FD_ELF_SHT_PROGBITS,           /* .text */
      .sh_flags = FD_ELF_SHF_ALLOC | FD_ELF_SHF_EXECINSTR,
      .sh_addr = TEXT_ADDR, .sh_offset = TEXT_ADDR, .sh_size = TEXT_SZ, .sh_addralign = 1UL },
    { .sh_name = 7U, .sh_type = FD_ELF_SHT_STRTAB,             /* .shstrtab */
      .sh_offset = shstrtab_off, .sh_size = sizeof(SHSTRTAB), .sh_addralign = 1UL }
  };
  uchar const text[ TEXT_SZ ] = {
    0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  /* mov64 r0, 1 */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   /* exit        */
  };

  fd_memcpy( bin,                   &ehdr, sizeof(ehdr)     );
  fd_memcpy( bin + SHOFF,            shdr, sizeof(shdr)     );
  fd_memcpy( bin + TEXT_ADDR,        text, sizeof(text)     );
  fd_memcpy( bin + shstrtab_off, SHSTRTAB, sizeof(SHSTRTAB) );

  return shstrtab_off + sizeof(SHSTRTAB);
}

void test_unaligned_text( void ) {
  fd_scratch_push();
  fd_sbpf_elf_info_t info;

  uchar bin[ 512 ];
  ulong bin_sz = build_unaligned_text_elf( bin );

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 1;
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  FD_TEST( fd_sbpf_elf_peek( &info, bin, bin_sz, &config )==FD_SBPF_ELF_SUCCESS );
  FD_TEST( info.text_off==TEXT_ADDR );

  void * rodata = fd_scratch_alloc( FD_SBPF_PROG_RODATA_ALIGN, info.bin_sz );
  FD_TEST( rodata );

  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_scratch_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );

  void * scratch = fd_scratch_alloc( 1UL, bin_sz );
  int res = fd_sbpf_program_load( prog, bin, bin_sz, syscalls, &config, scratch, bin_sz );

  FD_TEST( res == 0 );
  FD_TEST( prog->entry_pc==0UL );
  FD_TEST( !fd_ulong_is_aligned( (ulong)prog->text, 8UL ) );
}

int
main(   int argc,
        char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<25 ];  /* 32MB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<25, 4UL );

  // testing here
  test_duplicate_entrypoint_entry();
  test_zero_text_cnt();
  test_unaligned_text();

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
