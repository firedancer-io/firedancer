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
  // TODO: boilerplate
  fd_valloc_t valloc = fd_scratch_virtual();
  fd_sbpf_elf_info_t info;

  fd_sbpf_elf_peek( &info, duplicate_entrypoint_entry_elf, duplicate_entrypoint_entry_elf_sz );

  void* rodata = fd_valloc_malloc( valloc, 8UL, info.rodata_footprint );
  FD_TEST( rodata );

  

  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( valloc, fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ));
  for( uint const * x = _syscalls; *x; x++ )
      fd_sbpf_syscalls_insert( syscalls, *x );
  
  int res = fd_sbpf_program_load( prog, duplicate_entrypoint_entry_elf, duplicate_entrypoint_entry_elf_sz, syscalls );
  FD_TEST( res == 0 );

  // end of boilerplate

  FD_TEST( fd_sbpf_calldests_test( prog->calldests, 595 ) == 0 ); 
  FD_TEST( fd_sbpf_calldests_test( prog->calldests, 3920 ) == 1 );

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

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
