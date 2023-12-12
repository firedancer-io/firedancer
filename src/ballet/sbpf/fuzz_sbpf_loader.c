#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "../../util/sanitize/fd_fuzz.h"
#include "fd_sbpf_loader.h"
#include "fd_sbpf_maps.c"

#include <stdlib.h>


uint const _syscalls[] = {
  0xb6fc1a11, 0x686093bb, 0x207559bd, 0x5c2a3178, 0x52ba5096,
  0x7ef088ca, 0x9377323c, 0x48504a38, 0x11f49d86, 0xd7793abb,
  0x17e40350, 0x174c5122, 0xaa2607ca, 0xdd1c41a6, 0xd56b5fe9,
  0x23a29a61, 0x3b97b73c, 0xbf7188f6, 0x717cc4a3, 0x434371f8,
  0x5fdcde31, 0x3770fb22, 0xa22b9c85, 0xd7449092, 0x83f00e8f,
  0xa226d3eb, 0x5d2245e4, 0x7317b434, 0xadb8efc8, 0x85532d94,
  0U
};


int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  fd_sbpf_elf_info_t info;
  if( FD_UNLIKELY( !fd_sbpf_elf_peek( &info, data, size ) ) )
    return -1;

  /* Allocate objects */

  void * rodata = malloc( info.rodata_footprint );
  FD_TEST( rodata );

  fd_sbpf_program_t * prog = fd_sbpf_program_new( aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );
  FD_TEST( prog );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  for( uint const * x = _syscalls; *x; x++ )
    fd_sbpf_syscalls_insert( syscalls, *x );

  /* Load program */
  int res = fd_sbpf_program_load( prog, data, size, syscalls );

  /* Should be able to load at least one program and not load at least one program */
  if ( FD_UNLIKELY( !res ) ) {
    FD_FUZZ_MUST_BE_COVERED;
  } else {
    FD_FUZZ_MUST_BE_COVERED;
  }

  /* Clean up */
  free( rodata );
  free( fd_sbpf_syscalls_delete( syscalls ) );
  free( fd_sbpf_program_delete( prog ) );

  return 0;
}
