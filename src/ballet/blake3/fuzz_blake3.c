#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_blake3.h"

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
  // hash single message
  char const * msg = ( char const * ) data;

  uchar hash1[ 32 ] __attribute__((aligned(32)));
  uchar hash2[ 32 ] __attribute__((aligned(32)));

  fd_blake3_t sha[1];
  if( FD_UNLIKELY( fd_blake3_init( sha )!=sha ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_blake3_append( sha, msg, size )!=sha ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_blake3_fini( sha, hash1 )!=hash1 ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( fd_blake3_init( sha )!=sha ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_blake3_append( sha, msg, size )!=sha ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_blake3_fini( sha, hash2 )!=hash2 ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( memcmp( hash1, hash2, 32UL ) ) ) {
    __builtin_trap();
  }

  return 0;
}
