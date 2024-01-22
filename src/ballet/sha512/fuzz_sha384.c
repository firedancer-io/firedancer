#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_sha512.h"

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

  uchar hash1[ 48 ] __attribute__((aligned(64)));
  uchar hash2[ 48 ] __attribute__((aligned(64)));

  fd_sha384_t sha[1];
  assert( fd_sha384_init( sha ) == sha );
  assert( fd_sha384_append( sha, msg, size ) == sha );
  assert( fd_sha384_fini( sha, hash1 ) == hash1 );

  assert( fd_sha384_hash( data, size, hash2 ) == hash2 );

  assert( !memcmp( hash1, hash2, 48UL ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
