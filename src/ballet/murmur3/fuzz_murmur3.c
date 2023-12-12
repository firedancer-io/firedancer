#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_murmur3.h"

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

  uint hash1 = fd_murmur3_32( msg, size, 0 );
  uint hash2 = fd_murmur3_32( msg, size, 0 );

  assert( hash1 == hash2 );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
