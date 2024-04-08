#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_base58.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

/* touch reads every byte in the given memory region.  This is done to
   allow ASan to crash the program if uninitialized data is given to
   this function. */

static void __attribute__((noinline))
touch( void * in,
       ulong  in_sz ) {
  uchar * _in = in;
  ulong   x   = 0UL;
  for( ulong i=0UL; i<in_sz; i++ ) {
    x ^= _in[i];
  }
  FD_COMPILER_UNPREDICTABLE( x );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  /* Input must be a cstr */
  char * cstr = malloc( data_sz+1UL );
  FD_TEST( cstr );
  memcpy( cstr, data, data_sz );
  cstr[ data_sz ]='\0';

  do {
    uchar out[32];
    if( fd_base58_decode_32( cstr, out ) ) {
      FD_FUZZ_MUST_BE_COVERED;
      touch( out, sizeof(out) );
    }
  } while(0);

  do {
    uchar out[64];
    if( fd_base58_decode_64( cstr, out ) ) {
      FD_FUZZ_MUST_BE_COVERED;
      touch( out, sizeof(out) );
    }
  } while(0);

  free( cstr );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
