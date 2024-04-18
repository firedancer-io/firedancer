#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_secp256k1.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

struct verification_test {
  uchar msg[ 32 ];
  uchar sig[ 64 ];
  uchar pub[ 64 ];
};
typedef struct verification_test verification_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<sizeof(verification_test_t) ) ) return -1;

  verification_test_t * const test = ( verification_test_t * const ) data;
  uchar _pub[ 64 ]; uchar * pub = _pub;

  for ( int recid=0; recid<=3; recid++ ) {
    void * res = fd_secp256k1_recover(pub, test->msg, test->sig, recid);
    if ( FD_UNLIKELY( res != NULL && !memcmp( pub, test->pub, 64UL ) ) ) {
      // was able to verify fuzz input
      __builtin_trap();
    }
  }

  return 0;
}
