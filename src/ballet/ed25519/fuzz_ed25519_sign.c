#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_ed25519.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

struct signature_test {
  uchar prv[ 32 ];
  uchar msg[ ];
};
typedef struct signature_test signature_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<32UL ) ) return -1;

  signature_test_t * const test = ( signature_test_t * const ) data;
  ulong sz = size-32UL;

  fd_sha512_t _sha[1];
  fd_sha512_t *sha = fd_sha512_join( fd_sha512_new( _sha ) );

  uchar pub[ 32 ];
  fd_ed25519_public_from_private( pub, test->prv, sha );

  uchar sig[64];
  void * result = fd_ed25519_sign( sig, test->msg, sz, pub, test->prv, sha );
  int cmp = memcmp( ( char * ) sig, ( char * ) result, 64UL );
  if( FD_UNLIKELY( cmp!=0 ) ) {
    __builtin_trap();
  }

  return 0;
}
