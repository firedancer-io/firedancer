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
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

struct recover_test {
  uchar msg[ 32 ];
  uchar sig[ 64 ];
};
typedef struct recover_test recover_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<sizeof(recover_test_t) ) ) return -1;

  recover_test_t const * test = (recover_test_t const *)data;
  uchar pub[ 64 ];

  for( int recid=0; recid<=3; recid++ ) {
    fd_secp256k1_recover( pub, test->msg, test->sig, recid );
  }

  return 0;
}
