#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
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

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size < 64UL ) ) return -1;

  #define MAKE_FUZZ_TEST(n)                                                           \
  uchar dec##n[ n ];                                                                  \
  if( FD_UNLIKELY( fd_base58_decode_##n( ( char const * ) data, dec##n )!=NULL ) ) {  \
    __builtin_trap();                                                                 \
  }

  MAKE_FUZZ_TEST(32)
  MAKE_FUZZ_TEST(64)
  #undef MAKE_FUZZ_TEST

  return 0;
}
