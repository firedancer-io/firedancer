#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
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

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size < 64UL ) ) return -1;

  #define MAKE_FUZZ_TEST(n)                                                                 \
  ulong len##n;                                                                             \
  char  enc##n        [ FD_BASE58_ENCODED_##n##_SZ ];                                       \
  char  enc##n##_nolen[ FD_BASE58_ENCODED_##n##_SZ ];                                       \
  uchar dec##n        [ n ];                                                                \
  assert( fd_base58_encode_##n( data, &len##n, enc##n ) == enc##n );                        \
  assert( strlen( enc##n ) == len##n );                                                     \
  assert( len##n>=n##UL && len##n <= FD_BASE58_ENCODED_##n##_LEN );                          \
  assert( fd_base58_decode_##n( enc##n, dec##n ) == dec##n );                               \
  assert( !memcmp( dec##n, data, n##UL ) );                                                 \
  assert( fd_base58_encode_##n( data, NULL, enc##n##_nolen ) == enc##n##_nolen );           \
  assert( !strcmp( enc##n##_nolen, enc##n ) );

  MAKE_FUZZ_TEST(32)
  MAKE_FUZZ_TEST(64)
  #undef MAKE_FUZZ_TEST

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
