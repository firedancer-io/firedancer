#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ed25519.h"

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

struct verification_test {
  uchar sig[ 64 ];
  uchar pub[ 32 ];
  uchar msg[ ];
};
typedef struct verification_test verification_test_t;

/* This fuzzer tries to verify random data */

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<96UL ) ) return -1;

  verification_test_t * const test = ( verification_test_t * const ) data;
  ulong sz = size-96UL;

  fd_sha512_t _sha[1];
  fd_sha512_t *sha = fd_sha512_join( fd_sha512_new( _sha ) );

  int result = fd_ed25519_verify( test->msg, sz, test->sig, test->pub, sha );
  assert( result != FD_ED25519_SUCCESS );

  /* The cached verify must agree, cold and warm */
  static uchar __attribute__((aligned(FD_ED25519_CACHE_ALIGN))) cache_mem[ 1UL<<20 ];
  static fd_ed25519_cache_t * cache = NULL;
  if( FD_UNLIKELY( !cache ) ) {
    assert( fd_ed25519_cache_footprint( 64UL )<=sizeof(cache_mem) );
    cache = fd_ed25519_cache_join( fd_ed25519_cache_new( cache_mem, 64UL, 0UL ) );
  }
  for( ulong i=0UL; i<3UL; i++ ) assert( fd_ed25519_verify_cached( test->msg, sz, test->sig, test->pub, sha, cache )==result );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
