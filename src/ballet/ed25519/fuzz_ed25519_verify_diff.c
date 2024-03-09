#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ed25519.h"

typedef int
(* verify_fn_t)( uchar const * msg,
                 ulong         sz,
                 uchar const * sig,
                 uchar const * pub );

static union {
  verify_fn_t fn;
  void *      ptr;
} verify_fn;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  void * dalek = dlopen( "contrib/ed25519/dalek_target/target/x86_64-unknown-linux-gnu/release/libdalek_target.so", RTLD_LAZY );
  if( FD_UNLIKELY( !dalek ) )
    FD_LOG_CRIT(( "%s", dlerror() ));

  verify_fn.ptr = dlsym( dalek, "ed25519_dalek_verify" );
  if( FD_UNLIKELY( !verify_fn.ptr ) )
    FD_LOG_CRIT(( "%s", dlerror() ));

  return 0;
}

struct verification_test {
  uchar sig[ 64 ];
  uchar pub[ 32 ];
  uchar msg[ ];
};
typedef struct verification_test verification_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<96UL ) ) return -1;

  verification_test_t * const test = ( verification_test_t * const ) data;
  ulong sz = size-96UL;

  fd_sha512_t sha[1];
  int ok0 = fd_ed25519_verify( test->msg, sz, test->sig, test->pub, sha ) == FD_ED25519_SUCCESS;
  int ok1 = verify_fn.fn( test->msg, sz, test->sig, test->pub ) == 1;

  assert( ok0==ok1 );
  return 0;
}
