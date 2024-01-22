#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_hmac.h"
#include "../sha256/fd_sha256.h"
#include "../sha512/fd_sha512.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

struct hmac_test {
  ulong key_sz;
  uchar key[ ];
  /* uchar msg[ ]; */
};
typedef struct hmac_test hmac_test_t;

#define KEY_MAX (256UL)

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<64UL ) ) return -1;
  hmac_test_t * const test = ( hmac_test_t * const ) data;

  ulong key_size = test->key_sz & (KEY_MAX-1UL);
  if( FD_UNLIKELY( size<(64UL+key_size) ) ) return -1;
  char const * key = key_size ? ( char const * ) test->key : NULL;

  ulong msg_size = size-(64UL+key_size); 
  char const * msg = msg_size ? ( char const * ) test->key + key_size : NULL;

  uchar hash1[ 64 ] __attribute__((aligned(64)));
  uchar hash2[ 64 ] __attribute__((aligned(64)));

  assert( fd_hmac_sha256( msg, msg_size, key, key_size, hash1 ) == hash1 );
  assert( fd_hmac_sha256( msg, msg_size, key, key_size, hash2 ) == hash2 );
  assert( !memcmp( hash1, hash2, FD_SHA256_HASH_SZ ) );

  assert( fd_hmac_sha384( msg, msg_size, key, key_size, hash1 ) == hash1 );
  assert( fd_hmac_sha384( msg, msg_size, key, key_size, hash2 ) == hash2 );
  assert( !memcmp( hash1, hash2, FD_SHA384_HASH_SZ ) );

  assert( fd_hmac_sha512( msg, msg_size, key, key_size, hash1 ) == hash1 );
  assert( fd_hmac_sha512( msg, msg_size, key, key_size, hash2 ) == hash2 );
  assert( !memcmp( hash1, hash2, FD_SHA512_HASH_SZ ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
