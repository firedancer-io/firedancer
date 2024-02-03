#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_sha512.h"

#define BATCH_CNT 32UL /* must be at least 1UL */

static fd_sha512_batch_t batch_sha[1];
static uchar             hash1    [ FD_SHA512_HASH_SZ ];
static uchar             hash2    [ FD_SHA512_HASH_SZ ];
static uchar             ref_hash [ FD_SHA512_HASH_SZ ];
static uchar             hash_mem [ FD_SHA512_HASH_SZ * BATCH_CNT ];
static uchar *           hashes   [ BATCH_CNT ];
static char const *      messages [ BATCH_CNT ];
static ulong             msg_sizes[ BATCH_CNT ];

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
LLVMFuzzerTestOneInput( uchar const * fuzz_data,
                        ulong         fuzz_sz ) {
  // hash single message
  char const * msg = ( char const * ) fuzz_data;

  fd_sha512_t sha[1];
  assert( fd_sha512_init( sha ) == sha );
  assert( fd_sha512_append( sha, msg, fuzz_sz ) == sha );
  assert( fd_sha512_fini( sha, hash1 ) == hash1 );
  assert( fd_sha512_hash( fuzz_data, fuzz_sz, hash2 ) == hash2 );
  assert( !memcmp( hash1, hash2, FD_SHA512_HASH_SZ ) );

  // batch hashing
  if( fuzz_sz>=BATCH_CNT ) {
    FD_FUZZ_MUST_BE_COVERED;

    assert( fd_sha512_batch_init( batch_sha ) == batch_sha );

    ulong entry_sz = fuzz_sz/BATCH_CNT;
    for( ulong batch_idx=0UL; batch_idx<BATCH_CNT; batch_idx++ ) {
      FD_FUZZ_MUST_BE_COVERED;
      hashes   [ batch_idx ] = hash_mem + FD_SHA512_HASH_SZ*batch_idx;
      messages [ batch_idx ] = (char const *) fuzz_data + entry_sz*batch_idx;
      msg_sizes[ batch_idx ] = batch_idx<BATCH_CNT-1UL ? entry_sz : entry_sz+fuzz_sz%BATCH_CNT;
      assert( fd_sha512_batch_add( batch_sha, messages[ batch_idx ], msg_sizes[ batch_idx ], hashes[ batch_idx ] ) == batch_sha );
    }

    assert( fd_sha512_batch_fini( batch_sha ) == batch_sha );

    for( ulong batch_idx=0UL; batch_idx<BATCH_CNT; batch_idx++ ) {
      FD_FUZZ_MUST_BE_COVERED;
      assert( !memcmp( fd_sha512_hash( messages[ batch_idx ], msg_sizes[ batch_idx ], ref_hash ), hashes[ batch_idx ], FD_SHA512_HASH_SZ ) );
    }
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
