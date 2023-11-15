#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_sha256.h"

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

  uchar hash1[ FD_SHA256_HASH_SZ ] __attribute__((aligned(32)));
  uchar hash2[ FD_SHA256_HASH_SZ ] __attribute__((aligned(32)));

  fd_sha256_t sha[1];
  assert( fd_sha256_init( sha ) == sha );
  assert( fd_sha256_append( sha, msg, fuzz_sz ) == sha );

  assert( fd_sha256_fini( sha, hash1 ) == hash1 );

  assert( fd_sha256_hash( fuzz_data, fuzz_sz, hash2 ) == hash2 );

  assert( !memcmp( hash1, hash2, FD_SHA256_HASH_SZ ) );

  // batch hashing
  #define BATCH_CNT 32UL /* must be at least 1UL */
  if( fuzz_sz>=BATCH_CNT ) {
    uchar * hash_mem = malloc( FD_SHA256_HASH_SZ * BATCH_CNT );

    fd_sha256_batch_t * batch_sha; //= malloc( sizeof(fd_sha256_batch_t) );
    assert(!posix_memalign( (void**) &batch_sha, 128UL, sizeof(fd_sha256_batch_t) ) );

    assert( fd_sha256_batch_init( batch_sha ) == batch_sha );

    uchar **      hashes    = malloc( BATCH_CNT * sizeof(uchar *) );
    const char ** messages  = malloc( BATCH_CNT * sizeof(const char *) );
    ulong *       msg_sizes = malloc( BATCH_CNT * sizeof(ulong) );

    ulong entry_sz = fuzz_sz/BATCH_CNT;
    for( ulong batch_idx=0UL; batch_idx<BATCH_CNT; batch_idx++ ) {
      hashes   [ batch_idx ] = hash_mem + BATCH_CNT*batch_idx;
      messages [ batch_idx ] = ( char const *) fuzz_data + entry_sz*batch_idx;
      msg_sizes[ batch_idx ] = batch_idx<BATCH_CNT-1UL ? entry_sz : entry_sz+fuzz_sz%BATCH_CNT;
      assert( fd_sha256_batch_add( batch_sha, messages[ batch_idx ], msg_sizes[ batch_idx ], hashes[ batch_idx ] ) == batch_sha );
    }

    assert( fd_sha256_batch_fini( batch_sha ) == batch_sha );

    for( ulong batch_idx=0UL; batch_idx<BATCH_CNT; batch_idx++ ) {
      uchar * ref_hash = malloc( FD_SHA256_HASH_SZ );
      assert( !memcmp( fd_sha256_hash( messages[ batch_idx ], msg_sizes[ batch_idx ], ref_hash ), hashes[ batch_idx ], FD_SHA256_HASH_SZ ) );
      free( ref_hash );
    }
    free(msg_sizes);
    free(messages);
    free(hashes);
    free(batch_sha);
    free(hash_mem);
  }

  return 0;
}
