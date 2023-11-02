#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

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
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  // hash single message
  char const * msg = ( char const * ) data;

  uchar hash1[ 32 ] __attribute__((aligned(32)));
  uchar hash2[ 32 ] __attribute__((aligned(32)));

  fd_sha256_t sha[1];
  if( FD_UNLIKELY( fd_sha256_init( sha )!=sha ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_sha256_append( sha, msg, size )!=sha ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_sha256_fini( sha, hash1 )!=hash1 ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( fd_sha256_hash( data, size, hash2 )!=hash2 ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( memcmp( hash1, hash2, 32UL ) ) ) {
    __builtin_trap();
  }

  // batch hashing
  #define BATCH_CNT 32UL /* must be at least 1UL */
  if( size>=BATCH_CNT ) {
    uchar hash_mem[ 32UL*BATCH_CNT ] __attribute__((aligned(32)));

    fd_sha256_batch_t batch_sha[1];
    if( FD_UNLIKELY( fd_sha256_batch_init( batch_sha )!=batch_sha ) ) {
      __builtin_trap();
    }

    uchar *      hashes   [ BATCH_CNT ];
    const char * messages [ BATCH_CNT ];
    ulong        msg_sizes[ BATCH_CNT ];

    ulong sz = size/BATCH_CNT;
    for( ulong batch_idx=0UL; batch_idx<BATCH_CNT; batch_idx++ ) {
      hashes   [ batch_idx ] = hash_mem + sz*batch_idx;
      messages [ batch_idx ] = ( char const *) data + sz*batch_idx;
      msg_sizes[ batch_idx ] = batch_idx<BATCH_CNT-1UL ? sz : sz+size%BATCH_CNT;
      if( FD_UNLIKELY( fd_sha256_batch_add( batch_sha, messages[ batch_idx ], msg_sizes[ batch_idx ], hashes[ batch_idx ] )!=batch_sha ) ) {
        __builtin_trap();
      }
    }

    if( FD_UNLIKELY( fd_sha256_batch_fini( batch_sha )==batch_sha ) ) {
      __builtin_trap();
    }

    for( ulong batch_idx=0UL; batch_idx<BATCH_CNT; batch_idx++ ) {
      uchar ref_hash[ 32 ] __attribute__((aligned(32)));
      if( FD_UNLIKELY( memcmp( fd_sha256_hash( messages[ batch_idx ], msg_sizes[ batch_idx ], ref_hash ), hashes[ batch_idx ], 32UL ) ) ) {
        __builtin_trap();
      }
    }
  }

  return 0;
}
