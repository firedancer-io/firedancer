#include "../fd_ballet.h"

FD_STATIC_ASSERT( FD_SHA384_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_SHA384_FOOTPRINT==256UL, unit_test );

FD_STATIC_ASSERT( FD_SHA384_ALIGN    ==alignof(fd_sha384_t), unit_test );
FD_STATIC_ASSERT( FD_SHA384_FOOTPRINT==sizeof (fd_sha384_t), unit_test );

FD_STATIC_ASSERT( FD_SHA384_HASH_SZ==48UL, unit_test );

#ifdef HAS_CAVP_TEST_VECTORS
struct fd_sha384_test_vector {
  char const * msg;
  ulong        sz;
  uchar        hash[ FD_SHA384_HASH_SZ ];
};

typedef struct fd_sha384_test_vector fd_sha384_test_vector_t;

#include "cavp/sha384_short.inc"
#include "cavp/sha384_long.inc"

FD_STATIC_ASSERT( FD_SHA384_HASH_SZ==48UL, unit_test );
static void
test_sha384_vectors( fd_sha384_test_vector_t const * vec,
                     fd_sha384_t *                   sha,
                     fd_rng_t *                      rng ) {
  uchar hash[ FD_SHA384_HASH_SZ ] __attribute__((aligned(64)));

  for( ; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uchar const * expected = vec->hash;

    /* test single shot hashing */

    FD_TEST( fd_sha384_init( sha )==sha );
    FD_TEST( fd_sha384_append( sha, msg, sz )==sha );
    FD_TEST( fd_sha384_fini( sha, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA384_HASH_SZ ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ),
                   FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ) ));

    /* test incremental hashing */

    memset( hash, 0, FD_SHA384_HASH_SZ );
    FD_TEST( fd_sha384_init( sha )==sha );

    char const * nxt = msg;
    ulong        rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      FD_TEST( fd_sha384_append( sha, nxt, nxt_sz )==sha );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_sha384_append( sha, NULL, 0UL )==sha ); /* test zero append too */
    }

    FD_TEST( fd_sha384_fini( sha, hash )==hash );

    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA384_HASH_SZ ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ),
                   FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ) ));

    /* test streamlined hashing */

    FD_TEST( fd_sha384_hash( msg, sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA384_HASH_SZ ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ),
                   FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ) ));
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_sha384_align    ()==FD_SHA384_ALIGN     );
  FD_TEST( fd_sha384_footprint()==FD_SHA384_FOOTPRINT );

  fd_sha384_t   mem[1];

  FD_TEST( fd_sha384_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_sha384_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_sha384_new( mem ); FD_TEST( obj );

  FD_TEST( fd_sha384_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_sha384_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_sha384_t * sha = fd_sha384_join( obj ); FD_TEST( sha );

  /* Test NIST CAVP message fixtures */
  test_sha384_vectors( cavp_sha384_short, sha, rng );
  FD_LOG_NOTICE(( "OK: CAVP SHA384ShortMsg.rsp" ));
  test_sha384_vectors( cavp_sha384_long,  sha, rng );
  FD_LOG_NOTICE(( "OK: CAVP SHA384LongMsg.rsp" ));

  /* clean up */

  FD_TEST( fd_sha384_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_sha384_leave( sha  )==obj  ); /* ok */

  FD_TEST( fd_sha384_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_sha384_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_sha384_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else /* HAS_CAVP_TEST_VECTORS */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires HAS_CAVP_TEST_VECTORS" ));
  fd_halt();
  return 0;
}

#endif /* HAS_CAVP_TEST_VECTORS */
