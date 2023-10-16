#include "../fd_ballet.h"
#include "fd_sha512_test_vector.c"

#ifdef HAS_CAVP_TEST_VECTORS
#include "cavp/sha512_short.inc"
#include "cavp/sha512_long.inc"
#endif

FD_STATIC_ASSERT( FD_SHA512_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_SHA512_FOOTPRINT==256UL, unit_test );

FD_STATIC_ASSERT( FD_SHA512_ALIGN    ==alignof(fd_sha512_t), unit_test );
FD_STATIC_ASSERT( FD_SHA512_FOOTPRINT==sizeof (fd_sha512_t), unit_test );

FD_STATIC_ASSERT( FD_SHA512_LG_HASH_SZ==6, unit_test );
FD_STATIC_ASSERT( FD_SHA512_HASH_SZ==64UL, unit_test );

static void
test_sha512_vectors( fd_sha512_test_vector_t const * vec,
                     fd_sha512_t *                   sha,
                     fd_rng_t *                      rng ) {
  uchar hash[ 64 ] __attribute__((aligned(64)));

  for( ; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uchar const * expected = vec->hash;

    /* test single shot hashing */

    FD_TEST( fd_sha512_init( sha )==sha );
    FD_TEST( fd_sha512_append( sha, msg, sz )==sha );
    FD_TEST( fd_sha512_fini( sha, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA512_HASH_SZ ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ), FD_LOG_HEX16_FMT_ARGS(     hash+48 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ), FD_LOG_HEX16_FMT_ARGS( expected+48 ) ));

    /* test incremental hashing */

    memset( hash, 0, 64UL );
    FD_TEST( fd_sha512_init( sha )==sha );

    char const * nxt = msg;
    ulong        rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      FD_TEST( fd_sha512_append( sha, nxt, nxt_sz )==sha );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_sha512_append( sha, NULL, 0UL )==sha ); /* test zero append too */
    }

    FD_TEST( fd_sha512_fini( sha, hash )==hash );

    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA512_HASH_SZ ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ), FD_LOG_HEX16_FMT_ARGS(     hash+48 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ), FD_LOG_HEX16_FMT_ARGS( expected+48 ) ));

    /* test streamlined hashing */

    FD_TEST( fd_sha512_hash( msg, sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA512_HASH_SZ ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ), FD_LOG_HEX16_FMT_ARGS(     hash+48 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ), FD_LOG_HEX16_FMT_ARGS( expected+48 ) ));
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_sha512_align    ()==FD_SHA512_ALIGN     );
  FD_TEST( fd_sha512_footprint()==FD_SHA512_FOOTPRINT );

  fd_sha512_t   mem[1];

  FD_TEST( fd_sha512_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_sha512_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_sha512_new( mem ); FD_TEST( obj );

  FD_TEST( fd_sha512_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_sha512_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_sha512_t * sha = fd_sha512_join( obj ); FD_TEST( sha );

  /* Test random vectors */
  test_sha512_vectors( fd_sha512_test_vector, sha, rng );
  FD_LOG_NOTICE(( "OK: Random vectors" ));

  /* Test batching */

  FD_TEST( fd_ulong_is_pow2( FD_SHA512_BATCH_ALIGN )                                              );
  FD_TEST( (FD_SHA512_BATCH_FOOTPRINT>0UL) & !(FD_SHA512_BATCH_FOOTPRINT % FD_SHA512_BATCH_ALIGN) );

  FD_TEST( fd_sha512_batch_align()    ==FD_SHA512_BATCH_ALIGN     );
  FD_TEST( fd_sha512_batch_footprint()==FD_SHA512_BATCH_FOOTPRINT );

# define BATCH_MAX (16UL)
# define DATA_MAX  (512UL)
  uchar data_mem[ DATA_MAX       ]; for( ulong idx=0UL; idx<DATA_MAX; idx++ ) data_mem[ idx ] = fd_rng_uchar( rng );
  uchar hash_mem[ 64UL*BATCH_MAX ];

  uchar batch_mem[ FD_SHA512_BATCH_FOOTPRINT ] __attribute__((aligned(FD_SHA512_BATCH_ALIGN)));
  for( ulong trial_rem=131072UL; trial_rem; trial_rem-- ) {
    uchar const * data[ BATCH_MAX ];
    ulong         sz  [ BATCH_MAX ];
    uchar *       hash[ BATCH_MAX ];

    fd_sha512_batch_t * batch = fd_sha512_batch_init( batch_mem ); FD_TEST( batch );

    int   batch_abort = !(fd_rng_ulong( rng ) & 31UL);
    ulong batch_cnt   = fd_rng_ulong( rng ) & (BATCH_MAX-1UL);
    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
      ulong off0 = fd_rng_ulong( rng ) & (DATA_MAX-1UL);
      ulong off1 = fd_rng_ulong( rng ) & (DATA_MAX-1UL);
      data[ batch_idx ] = data_mem + fd_ulong_min( off0, off1 );
      sz  [ batch_idx ] = fd_ulong_max( off0, off1 ) - fd_ulong_min( off0, off1 );
      hash[ batch_idx ] = hash_mem + batch_idx*64UL;
      FD_TEST( fd_sha512_batch_add( batch, data[ batch_idx ], sz[ batch_idx ], hash[ batch_idx ] )==batch );
    }

    if( FD_UNLIKELY( batch_abort ) ) FD_TEST( fd_sha512_batch_abort( batch )==(void *)batch_mem );
    else {
      FD_TEST( fd_sha512_batch_fini( batch )==(void *)batch_mem );
      for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
        uchar ref_hash[ 64 ];
        FD_TEST( !memcmp( fd_sha512_hash( data[ batch_idx ], sz[ batch_idx ], ref_hash ), hash[ batch_idx ], 64UL ) );
      }
    }
  }
# undef DATA_MAX
# undef BATCH_MAX

# ifdef HAS_CAVP_TEST_VECTORS
  /* Test NIST CAVP message fixtures */
  test_sha512_vectors( cavp_sha512_short, sha, rng );
  FD_LOG_NOTICE(( "OK: CAVP SHA512ShortMsg.rsp" ));
  test_sha512_vectors( cavp_sha512_long,  sha, rng );
  FD_LOG_NOTICE(( "OK: CAVP SHA512LongMsg.rsp" ));
# endif

  /* do a quick benchmark of sha-512 on small and large UDP payloads
     packets from UDP/IP4/VLAN/Ethernet */

  static ulong const bench_sz[2] = { 14UL, 1472UL };

  uchar hash[   64 ] __attribute__((aligned(64)));
  uchar buf [ 1472 ] __attribute__((aligned(128)));
  for( ulong b=0UL; b<1472UL; b++ ) buf[b] = fd_rng_uchar( rng );

  FD_LOG_NOTICE(( "Benchmarking incremental (best case)" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_sha512_fini( fd_sha512_append( fd_sha512_init( sha ), buf, sz ), hash );

    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_sha512_fini( fd_sha512_append( fd_sha512_init( sha ), buf, sz ), hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking streamlined" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_sha512_hash( buf, sz, hash );

    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_sha512_hash( buf, sz, hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking batched" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];
    for( ulong batch_cnt=1UL; batch_cnt<=24UL; batch_cnt++ ) {

      /* warmup */
      for( ulong rem=10UL; rem; rem-- ) {
        fd_sha512_batch_t * batch = fd_sha512_batch_init( batch_mem );
        for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) fd_sha512_batch_add( batch, buf, sz, hash );
        fd_sha512_batch_fini( batch );
      }

      /* for real */
      ulong iter = 10000UL;
      long  dt   = -fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) {
        fd_sha512_batch_t * batch = fd_sha512_batch_init( batch_mem );
        for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) fd_sha512_batch_add( batch, buf, sz, hash );
        fd_sha512_batch_fini( batch );
      }
      dt += fd_log_wallclock();
      float gbps = ((float)(batch_cnt*8UL*(70UL+sz)*iter)) / ((float)dt);
      FD_LOG_NOTICE(( "~%6.3f Gbps Ethernet equiv throughput / core (batch_cnt %2lu sz %4lu)", (double)gbps, batch_cnt, sz ));
    }
  }

  /* Test large hash input

     $ head --bytes 4294967311 /dev/zero | openssl dgst -sha512
     441ae9ca417cc3114e5dde106fc1a91fb6e6090a1c356434a6939b6759b1a39ecc2045e455f0047246534857fac020e8a7e825c55ee3b287d84d3b38ea31e33a */

# define INPUT_SZ (4294967311UL) /* prime larger than 2^32 */
# define CHUNK_SZ (4096UL)
  uchar chunk[ CHUNK_SZ ] __attribute__((aligned(64)));
  fd_memset( chunk, 0, CHUNK_SZ );

  fd_sha512_init( sha );
  ulong left_sz;
  for( left_sz=INPUT_SZ; left_sz>=CHUNK_SZ; left_sz-=CHUNK_SZ )
    fd_sha512_append( sha, chunk, CHUNK_SZ );
  fd_sha512_append( sha, chunk, left_sz );
  fd_sha512_fini( sha, hash );
  FD_TEST( 0==memcmp( hash,
                      "\x44\x1a\xe9\xca\x41\x7c\xc3\x11\x4e\x5d\xde\x10\x6f\xc1\xa9\x1f"
                      "\xb6\xe6\x09\x0a\x1c\x35\x64\x34\xa6\x93\x9b\x67\x59\xb1\xa3\x9e"
                      "\xcc\x20\x45\xe4\x55\xf0\x04\x72\x46\x53\x48\x57\xfa\xc0\x20\xe8"
                      "\xa7\xe8\x25\xc5\x5e\xe3\xb2\x87\xd8\x4d\x3b\x38\xea\x31\xe3\x3a",
                      64UL ) );
# undef CHUNK_SZ
# undef INPUT_SZ

  /* clean up */

  FD_TEST( fd_sha512_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_sha512_leave( sha  )==obj  ); /* ok */

  FD_TEST( fd_sha512_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_sha512_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_sha512_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
