#include "../fd_ballet.h"
#include "fd_sha256_test_vector.c"

FD_STATIC_ASSERT( FD_SHA256_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_SHA256_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_SHA256_ALIGN    ==alignof(fd_sha256_t), unit_test );
FD_STATIC_ASSERT( FD_SHA256_FOOTPRINT==sizeof (fd_sha256_t), unit_test );

FD_STATIC_ASSERT( FD_SHA256_LG_HASH_SZ==5,    unit_test );
FD_STATIC_ASSERT( FD_SHA256_HASH_SZ   ==32UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_sha256_align    ()==FD_SHA256_ALIGN     );
  FD_TEST( fd_sha256_footprint()==FD_SHA256_FOOTPRINT );

  fd_sha256_t mem[1];

  FD_TEST( fd_sha256_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_sha256_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_sha256_new( mem ); FD_TEST( obj );

  FD_TEST( fd_sha256_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_sha256_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_sha256_t * sha = fd_sha256_join( obj ); FD_TEST( sha );

  uchar hash[ 32 ] __attribute__((aligned(32)));

  for( fd_sha256_test_vector_t const * vec = fd_sha256_test_vector; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uchar const * expected = vec->hash;

    /* test single shot hashing */

    FD_TEST( fd_sha256_init( sha )==sha );
    FD_TEST( fd_sha256_append( sha, msg, sz )==sha );
    FD_TEST( fd_sha256_fini( sha, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

    /* test incremental hashing */

    memset( hash, 0, 32UL );
    FD_TEST( fd_sha256_init( sha )==sha );

    char const * nxt = msg;
    ulong        rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      FD_TEST( fd_sha256_append( sha, nxt, nxt_sz )==sha );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_sha256_append( sha, NULL, 0UL )==sha ); /* test zero append too */
    }

    FD_TEST( fd_sha256_fini( sha, hash )==hash );

    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

    /* test streamlined hashing */

    FD_TEST( fd_sha256_hash( msg, sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
  }

  /* Test batching */

  FD_TEST( fd_ulong_is_pow2( FD_SHA256_BATCH_ALIGN )                                              );
  FD_TEST( (FD_SHA256_BATCH_FOOTPRINT>0UL) & !(FD_SHA256_BATCH_FOOTPRINT % FD_SHA256_BATCH_ALIGN) );

  FD_TEST( fd_sha256_batch_align()    ==FD_SHA256_BATCH_ALIGN     );
  FD_TEST( fd_sha256_batch_footprint()==FD_SHA256_BATCH_FOOTPRINT );

# define BATCH_MAX (32UL)
# define DATA_MAX  (256UL)
  uchar data_mem[ DATA_MAX       ]; for( ulong idx=0UL; idx<DATA_MAX; idx++ ) data_mem[ idx ] = fd_rng_uchar( rng );
  uchar hash_mem[ 32UL*BATCH_MAX ];

  uchar batch_mem[ FD_SHA256_BATCH_FOOTPRINT ] __attribute__((aligned(FD_SHA256_BATCH_ALIGN)));
  for( ulong trial_rem=262144UL; trial_rem; trial_rem-- ) {
    uchar const * data[ BATCH_MAX ];
    ulong         sz  [ BATCH_MAX ];
    uchar *       hash[ BATCH_MAX ];

    fd_sha256_batch_t * batch = fd_sha256_batch_init( batch_mem ); FD_TEST( batch );

    int   batch_abort = !(fd_rng_ulong( rng ) & 31UL);
    ulong batch_cnt   = fd_rng_ulong( rng ) & (BATCH_MAX-1UL);
    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
      ulong off0 = fd_rng_ulong( rng ) & (DATA_MAX-1UL);
      ulong off1 = fd_rng_ulong( rng ) & (DATA_MAX-1UL);
      data[ batch_idx ] = data_mem + fd_ulong_min( off0, off1 );
      sz  [ batch_idx ] = fd_ulong_max( off0, off1 ) - fd_ulong_min( off0, off1 );
      hash[ batch_idx ] = hash_mem + batch_idx*32UL;
      FD_TEST( fd_sha256_batch_add( batch, data[ batch_idx ], sz[ batch_idx ], hash[ batch_idx ] )==batch );
    }

    if( FD_UNLIKELY( batch_abort ) ) FD_TEST( fd_sha256_batch_abort( batch )==(void *)batch_mem );
    else {
      FD_TEST( fd_sha256_batch_fini( batch )==(void *)batch_mem );
      for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
        uchar ref_hash[ 32 ];
        FD_TEST( !memcmp( fd_sha256_hash( data[ batch_idx ], sz[ batch_idx ], ref_hash ), hash[ batch_idx ], 32UL ) );
      }
    }
  }
# undef DATA_MAX
# undef BATCH_MAX

  /* do a quick benchmark of sha-256 on small and large UDP payload
     packets from UDP/IP4/VLAN/Ethernet */

  static ulong const bench_sz[2] = { 14UL, 1472UL };

  uchar buf[ 1472 ] __attribute__((aligned(128)));
  for( ulong b=0UL; b<1472UL; b++ ) buf[b] = fd_rng_uchar( rng );

  FD_LOG_NOTICE(( "Benchmarking incremental (best case)" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), buf, sz ), hash );

    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), buf, sz ), hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%6.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking streamlined" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_sha256_hash( buf, sz, hash );

    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_sha256_hash( buf, sz, hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%6.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking batched" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];
    for( ulong batch_cnt=1UL; batch_cnt<=48UL; batch_cnt++ ) {

      /* warmup */
      for( ulong rem=10UL; rem; rem-- ) {
        fd_sha256_batch_t * batch = fd_sha256_batch_init( batch_mem );
        for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) fd_sha256_batch_add( batch, buf, sz, hash );
        fd_sha256_batch_fini( batch );
      }

      /* for real */
      ulong iter = 10000UL;
      long  dt   = -fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) {
        fd_sha256_batch_t * batch = fd_sha256_batch_init( batch_mem );
        for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) fd_sha256_batch_add( batch, buf, sz, hash );
        fd_sha256_batch_fini( batch );
      }
      dt += fd_log_wallclock();
      float gbps = ((float)(batch_cnt*8UL*(70UL+sz)*iter)) / ((float)dt);
      FD_LOG_NOTICE(( "~%6.3f Gbps Ethernet equiv throughput / core (batch_cnt %2lu sz %4lu)", (double)gbps, batch_cnt, sz ));
    }
  }

  /* Test large hash input

     $ head --bytes 4294967311 /dev/zero | openssl dgst -sha256
     326346c80cdb84ec6e143e15f4c419bd266a852b6ed55aa8ad69eebefb56eead */

# define INPUT_SZ (4294967311UL) /* prime larger than 2^32 */
# define CHUNK_SZ (4096UL)
  uchar chunk[ CHUNK_SZ ] __attribute__((aligned(32)));
  fd_memset( chunk, 0, CHUNK_SZ );

  fd_sha256_init( sha );
  ulong left_sz;
  for( left_sz=INPUT_SZ; left_sz>=CHUNK_SZ; left_sz-=CHUNK_SZ )
    fd_sha256_append( sha, chunk, CHUNK_SZ );
  fd_sha256_append( sha, chunk, left_sz );
  fd_sha256_fini( sha, hash );
  FD_TEST( 0==memcmp( hash,
                      "\x32\x63\x46\xc8\x0c\xdb\x84\xec\x6e\x14\x3e\x15\xf4\xc4\x19\xbd"
                      "\x26\x6a\x85\x2b\x6e\xd5\x5a\xa8\xad\x69\xee\xbe\xfb\x56\xee\xad",
                      32UL ) );
# undef CHUNK_SZ
# undef INPUT_SZ

  /* clean up */

  FD_TEST( fd_sha256_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_sha256_leave( sha  )==obj  ); /* ok */

  FD_TEST( fd_sha256_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_sha256_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_sha256_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
