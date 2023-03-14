#include "../fd_ballet.h"
#include "fd_keccak256.h"
#include "fd_keccak256_test_vector.c"

FD_STATIC_ASSERT( FD_KECCAK256_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_KECCAK256_FOOTPRINT==256UL, unit_test );

FD_STATIC_ASSERT( FD_KECCAK256_ALIGN    ==alignof(fd_keccak256_t), unit_test );
FD_STATIC_ASSERT( FD_KECCAK256_FOOTPRINT==sizeof (fd_keccak256_t), unit_test );

FD_STATIC_ASSERT( FD_KECCAK256_HASH_SZ==32UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_keccak256_align    ()==FD_KECCAK256_ALIGN     );
  FD_TEST( fd_keccak256_footprint()==FD_KECCAK256_FOOTPRINT );

  fd_keccak256_t mem[1];

  FD_TEST( fd_keccak256_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_keccak256_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_keccak256_new( mem ); FD_TEST( obj );

  FD_TEST( fd_keccak256_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_keccak256_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_keccak256_t * sha = fd_keccak256_join( obj ); FD_TEST( sha );

  uchar hash[ 32 ] __attribute__((aligned(32)));

  for( fd_keccak256_test_vector_t const * vec = fd_keccak256_test_vector; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uchar const * expected = vec->hash;

    /* test single shot hashing */

    FD_TEST( fd_keccak256_init( sha )==sha );
    FD_TEST( fd_keccak256_append( sha, msg, sz )==sha );
    FD_TEST( fd_keccak256_fini( sha, hash )==hash );
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
    FD_TEST( fd_keccak256_init( sha )==sha );

    char const * nxt = msg;
    ulong        rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      FD_TEST( fd_keccak256_append( sha, nxt, nxt_sz )==sha );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_keccak256_append( sha, NULL, 0UL )==sha ); /* test zero append too */
    }

    FD_TEST( fd_keccak256_fini( sha, hash )==hash );

    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

  }

  /* do a quick benchmark of keccak-256 on small and large UDP payload
     packets from UDP/IP4/VLAN/Ethernet */

  static ulong const bench_sz[2] = { 14UL, 1472UL };

  uchar buf[ 1472 ] __attribute__((aligned(128)));
  for( ulong b=0UL; b<1472UL; b++ ) buf[b] = fd_rng_uchar( rng );

  FD_LOG_NOTICE(( "Benchmarking incremental (best case)" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];
  
    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_keccak256_fini( fd_keccak256_append( fd_keccak256_init( sha ), buf, sz ), hash );
  
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_keccak256_fini( fd_keccak256_append( fd_keccak256_init( sha ), buf, sz ), hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking streamlined" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_keccak256_hash( buf, sz, hash );

    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_keccak256_hash( buf, sz, hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  /* clean up */

  FD_TEST( fd_keccak256_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_keccak256_leave( sha  )==obj  ); /* ok */

  FD_TEST( fd_keccak256_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_keccak256_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_keccak256_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

