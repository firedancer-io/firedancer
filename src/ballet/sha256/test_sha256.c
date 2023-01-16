#include "../fd_ballet.h"
#include "fd_sha256_test_vector.c"

FD_STATIC_ASSERT( FD_SHA256_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_SHA256_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_SHA256_ALIGN    ==alignof(fd_sha256_t), unit_test );
FD_STATIC_ASSERT( FD_SHA256_FOOTPRINT==sizeof (fd_sha256_t), unit_test );

FD_STATIC_ASSERT( FD_SHA256_LG_HASH_SZ==5, unit_test );
FD_STATIC_ASSERT( FD_SHA256_HASH_SZ==32UL, unit_test );

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
  }

  /* do a quick benchmark of sha-256 to UDP payloads of MTU Ethernet
     packets on UDP/IP4/VLAN/Ethernet */

# define SZ (1472UL)
  uchar buf[ SZ ] __attribute__((aligned(32)));
  for( ulong b=0UL; b<SZ; b++ ) buf[b] = fd_rng_uchar( rng );

  /* warmup */
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), buf, SZ ), hash );
  dt = fd_log_wallclock() - dt;

  /* for real */
  iter = 100000UL;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), buf, SZ ), hash );
  dt = fd_log_wallclock() - dt;

  FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput per core", (double)(((float)(8UL*(70UL+SZ)*iter))/((float)dt)) ));
# undef SZ

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

