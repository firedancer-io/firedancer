#include "../fd_ballet.h"
#include "fd_blake3_test_vector.c"

FD_STATIC_ASSERT( FD_BLAKE3_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_BLAKE3_FOOTPRINT==1920UL, unit_test );

FD_STATIC_ASSERT( FD_BLAKE3_ALIGN    ==alignof(fd_blake3_t), unit_test );
FD_STATIC_ASSERT( FD_BLAKE3_FOOTPRINT==sizeof (fd_blake3_t), unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_blake3_align    ()==FD_BLAKE3_ALIGN     );
  FD_TEST( fd_blake3_footprint()==FD_BLAKE3_FOOTPRINT );

  fd_blake3_t mem[1];

  FD_TEST( fd_blake3_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_blake3_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_blake3_new( mem ); FD_TEST( obj );

  FD_TEST( fd_blake3_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_blake3_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_blake3_t * sha = fd_blake3_join( obj ); FD_TEST( sha );

  uchar hash[ 32 ] __attribute__((aligned(32)));

  for( fd_blake3_test_vector_t const * vec = fd_blake3_test_vector; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uchar const * expected = vec->hash;

    /* test single shot hashing */

    FD_TEST( fd_blake3_init( sha )==sha );
    FD_TEST( fd_blake3_append( sha, msg, sz )==sha );
    FD_TEST( fd_blake3_fini( sha, hash )==hash );
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
    FD_TEST( fd_blake3_init( sha )==sha );

    char const * nxt = msg;
    ulong        rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      FD_TEST( fd_blake3_append( sha, nxt, nxt_sz )==sha );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_blake3_append( sha, NULL, 0UL )==sha ); /* test zero append too */
    }

    FD_TEST( fd_blake3_fini( sha, hash )==hash );

    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
  }

  static uchar buf[ 1<<24 ] __attribute__((aligned(32)));
  for( ulong b=0UL; b<sizeof(buf); b++ ) buf[b] = fd_rng_uchar( rng );

  for( ulong shift=6; shift<24UL; shift++ ) {
    ulong sz          = 1UL<<shift;
    ulong iter_target = (1UL<<28)>>shift;

    /* warmup */
    ulong iter = iter_target / 100;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini( fd_blake3_append( fd_blake3_init( sha ), buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    /* for real */
    iter = iter_target;
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini( fd_blake3_append( fd_blake3_init( sha ), buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    FD_LOG_NOTICE(( "~%02.3f Gbps per core; %f ns per byte (sz %lu)",
                    (double)(((float)(8UL*sz*iter))/((float)dt)),
                    (double)dt/((double)sz*(double)iter),
                    sz ));
  }

  /* clean up */

  FD_TEST( fd_blake3_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_blake3_leave( sha  )==obj  ); /* ok */

  FD_TEST( fd_blake3_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_blake3_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_blake3_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

