#include "../fd_disco.h"

#include "fd_circq.h"

void
test_simple1( void ) {
  uchar buf[ 128UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 128 ) );
  FD_TEST( circq );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong i=0UL; i<8192UL*8192UL; i++ ) {
    uchar * msg = fd_circq_push_back( circq, fd_ulong_pow2( (int)fd_rng_ulong_roll( rng, 5 ) ), 1UL+fd_rng_ulong_roll( rng, 64 ) );
    FD_TEST( msg );
  }
}

void
test_simple2( void ) {
  uchar buf[ 32UL+1024UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 64UL ) );
  FD_TEST( circq );

  uchar * msg = fd_circq_push_back( circq, 1UL, 8UL );
  msg[ 0 ] = 'X';
  msg[ 7 ] = 'A';

  uchar const * msg2 = fd_circq_pop_front( circq );

  FD_TEST( msg2 );
  FD_TEST( msg2[0]=='X' );
  FD_TEST( msg2[7]=='A' );

  FD_TEST( !fd_circq_pop_front( circq ) );
  FD_TEST( !fd_circq_pop_front( circq ) );
  FD_TEST( !fd_circq_pop_front( circq ) );

  msg = fd_circq_push_back( circq, 1UL, 8UL );
  msg[ 0 ] = 'X';
  msg[ 7 ] = 'A';

  msg = fd_circq_push_back( circq, 1UL, 8UL );
  FD_TEST( circq->cnt==2UL );
  msg[ 0 ] = '2';
  msg[ 7 ] = '3';

  msg2 = fd_circq_pop_front( circq );
  FD_TEST( msg2 );
  FD_TEST( msg2[0]=='X' );
  FD_TEST( msg2[7]=='A' );

  msg2 = fd_circq_pop_front( circq );
  FD_TEST( msg2 );
  FD_TEST( msg2[0]=='2' );
  FD_TEST( msg2[7]=='3' );

  FD_TEST( !fd_circq_pop_front( circq ) );

  msg = fd_circq_push_back( circq, 1UL, 9UL );
  msg[ 0 ] = 'X';
  msg[ 7 ] = 'A';

  msg = fd_circq_push_back( circq, 1UL, 8UL );
  msg[ 0 ] = '2';
  msg[ 7 ] = '3';

  msg2 = fd_circq_pop_front( circq );
  FD_TEST( msg2 );
  FD_TEST( msg2[0]=='2' );
  FD_TEST( msg2[7]=='3' );

  FD_TEST( !fd_circq_pop_front( circq ) );
}

void
test_simple3( void ) {
  uchar buf[ 32UL+1024UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 128 ) );
  FD_TEST( circq );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 6U, 0UL ) );

  for( ulong i=0UL; i<8192UL; i++ ) {
    if( 0UL==fd_rng_ulong_roll( rng, 2 ) ) fd_circq_pop_front( circq );
    fd_circq_push_back( circq, 1+fd_rng_ulong_roll( rng, 256UL ), 1UL+fd_rng_ulong_roll( rng, 25UL ) );
  }
}

void
test_bounds( void ) {
  uchar buf[ 32UL+1024UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 1024UL ) );
  FD_TEST( circq );

  FD_TEST( fd_circq_push_back( circq, 1UL, 1024UL-25UL ) );
  FD_TEST( fd_circq_push_back( circq, 1UL, 1024UL-24UL ) );
  FD_TEST( fd_circq_push_back( circq, 8UL, 1024UL-24UL ) );
  FD_TEST( !fd_circq_push_back( circq, 1UL, 1024UL-23UL ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_simple1();
  FD_LOG_NOTICE(( "OK: simple1"));

  test_simple2();
  FD_LOG_NOTICE(( "OK: simple2"));

  test_simple3();
  FD_LOG_NOTICE(( "OK: simple3"));

  test_bounds();
  FD_LOG_NOTICE(( "OK: bounds"));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
