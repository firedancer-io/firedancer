#define _GNU_SOURCE
#include "../fd_util.h"
#include "fd_tile_private.h"
#include <sched.h>

/* Test fd_cpuset_t replacements for the cpu_set_t API.
   This test ensures that inputs to POSIX functions expecting a
   cpu_set_t will behave as intended when given a fd_cpuset_t. */

FD_STATIC_ASSERT( FD_TILE_MAX>=CPU_SETSIZE, compat );

static fd_cpuset_t *
fd_cpuset_from_libc( fd_cpuset_t *     out,
                     cpu_set_t const * pun ) {
  fd_cpuset_null( out );
  fd_memcpy( out, pun, sizeof(cpu_set_t) );
  return out;
}

static cpu_set_t *
fd_cpuset_to_libc( cpu_set_t *         out,
                   fd_cpuset_t const * pun ) {
  CPU_ZERO( out );
  fd_memcpy( out, pun, sizeof(cpu_set_t) );
  return out;
}

static void
test_cpu_zero( void ) {

  /* Zero initialization */

  do {
    FD_CPUSET_DECL( foo );

    cpu_set_t pun[1]; fd_cpuset_to_libc( pun, foo );
    FD_TEST( CPU_COUNT( pun )==0 );
  } while(0);

  /* CPU_ZERO */

  do {
    cpu_set_t foo[1];
    CPU_ZERO( foo );

    FD_CPUSET_DECL( pun ); fd_cpuset_from_libc( pun, foo );
    FD_TEST( fd_cpuset_cnt( pun )==0 );
  } while(0);

}

static void
test_cpu_insert( fd_rng_t * rng ) {

  ulong load_cnt = 8 + fd_rng_ulong_roll( rng, CPU_SETSIZE/3 );
  FD_TEST( load_cnt > 0 && load_cnt < (CPU_SETSIZE/2) );

  /* fd_cpuset_insert */

  do {
    FD_CPUSET_DECL( foo );
    for( ulong j=0UL; j<load_cnt; j++ ) {
      ulong idx = fd_rng_ulong_roll( rng, CPU_SETSIZE );
      fd_cpuset_insert( foo, idx );
    }

    cpu_set_t pun[1]; fd_cpuset_to_libc( pun, foo );
    for( ulong j=0UL; j<CPU_SETSIZE; j++ )
      FD_TEST( fd_cpuset_test( foo, j ) == !!CPU_ISSET( j, pun ) );
    FD_TEST( fd_cpuset_cnt( foo ) == (ulong)CPU_COUNT( pun ) );
  } while(0);

  /* CPU_SET */

  do {
    cpu_set_t foo[1];
    CPU_ZERO( foo );
    for( ulong j=0UL; j<load_cnt; j++ ) {
      ulong idx = fd_rng_ulong_roll( rng, CPU_SETSIZE );
      CPU_SET( idx, foo );
    }

    FD_CPUSET_DECL( pun ); fd_cpuset_from_libc( pun, foo );
    for( ulong j=0UL; j<CPU_SETSIZE; j++ )
      FD_TEST( fd_cpuset_test( pun, j ) == !!CPU_ISSET( j, foo ) );
    FD_TEST( fd_cpuset_cnt( pun ) == (ulong)CPU_COUNT( foo ) );
  } while(0);

}

static void
test_cpu_remove( fd_rng_t * rng ) {

  ulong load_cnt = 8 + fd_rng_ulong_roll( rng, CPU_SETSIZE/3 );
  FD_TEST( load_cnt > 0 && load_cnt < (CPU_SETSIZE/2) );

  /* fd_cpuset_remove */

  do {
    FD_CPUSET_DECL( foo );
    fd_memset( foo, 0xFF, sizeof(cpu_set_t) );
    for( ulong j=0UL; j<load_cnt; j++ ) {
      ulong idx = fd_rng_ulong_roll( rng, CPU_SETSIZE );
      fd_cpuset_remove( foo, idx );
    }

    cpu_set_t pun[1]; fd_cpuset_to_libc( pun, foo );
    for( ulong j=0UL; j<CPU_SETSIZE; j++ )
      FD_TEST( fd_cpuset_test( foo, j ) == !!CPU_ISSET( j, pun ) );
    FD_TEST( fd_cpuset_cnt( foo ) == (ulong)CPU_COUNT( pun ) );
  } while(0);

  /* CPU_CLR */

  do {
    cpu_set_t foo[1];
    for( ulong j=0UL; j<CPU_SETSIZE; j++ )
      CPU_SET( j, foo );

    for( ulong j=0UL; j<load_cnt; j++ ) {
      ulong idx = fd_rng_ulong_roll( rng, CPU_SETSIZE );
      CPU_CLR( idx, foo );
    }

    FD_CPUSET_DECL( pun ); fd_cpuset_from_libc( pun, foo );
    for( ulong j=0UL; j<CPU_SETSIZE; j++ )
      FD_TEST( fd_cpuset_test( pun, j ) == !!CPU_ISSET( j, foo ) );
    FD_TEST( fd_cpuset_cnt( pun ) == (ulong)CPU_COUNT( foo ) );
  } while(0);

}

static void
test_cpu_set( fd_rng_t * rng ) {

  ulong load_cnt = 8 + fd_rng_ulong_roll( rng, CPU_SETSIZE/3 );
  FD_TEST( load_cnt > 0 && load_cnt < (CPU_SETSIZE/2) );

  FD_CPUSET_DECL( foo0 );
  FD_CPUSET_DECL( foo1 );
  for( ulong j=0UL; j<load_cnt; j++ ) {
    ulong idx0 = fd_rng_ulong_roll( rng, CPU_SETSIZE );
    ulong idx1 = fd_rng_ulong_roll( rng, CPU_SETSIZE );
    fd_cpuset_insert( foo0, idx0 );
    fd_cpuset_insert( foo1, idx1 );
  }

  FD_CPUSET_DECL( foo_and );  fd_cpuset_intersect( foo_and, foo0, foo1 );
  FD_CPUSET_DECL( foo_or  );  fd_cpuset_union    ( foo_or , foo0, foo1 );
  FD_CPUSET_DECL( foo_xor );  fd_cpuset_xor      ( foo_xor, foo0, foo1 );


  cpu_set_t bar0[1]; fd_cpuset_to_libc( bar0, foo0 );
  cpu_set_t bar1[1]; fd_cpuset_to_libc( bar1, foo1 );

  cpu_set_t bar_and[1];  CPU_AND( bar_and, bar0, bar1 );
  cpu_set_t bar_or [1];  CPU_OR ( bar_or,  bar0, bar1 );
  cpu_set_t bar_xor[1];  CPU_XOR( bar_xor, bar0, bar1 );

  for( ulong j=0UL; j<CPU_SETSIZE; j++ ) {
    FD_TEST( fd_cpuset_test( foo_and, j ) == !!CPU_ISSET( j, bar_and ) );
    FD_TEST( fd_cpuset_test( foo_or , j ) == !!CPU_ISSET( j, bar_or  ) );
    FD_TEST( fd_cpuset_test( foo_xor, j ) == !!CPU_ISSET( j, bar_xor ) );
  }

  FD_CPUSET_DECL( pun_and ); fd_cpuset_from_libc( pun_and, bar_and );
  FD_CPUSET_DECL( pun_or  ); fd_cpuset_from_libc( pun_or,  bar_or  );
  FD_CPUSET_DECL( pun_xor ); fd_cpuset_from_libc( pun_xor, bar_xor );
  FD_TEST( fd_cpuset_eq( foo_and, pun_and ) );
  FD_TEST( fd_cpuset_eq( foo_or , pun_or  ) );
  FD_TEST( fd_cpuset_eq( foo_xor, pun_xor ) );

  FD_TEST( CPU_EQUAL   ( &bar0, &bar0 ) );
  FD_TEST( fd_cpuset_eq(  foo0,  foo0 ) );

  CPU_CLR( 0, bar0 );  fd_cpuset_remove( foo0, 0 );
  CPU_SET( 0, bar1 );  fd_cpuset_insert( foo1, 0 );

  FD_TEST( !CPU_EQUAL   ( &bar0, &bar1 ) );
  FD_TEST( !fd_cpuset_eq(  foo0,  foo1 ) );

}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_cpuset_footprint() >= sizeof(cpu_set_t) );

  test_cpu_zero  ();
  test_cpu_insert( rng );
  test_cpu_remove( rng );
  test_cpu_set   ( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}

