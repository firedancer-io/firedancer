#include "ag_epoch_info.h"
#include <stdlib.h>

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_validator_info_t * v = (ag_validator_info_t *)malloc( n*sizeof(ag_validator_info_t) );
  FD_TEST( v );
  for( ulong i=0UL; i<n; i++ ) {
    memset( &v[i], 0, sizeof(ag_validator_info_t) );
    v[i].id    = i;
    v[i].stake = 1UL;
    ag_bls_sec_t sk; fd_memset( sk, (int)(i+1UL), AG_BLS_SEC_SZ );
    ag_bls_sec_to_pub( sk, v[i].bls_key );
  }
  ag_epoch_info_t * ei = aligned_alloc( alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t) );
  FD_TEST( ei );
  ag_epoch_info( ei, v, n );
  free( v );
  *out_mem = ei;
  return ei;
}

/* src/consensus/epoch_info.rs::quorums */

static void
test_quorums( void ) {
  void * m6; ag_epoch_info_t * e6 = make_epoch( 6UL, &m6 );
  FD_TEST( ag_epoch_info_total_stake( e6 )==6UL );
  FD_TEST(  ag_epoch_info_is_weak_quorum  ( e6, 3UL ) );
  FD_TEST( !ag_epoch_info_is_quorum       ( e6, 3UL ) );
  FD_TEST(  ag_epoch_info_is_quorum       ( e6, 4UL ) );
  FD_TEST( !ag_epoch_info_is_strong_quorum( e6, 4UL ) );
  FD_TEST(  ag_epoch_info_is_strong_quorum( e6, 5UL ) );
  free( m6 );

  void * m11; ag_epoch_info_t * e11 = make_epoch( 11UL, &m11 );
  FD_TEST(  ag_epoch_info_is_weak_quorum  ( e11, 5UL ) );
  FD_TEST( !ag_epoch_info_is_quorum       ( e11, 5UL ) );
  FD_TEST(  ag_epoch_info_is_quorum       ( e11, 7UL ) );
  FD_TEST( !ag_epoch_info_is_strong_quorum( e11, 7UL ) );
  FD_TEST(  ag_epoch_info_is_strong_quorum( e11, 9UL ) );
  free( m11 );

  void * m5; ag_epoch_info_t * e5 = make_epoch( 5UL, &m5 );
  FD_TEST( !ag_epoch_info_is_weakest_quorum( e5, 0UL ) );
  FD_TEST(  ag_epoch_info_is_weakest_quorum( e5, 1UL ) );
  free( m5 );

  void * m100; ag_epoch_info_t * e100 = make_epoch( 100UL, &m100 );
  FD_TEST(  ag_epoch_info_is_quorum       ( e100, 60UL ) );
  FD_TEST(  ag_epoch_info_is_strong_quorum( e100, 80UL ) );
  FD_TEST( !ag_epoch_info_is_strong_quorum( e100, 79UL ) );
  free( m100 );
}

static void
test_leader( void ) {
  void * m; ag_epoch_info_t * e = make_epoch( 3UL, &m );

  FD_TEST( ag_epoch_info_leader( e, 0UL  )->id==0UL );
  FD_TEST( ag_epoch_info_leader( e, 3UL  )->id==0UL );
  FD_TEST( ag_epoch_info_leader( e, 4UL  )->id==1UL );
  FD_TEST( ag_epoch_info_leader( e, 8UL  )->id==2UL );
  FD_TEST( ag_epoch_info_leader( e, 12UL )->id==0UL );
  FD_TEST( ag_epoch_info_validator( e, 2UL )->id==2UL );
  free( m );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_quorums();
  test_leader();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
