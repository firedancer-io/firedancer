#include "fd_epoch_info.h"
#include <stdlib.h> /* malloc/free/aligned_alloc */

/* Builds a unit-stake validator set of n validators in a malloc'd buffer. */

static fd_epoch_info_t *
make_epoch( ulong n, void ** out_mem ) {
  fd_validator_info_t * v = (fd_validator_info_t *)malloc( n*sizeof(fd_validator_info_t) );
  FD_TEST( v );
  for( ulong i=0UL; i<n; i++ ) {
    memset( &v[i], 0, sizeof(fd_validator_info_t) );
    v[i].id    = i;
    v[i].stake = 1UL;
    fd_aggsig_sk_t sk; fd_memset( sk.v, (int)(i+1UL), FD_AGGSIG_SECKEY_SZ );
    fd_aggsig_sk_to_pk( &v[i].voting_pubkey, &sk );
  }
  void * mem = aligned_alloc( fd_epoch_info_align(), fd_epoch_info_footprint( n ) );
  FD_TEST( mem );
  fd_epoch_info_t * ei = fd_epoch_info_join( fd_epoch_info_new( mem, v, n ) );
  free( v );
  *out_mem = mem;
  return ei;
}

/* Mirrors alpenglow/src/consensus/epoch_info.rs mod tests::quorums. */

static void
test_quorums( void ) {
  void * m6; fd_epoch_info_t * e6 = make_epoch( 6UL, &m6 );
  FD_TEST( fd_epoch_info_total_stake( e6 )==6UL );
  FD_TEST(  fd_epoch_info_is_weak_quorum  ( e6, 3UL ) );
  FD_TEST( !fd_epoch_info_is_quorum       ( e6, 3UL ) );
  FD_TEST(  fd_epoch_info_is_quorum       ( e6, 4UL ) );
  FD_TEST( !fd_epoch_info_is_strong_quorum( e6, 4UL ) );
  FD_TEST(  fd_epoch_info_is_strong_quorum( e6, 5UL ) );
  free( m6 );

  void * m11; fd_epoch_info_t * e11 = make_epoch( 11UL, &m11 );
  FD_TEST(  fd_epoch_info_is_weak_quorum  ( e11, 5UL ) );
  FD_TEST( !fd_epoch_info_is_quorum       ( e11, 5UL ) );
  FD_TEST(  fd_epoch_info_is_quorum       ( e11, 7UL ) );
  FD_TEST( !fd_epoch_info_is_strong_quorum( e11, 7UL ) );
  FD_TEST(  fd_epoch_info_is_strong_quorum( e11, 9UL ) );
  free( m11 );
}

static void
test_leader( void ) {
  void * m; fd_epoch_info_t * e = make_epoch( 3UL, &m );
  /* round-robin over windows: window = slot/4, leader = window % 3 */
  FD_TEST( fd_epoch_info_leader( e, 0UL  )->id==0UL ); /* window 0 */
  FD_TEST( fd_epoch_info_leader( e, 3UL  )->id==0UL ); /* window 0 */
  FD_TEST( fd_epoch_info_leader( e, 4UL  )->id==1UL ); /* window 1 */
  FD_TEST( fd_epoch_info_leader( e, 8UL  )->id==2UL ); /* window 2 */
  FD_TEST( fd_epoch_info_leader( e, 12UL )->id==0UL ); /* window 3 % 3 */
  FD_TEST( fd_epoch_info_validator( e, 2UL )->id==2UL );
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
