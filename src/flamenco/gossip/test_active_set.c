#include "fd_active_set.h"
#include "fd_active_set_private.h"
#include "test_crds_utils.c"


FD_STATIC_ASSERT( FD_ACTIVE_SET_ALIGN==64UL,  unit_test );
FD_STATIC_ASSERT( FD_ACTIVE_SET_ALIGN==alignof(fd_active_set_t), unit_test );

void
test_get_stake_bucket( void ) {
  ulong buckets[] = { 0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5 };
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( fd_active_set_stake_bucket( i*1000000000UL )==buckets[ i ] );
  }

  ulong stake1[] = { 4194303UL, 4194304UL, 8388607UL, 8388608UL };
  ulong buckets1[] = { 22UL, 23UL, 23UL, 24UL };
  for( ulong i=0UL; i<4UL; i++ ) {
    FD_TEST( fd_active_set_stake_bucket( stake1[ i ]*1000000000UL )==buckets1[ i ] );
  }

  FD_TEST( fd_active_set_stake_bucket( ULONG_MAX )==24UL );
}

void
test_push_active_set( void ) {
  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  /* Create a test CRDS with peers */
  fd_crds_t * crds = create_test_crds_with_ci( rng, 50UL );
  FD_TEST( crds );

  uchar identity_pubkey[ 32UL ];
  for( ulong i=0UL; i<32UL; i++ ) identity_pubkey[ i ] = fd_rng_uchar( rng );
  ulong identity_stake = (fd_rng_ulong( rng ) % (1048576000000000UL-1UL))+1UL;

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  for( ulong i=0UL; i<25UL; i++ ) {
    FD_TEST( active_set->entries[ i ]->nodes_len==0UL );
  }

  /* Test fd_active_set_rotate with the CRDS */
  fd_active_set_rotate( active_set, crds );

  for( ulong i=0UL; i<25UL; i++ ) {
    FD_TEST( active_set->entries[ i ]->nodes_len<=12UL );
    for( ulong j=0UL; j<active_set->entries[ i ]->nodes_len; j++ ) {
      FD_TEST( fd_bloom_contains( active_set->entries[ i ]->nodes[ j ]->bloom, active_set->entries[ i ]->nodes[ j ]->pubkey, 32UL ) );
    }
  }

  /* Test fd_active_set_nodes */
  ulong out_nodes[ 12UL ];
  uchar target_pubkey[ 32UL ];
  for( ulong i=0UL; i<32UL; i++ ) target_pubkey[ i ] = fd_rng_uchar( rng );
  ulong target_stake = fd_rng_ulong_roll( rng, 1000000UL );

  ulong out_cnt = fd_active_set_nodes( active_set, identity_pubkey, identity_stake, target_pubkey, target_stake, 0, out_nodes );
  (void)out_cnt;
  free_test_crds( crds );
  free( bytes );
}



int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_get_stake_bucket();
  test_push_active_set();

  FD_LOG_NOTICE(( "pass" ));
}
