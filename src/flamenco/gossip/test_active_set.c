#include "fd_active_set.h"
#include "fd_active_set_private.h"

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

  uchar identity_pubkey[ 32UL ];
  for( ulong i=0UL; i<32UL; i++ ) identity_pubkey[ i ] = fd_rng_uchar( rng );
  ulong identity_stake = (fd_rng_ulong( rng ) % (1048576000000000UL-1UL))+1UL;

  uchar nodes[ 20UL ][ 32UL ];
  for( ulong i=0UL; i<20UL; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) nodes[ i ][ j ] = fd_rng_uchar( rng );
  }

  ulong stakes[ 20UL ];
  for( ulong i=0UL; i<20UL; i++ ) stakes[ i ] = (fd_rng_ulong( rng ) % (1048576000000000UL-1UL))+1UL;

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  for( ulong i=0UL; i<25UL; i++ ) {
    FD_TEST( active_set->entries[ i ]->nodes_len==0UL );
  }

  uchar * nodes2[ 20UL ];
  for( ulong i=0UL; i<20UL; i++ ) nodes2[ i ] = nodes[ i ];
  fd_active_set_rotate( active_set, 117UL, (uchar const **)nodes2, stakes, 20UL );

  for( ulong i=0UL; i<25UL; i++ ) {
    FD_TEST( active_set->entries[ i ]->nodes_len==12UL );
    for( ulong j=0UL; j<12UL; j++ ) {
      FD_TEST( fd_bloom_contains( active_set->entries[ i ]->nodes[ j ]->bloom, active_set->entries[ i ]->nodes[ j ]->pubkey, 32UL ) );
    }
  }

  uchar * out[ 12UL ];
  ulong out_cnt = fd_active_set_nodes( active_set, identity_pubkey, identity_stake, nodes[ 17UL ], stakes[ 17UL ], out );
  (void)out_cnt;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_get_stake_bucket();
  FD_LOG_NOTICE(( "test_get_stake_bucket() passed" ));

  test_push_active_set();
  FD_LOG_NOTICE(( "test_push_active_set() passed" ));
}
