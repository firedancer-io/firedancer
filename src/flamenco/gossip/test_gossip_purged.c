#include "../../util/fd_util.h"
#include "fd_gossip_purged_private.h"
#include "fd_gossip_hset.h"

#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_gossip_purged_footprint( 2097152UL )==332071424UL );

  ulong footprint = fd_gossip_purged_footprint( 8UL );
  void * mem = aligned_alloc( fd_gossip_purged_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 0UL ) );
  FD_TEST( rng );

  fd_gossip_purged_t * purged = fd_gossip_purged_join( fd_gossip_purged_new( mem, rng, 8UL ) );
  FD_TEST( purged );
  FD_TEST( !fd_gossip_purged_len( purged ) );

  ulong const seed = 0x0123456789abcdefUL;
  fd_pubkey_t key0 = {0};
  fd_pubkey_t key1 = {0};
  key1.uc[ 31UL ] = 1U;

  ulong hash0 = nci_origin_map_key_hash( &key0, seed );
  ulong hash1 = nci_origin_map_key_hash( &key1, seed );
  FD_TEST( hash0==fd_hash32( key0.uc, seed ) );
  FD_TEST( hash1==fd_hash32( key1.uc, seed ) );
  FD_TEST( hash0!=hash1 );

  fd_gossip_hset_iter_t it[1];
  fd_gossip_hset_iter_init( it, fd_gossip_purged_hset( purged ), 0UL, ULONG_MAX );
  FD_TEST( fd_gossip_hset_iter_done( it ) );

  /* a hash is recorded once, whichever list it lands on */
  uchar h[ 32 ] = { 1, 2, 3 };
  fd_gossip_purged_insert_replaced( purged, h, 1L );
  fd_gossip_purged_insert_failed_insert( purged, h, 1L );
  fd_gossip_purged_insert_no_contact_info( purged, key0.uc, h, 1L );
  FD_TEST( fd_gossip_purged_len( purged )==1UL );
  h[ 31 ] = 1; /* same prefix, treated as a duplicate */
  fd_gossip_purged_insert_failed_insert( purged, h, 1L );
  FD_TEST( fd_gossip_purged_len( purged )==1UL );
  h[ 0 ] = 2;
  fd_gossip_purged_insert_no_contact_info( purged, key1.uc, h, 1L );
  FD_TEST( fd_gossip_purged_len( purged )==2UL );
  fd_gossip_purged_drain_no_contact_info( purged, key1.uc );
  FD_TEST( fd_gossip_purged_len( purged )==1UL );
  fd_gossip_purged_insert_failed_insert( purged, h, 1L );
  FD_TEST( fd_gossip_purged_len( purged )==2UL );
  fd_gossip_purged_expire( purged, 1L+120L*1000L*1000L*1000L );
  FD_TEST( !fd_gossip_purged_len( purged ) );
  fd_gossip_hset_iter_init( it, fd_gossip_purged_hset( purged ), 0UL, ULONG_MAX );
  FD_TEST( fd_gossip_hset_iter_done( it ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
