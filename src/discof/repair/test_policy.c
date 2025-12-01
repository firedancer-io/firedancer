#include "fd_policy.h"

void
test_peer_removal( fd_wksp_t * wksp ) {
  ulong dedup_max = 1024;
  ulong peer_max  = 1024;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( dedup_max, peer_max ), 1 );
  fd_policy_t * policy = fd_policy_join( fd_policy_new( mem, dedup_max, peer_max, 0 ) );
  FD_TEST( policy );

  int num_slow = 0;
  int num_fast = 0;
  for( int i = 1; i < 64; i++ ){
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { 0 };
    fd_policy_peer_t const * peer = fd_policy_peer_insert( policy, &key, &addr );
    fd_policy_peer_response_update( policy, &key, (long)(i*10e6L));
    if ( i <= 8 ) num_fast++;
    else          num_slow++;
    FD_TEST( peer );
  }
  /* peek the first peer in the fast dlist */
  fd_peer_t * peer = fd_peer_dlist_ele_peek_head( policy->peers.fast, policy->peers.pool );
  FD_TEST( peer );
  fd_pubkey_t key1 = peer->identity;
  FD_TEST( fd_policy_peer_remove( policy, &peer->identity ) );


  peer = fd_peer_dlist_ele_peek_head( policy->peers.slow, policy->peers.pool );
  FD_TEST( peer );
  fd_pubkey_t key2 = peer->identity;
  FD_TEST( fd_policy_peer_remove( policy, &peer->identity ) );

  /* check that neither dlist contains the peer */
  int i = 0;
  for( fd_peer_dlist_iter_t iter = fd_peer_dlist_iter_fwd_init( policy->peers.fast, policy->peers.pool );
                                   !fd_peer_dlist_iter_done( iter, policy->peers.fast, policy->peers.pool );
                            iter = fd_peer_dlist_iter_fwd_next( iter, policy->peers.fast, policy->peers.pool ) ){
    fd_peer_t * peer = fd_peer_dlist_iter_ele( iter, policy->peers.fast, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->identity.key, p );
    FD_TEST( memcmp( peer->identity.key, key1.key, 32UL ) != 0 );
    FD_TEST( memcmp( peer->identity.key, key2.key, 32UL ) != 0 );
    FD_LOG_DEBUG(( " %d. fast peer identity: %s", i, p ));
    i++;
  }
  FD_TEST( num_fast-1 == i );

  i = 0;
  for( fd_peer_dlist_iter_t iter = fd_peer_dlist_iter_fwd_init( policy->peers.slow, policy->peers.pool ); !fd_peer_dlist_iter_done( iter, policy->peers.slow, policy->peers.pool ); iter = fd_peer_dlist_iter_fwd_next( iter, policy->peers.slow, policy->peers.pool ) ){
    fd_peer_t * peer = fd_peer_dlist_iter_ele( iter, policy->peers.slow, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->identity.key, p );
    i++;
    FD_TEST( memcmp( peer->identity.key, key1.key, 32UL ) != 0 );
    FD_TEST( memcmp( peer->identity.key, key2.key, 32UL ) != 0 );
    FD_LOG_DEBUG(( " %d. slow peer identity: %s", i, p ));
  }
  FD_TEST( num_slow-1 == i );

  peer = fd_peer_dlist_ele_peek_tail( policy->peers.fast, policy->peers.pool );
  FD_TEST( peer );
  FD_TEST( fd_policy_peer_remove( policy, &peer->identity ) );

  peer = fd_peer_dlist_ele_peek_tail( policy->peers.slow, policy->peers.pool );
  FD_TEST( peer );
  FD_TEST( fd_policy_peer_remove( policy, &peer->identity ) );

  fd_pubkey_t key65 = { .key = { (uchar)65 } };
  fd_ip4_port_t addr65 = { 0 };
  FD_TEST( fd_policy_peer_insert( policy, &key65, &addr65 ) );
  /* check this peer is in the slow dlist */

  int found = 0;
  i = 0;
  for( fd_peer_dlist_iter_t iter = fd_peer_dlist_iter_fwd_init( policy->peers.slow, policy->peers.pool );
                                  !fd_peer_dlist_iter_done    ( iter, policy->peers.slow, policy->peers.pool );
                            iter = fd_peer_dlist_iter_fwd_next( iter, policy->peers.slow, policy->peers.pool ) ){
    fd_peer_t * peer = fd_peer_dlist_iter_ele( iter, policy->peers.slow, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->identity.key, p );
    FD_LOG_DEBUG(( " %d. slow peer identity: %s", i, p ));
    i++;
    if( memcmp( peer->identity.key, key65.key, 32UL ) == 0 ) found = 1;
  }
  FD_TEST( num_slow-1 == i );
  FD_TEST( found );

  /* print fast peers */
  i = 0;
  for( fd_peer_dlist_iter_t iter = fd_peer_dlist_iter_fwd_init( policy->peers.fast, policy->peers.pool );
                                  !fd_peer_dlist_iter_done    ( iter, policy->peers.fast, policy->peers.pool );
                            iter = fd_peer_dlist_iter_fwd_next( iter, policy->peers.fast, policy->peers.pool ) ){
    fd_peer_t * peer = fd_peer_dlist_iter_ele( iter, policy->peers.fast, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->identity.key, p );
    FD_LOG_DEBUG(( " %d. fast peer identity: %s", i, p ));
    FD_TEST( memcmp( peer->identity.key, key65.key, 32UL ) != 0 );
    i++;
  }
  FD_TEST( num_fast-2 == i );

  /* put another peer in the slow -> fast dlist */
  fd_pubkey_t key66 = { .key = { (uchar)66 } };
  fd_ip4_port_t addr66 = { 0 };
  FD_TEST( fd_policy_peer_insert( policy, &key66, &addr66 ) );
  /* update key66s latency to move it to the fast dlist */
  fd_policy_peer_response_update( policy, &key66, (long)(10e6L));
  peer = fd_peer_dlist_ele_peek_tail( policy->peers.fast, policy->peers.pool );
  FD_TEST( peer );
  FD_BASE58_ENCODE_32_BYTES( peer->identity.key, p );
  FD_TEST( memcmp( peer->identity.key, key66.key, 32UL ) == 0 );

  /* move it to slow list */
  fd_policy_peer_response_update( policy, &key66, (long)(500e6L));
  peer = fd_peer_dlist_ele_peek_tail( policy->peers.slow, policy->peers.pool );
  FD_TEST( peer );
  FD_BASE58_ENCODE_32_BYTES( peer->identity.key, p2 );
  FD_TEST( memcmp( peer->identity.key, key66.key, 32UL ) == 0 );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_peer_removal( wksp );

  fd_halt();
}
