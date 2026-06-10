#include "fd_policy.h"

void
test_peer_removal( fd_wksp_t * wksp ) {
  ulong peer_max  = 1024;

  fd_rnonce_ss_t rnonce[1];
  fd_memset( rnonce, '\xCC', sizeof(fd_rnonce_ss_t) );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1 );
  fd_policy_t * policy = fd_policy_join( fd_policy_new( mem, peer_max, 0, rnonce ) );
  FD_TEST( policy );

  int num_slow = 0;
  int num_fast = 0;
  for( int i = 1; i < 64; i++ ){
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { 0 };
    fd_policy_peer_t const * peer = fd_policy_peer_upsert( policy, &key, &addr );
    fd_policy_peer_response_update( policy, &key, (long)(i*10e6L));
    if ( i <= 10 ) num_fast++;
    else          num_slow++;
    FD_TEST( peer );
  }
  /* peek the first peer in the fast dlist */
  fd_policy_peer_t * peer = fd_policy_peer_dlist_ele_peek_head( policy->peers.fast, policy->peers.pool );
  FD_TEST( peer );
  fd_pubkey_t key1 = peer->key;
  FD_TEST( fd_policy_peer_remove( policy, &peer->key ) );


  peer = fd_policy_peer_dlist_ele_peek_head( policy->peers.slow, policy->peers.pool );
  FD_TEST( peer );
  fd_pubkey_t key2 = peer->key;
  FD_TEST( fd_policy_peer_remove( policy, &peer->key ) );

  /* check that neither dlist contains the peer */
  int i = 0;
  for( fd_policy_peer_dlist_iter_t iter = fd_policy_peer_dlist_iter_fwd_init( policy->peers.fast, policy->peers.pool );
                                   !fd_policy_peer_dlist_iter_done( iter, policy->peers.fast, policy->peers.pool );
                            iter = fd_policy_peer_dlist_iter_fwd_next( iter, policy->peers.fast, policy->peers.pool ) ){
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( iter, policy->peers.fast, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->key.key, p );
    FD_TEST( memcmp( peer->key.key, key1.key, 32UL ) != 0 );
    FD_TEST( memcmp( peer->key.key, key2.key, 32UL ) != 0 );
    FD_LOG_DEBUG(( " %d. fast peer identity: %s", i, p ));
    i++;
  }
  FD_TEST( num_fast-1 == i );

  i = 0;
  for( fd_policy_peer_dlist_iter_t iter = fd_policy_peer_dlist_iter_fwd_init( policy->peers.slow, policy->peers.pool ); !fd_policy_peer_dlist_iter_done( iter, policy->peers.slow, policy->peers.pool ); iter = fd_policy_peer_dlist_iter_fwd_next( iter, policy->peers.slow, policy->peers.pool ) ){
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( iter, policy->peers.slow, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->key.key, p );
    i++;
    FD_TEST( memcmp( peer->key.key, key1.key, 32UL ) != 0 );
    FD_TEST( memcmp( peer->key.key, key2.key, 32UL ) != 0 );
    FD_LOG_DEBUG(( " %d. slow peer identity: %s", i, p ));
  }
  FD_TEST( num_slow-1 == i );

  peer = fd_policy_peer_dlist_ele_peek_tail( policy->peers.fast, policy->peers.pool );
  FD_TEST( peer );
  FD_TEST( fd_policy_peer_remove( policy, &peer->key ) );

  peer = fd_policy_peer_dlist_ele_peek_tail( policy->peers.slow, policy->peers.pool );
  FD_TEST( peer );
  FD_TEST( fd_policy_peer_remove( policy, &peer->key ) );

  fd_pubkey_t key65 = { .key = { (uchar)65 } };
  fd_ip4_port_t addr65 = { 0 };
  FD_TEST( fd_policy_peer_upsert( policy, &key65, &addr65 ) );
  /* check this peer is in the slow dlist */

  int found = 0;
  i = 0;
  for( fd_policy_peer_dlist_iter_t iter = fd_policy_peer_dlist_iter_fwd_init( policy->peers.slow, policy->peers.pool );
                                  !fd_policy_peer_dlist_iter_done    ( iter, policy->peers.slow, policy->peers.pool );
                            iter = fd_policy_peer_dlist_iter_fwd_next( iter, policy->peers.slow, policy->peers.pool ) ){
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( iter, policy->peers.slow, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->key.key, p );
    FD_LOG_DEBUG(( " %d. slow peer identity: %s", i, p ));
    i++;
    if( memcmp( peer->key.key, key65.key, 32UL ) == 0 ) found = 1;
  }
  FD_TEST( num_slow-1 == i );
  FD_TEST( found );

  /* print fast peers */
  i = 0;
  for( fd_policy_peer_dlist_iter_t iter = fd_policy_peer_dlist_iter_fwd_init( policy->peers.fast, policy->peers.pool );
                                  !fd_policy_peer_dlist_iter_done    ( iter, policy->peers.fast, policy->peers.pool );
                            iter = fd_policy_peer_dlist_iter_fwd_next( iter, policy->peers.fast, policy->peers.pool ) ){
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( iter, policy->peers.fast, policy->peers.pool );
    FD_BASE58_ENCODE_32_BYTES( peer->key.key, p );
    FD_LOG_DEBUG(( " %d. fast peer identity: %s", i, p ));
    FD_TEST( memcmp( peer->key.key, key65.key, 32UL ) != 0 );
    i++;
  }
  FD_TEST( num_fast-2 == i );

  /* put another peer in the slow -> fast dlist */
  fd_pubkey_t key66 = { .key = { (uchar)66 } };
  fd_ip4_port_t addr66 = { 0 };
  FD_TEST( fd_policy_peer_upsert( policy, &key66, &addr66 ) );
  /* update key66s latency to move it to the fast dlist */
  fd_policy_peer_response_update( policy, &key66, (long)(10e6L));
  peer = fd_policy_peer_dlist_ele_peek_tail( policy->peers.fast, policy->peers.pool );
  FD_TEST( peer );
  FD_BASE58_ENCODE_32_BYTES( peer->key.key, p );
  FD_TEST( memcmp( peer->key.key, key66.key, 32UL ) == 0 );

  /* move it to slow list (EWMA needs a large enough sample to cross threshold) */
  fd_policy_peer_response_update( policy, &key66, (long)(1000e6L));
  peer = fd_policy_peer_dlist_ele_peek_tail( policy->peers.slow, policy->peers.pool );
  FD_TEST( peer );
  FD_TEST( memcmp( peer->key.key, key66.key, 32UL ) == 0 );
}

void
test_peer_interleave( fd_wksp_t * wksp ) {
  ulong peer_max  = 1024;

  fd_rnonce_ss_t rnonce[1];
  fd_memset( rnonce, '\xCC', sizeof(fd_rnonce_ss_t) );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1 );
  fd_policy_t * policy = fd_policy_join( fd_policy_new( mem, peer_max, 0, rnonce ) );
  FD_TEST( policy );

  /* Insert 6 fast peers (ids 1-6) and 6 slow peers (ids 7-12). */
  for( int i = 1; i <= 12; i++ ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { 0 };
    fd_policy_peer_upsert( policy, &key, &addr );
    if( i <= 6 ) {
      fd_policy_peer_response_update( policy, &key, (long)(10e6L) );
    }
  }

  /* Verify 6:1 interleaving pattern over two full cycles (14 selects). */
  for( int cycle = 0; cycle < 2; cycle++ ) {
    for( int j = 0; j < (int)FD_POLICY_FAST_PER_SLOW; j++ ) {
      fd_pubkey_t const * sel = fd_policy_peer_select( policy );
      FD_TEST( sel );
      fd_policy_peer_t * p = fd_policy_peer_query( policy, sel );
      FD_TEST( p && p->res_cnt > 0 ); /* fast peer */
    }
    fd_pubkey_t const * sel = fd_policy_peer_select( policy );
    FD_TEST( sel );
    fd_policy_peer_t * p = fd_policy_peer_query( policy, sel );
    FD_TEST( p && p->res_cnt == 0 ); /* slow peer */
  }

  /* Test all-slow: insert only slow peers. */
  void * mem2 = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1 );
  fd_policy_t * policy2 = fd_policy_join( fd_policy_new( mem2, peer_max, 0, rnonce ) );
  for( int i = 1; i <= 5; i++ ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { 0 };
    fd_policy_peer_upsert( policy2, &key, &addr );
  }
  for( int i = 0; i < 15; i++ ) {
    fd_pubkey_t const * sel = fd_policy_peer_select( policy2 );
    FD_TEST( sel );
  }

  /* Test all-fast: insert only fast peers. */
  void * mem3 = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1 );
  fd_policy_t * policy3 = fd_policy_join( fd_policy_new( mem3, peer_max, 0, rnonce ) );
  for( int i = 1; i <= 5; i++ ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { 0 };
    fd_policy_peer_upsert( policy3, &key, &addr );
    fd_policy_peer_response_update( policy3, &key, (long)(10e6L) );
  }
  for( int i = 0; i < 15; i++ ) {
    fd_pubkey_t const * sel = fd_policy_peer_select( policy3 );
    FD_TEST( sel );
  }
}

void
test_ewma_latency( fd_wksp_t * wksp ) {
  ulong peer_max  = 1024;

  fd_rnonce_ss_t rnonce[1];
  fd_memset( rnonce, '\xCC', sizeof(fd_rnonce_ss_t) );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1 );
  fd_policy_t * policy = fd_policy_join( fd_policy_new( mem, peer_max, 0, rnonce ) );
  FD_TEST( policy );

  fd_pubkey_t key = { .key = { 1 } };
  fd_ip4_port_t addr = { 0 };
  fd_policy_peer_upsert( policy, &key, &addr );

  /* First response seeds EWMA. */
  fd_policy_peer_response_update( policy, &key, (long)(50e6L) );
  fd_policy_peer_t * peer = fd_policy_peer_query( policy, &key );
  FD_TEST( peer );
  FD_TEST( peer->ewma_lat == (long)(50e6L) );
  FD_TEST( fd_policy_peer_latency_bucket( policy, peer->ewma_lat, peer->res_cnt ) == policy->peers.fast );

  /* Several fast responses should keep it fast. */
  for( int i = 0; i < 10; i++ ) {
    fd_policy_peer_response_update( policy, &key, (long)(40e6L) );
  }
  peer = fd_policy_peer_query( policy, &key );
  FD_TEST( peer->ewma_lat < (long)FD_POLICY_LATENCY_THRESH );
  FD_TEST( fd_policy_peer_latency_bucket( policy, peer->ewma_lat, peer->res_cnt ) == policy->peers.fast );

  /* Sustained high-latency responses should eventually push to slow. */
  for( int i = 0; i < 30; i++ ) {
    fd_policy_peer_response_update( policy, &key, (long)(200e6L) );
  }
  peer = fd_policy_peer_query( policy, &key );
  FD_TEST( peer->ewma_lat > (long)FD_POLICY_LATENCY_THRESH );
  FD_TEST( fd_policy_peer_latency_bucket( policy, peer->ewma_lat, peer->res_cnt ) == policy->peers.slow );
}

void
test_remove_sole_peer( fd_wksp_t * wksp ) {
  ulong peer_max  = 1024;

  fd_rnonce_ss_t rnonce[1];
  fd_memset( rnonce, '\xCC', sizeof(fd_rnonce_ss_t) );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1 );
  fd_policy_t * policy = fd_policy_join( fd_policy_new( mem, peer_max, 0, rnonce ) );
  FD_TEST( policy );

  /* Single slow peer — iterator sits on it. */
  fd_pubkey_t key1 = { .key = { 1 } };
  fd_ip4_port_t addr = { 0 };
  fd_policy_peer_upsert( policy, &key1, &addr );
  fd_policy_peer_select( policy ); /* parks slow_iter on key1 */
  FD_TEST( fd_policy_peer_remove( policy, &key1 ) );

  /* Iterator must not dangle — select should return NULL (no peers). */
  FD_TEST( fd_policy_peer_select( policy ) == NULL );

  /* Re-insert a peer and verify select still works. */
  fd_pubkey_t key2 = { .key = { 2 } };
  fd_policy_peer_upsert( policy, &key2, &addr );
  fd_pubkey_t const * sel = fd_policy_peer_select( policy );
  FD_TEST( sel && memcmp( sel->key, key2.key, 32UL ) == 0 );

  /* Single fast peer — same scenario. */
  fd_policy_peer_response_update( policy, &key2, (long)(10e6L) );
  fd_policy_peer_select( policy ); /* parks fast_iter on key2 */
  FD_TEST( fd_policy_peer_remove( policy, &key2 ) );
  FD_TEST( fd_policy_peer_select( policy ) == NULL );
}

/* Helper: count elements in a peer dlist. */
static ulong
dlist_cnt( fd_policy_peer_dlist_t * dlist, fd_policy_peer_t * pool ) {
  ulong cnt = 0;
  for( fd_policy_peer_dlist_iter_t it = fd_policy_peer_dlist_iter_fwd_init( dlist, pool );
       !fd_policy_peer_dlist_iter_done( it, dlist, pool );
       it = fd_policy_peer_dlist_iter_fwd_next( it, dlist, pool ) ) {
    cnt++;
  }
  return cnt;
}

/* Helper: return 1 if pubkey is found in dlist, 0 otherwise. */
static int
dlist_contains( fd_policy_peer_dlist_t * dlist, fd_policy_peer_t * pool, fd_pubkey_t const * key ) {
  for( fd_policy_peer_dlist_iter_t it = fd_policy_peer_dlist_iter_fwd_init( dlist, pool );
       !fd_policy_peer_dlist_iter_done( it, dlist, pool );
       it = fd_policy_peer_dlist_iter_fwd_next( it, dlist, pool ) ) {
    fd_policy_peer_t * p = fd_policy_peer_dlist_iter_ele( it, dlist, pool );
    if( !memcmp( p->key.key, key->key, 32UL ) ) return 1;
  }
  return 0;
}

/* Helper: create a fresh policy on wksp. */
static fd_policy_t *
new_policy( fd_wksp_t * wksp ) {
  fd_rnonce_ss_t rnonce[1];
  fd_memset( rnonce, '\xCC', sizeof(fd_rnonce_ss_t) );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( 1024UL ), 1 );
  return fd_policy_join( fd_policy_new( mem, 1024UL, 0, rnonce ) );
}

/* Verify dlist counts and map/pool counts stay in sync after removals. */
void
test_dlist_consistency_after_remove( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  /* Insert 4 fast peers (low RTT) and 4 slow peers (no responses). */
  for( int i = 1; i <= 8; i++ ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { .addr = (uint)i, .port = (ushort)(8000+i) };
    fd_policy_peer_upsert( policy, &key, &addr );
    if( i <= 4 ) fd_policy_peer_response_update( policy, &key, (long)(10e6L) );
  }
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 4 );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 4 );
  FD_TEST( fd_policy_peer_pool_used( policy->peers.pool ) == 8 );

  /* Remove one fast, one slow. */
  fd_pubkey_t k_fast = { .key = { 2 } };
  fd_pubkey_t k_slow = { .key = { 6 } };
  FD_TEST( fd_policy_peer_remove( policy, &k_fast ) );
  FD_TEST( fd_policy_peer_remove( policy, &k_slow ) );

  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 3 );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 3 );
  FD_TEST( fd_policy_peer_pool_used( policy->peers.pool ) == 6 );
  FD_TEST( !dlist_contains( policy->peers.fast, policy->peers.pool, &k_fast ) );
  FD_TEST( !dlist_contains( policy->peers.slow, policy->peers.pool, &k_slow ) );

  /* Query must return NULL for removed peers. */
  FD_TEST( !fd_policy_peer_query( policy, &k_fast ) );
  FD_TEST( !fd_policy_peer_query( policy, &k_slow ) );

  /* Remaining peers must still be queryable. */
  for( int i = 1; i <= 8; i++ ) {
    if( i == 2 || i == 6 ) continue;
    fd_pubkey_t key = { .key = { (uchar)i } };
    FD_TEST( fd_policy_peer_query( policy, &key ) );
  }

  /* Double-remove must return 0 (no-op). */
  FD_TEST( !fd_policy_peer_remove( policy, &k_fast ) );
}

/* Verify that response_update on a removed/unknown peer is a no-op and
   does not corrupt dlist state. */
void
test_response_update_unknown_peer( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  fd_pubkey_t k1 = { .key = { 1 } };
  fd_ip4_port_t addr = { 0 };
  fd_policy_peer_upsert( policy, &k1, &addr );

  ulong fast_before = dlist_cnt( policy->peers.fast, policy->peers.pool );

  /* Update a peer that was never inserted. */
  fd_pubkey_t k_unknown = { .key = { 99 } };
  fd_policy_peer_response_update( policy, &k_unknown, (long)(10e6L) );

  /* Remove k1 then update it — should be a no-op. */
  fd_policy_peer_remove( policy, &k1 );
  fd_policy_peer_response_update( policy, &k1, (long)(10e6L) );

  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == fast_before );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 0 );
  FD_TEST( fd_policy_peer_pool_used( policy->peers.pool ) == 0 );
}

/* Verify the null pubkey guard returns NULL and does not crash. */
void
test_null_pubkey_query( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  fd_pubkey_t null_key;
  fd_memset( &null_key, 0, sizeof(fd_pubkey_t) );
  FD_TEST( !fd_policy_peer_query( policy, &null_key ) );

  /* Insert a real peer and verify null query still returns NULL. */
  fd_pubkey_t k1 = { .key = { 1 } };
  fd_ip4_port_t addr = { 0 };
  fd_policy_peer_upsert( policy, &k1, &addr );
  FD_TEST( !fd_policy_peer_query( policy, &null_key ) );
  FD_TEST(  fd_policy_peer_query( policy, &k1 ) );

  /* request_update and response_update with null pubkey must be no-ops. */
  ulong used_before = fd_policy_peer_pool_used( policy->peers.pool );
  fd_policy_peer_request_update( policy, &null_key );
  fd_policy_peer_response_update( policy, &null_key, (long)(10e6L) );
  FD_TEST( fd_policy_peer_pool_used( policy->peers.pool ) == used_before );
}

/* Verify dlist integrity across slow->fast and fast->slow bucket
   transitions.  Each peer must be in exactly one dlist at all times. */
void
test_bucket_transition_dlist_integrity( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  fd_pubkey_t k1 = { .key = { 1 } };
  fd_ip4_port_t addr = { 0 };
  fd_policy_peer_upsert( policy, &k1, &addr );

  /* Starts in slow (no responses yet). */
  FD_TEST(  dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
  FD_TEST( !dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 1 );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 0 );

  /* Fast response → should move to fast. */
  fd_policy_peer_response_update( policy, &k1, (long)(10e6L) );
  FD_TEST( !dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
  FD_TEST(  dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 0 );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 1 );

  /* Sustained high latency → should move back to slow. */
  for( int i = 0; i < 50; i++ ) {
    fd_policy_peer_response_update( policy, &k1, (long)(300e6L) );
  }
  fd_policy_peer_t * p = fd_policy_peer_query( policy, &k1 );
  FD_TEST( p && p->ewma_lat > (long)FD_POLICY_LATENCY_THRESH );
  FD_TEST(  dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
  FD_TEST( !dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 1 );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 0 );

  /* Sustained fast again → back to fast. */
  for( int i = 0; i < 50; i++ ) {
    fd_policy_peer_response_update( policy, &k1, (long)(5e6L) );
  }
  p = fd_policy_peer_query( policy, &k1 );
  FD_TEST( p && p->ewma_lat < (long)FD_POLICY_LATENCY_THRESH );
  FD_TEST( !dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
  FD_TEST(  dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );

  /* Total across both dlists must always equal pool used. */
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool )
         + dlist_cnt( policy->peers.slow, policy->peers.pool )
        == fd_policy_peer_pool_used( policy->peers.pool ) );
}

/* Verify that removing the peer the select iterator is parked on does
   not break subsequent selects from the same or opposite dlist. */
void
test_remove_iter_peer_dlist_intact( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  /* 3 fast, 3 slow. */
  for( int i = 1; i <= 6; i++ ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_ip4_port_t addr = { 0 };
    fd_policy_peer_upsert( policy, &key, &addr );
    if( i <= 3 ) fd_policy_peer_response_update( policy, &key, (long)(10e6L) );
  }

  /* Park fast_iter on first fast peer via select. */
  fd_pubkey_t const * sel = fd_policy_peer_select( policy );
  FD_TEST( sel );
  fd_pubkey_t parked = *sel;

  /* Remove that peer. */
  FD_TEST( fd_policy_peer_remove( policy, &parked ) );
  FD_TEST( !dlist_contains( policy->peers.fast, policy->peers.pool, &parked ) );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 2 );

  /* Subsequent selects must not return the removed peer and must not crash. */
  for( int i = 0; i < 20; i++ ) {
    sel = fd_policy_peer_select( policy );
    FD_TEST( sel );
    FD_TEST( memcmp( sel->key, parked.key, 32UL ) != 0 );
  }

  /* Dlist totals must match pool. */
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool )
         + dlist_cnt( policy->peers.slow, policy->peers.pool )
        == fd_policy_peer_pool_used( policy->peers.pool ) );
}

/* Verify dlist integrity after a peer is evicted by
   fd_policy_peer_request_update (unanswered threshold). */
void
test_eviction_dlist_integrity( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  /* Insert a fast peer and a slow peer. */
  fd_pubkey_t k_fast = { .key = { 1 } };
  fd_pubkey_t k_slow = { .key = { 2 } };
  fd_ip4_port_t addr = { 0 };
  fd_policy_peer_upsert( policy, &k_fast, &addr );
  fd_policy_peer_response_update( policy, &k_fast, (long)(10e6L) );
  fd_policy_peer_upsert( policy, &k_slow, &addr );

  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 1 );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 1 );

  /* Slow peer must be unaffected. */
  FD_TEST(  fd_policy_peer_query( policy, &k_slow ) );
  FD_TEST(  dlist_contains( policy->peers.slow, policy->peers.pool, &k_slow ) );

  /* Pool used must match dlist totals. */
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool )
         + dlist_cnt( policy->peers.slow, policy->peers.pool )
        == fd_policy_peer_pool_used( policy->peers.pool ) );
}

/* Verify that reinserting a previously removed peer places it into the
   correct dlist and that the old state does not leak. */
void
test_remove_and_reinsert( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  fd_pubkey_t k1 = { .key = { 1 } };
  fd_ip4_port_t addr = { .addr = 0x01020304, .port = 8000 };
  fd_policy_peer_upsert( policy, &k1, &addr );
  fd_policy_peer_response_update( policy, &k1, (long)(10e6L) );
  FD_TEST( dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );

  /* Remove it. */
  FD_TEST( fd_policy_peer_remove( policy, &k1 ) );
  FD_TEST( fd_policy_peer_pool_used( policy->peers.pool ) == 0 );

  /* Reinsert — should go to slow (fresh peer, no responses). */
  fd_policy_peer_upsert( policy, &k1, &addr );
  FD_TEST( fd_policy_peer_pool_used( policy->peers.pool ) == 1 );
  FD_TEST(  dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
  FD_TEST( !dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );

  /* Counters should be reset. */
  fd_policy_peer_t * p = fd_policy_peer_query( policy, &k1 );
  FD_TEST( p );
  FD_TEST( p->req_cnt == 0 );
  FD_TEST( p->res_cnt == 0 );
  FD_TEST( p->ewma_lat == 0 );
  FD_TEST( p->unanswered == 0 );

  /* Move to fast again and verify. */
  fd_policy_peer_response_update( policy, &k1, (long)(10e6L) );
  FD_TEST(  dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );
  FD_TEST( !dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
}

/* Verify that multiple peers can transition buckets independently
   without corrupting each other's dlist membership. */
void
test_multi_peer_bucket_transitions( fd_wksp_t * wksp ) {
  fd_policy_t * policy = new_policy( wksp );
  FD_TEST( policy );

  fd_ip4_port_t addr = { 0 };

  /* Insert 5 peers, all start slow. */
  for( int i = 1; i <= 5; i++ ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_policy_peer_upsert( policy, &key, &addr );
  }
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 5 );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 0 );

  /* Move peers 1, 3, 5 to fast. */
  for( int i = 1; i <= 5; i += 2 ) {
    fd_pubkey_t key = { .key = { (uchar)i } };
    fd_policy_peer_response_update( policy, &key, (long)(10e6L) );
  }
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 3 );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 2 );

  /* Remove peer 3 (fast) and peer 2 (slow). */
  fd_pubkey_t k3 = { .key = { 3 } };
  fd_pubkey_t k2 = { .key = { 2 } };
  fd_policy_peer_remove( policy, &k3 );
  fd_policy_peer_remove( policy, &k2 );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 2 );
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 1 );

  /* Move peer 1 from fast to slow with high latency. */
  fd_pubkey_t k1 = { .key = { 1 } };
  for( int i = 0; i < 50; i++ ) {
    fd_policy_peer_response_update( policy, &k1, (long)(300e6L) );
  }
  FD_TEST(  dlist_contains( policy->peers.slow, policy->peers.pool, &k1 ) );
  FD_TEST( !dlist_contains( policy->peers.fast, policy->peers.pool, &k1 ) );
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool ) == 1 ); /* only peer 5 */
  FD_TEST( dlist_cnt( policy->peers.slow, policy->peers.pool ) == 2 ); /* peers 1, 4 */

  /* Invariant: dlist total == pool used. */
  FD_TEST( dlist_cnt( policy->peers.fast, policy->peers.pool )
         + dlist_cnt( policy->peers.slow, policy->peers.pool )
        == fd_policy_peer_pool_used( policy->peers.pool ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_wksp_t * wksp = fd_wksp_new_anon_from_env( &argc, &argv, "gigantic", 1UL, "wksp", 0UL );
  FD_TEST( wksp );

  test_peer_removal( wksp );
  test_peer_interleave( wksp );
  test_ewma_latency( wksp );
  test_remove_sole_peer( wksp );
  test_dlist_consistency_after_remove( wksp );
  test_response_update_unknown_peer( wksp );
  test_null_pubkey_query( wksp );
  test_bucket_transition_dlist_integrity( wksp );
  test_remove_iter_peer_dlist_intact( wksp );
  test_eviction_dlist_integrity( wksp );
  test_remove_and_reinsert( wksp );
  test_multi_peer_bucket_transitions( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
