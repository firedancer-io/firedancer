#include "fd_sspeer_selector.h"

#include "../../../util/fd_util.h"

static ulong
add_peer( fd_sspeer_selector_t *  selector,
          fd_sspeer_key_t const * key,
          fd_ip4_port_t           addr,
          ulong                   full_slot,
          ulong                   incremental_slot,
          ulong                   latency ) {
  return fd_sspeer_selector_add( selector, key, addr, latency, full_slot, incremental_slot, NULL, NULL );
}

static int
generate_rand_pubkey( fd_pubkey_t * pubkey,
                      fd_rng_t *    rng ) {
  for( ulong i=0UL; i<FD_HASH_FOOTPRINT/sizeof(ulong); i++ ) {
    pubkey->ul[ i ] = fd_rng_ulong( rng );
  }
  return 1;
}

static int
generate_rand_url( char *     url,
                   ulong      max_sz,
                   fd_rng_t * rng ) {
  ulong max_len = 5UL/*https*/ + 21UL/*fake_url*/ + 6UL/*:udp_port*/ + 1UL/*\0*/;
  if( max_len > max_sz ) return 0;

  char *p = fd_cstr_init( url );
  int is_https = fd_rng_int( rng ) & 0x1;
  p = fd_cstr_append_cstr( p, "http" );
  if( is_https ) p = fd_cstr_append_cstr( p, "s" );
  p = fd_cstr_append_printf( p, "://fake_url_%u.com", fd_rng_ushort( rng ) );
  if( !is_https ) p = fd_cstr_append_printf( p, ":%u", fd_rng_ushort( rng ) );
  fd_cstr_fini( p );
  return 1;
}

static int
generate_rand_addr_non_zero( fd_ip4_port_t * addr,
                             fd_rng_t *      rng ) {
  for(;;) {
    addr->addr = fd_rng_uint( rng );
    addr->port = fd_ushort_bswap( fd_rng_ushort( rng ) );
    if( FD_LIKELY( !!addr->l ) ) break;
  }
  return 1;
}

static int
generate_rand_sspeer_key( fd_sspeer_key_t * key,
                          fd_rng_t *        rng,
                          int               is_url ) {
  key->is_url = !!is_url;
  int ret = 0;
  if( is_url ) {
    ret = generate_rand_addr_non_zero( &key->url.resolved_addr, rng );
    ret &= generate_rand_url( key->url.hostname, sizeof(key->url.hostname), rng );
  } else {
    ret = generate_rand_pubkey( key->pubkey, rng );
  }
  return ret;
}


struct test_wksp_struct {
   fd_sspeer_selector_t * selector;
   void *                 shmem;
   ulong                  max_peers;
   ulong                  seed;
};
typedef struct test_wksp_struct test_wksp_t;

static void
test_wksp_init( fd_wksp_t *   wksp,
                test_wksp_t * t_wksp,
                ulong         max_peers,
                ulong         seed ) {
  FD_TEST( t_wksp->selector==NULL );
  FD_TEST( t_wksp->shmem==NULL );
  t_wksp->shmem    = fd_wksp_alloc_laddr( wksp, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( max_peers ), 1UL );
  t_wksp->selector = fd_sspeer_selector_join( fd_sspeer_selector_new( t_wksp->shmem, max_peers, seed ) );
  FD_TEST( t_wksp->selector );
  t_wksp->max_peers = max_peers;
  t_wksp->seed      = seed;
}

static void
test_wksp_reinit( test_wksp_t * t_wksp ) {
  FD_TEST( t_wksp->selector!=NULL );
  FD_TEST( fd_sspeer_selector_delete( fd_sspeer_selector_leave( t_wksp->selector ) )==t_wksp->shmem );
  FD_TEST( fd_sspeer_selector_join( fd_sspeer_selector_new( t_wksp->shmem, t_wksp->max_peers, t_wksp->seed ) )==t_wksp->selector );
}

static void
test_wksp_fini( test_wksp_t * t_wksp ) {
  FD_TEST( t_wksp->selector!=NULL );
  fd_wksp_free_laddr( fd_sspeer_selector_delete( fd_sspeer_selector_leave( t_wksp->selector ) ) );
  t_wksp->shmem    = NULL;
  t_wksp->selector = NULL;
}

static void
verify_initial_cluster_slot( fd_sspeer_selector_t * selector ) {
  fd_sscluster_slot_t cluster_slot_0 = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cluster_slot_0.full==0UL );
  FD_TEST( cluster_slot_0.incremental==FD_SSPEER_SLOT_UNKNOWN );
}

static void
test_basic_peer_selection( fd_sspeer_selector_t * selector,
                           fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing basic peer selection"));

  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer and compute the cluster slot from the max of its
     slots.  With 1 peer at (1000, 1500), the max is (1000, 1500). */
  fd_sspeer_key_t key[1]; FD_TEST( generate_rand_sspeer_key( key, rng, fd_rng_int( rng )&0x1/*is_url*/) );
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 35, 123, 172, 227 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key, addr, 1000UL, 1500UL, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000UL );
  FD_TEST( cs.incremental==1500UL );

  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==5UL*1000UL*1000UL );
  FD_TEST( fd_sspeer_key_eq( &best.key, key ) );

  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer with better latency at the same slot and it should be
     the best peer.  Cluster is (1000, 1500), peer at (1000, 1500),
     so slots_behind=0, score=latency. */
  fd_sspeer_key_t key2[1]; FD_TEST( generate_rand_sspeer_key( key2, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr2 = { .addr = FD_IP4_ADDR( 35, 123, 172, 228 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key2, addr2, 1000UL, 1500UL, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( fd_sspeer_key_eq( &best.key, key2 ) );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer with the same latency but lagging slots behind.
     Cluster incr is 1500, peer incr is 1400.  slots_behind=100.
     score = 3_000_000 + 200*100^2 = 5_000_000. */
  fd_sspeer_key_t key3[1]; FD_TEST( generate_rand_sspeer_key( key3, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr3 = { .addr = FD_IP4_ADDR( 35, 123, 172, 229 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key3, addr3, 1000UL, 1400UL, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL + 200UL*100UL*100UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 3UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 3UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer that is slightly slower but caught up in slots */
  fd_sspeer_key_t key4[1]; FD_TEST( generate_rand_sspeer_key( key4, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr4 = { .addr = FD_IP4_ADDR( 35, 123, 172, 230 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key4, addr4, 1000UL, 1500UL, 3UL*1000UL*1000UL + 75UL*1000UL )==3UL*1000UL*1000UL + 75UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 4UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 4UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a fast peer that doesn't have resolved slots */
  fd_sspeer_key_t key5[1]; FD_TEST( generate_rand_sspeer_key( key5, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr5 = { .addr = FD_IP4_ADDR( 35, 123, 172, 231 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key5, addr5, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL + 200UL*1000UL*1000UL*1000UL*1000UL);
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Test incremental peer selection */
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  /* Add a peer that is fast and at the highest incr slot but not
     building off full slot 1000, which makes it an invalid incremental
     candidate for base_slot=1000. */
  fd_sspeer_key_t key6[1]; FD_TEST( generate_rand_sspeer_key( key6, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr6 = { .addr = FD_IP4_ADDR( 35, 123, 172, 232 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key6, addr6, 900UL, 1700UL, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 6UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 6UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a fast incremental peer that is caught up to the cluster slot */
  fd_sspeer_key_t key7[1]; FD_TEST( generate_rand_sspeer_key( key7, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr7 = { .addr = FD_IP4_ADDR( 35, 123, 172, 233 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key7, addr7, 1000UL, 1700UL, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr7.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1700UL );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  FD_TEST( 7UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 7UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key  );
  fd_sspeer_selector_remove( selector, key2 );
  fd_sspeer_selector_remove( selector, key3 );
  fd_sspeer_selector_remove( selector, key4 );
  fd_sspeer_selector_remove( selector, key5 );
  fd_sspeer_selector_remove( selector, key6 );
  fd_sspeer_selector_remove( selector, key7 );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_duplicate_peers( fd_sspeer_selector_t * selector,
                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing duplicate peers" ));

  ulong cluster_full_slot = 2000UL;
  ulong cluster_incr_slot = 2500UL;

  fd_sspeer_key_t key_pub_A[1]; FD_TEST( generate_rand_sspeer_key( key_pub_A, rng, 0 ) );
  fd_sspeer_key_t key_pub_B[1]; FD_TEST( generate_rand_sspeer_key( key_pub_B, rng, 0 ) );
  fd_sspeer_key_t key_url_A[1]; FD_TEST( generate_rand_sspeer_key( key_url_A, rng, 1 ) );
  fd_sspeer_key_t key_url_B[1]; FD_TEST( generate_rand_sspeer_key( key_url_B, rng, 1 ) );
  fd_ip4_port_t addr0; FD_TEST( generate_rand_addr_non_zero( &addr0, rng ) );
  /* This is a test, but in reality resolved_addr should match addr0. */
  fd_sspeer_key_t key_url_C[1]; *key_url_C = *key_url_A; key_url_C->url.resolved_addr.l = (key_url_A->url.resolved_addr.l ^ 2UL) | 1UL;

  /* Add peers with same addr, same full_slot and incr_slot.
     With cluster at {0, UNKNOWN}, peers are ahead so scores = latency. */

  /* ... pubkey peer, latency 2us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_pub_A, addr0, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... pubkey peer, latency 3us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_pub_B, addr0, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... url peer, latency 4us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_url_A, addr0, cluster_full_slot, cluster_incr_slot, 4UL*1000UL*1000UL )==4UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... url peer, latency 5us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_url_B, addr0, cluster_full_slot, cluster_incr_slot, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... url peer, latency 1us, expected best score 1e6. */
  FD_TEST( add_peer( selector, key_url_C, addr0, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL )==1UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==1UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove_by_addr( selector, addr0 );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_peer_addr_change( fd_sspeer_selector_t * selector,
                       fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing peer addr change" ));

  ulong cluster_full_slot = 3000UL;
  ulong cluster_incr_slot = 3500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A;  FD_TEST( generate_rand_addr_non_zero( &addr_A,  rng ) );
  fd_ip4_port_t addr_A1; FD_TEST( generate_rand_addr_non_zero( &addr_A1, rng ) );
  fd_ip4_port_t addr_B;  FD_TEST( generate_rand_addr_non_zero( &addr_B,  rng ) );

  /* Add 2 peers change the addr of one of them.
     With cluster at {0, UNKNOWN}, peers are ahead so scores = latency. */

  /* ... peer A, latency 2us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... peer B, latency 3us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... peer A, new addr, latency 4us, expected best score 3e6 */
  FD_TEST( add_peer( selector, key_A, addr_A1, cluster_full_slot, cluster_incr_slot, 4UL*1000UL*1000UL )==4UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_update_on_ping( fd_sspeer_selector_t * selector,
                     fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing update on_ping" ));

  ulong cluster_full_slot = 4000UL;
  ulong cluster_incr_slot = 4500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_D[1]; FD_TEST( generate_rand_sspeer_key( key_D, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_E[1]; FD_TEST( generate_rand_sspeer_key( key_E, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_AB; FD_TEST( generate_rand_addr_non_zero( &addr_AB, rng ) );
  fd_ip4_port_t addr_CD; FD_TEST( generate_rand_addr_non_zero( &addr_CD, rng ) );
  fd_ip4_port_t addr_E;  FD_TEST( generate_rand_addr_non_zero( &addr_E,  rng ) );
  fd_ip4_port_t addr_X;  FD_TEST( generate_rand_addr_non_zero( &addr_X,  rng ) );

  /* Add 5 peers: pairs AB, CD and single E.
     With cluster at {0, UNKNOWN}, peers are ahead so scores = latency. */

  /* ... peers A and B, latency 2us, expected best score 2e6 (pair AB). */
  FD_TEST( add_peer( selector, key_A, addr_AB, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  FD_TEST( add_peer( selector, key_B, addr_AB, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... peers C and D, latency 3us, expected best score 2e6 (pair AB). */
  FD_TEST( add_peer( selector, key_C, addr_CD, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  FD_TEST( add_peer( selector, key_D, addr_CD, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... peers E, latency 4us, expected best score 2e6 (pair AB). */
  FD_TEST( add_peer( selector, key_E, addr_E, cluster_full_slot, cluster_incr_slot, 4UL*1000UL*1000UL )==4UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* ... update addr_AB to 5us, expected best score 3e6 (pair CD). */
  FD_TEST( 2UL==fd_sspeer_selector_update_on_ping( selector, addr_AB, 5UL*1000UL*1000UL ) );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_CD.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  /* ... update addr_CD to 6us, expected best score 4e6 (single E). */
  FD_TEST( 2UL==fd_sspeer_selector_update_on_ping( selector, addr_CD, 6UL*1000UL*1000UL ) );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_E.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==4UL*1000UL*1000UL );

  /* ... update addr_E to 7us, expected best score 5e6 (pair AB). */
  FD_TEST( 1UL==fd_sspeer_selector_update_on_ping( selector, addr_E, 7UL*1000UL*1000UL ) );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==5UL*1000UL*1000UL );

  /* ... update unknown addr returns 0 (no peers updated). */
  FD_TEST( 0UL==fd_sspeer_selector_update_on_ping( selector, addr_X, 1UL*1000UL*1000UL ) );

  /* Verify how many peers were added to selector. */
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Verify hashes are preserved after update_on_ping. */
  fd_sspeer_selector_remove_by_addr( selector, addr_AB );
  fd_sspeer_selector_remove_by_addr( selector, addr_CD );
  fd_sspeer_selector_remove_by_addr( selector, addr_E  );

  uchar test_full_hash[ FD_HASH_FOOTPRINT ];
  uchar test_incr_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( test_full_hash, fd_rng_uchar( rng ), FD_HASH_FOOTPRINT );
  fd_memset( test_incr_hash, fd_rng_uchar( rng ), FD_HASH_FOOTPRINT );

  fd_sspeer_key_t key_F[1]; FD_TEST( generate_rand_sspeer_key( key_F, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t   addr_F;   FD_TEST( generate_rand_addr_non_zero( &addr_F, rng ) );

  fd_sspeer_selector_add( selector, key_F, addr_F, 2UL*1000UL*1000UL,
                          cluster_full_slot, cluster_incr_slot,
                          test_full_hash, test_incr_hash );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( fd_memeq( best.full_hash, test_full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.incr_hash, test_incr_hash, FD_HASH_FOOTPRINT ) );

  /* Update latency via ping, hashes should be preserved. */
  FD_TEST( 1UL==fd_sspeer_selector_update_on_ping( selector, addr_F, 3UL*1000UL*1000UL ) );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_F.l );
  FD_TEST( best.score==3UL*1000UL*1000UL );
  FD_TEST( fd_memeq( best.full_hash, test_full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.incr_hash, test_incr_hash, FD_HASH_FOOTPRINT ) );

  /* Cleanup. */
  fd_sspeer_selector_remove( selector, key_F );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_resolve_via_add( fd_sspeer_selector_t * selector,
                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing resolve via add" ));

  ulong cluster_full_slot = 5000UL;
  ulong cluster_incr_slot = 5500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, 1/*is_url*/ ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, 1/*is_url*/ ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Add 2 peers with UNKNOWN slots (simulating initial discovery).
     With cluster at {0, UNKNOWN}, unresolved peers get
     DEFAULT_SLOTS_BEHIND penalty. */

  /* ... peer A latency 3us, expected best score != 3e6 (penalized). */
  FD_TEST( add_peer( selector, key_A, addr_A, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )!=3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* add() with NULL key must return SCORE_INVALID. */
  FD_TEST( fd_sspeer_selector_add( selector, NULL, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_SCORE_INVALID );

  /* add() with UNKNOWN slots for both is a no-op on existing peer
     (slots unchanged). */
  FD_TEST( add_peer( selector, key_A, addr_A, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_LATENCY_UNKNOWN )!=FD_SSPEER_SCORE_INVALID );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* full_slot==UNKNOWN with incr_slot!=UNKNOWN is rejected
     (an incremental slot requires a known full slot). */
  FD_TEST( add_peer( selector, key_A, addr_A, FD_SSPEER_SLOT_UNKNOWN, cluster_incr_slot, FD_SSPEER_LATENCY_UNKNOWN )==FD_SSPEER_SCORE_INVALID );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Resolve peer A with valid slots via add() (production path). */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_incr_slot, FD_SSPEER_LATENCY_UNKNOWN )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* ... peer B latency 2us. */
  FD_TEST( add_peer( selector, key_B, addr_B, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )!=2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Resolve peer B with valid slots via add(). */
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Cleanup and verification. */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_address_zero( fd_sspeer_selector_t * selector,
                   fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing address zero" ));

  ulong cluster_full_slot = 6000UL;
  ulong cluster_incr_slot = 6500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_0 = { .addr = 0U, .port = 0U };

  /* Try to add both peers with addr_0. */
  FD_TEST( add_peer( selector, key_A, addr_0, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_0, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add both peers with valid addresses.
     With cluster at {0, UNKNOWN}, peers are ahead so scores = latency. */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Try to add both peers with addr_0. Selector state must not change. */
  FD_TEST( add_peer( selector, key_A, addr_0, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_0, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup */
  fd_sspeer_selector_remove_by_addr( selector, addr_A );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );
  fd_sspeer_selector_remove_by_addr( selector, addr_B );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_duplicate_hostnames( fd_sspeer_selector_t * selector,
                          fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing duplicate hostnames" ));

  ulong cluster_full_slot = 7000UL;
  ulong cluster_incr_slot = 7500UL;

  /* Two HTTP servers with same hostname but different resolved_addr. */
  fd_sspeer_key_t key_url_A[1]; FD_TEST( generate_rand_sspeer_key( key_url_A, rng, 1 ) );
  fd_sspeer_key_t key_url_B[1]; *key_url_B = *key_url_A; key_url_B->url.resolved_addr.l = (key_url_A->url.resolved_addr.l ^ 2UL) | 1UL;
  fd_ip4_port_t addr_A = key_url_A->url.resolved_addr;
  fd_ip4_port_t addr_B = key_url_B->url.resolved_addr;

  /* Add both peers with valid addresses.
     With cluster at {0, UNKNOWN}, peers are ahead so scores = latency. */
  FD_TEST( add_peer( selector, key_url_A, addr_A, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( add_peer( selector, key_url_B, addr_B, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_url_A );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );
  fd_sspeer_selector_remove( selector, key_url_B );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_add_clears_incremental( fd_sspeer_selector_t * selector,
                             fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing add clears incremental" ));

  ulong cluster_full_slot = 8000UL;
  ulong cluster_incr_slot = 8500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_N; FD_TEST( generate_rand_addr_non_zero( &addr_N, rng ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Add peer A with valid incremental. */
  FD_TEST( add_peer( selector, key_A, addr_N, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );

  /* Establish the cluster slot. */
  fd_sspeer_selector_process_cluster_slot( selector );

  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_N.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Peer A should be a valid incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_N.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Re-add same peer with FD_SSPEER_SLOT_UNKNOWN for incr_slot (it
     simulates a gossip contact-info update that only carries address,
     no slot info).  The existing incr_slot should be preserved. */
  FD_TEST( add_peer( selector, key_A, addr_A, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_LATENCY_UNKNOWN )==2UL*1000UL*1000UL );

  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* New gossip message for peer A arrives without an incremental but
     with the SAME full_slot.  The peer's existing incr_slot (8500) is
     >= full_slot (8000), so the incremental is not stale and should
     be preserved. */
  uchar temp_full_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( temp_full_hash, fd_rng_uchar( rng ), FD_HASH_FOOTPRINT );
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   temp_full_hash, NULL )==2UL*1000UL*1000UL );

  /* Peer A should STILL be a valid incremental candidate (not stale). */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* full_hash should be updated even though incremental was preserved. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( fd_memeq( best.full_hash, temp_full_hash, FD_HASH_FOOTPRINT ) );

  /* Clear incremental by advancing full_slot past the peer's incr_slot. */
  ulong new_full_slot = cluster_incr_slot + 1UL;
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   new_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   temp_full_hash, NULL )==2UL*1000UL*1000UL );

  /* Peer A should no longer be an incremental candidate (cleared). */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );
  best = fd_sspeer_selector_best( selector, 1, new_full_slot );
  FD_TEST( !best.addr.l );

  /* Full selection should return peer A with updated full_slot. */
  uchar zeroed_hash[ FD_HASH_FOOTPRINT ] = {0};
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==new_full_slot );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( fd_memeq( best.incr_hash, zeroed_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.full_hash, temp_full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Restore peer A with a valid incremental for subsequent tests. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, cluster_incr_slot,
                                   temp_full_hash, temp_full_hash )!=FD_SSPEER_SCORE_INVALID );

  /* Same full_slot again (idempotent): incr_slot (8500) >= full_slot
     (8000) means the incremental is not stale, so it is preserved. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   temp_full_hash, NULL )==2UL*1000UL*1000UL );

  /* Peer A should still be an incremental candidate (not stale). */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( fd_memeq( best.full_hash, temp_full_hash, FD_HASH_FOOTPRINT ) );

  /* full_slot exactly at incr_slot: incr_slot (8500) >= full_slot
     (8500) so the incremental is not stale and is preserved. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_incr_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   temp_full_hash, NULL )!=FD_SSPEER_SCORE_INVALID );
  best = fd_sspeer_selector_best( selector, 1, cluster_incr_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Now clear with full_slot one past incr_slot: genuinely stale. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_incr_slot + 1UL, FD_SSPEER_SLOT_UNKNOWN,
                                   temp_full_hash, NULL )!=FD_SSPEER_SCORE_INVALID );
  best = fd_sspeer_selector_best( selector, 1, cluster_incr_slot + 1UL );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Add peer B without incremental (new peer). */
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Peer A is still best for full (lower latency). */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );

  /* Neither peer should be an incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Re-add peer A with a valid incremental slot. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, cluster_incr_slot,
                                   temp_full_hash, temp_full_hash )==2UL*1000UL*1000UL );

  /* Peer A should once again be a valid incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );
  FD_TEST( fd_memeq( best.full_hash, temp_full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.incr_hash, temp_full_hash, FD_HASH_FOOTPRINT ) );

  /* add() with full_hash==NULL, incr_hash!=NULL: the full_hash should
     be preserved and the incr_hash should be updated. */
  uchar new_incr_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( new_incr_hash, 0xEE, FD_HASH_FOOTPRINT );
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN,
                                   NULL, new_incr_hash )!=FD_SSPEER_SCORE_INVALID );

  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( fd_memeq( best.full_hash, temp_full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.incr_hash, new_incr_hash, FD_HASH_FOOTPRINT ) );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_on_resolve_clears_incremental( fd_sspeer_selector_t * selector,
                                    fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing on_resolve clears incremental" ));

  ulong cluster_full_slot = 8700UL;
  ulong cluster_incr_slot = 8800UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );

  /* Add peer A with valid full+incremental and explicit hashes. */
  uchar rand_uchar = fd_rng_uchar( rng );
  uchar full_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( full_hash,  rand_uchar, FD_HASH_FOOTPRINT );
  uchar incr_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( incr_hash, ~rand_uchar, FD_HASH_FOOTPRINT );
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, 2UL*1000UL*1000UL,
                                   cluster_full_slot, cluster_incr_slot,
                                   full_hash, incr_hash )!=FD_SSPEER_SCORE_INVALID );

  /* Establish the cluster slot. */
  fd_sspeer_selector_process_cluster_slot( selector );

  /* Peer A should be a valid incremental candidate. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Re-add with the SAME full_slot via add() (production resolve path).
     The peer's incr_slot (8800) >= full_slot (8700), not stale,
     preserved. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   full_hash, NULL )!=FD_SSPEER_SCORE_INVALID );

  /* Peer A should STILL be a valid incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Advance full_slot past incr_slot so slot-based clear fires. */
  ulong new_full_slot = cluster_incr_slot + 1UL;
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   new_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   full_hash, NULL )!=FD_SSPEER_SCORE_INVALID );

  /* Peer A should no longer be an incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Peer A should still be valid for full selection with cleared incremental. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==new_full_slot );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  uchar zeroed_hash[ FD_HASH_FOOTPRINT ] = {0};
  FD_TEST( fd_memeq( best.incr_hash, zeroed_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.full_hash, full_hash, FD_HASH_FOOTPRINT ) );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cluster_slot_rescoring( fd_sspeer_selector_t * selector,
                             fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing cluster slot rescoring" ));

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_C; FD_TEST( generate_rand_addr_non_zero( &addr_C, rng ) );

  /* Add two peers with different incremental slots. */
  FD_TEST( add_peer( selector, key_A, addr_A, 9000UL, 9500UL, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_B, 9000UL, 9200UL, 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Compute max.  Full max = 9000.  Incr max = max(9200, 9500) = 9500.
     Cluster = (9000, 9500). */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==9000UL );
  FD_TEST( cs.incremental==9500UL );

  /* After rescore:
     Peer A: behind = max(0, 9500-9500) = 0.   score = 2_000_000.
     Peer B: behind = max(0, 9500-9200) = 300. score = 3_300_000. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Add a third peer to shift the max. */
  FD_TEST( add_peer( selector, key_C, addr_C, 9000UL, 9800UL, 4UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Recompute max.  Incr max = max(9200, 9500, 9800) = 9800.
     Cluster = (9000, 9800). */
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==9000UL );
  FD_TEST( cs.incremental==9800UL );

  /* Remove peer A (the one at 9500).
     Remaining incr: max(9200, 9800) = 9800.
     Cluster stays at (9000, 9800), no rescore needed. */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==9000UL );
  FD_TEST( cs.incremental==9800UL );

  /* Scores unchanged from the previous rescore at (9000, 9800):
     Peer B: behind = 9800-9200 = 600. score = 3_000_000 + 200*600^2 = 75_000_000.
     Peer C: behind = max(0, 9800-9800) = 0.   score = 4_000_000. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_C.l );
  FD_TEST( best.score==4UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_B );
  fd_sspeer_selector_remove( selector, key_C );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cluster_slot_regression( fd_sspeer_selector_t * selector,
                              fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing cluster slot regression" ));

  /* Verify that removing high-slot peers causes the max-based
     cluster slot to decrease, and that scoring adjusts correctly. */

  fd_sspeer_key_t keys[5];
  fd_ip4_port_t   addrs[5];
  for( ulong i=0; i<5UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &addrs[i], rng ) );
  }

  /* Add 5 peers: 3 at full=1000, 2 at full=500.
     Full max = 1000. */
  FD_TEST( add_peer( selector, &keys[0], addrs[0], 1000UL, 1500UL, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, &keys[1], addrs[1], 1000UL, 1500UL, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, &keys[2], addrs[2], 1000UL, 1500UL, 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, &keys[3], addrs[3],  500UL,  800UL, 4UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, &keys[4], addrs[4],  500UL,  800UL, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000UL );
  FD_TEST( cs.incremental==1500UL );

  /* Peer 3 (full=500): behind = 1000-500 = 500.
     score = 4_000_000 + 500*1000 = 4_500_000.
     Peer 0 (full=1000): behind = 0.
     score = 1_000_000. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addrs[0].l );
  FD_TEST( best.score==1UL*1000UL*1000UL );

  /* Remove 2 of the 3 high-slot peers.  Remaining:
     keys[2] at full=1000, keys[3] at full=500, keys[4] at full=500.
     Full max = 1000.  Incr max = 1500.
     Cluster stays at (1000, 1500), no regression yet. */
  fd_sspeer_selector_remove( selector, &keys[0] );
  fd_sspeer_selector_remove( selector, &keys[1] );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000UL );
  FD_TEST( cs.incremental==1500UL );

  /* No rescore needed (cluster unchanged).
     Peer 2 (full=1000, incr=1500): behind=0.  score = 3_000_000.
     Peer 3 (full=500, incr=800): behind=1500-800=700.
       score = 4_000_000 + 700_000 = 4_700_000.
     Peer 4 (full=500, incr=800): behind=700.
       score = 5_000_000 + 700_000 = 5_700_000.
     Best = peer 2 (lowest score). */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addrs[2].l );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  /* Remove the last high-slot peer.  Remaining:
     keys[3] at full=500, keys[4] at full=500.
     Full max = 500.  Incr max = 800.
     Cluster REGRESSES from (1000, 1500) to (500, 800). */
  fd_sspeer_selector_remove( selector, &keys[2] );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==500UL );
  FD_TEST( cs.incremental==800UL );

  /* Best = peer 3 (lat=4ms, behind=0). */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addrs[3].l );
  FD_TEST( best.score==4UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, &keys[3] );
  fd_sspeer_selector_remove( selector, &keys[4] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cluster_slot_recovery_after_poison( fd_sspeer_selector_t * selector,
                                         fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing cluster slot recovery after poison" ));

  /* Simulate the exact malicious scenario: a single malicious peer
     poisons the cluster slot with an extreme value, gets removed
     (blacklisted), and then an honest peer arrives and corrects
     the cluster slot. */

  fd_sspeer_key_t malicious_key[1]; FD_TEST( generate_rand_sspeer_key( malicious_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t honest_key[1];    FD_TEST( generate_rand_sspeer_key( honest_key,   rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t malicious_addr; FD_TEST( generate_rand_addr_non_zero( &malicious_addr, rng ) );
  fd_ip4_port_t honest_addr;    FD_TEST( generate_rand_addr_non_zero( &honest_addr,   rng ) );

  ulong poison_slot = FD_SSPEER_PLAUSIBLE_MAX_SLOT - 2UL;  /* just below plausibility bound */
  ulong honest_slot = 300000000UL;        /* realistic mainnet slot */

  /* Step 1: Malicious is the first and only peer.
     Max of 1 = the malicious's slot.  Cluster slot is poisoned. */
  FD_TEST( add_peer( selector, malicious_key, malicious_addr, poison_slot, poison_slot+1UL,
                     2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==poison_slot );
  FD_TEST( cs.incremental==poison_slot+1UL );

  /* Step 2: Malicious is removed (simulating blacklist_peer removing
     from selector).  With 0 peers, process_cluster_slot resets the
     cluster slot to {0, UNKNOWN}, clearing the poisoned value. */
  fd_sspeer_selector_remove( selector, malicious_key );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Verify no peer is available. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Step 3: Honest peer arrives.  Because the cluster slot was reset,
     add() scores the honest peer against {0, UNKNOWN}, the peer is
     ahead of the cluster, so slots_behind=0 and score=latency. */
  ulong initial_score = add_peer( selector, honest_key, honest_addr, honest_slot, honest_slot+100UL,
                                  5UL*1000UL*1000UL );
  FD_TEST( initial_score!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( initial_score==5UL*1000UL*1000UL ); /* no penalty inflation */

  /* Step 4: process_cluster_slot recomputes the max from the
     single honest peer.  Cluster slot updates to the honest value.
     No rescore is needed since the peer was already scored correctly. */
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==honest_slot );
  FD_TEST( cs.incremental==honest_slot+100UL );

  /* score = latency = 5_000_000. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==honest_addr.l );
  FD_TEST( best.full_slot==honest_slot );
  FD_TEST( best.incr_slot==honest_slot+100UL );
  FD_TEST( best.score==5UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, honest_key );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_poison_recovery_with_unresolved_peers( fd_sspeer_selector_t * selector,
                                             fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing poison recovery with unresolved peers" ));

  /* If a malicious peer poisons the cluster slot and is then removed
     while only unresolved (SLOT_UNKNOWN) peers remain, the cluster
     slot must reset. */

  fd_sspeer_key_t malicious_key[1]; FD_TEST( generate_rand_sspeer_key( malicious_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t unresolved_key[1]; FD_TEST( generate_rand_sspeer_key( unresolved_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t honest_key[1]; FD_TEST( generate_rand_sspeer_key( honest_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t malicious_addr; FD_TEST( generate_rand_addr_non_zero( &malicious_addr, rng ) );
  fd_ip4_port_t unresolved_addr; FD_TEST( generate_rand_addr_non_zero( &unresolved_addr, rng ) );
  fd_ip4_port_t honest_addr; FD_TEST( generate_rand_addr_non_zero( &honest_addr, rng ) );

  ulong poison_slot = 999UL;
  ulong honest_slot = 300UL;

  /* Malicious peer poisons the cluster slot. */
  FD_TEST( add_peer( selector, malicious_key, malicious_addr, poison_slot, poison_slot+1UL,
                     2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==poison_slot );

  /* Add an unresolved peer (full_slot==UNKNOWN). */
  FD_TEST( add_peer( selector, unresolved_key, unresolved_addr,
                     FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN,
                     3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Remove the malicious peer.  The unresolved peer remains.
     process_cluster_slot must reset because full_cnt==0 (the only
     remaining peer has UNKNOWN slots). */
  fd_sspeer_selector_remove( selector, malicious_key );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Honest peer arrives with real slots.  It should be scored
     against {0, UNKNOWN}, not the poisoned value. */
  ulong score = add_peer( selector, honest_key, honest_addr, honest_slot, honest_slot+100UL,
                           5UL*1000UL*1000UL );
  FD_TEST( score!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( score==5UL*1000UL*1000UL );  /* no penalty inflation */

  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==honest_slot );

  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==honest_addr.l );
  FD_TEST( best.score==5UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, unresolved_key );
  fd_sspeer_selector_remove( selector, honest_key );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_slot_zero( fd_sspeer_selector_t * selector,
                fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing slot zero" ));

  /* full_slot==0 and incr_slot==0 are valid slot values (e.g. genesis). */

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Peer at full_slot=0, incr_slot=0, latency 2ms. */
  FD_TEST( add_peer( selector, key_A, addr_A, 0UL, 0UL, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Compute cluster slot.  cluster = (0, 0). */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==0UL );

  /* Full selection: peer should be valid and best.  score = 2_000_000. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==0UL );
  FD_TEST( best.incr_slot==0UL );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Incremental selection with base_slot=0: peer's full_slot==0
     matches base_slot, and incr_slot==0 != FD_SSPEER_SLOT_UNKNOWN. */
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==0UL );
  FD_TEST( best.incr_slot==0UL );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Peer with full_slot==0, incr_slot==FD_SSPEER_SLOT_UNKNOWN: valid
     for full but NOT for incremental selection. */
  FD_TEST( add_peer( selector, key_B, addr_B, 0UL, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==0UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_score_saturation( fd_sspeer_selector_t * selector,
                       fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing score saturation" ));

  fd_sspeer_key_t key[1]; FD_TEST( generate_rand_sspeer_key( key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t   addr;   FD_TEST( generate_rand_addr_non_zero( &addr, rng ) );

  /* Cluster incremental is FD_SSPEER_SLOT_UNKNOWN (initial state):
     the score function falls back to comparing full_slot against
     cluster full slot.  Cluster full is 0, peer full is 10000, so
     the peer is ahead of the cluster and slots_behind=0.
     score = 5_000_000. */
  ulong score = add_peer( selector, key, addr, 10000UL, 10500UL, 5UL*1000UL*1000UL );
  FD_TEST( score==5UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Score is never FD_SSPEER_SCORE_INVALID. */
  FD_TEST( score!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( FD_SSPEER_SCORE_MAX<FD_SSPEER_SCORE_INVALID );

  /* Establish a cluster slot by adding a helper peer and computing
     the max. */
  fd_sspeer_key_t helper_key[1]; FD_TEST( generate_rand_sspeer_key( helper_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t   helper_addr;   FD_TEST( generate_rand_addr_non_zero( &helper_addr, rng ) );
  FD_TEST( add_peer( selector, helper_key, helper_addr, 10000UL, 10500UL, 100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==10000UL );
  FD_TEST( cs.incremental==10500UL );

  /* Normal score, no overflow: peer at cluster slot, latency 5ms. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10500UL, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Slots-behind penalty: peer incr_slot 100 behind cluster. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10400UL, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL + 200UL*100UL*100UL );
  fd_sspeer_selector_remove( selector, key );

  /* Default latency (FD_SSPEER_LATENCY_UNKNOWN input). */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10500UL, FD_SSPEER_LATENCY_UNKNOWN )==100UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Default latency + slot-behind penalty combined. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10400UL, FD_SSPEER_LATENCY_UNKNOWN )==100UL*1000UL*1000UL + 200UL*100UL*100UL );
  fd_sspeer_selector_remove( selector, key );

  /* Unresolved full slot: DEFAULT_SLOTS_BEHIND penalty. */
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL + 200UL*1000UL*1000UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* full_slot==UNKNOWN with incr_slot!=UNKNOWN is rejected. */
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_SLOT_UNKNOWN, 10500UL, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );

  /* Implausible slot values are rejected at the boundary. */
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_PLAUSIBLE_MAX_SLOT,    FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_PLAUSIBLE_MAX_SLOT+1UL,FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key, addr, 100UL, FD_SSPEER_PLAUSIBLE_MAX_SLOT,    5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_PLAUSIBLE_MAX_SLOT-1UL,FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_remove( selector, key );

  /* Score saturation: establish cluster near FD_SSPEER_PLAUSIBLE_MAX_SLOT
     via helper.  With MAX_SLOTS_BEHIND_CAP, the peer's slots_behind is
     capped to 864000 instead of the raw distance.
     score = 5_000_000 (latency) + 200 * 864_000^2 (capped penalty) = 149_299_205_000_000. */
  fd_sspeer_selector_remove( selector, helper_key );
  FD_TEST( add_peer( selector, helper_key, helper_addr, FD_SSPEER_PLAUSIBLE_MAX_SLOT-1UL, FD_SSPEER_PLAUSIBLE_MAX_SLOT-1UL, 100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  FD_TEST( add_peer( selector, key, addr, 0UL, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL + 200UL*864000UL*864000UL );
  fd_sspeer_selector_remove( selector, key );
  fd_sspeer_selector_remove( selector, helper_key );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_slots_behind_cap( fd_sspeer_selector_t * selector,
                       fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing slots_behind cap" ));

  fd_sspeer_key_t attacker_key[1]; FD_TEST( generate_rand_sspeer_key( attacker_key, rng, 0 ) );
  fd_ip4_port_t   attacker_addr;   FD_TEST( generate_rand_addr_non_zero( &attacker_addr, rng ) );

  fd_sspeer_key_t honest_key_A[1]; FD_TEST( generate_rand_sspeer_key( honest_key_A, rng, 0 ) );
  fd_ip4_port_t   honest_addr_A;   FD_TEST( generate_rand_addr_non_zero( &honest_addr_A, rng ) );

  fd_sspeer_key_t honest_key_B[1]; FD_TEST( generate_rand_sspeer_key( honest_key_B, rng, 0 ) );
  fd_ip4_port_t   honest_addr_B;   FD_TEST( generate_rand_addr_non_zero( &honest_addr_B, rng ) );

  /* Add attacker at slot 1,000,000. */
  FD_TEST( add_peer( selector, attacker_key, attacker_addr, 1000000UL, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Add honest peers at slot 300. */
  FD_TEST( add_peer( selector, honest_key_A, honest_addr_A, 300UL, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, honest_key_B, honest_addr_B, 300UL, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Recompute cluster_slot: max full becomes 1,000,000. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000000UL );

  /* Honest peers' scores should use capped slots_behind (864,000)
     instead of the raw 999,700.
     score = 5_000_000 (latency) + 200 * 864_000^2 (capped penalty) = 149_299_205_000_000. */
  fd_sspeer_key_t probe_key[1]; FD_TEST( generate_rand_sspeer_key( probe_key, rng, 0 ) );
  fd_ip4_port_t   probe_addr;   FD_TEST( generate_rand_addr_non_zero( &probe_addr, rng ) );
  ulong capped_score = add_peer( selector, probe_key, probe_addr, 300UL, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL );
  FD_TEST( capped_score==5UL*1000UL*1000UL + 200UL*864000UL*864000UL );

  /* Honest peers remain selectable (not saturated to SCORE_MAX). */
  FD_TEST( capped_score<FD_SSPEER_SCORE_MAX );

  /* Without the cap, score would have been 5_000_000 + 200 * 999_700^2 = 199_880_023_000_000,
     verify the capped score is strictly less. */
  FD_TEST( capped_score<5UL*1000UL*1000UL + 200UL*999700UL*999700UL );

  /* Cleanup. */
  fd_sspeer_selector_remove( selector, attacker_key );
  fd_sspeer_selector_remove( selector, honest_key_A );
  fd_sspeer_selector_remove( selector, honest_key_B );
  fd_sspeer_selector_remove( selector, probe_key );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_pool_exhaustion( fd_sspeer_selector_t * selector,
                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing pool exhaustion" ));

  ulong cluster_full = 1000UL;
  ulong cluster_incr = 1500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, 0 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, 0 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, 0 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_C; FD_TEST( generate_rand_addr_non_zero( &addr_C, rng ) );

  /* Fill to max capacity (max_peers=2). */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full, cluster_incr, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full, cluster_incr, 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* 3rd unique peer should be rejected (max capacity). */
  FD_TEST( add_peer( selector, key_C, addr_C, cluster_full, cluster_incr, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );

  /* Existing peers are unaffected. */
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Updating an existing peer still succeeds. */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full, cluster_incr, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Best peer should be A (updated to 1ms latency, score 1_000_000). */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==1UL*1000UL*1000UL );

  /* Remove a peer, then adding the 3rd peer should succeed. */
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( add_peer( selector, key_C, addr_C, cluster_full, cluster_incr, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  /* Clean up. */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_C );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_add_null_key( fd_sspeer_selector_t * selector,
                   fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing add null key" ));

  fd_ip4_port_t addr_A[1];
  FD_TEST( generate_rand_addr_non_zero( addr_A, rng ) );

  /* Adding with NULL key should return FD_SSPEER_SCORE_INVALID. */

  FD_TEST( add_peer( selector, NULL, *addr_A, 100UL, 200UL, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a valid peer, then try NULL key again to confirm no corruption. */

  fd_sspeer_key_t key_A[1];
  FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );

  ulong cluster_full_slot = 100UL;
  ulong cluster_incr_slot = 200UL;

  add_peer( selector, key_A, *addr_A, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_TEST( add_peer( selector, NULL, *addr_A, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup. */

  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_remove_null_key( fd_sspeer_selector_t * selector,
                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing remove null key" ));

  /* Remove with NULL key on empty selector should be a safe no-op. */

  fd_sspeer_selector_remove( selector, NULL );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a valid peer, then remove with NULL key to confirm no corruption. */

  fd_sspeer_key_t key_A[1];
  FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr_A[1];
  FD_TEST( generate_rand_addr_non_zero( addr_A, rng ) );

  ulong cluster_full_slot = 100UL;
  ulong cluster_incr_slot = 200UL;

  add_peer( selector, key_A, *addr_A, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  fd_sspeer_selector_remove( selector, NULL );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup. */

  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_remove_unknown_key( fd_sspeer_selector_t * selector,
                         fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing remove unknown key" ));

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr_A[1]; FD_TEST( generate_rand_addr_non_zero( addr_A, rng ) );

  /* Remove unknown key on empty selector should be a safe no-op. */

  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a valid peer, then remove a different unknown key. */

  ulong cluster_full_slot = 100UL;
  ulong cluster_incr_slot = 200UL;

  add_peer( selector, key_A, *addr_A, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup. */

  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_remove_by_addr_unknown( fd_sspeer_selector_t * selector,
                             fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing remove by addr unknown" ));

  fd_ip4_port_t addr_A[1]; FD_TEST( generate_rand_addr_non_zero( addr_A, rng ) );
  fd_ip4_port_t addr_B[1]; FD_TEST( generate_rand_addr_non_zero( addr_B, rng ) );

  /* Remove unknown addr on empty selector should be a safe no-op. */

  fd_sspeer_selector_remove_by_addr( selector, *addr_A );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a valid peer, then remove a different unknown addr. */

  fd_sspeer_key_t key_A[1];
  FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );

  ulong cluster_full_slot = 100UL;
  ulong cluster_incr_slot = 200UL;

  add_peer( selector, key_A, *addr_A, cluster_full_slot, cluster_incr_slot, 1UL*1000UL*1000UL );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  fd_sspeer_selector_remove_by_addr( selector, *addr_B );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup. */

  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_best_empty_selector( fd_sspeer_selector_t * selector,
                          fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing best on empty selector" ));
  (void)rng;

  /* Best on empty selector should return sentinel values. */

  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==0UL );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_ping_preserves_cleared_incremental( fd_sspeer_selector_t * selector,
                                         fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing ping preserves cleared incremental" ));

  ulong cluster_full_slot = 31000UL;
  ulong cluster_incr_slot = 31500UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );

  uchar full_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( full_hash, 0xAA, FD_HASH_FOOTPRINT );
  fd_memset( incr_hash, 0xBB, FD_HASH_FOOTPRINT );

  /* Add peer A with valid full + incremental and explicit hashes. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, 2UL*1000UL*1000UL,
                                   cluster_full_slot, cluster_incr_slot,
                                   full_hash, incr_hash )!=FD_SSPEER_SCORE_INVALID );

  /* Establish the cluster slot. */
  fd_sspeer_selector_process_cluster_slot( selector );

  /* Peer A should be a valid incremental candidate. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( fd_memeq( best.incr_hash, incr_hash, FD_HASH_FOOTPRINT ) );

  /* Clear the peer's incremental via slot-based clearing. */
  ulong new_full_slot = cluster_incr_slot + 1UL;
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   new_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   full_hash, NULL )!=FD_SSPEER_SCORE_INVALID );

  /* Peer A should no longer be an incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Verify cleared state. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==new_full_slot );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  uchar zeroed_hash[ FD_HASH_FOOTPRINT ] = {0};
  FD_TEST( fd_memeq( best.incr_hash, zeroed_hash, FD_HASH_FOOTPRINT ) );

  /* Send a ping update.  This must NOT restore the cleared
     incremental data. */
  FD_TEST( 1UL==fd_sspeer_selector_update_on_ping( selector, addr_A, 1UL*1000UL*1000UL ) );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( fd_memeq( best.incr_hash, zeroed_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.full_hash, full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( best.score==1UL*1000UL*1000UL );

  /* Still not a valid incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Send another ping update to verify repeated pings
     never restore stale incremental data. */
  FD_TEST( 1UL==fd_sspeer_selector_update_on_ping( selector, addr_A, 500UL*1000UL ) );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( fd_memeq( best.incr_hash, zeroed_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.full_hash, full_hash, FD_HASH_FOOTPRINT ) );

  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_stress_peer_count( fd_sspeer_selector_t * selector,
                        fd_rng_t *             rng,
                        ulong                  max_peers ) {
  FD_LOG_NOTICE(( "testing stress peer count (max_peers=%lu)", max_peers ));

  ulong const MAX_PEERS = 32UL;
  FD_TEST( MAX_PEERS==max_peers );
  ulong const TRY_CNT   = 34UL;

  ulong cluster_full_slot = 50000UL;
  ulong cluster_incr_slot = 50500UL;

  fd_sspeer_key_t keys[ 34 ];
  fd_ip4_port_t   addrs[ 34 ];

  /* Try to add 34 peers.  The first 32 should succeed, the remaining
     2 should be rejected (pool exhaustion).  With cluster at
     {0, UNKNOWN}, all peers are ahead so scores = latency. */

  ulong best_full_score = FD_SSPEER_SCORE_INVALID;
  ulong best_full_idx   = ULONG_MAX;
  ulong best_incr_score = FD_SSPEER_SCORE_INVALID;
  ulong best_incr_idx   = ULONG_MAX;
  ulong added_cnt       = 0UL;

  for( ulong i=0UL; i<TRY_CNT; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &addrs[i], rng ) );

    ulong latency = (i + 1UL) * 1000UL * 1000UL;

    ulong peer_incr_slot;
    if( i % 2UL == 0UL ) {
      ulong behind = i % 10UL;
      peer_incr_slot = cluster_incr_slot - behind;
    } else {
      peer_incr_slot = FD_SSPEER_SLOT_UNKNOWN;
    }

    ulong score = add_peer( selector, &keys[i], addrs[i], cluster_full_slot, peer_incr_slot, latency );

    if( i<MAX_PEERS ) {
      FD_TEST( score!=FD_SSPEER_SCORE_INVALID );
      added_cnt++;
      if( score<best_full_score ) {
        best_full_score = score;
        best_full_idx   = i;
      }
      if( i % 2UL == 0UL && score<best_incr_score ) {
        best_incr_score = score;
        best_incr_idx   = i;
      }
    } else {
      FD_TEST( score==FD_SSPEER_SCORE_INVALID );
    }
  }

  FD_TEST( added_cnt==MAX_PEERS );
  FD_TEST( best_full_idx==0UL );
  FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Verify best full and incremental peers. */

  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addrs[ best_full_idx ].l );
  FD_TEST( best.score==best_full_score );

  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addrs[ best_incr_idx ].l );
  FD_TEST( best.score==best_incr_score );

  /* Remove the best full peer and verify the next best. */

  fd_sspeer_selector_remove( selector, &keys[ best_full_idx ] );
  FD_TEST( (MAX_PEERS - 1UL)==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l!=0UL );
  FD_TEST( best.score>=best_full_score );

  /* Now that a slot is free, one of the previously rejected peers
     (index 32) should succeed. */

  {
    ulong overflow_idx = 32UL;
    ulong overflow_lat = (overflow_idx + 1UL) * 1000UL * 1000UL;
    ulong overflow_inc = overflow_idx % 2UL == 0UL
                         ? cluster_incr_slot - (overflow_idx % 10UL)
                         : FD_SSPEER_SLOT_UNKNOWN;
    FD_TEST( add_peer( selector, &keys[ overflow_idx ], addrs[ overflow_idx ],
                       cluster_full_slot, overflow_inc, overflow_lat )!=FD_SSPEER_SCORE_INVALID );
    FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

    fd_sspeer_selector_remove( selector, &keys[ overflow_idx ] );
  }
  for( ulong i=0UL; i<MAX_PEERS; i+=2UL ) {
    fd_sspeer_selector_remove( selector, &keys[ i ] );
  }

  ulong remaining = fd_sspeer_selector_peer_map_by_key_ele_cnt( selector );
  FD_TEST( remaining==16UL );
  FD_TEST( remaining==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  if( remaining>0UL ) {
    FD_TEST( best.addr.l!=0UL );
    FD_TEST( best.score!=FD_SSPEER_SCORE_INVALID );
  }

  /* Compute the cluster slot from the max of remaining peers. */

  fd_sspeer_selector_process_cluster_slot( selector );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  if( remaining>0UL ) {
    FD_TEST( best.addr.l!=0UL );
    FD_TEST( best.score!=FD_SSPEER_SCORE_INVALID );
  }

  /* Re-add removed peers to fill back to capacity. */

  for( ulong i=0UL; i<MAX_PEERS; i+=2UL ) {
    ulong lat = (i + 1UL) * 1000UL * 1000UL;
    ulong inc = cluster_incr_slot - (i % 10UL);
    add_peer( selector, &keys[ i ], addrs[ i ], cluster_full_slot, inc, lat );
  }

  FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Verify incremental selection still works. */

  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  if( best.addr.l ) {
    FD_TEST( best.full_slot==cluster_full_slot );
    FD_TEST( best.incr_slot!=FD_SSPEER_SLOT_UNKNOWN );
    FD_TEST( best.score!=FD_SSPEER_SCORE_INVALID );
  }

  /* Clean up all peers. */
  for( ulong i=0UL; i<TRY_CNT; i++ ) {
    fd_sspeer_selector_remove( selector, &keys[i] );
  }
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_genesis_cluster_slot( fd_sspeer_selector_t * selector,
                           fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing genesis cluster slot" ));

  /* Verify initial state. */
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Add peers to establish cluster = (0, 0) via max. */
  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_C; FD_TEST( generate_rand_addr_non_zero( &addr_C, rng ) );

  FD_TEST( add_peer( selector, key_A, addr_A, 0UL, 0UL,                      2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_B, 0UL, FD_SSPEER_SLOT_UNKNOWN,   3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==0UL );

  /* Verify scoring when cluster.incremental == cluster.full == 0. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==0UL );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Add peer C at (0, 5).
     Incr max = max(0, 5) = 5 (peer B has UNKNOWN).
     Cluster = (0, 5). */
  FD_TEST( add_peer( selector, key_C, addr_C, 0UL, 5UL, 4UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==5UL );

  /* After rescore with cluster=(0, 5):
     Peer A (incr=0): behind = 5-0 = 5.  score = 2_005_000.
     Peer C (incr=5): behind = 0.  score = 4_000_000.
     Best incremental = Peer A. */
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 5UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  fd_sspeer_selector_remove( selector, key_C );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_invalid_clear_and_best_sentinel( fd_sspeer_selector_t * selector,
                                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing invalid clear and best sentinel" ));

  ulong cluster_full_slot = 9500UL;
  ulong cluster_incr_slot = 9600UL;

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );

  uchar full_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( full_hash, 0xAB, FD_HASH_FOOTPRINT );
  uchar incr_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( incr_hash, 0xCD, FD_HASH_FOOTPRINT );

  /* Add peer A with valid full+incremental. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, 2UL*1000UL*1000UL,
                                   cluster_full_slot, cluster_incr_slot,
                                   full_hash, incr_hash )!=FD_SSPEER_SCORE_INVALID );

  /* Establish cluster slot. */
  fd_sspeer_selector_process_cluster_slot( selector );

  /* add() with same full_slot preserves incremental. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                   full_hash, NULL )!=FD_SSPEER_SCORE_INVALID );

  /* Peer A should be unaffected (incremental preserved). */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( fd_memeq( best.full_hash, full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.incr_hash, incr_hash, FD_HASH_FOOTPRINT ) );

  /* full_slot==UNKNOWN with incr_slot!=UNKNOWN is invalid for new peer. */
  fd_sspeer_key_t key_new[1]; FD_TEST( generate_rand_sspeer_key( key_new, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_new; FD_TEST( generate_rand_addr_non_zero( &addr_new, rng ) );
  FD_TEST( fd_sspeer_selector_add( selector, key_new, addr_new, 2UL*1000UL*1000UL,
                                   FD_SSPEER_SLOT_UNKNOWN, cluster_incr_slot,
                                   NULL, NULL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* add() with full_slot==UNKNOWN and incr_slot!=UNKNOWN on an
     existing peer with known full_slot succeeds because the update
     path uses the peer's stored full_slot. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   FD_SSPEER_SLOT_UNKNOWN, cluster_incr_slot,
                                   NULL, incr_hash )!=FD_SSPEER_SCORE_INVALID );

  /* fd_sspeer_selector_best with incremental=1 and
     base_slot=FD_SSPEER_SLOT_UNKNOWN should return the sentinel. */
  best = fd_sspeer_selector_best( selector, 1, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* incr_slot < full_slot rejection. */

  /* add() for a new peer with incr_slot < full_slot must be rejected. */
  FD_TEST( add_peer( selector, key_new, addr_new, 200UL, 100UL, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* add() updating an existing peer with incr_slot < full_slot must be
     rejected, and the peer must remain unmodified. */
  FD_TEST( add_peer( selector, key_A, addr_A, 300UL, 100UL, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* incr_slot == full_slot boundary (non-genesis). */

  /* add() for a new peer with incr_slot == full_slot must be accepted. */
  FD_TEST( add_peer( selector, key_new, addr_new, 500UL, 500UL, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_remove( selector, key_new );

  /* add() updating an existing peer with incr_slot == full_slot must
     be accepted. */
  FD_TEST( add_peer( selector, key_A, addr_A, 500UL, 500UL, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* add() updating with incr_slot == full_slot via full add path. */
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   600UL, 600UL,
                                   full_hash, incr_hash )!=FD_SSPEER_SCORE_INVALID );

  /* Cleanup. */
  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_max_high_slot_outlier( fd_sspeer_selector_t * selector,
                            fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing max high slot outlier" ));

  /* Add 5 honest peers at slot 300. */
  fd_sspeer_key_t honest_keys[5];
  fd_ip4_port_t   honest_addrs[5];
  for( ulong i=0; i<5UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &honest_keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &honest_addrs[i], rng ) );
    FD_TEST( add_peer( selector, &honest_keys[i], honest_addrs[i],
                       300UL, 300UL,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  /* Add malicious peer with high slot. */
  fd_sspeer_key_t atk_key[1]; FD_TEST( generate_rand_sspeer_key( atk_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t   atk_addr;   FD_TEST( generate_rand_addr_non_zero( &atk_addr, rng ) );
  FD_TEST( add_peer( selector, atk_key, atk_addr,
                     1000UL, 1000UL,
                     100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Compute max.  6 peers total.
     Full max = 1000.  Incr max = 1000.
     The outlier shifts the cluster slot to (1000, 1000), but the
     attacker's high latency (100ms) makes it uncompetitive. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000UL );
  FD_TEST( cs.incremental==1000UL );

  /* Honest peer 0: behind = 1000-300 = 700.
     score = 1_000_000 + 200*700^2 = 99_000_000.
     Attacker: behind = 0.  score = 100_000_000.
     Best is still honest peer 0. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==honest_addrs[0].l );
  FD_TEST( best.score==1UL*1000UL*1000UL + 200UL*700UL*700UL );

  /* Cleanup */
  for( ulong i=0; i<5UL; i++ ) {
    fd_sspeer_selector_remove( selector, &honest_keys[i] );
  }
  fd_sspeer_selector_remove( selector, atk_key );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* ... Two malicious: 5 honest + 2 malicious = 7 total.
     Max = 1000.  The outliers shift the cluster slot but honest
     peer 0 is still best due to lower latency. */

  for( ulong i=0; i<5UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &honest_keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &honest_addrs[i], rng ) );
    FD_TEST( add_peer( selector, &honest_keys[i], honest_addrs[i],
                       300UL, 300UL,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_key_t mal_keys_2[2];
  fd_ip4_port_t   mal_addrs_2[2];
  for( ulong i=0; i<2UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &mal_keys_2[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &mal_addrs_2[i], rng ) );
    FD_TEST( add_peer( selector, &mal_keys_2[i], mal_addrs_2[i],
                       1000UL, 1000UL,
                       100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000UL );
  FD_TEST( cs.incremental==1000UL );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==honest_addrs[0].l );
  FD_TEST( best.score==1UL*1000UL*1000UL + 200UL*700UL*700UL );

  for( ulong i=0; i<5UL; i++ ) fd_sspeer_selector_remove( selector, &honest_keys[i] );
  for( ulong i=0; i<2UL; i++ ) fd_sspeer_selector_remove( selector, &mal_keys_2[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  /* ... N/2 malicious: 3 honest + 3 malicious = 6 total.
     Max = 1000.  Even at 50% malicious, the max stays at 1000 and
     honest peer 0 (lowest latency) is still the best choice. */

  for( ulong i=0; i<3UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &honest_keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &honest_addrs[i], rng ) );
    FD_TEST( add_peer( selector, &honest_keys[i], honest_addrs[i],
                       300UL, 300UL,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_key_t mal_keys_3[3];
  fd_ip4_port_t   mal_addrs_3[3];
  for( ulong i=0; i<3UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &mal_keys_3[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &mal_addrs_3[i], rng ) );
    FD_TEST( add_peer( selector, &mal_keys_3[i], mal_addrs_3[i],
                       1000UL, 1000UL,
                       100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==1000UL );
  FD_TEST( cs.incremental==1000UL );

  for( ulong i=0; i<3UL; i++ ) fd_sspeer_selector_remove( selector, &honest_keys[i] );
  for( ulong i=0; i<3UL; i++ ) fd_sspeer_selector_remove( selector, &mal_keys_3[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_max_low_slot_outlier( fd_sspeer_selector_t * selector,
                           fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing max low slot outlier" ));

  /* Verify that malicious peers reporting low slot values cannot drag
     the cluster slot down — max ignores low outliers entirely. */

  fd_sspeer_key_t honest_keys[5];
  fd_ip4_port_t   honest_addrs[5];
  for( ulong i=0; i<5UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &honest_keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &honest_addrs[i], rng ) );
    FD_TEST( add_peer( selector, &honest_keys[i], honest_addrs[i],
                       300UL, 300UL,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  /* Add 1 malicious peer with slot 0. */
  fd_sspeer_key_t mal_key[1]; FD_TEST( generate_rand_sspeer_key( mal_key, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t   mal_addr;   FD_TEST( generate_rand_addr_non_zero( &mal_addr, rng ) );
  FD_TEST( add_peer( selector, mal_key, mal_addr,
                     0UL, 0UL,
                     100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* 6 peers total.  Full max = 300.  Incr max = 300.
     Low outlier at 0 cannot affect the max. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==300UL );
  FD_TEST( cs.incremental==300UL );

  /* Cleanup */
  for( ulong i=0; i<5UL; i++ ) fd_sspeer_selector_remove( selector, &honest_keys[i] );
  fd_sspeer_selector_remove( selector, mal_key );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  /* 2 malicious low-slot + 5 honest = 7 total.
     Max = 300.  Low outliers do not affect the max. */
  for( ulong i=0; i<5UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &honest_keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &honest_addrs[i], rng ) );
    FD_TEST( add_peer( selector, &honest_keys[i], honest_addrs[i],
                       300UL, 300UL,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_key_t mal_keys_2[2];
  fd_ip4_port_t   mal_addrs_2[2];
  for( ulong i=0; i<2UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &mal_keys_2[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &mal_addrs_2[i], rng ) );
    FD_TEST( add_peer( selector, &mal_keys_2[i], mal_addrs_2[i],
                       0UL, 0UL,
                       100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==300UL );
  FD_TEST( cs.incremental==300UL );

  for( ulong i=0; i<5UL; i++ ) fd_sspeer_selector_remove( selector, &honest_keys[i] );
  for( ulong i=0; i<2UL; i++ ) fd_sspeer_selector_remove( selector, &mal_keys_2[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  /* 3 malicious low-slot + 3 honest = 6 total (50% split).
     Max = max(0, 0, 0, 300, 300, 300) = 300.
     Unlike median, max is fully robust against low-slot attackers
     regardless of their count. */
  for( ulong i=0; i<3UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &honest_keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &honest_addrs[i], rng ) );
    FD_TEST( add_peer( selector, &honest_keys[i], honest_addrs[i],
                       300UL, 300UL,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_key_t mal_keys_3[3];
  fd_ip4_port_t   mal_addrs_3[3];
  for( ulong i=0; i<3UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &mal_keys_3[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &mal_addrs_3[i], rng ) );
    FD_TEST( add_peer( selector, &mal_keys_3[i], mal_addrs_3[i],
                       0UL, 0UL,
                       100UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==300UL );
  FD_TEST( cs.incremental==300UL );

  for( ulong i=0; i<3UL; i++ ) fd_sspeer_selector_remove( selector, &honest_keys[i] );
  for( ulong i=0; i<3UL; i++ ) fd_sspeer_selector_remove( selector, &mal_keys_3[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_all_unknown_slots( fd_sspeer_selector_t * selector,
                        fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing all unknown slots" ));

  /* When every tracked peer has full_slot==UNKNOWN, adding those
     peers does not mark the cluster slot dirty, so
     process_cluster_slot() is a no-op here.  If the cluster slot were
     dirty and there were still no known full slots, processing would
     reset it to {0, UNKNOWN}. */

  fd_sspeer_key_t keys[3];
  fd_ip4_port_t   addrs[3];
  for( ulong i=0; i<3UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &addrs[i], rng ) );
    FD_TEST( add_peer( selector, &keys[i], addrs[i],
                       FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN,
                       (i+1UL)*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  /* Cluster slot should remain at initial values {0, UNKNOWN} since
     no peer has a known full_slot.  The dirty flag should not have been
     set (add with UNKNOWN full_slot doesn't set dirty). */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* None of the peers are valid (full_slot==UNKNOWN), so best
     should return the sentinel. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Cleanup */
  for( ulong i=0; i<3UL; i++ ) fd_sspeer_selector_remove( selector, &keys[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_process_cluster_slot_idempotent( fd_sspeer_selector_t * selector,
                                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing process_cluster_slot idempotency" ));

  /* Calling process_cluster_slot multiple times with no changes in
     between should be a no-op (the dirty flag prevents recomputation). */

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  FD_TEST( add_peer( selector, key_A, addr_A, 5000UL, 5500UL, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_B, 6000UL, 6500UL, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* First call: computes max and rescores. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs1 = fd_sspeer_selector_cluster_slot( selector );
  fd_sspeer_t best1 = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );

  /* Second call: dirty flag is clear, should be a no-op. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs2 = fd_sspeer_selector_cluster_slot( selector );
  fd_sspeer_t best2 = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );

  FD_TEST( cs1.full==cs2.full );
  FD_TEST( cs1.incremental==cs2.incremental );
  FD_TEST( best1.addr.l==best2.addr.l );
  FD_TEST( best1.score==best2.score );

  /* Third call: still a no-op. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs3 = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs2.full==cs3.full );
  FD_TEST( cs2.incremental==cs3.incremental );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_full_only_cluster_rescore( fd_sspeer_selector_t * selector,
                                fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing full only cluster rescore" ));

  /* When no peers have incremental slots, the cluster incremental
     should remain UNKNOWN and scoring should fall back to comparing
     full_slot against the cluster full slot. */

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_C; FD_TEST( generate_rand_addr_non_zero( &addr_C, rng ) );

  /* Add 3 peers with only full slots (incr=UNKNOWN). */
  FD_TEST( add_peer( selector, key_A, addr_A, 1000UL, FD_SSPEER_SLOT_UNKNOWN, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_B, 2000UL, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_C, addr_C, 3000UL, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Max of full slots [1000, 2000, 3000] = 3000.
     Incr: no known values -> stays UNKNOWN. */
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==3000UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Scoring falls back to full_slot comparison:
     Peer A: behind = 3000-1000 = 2000.
       score = 1_000_000 + 2000*1000 = 3_000_000.
     Peer B: behind = 3000-2000 = 1000.
       score = 2_000_000 + 1000*1000 = 3_000_000.
     Peer C: behind = max(0, 3000-3000) = 0.
       score = 3_000_000.
     All tied at 3_000_000, treap ordering decides. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  /* Remove the highest-slot peer.  Remaining: [1000, 2000].
     Max = 2000.  Incr: still UNKNOWN. */
  fd_sspeer_selector_remove( selector, key_C );
  fd_sspeer_selector_process_cluster_slot( selector );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==2000UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* After rescore with cluster=(2000, UNKNOWN):
     Peer A: behind = 2000-1000 = 1000.  score = 2_000_000.
     Peer B: behind = max(0, 2000-2000) = 0.  score = 2_000_000.
     Both tied at 2_000_000, treap ordering decides. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_max_incr_clamped_to_full( fd_sspeer_selector_t * selector,
                               fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing max_incr < max_full clamping" ));

  /* A(full=2000,incr=UNKNOWN), B(full=3000,incr=UNKNOWN), C(full=500,incr=500).
     Full max = 3000.  Incr max = 500.
     500 < 3000 -> clamped to (3000, 3000). */
  fd_sspeer_key_t keys[3]; fd_ip4_port_t addrs[3];
  for( ulong i=0; i<3UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &keys[i], rng, fd_rng_uint( rng )&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &addrs[i], rng ) );
  }
  FD_TEST( add_peer( selector, &keys[0], addrs[0], 2000UL, FD_SSPEER_SLOT_UNKNOWN, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, &keys[1], addrs[1], 3000UL, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, &keys[2], addrs[2],  500UL,  500UL,                 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==3000UL );
  FD_TEST( cs.incremental==3000UL );  /* clamped from 500 */

  for( ulong i=0; i<3UL; i++ ) fd_sspeer_selector_remove( selector, &keys[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_max_four_distinct( fd_sspeer_selector_t * selector,
                        fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing max four distinct" ));

  /* max of [300,100,400,200] = 400 */
  fd_sspeer_key_t keys[4];
  fd_ip4_port_t   addrs[4];
  ulong slots[] = { 300UL, 100UL, 400UL, 200UL }; /* insertion order != sorted */
  for( ulong i=0; i<4UL; i++ ) {
    FD_TEST( generate_rand_sspeer_key( &keys[i], rng, fd_rng_uint(rng)&0x1 ) );
    FD_TEST( generate_rand_addr_non_zero( &addrs[i], rng ) );
    FD_TEST( add_peer( selector, &keys[i], addrs[i], slots[i], FD_SSPEER_SLOT_UNKNOWN, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  }

  fd_sspeer_selector_process_cluster_slot( selector );
  FD_TEST( fd_sspeer_selector_cluster_slot( selector ).full==400UL );

  for( ulong i=0; i<4UL; i++ ) fd_sspeer_selector_remove( selector, &keys[i] );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_dirty_but_max_unchanged( fd_sspeer_selector_t * selector,
                              fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing dirty but max unchanged" ));

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, 0 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, 0 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  FD_TEST( add_peer( selector, key_A, addr_A, 5000UL, 5500UL, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );
  fd_sspeer_t best1 = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );

  /* Add and then remove a peer with UNKNOWN slots.  The add cannot
     change max; the remove is what marks the selector dirty. */
  FD_TEST( add_peer( selector, key_B, addr_B, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_remove( selector, key_B );
  fd_sspeer_selector_process_cluster_slot( selector );

  fd_sspeer_t best2 = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best1.score==best2.score );

  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_noop_readd( fd_sspeer_selector_t * selector,
                 fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing noop readd" ));

  fd_sspeer_key_t key[1]; FD_TEST( generate_rand_sspeer_key( key, rng, 0 ) );
  fd_ip4_port_t addr; FD_TEST( generate_rand_addr_non_zero( &addr, rng ) );

  ulong score1 = add_peer( selector, key, addr, 5000UL, 5500UL, 1UL*1000UL*1000UL );
  FD_TEST( score1!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( selector );

  /* Re-add with same slots, should not change score. */
  ulong score2 = add_peer( selector, key, addr, 5000UL, 5500UL, 1UL*1000UL*1000UL );
  FD_TEST( score1==score2 );

  fd_sspeer_selector_remove( selector, key );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  uint rng_seed = fd_env_strip_cmdline_uint( &argc, &argv, "--seed", NULL, 3714951721/* arbitrary seed, reproducible CI */ );
  if( FD_UNLIKELY( !rng_seed ) ) rng_seed = (uint)fd_log_wallclock(); /* random seed, used for development */
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, rng_seed, 0UL ) );
  FD_LOG_NOTICE(( "rng seed %u", rng_seed ));

  /* Initialize and verify. */

  FD_TEST( wksp );
  test_wksp_t t_wksp_base  = {0};
  test_wksp_t t_wksp_small = {0};
  test_wksp_t t_wksp_stress= {0};

  test_wksp_init( wksp,
                  &t_wksp_base,
                  65536UL/*max_peers*/,
                  fd_rng_ulong( rng )/*seed*/ );

  test_wksp_init( wksp,
                  &t_wksp_small,
                  2UL/*max_peers*/,
                  fd_rng_ulong( rng )/*seed*/ );

  test_wksp_init( wksp,
                  &t_wksp_stress,
                  32UL/*max_peers*/,
                  fd_rng_ulong( rng )/*seed*/ );

  verify_initial_cluster_slot( t_wksp_base.selector );
  verify_initial_cluster_slot( t_wksp_small.selector );
  verify_initial_cluster_slot( t_wksp_stress.selector );

  /* Subtests.  Each test reinitializes its workspace to start from
     a clean state. */

  test_wksp_reinit( &t_wksp_base );
  test_slot_zero( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_basic_peer_selection( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_duplicate_peers( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_peer_addr_change( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_update_on_ping( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_resolve_via_add( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_address_zero( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_duplicate_hostnames( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_add_clears_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_on_resolve_clears_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_cluster_slot_rescoring( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_cluster_slot_regression( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_cluster_slot_recovery_after_poison( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_poison_recovery_with_unresolved_peers( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_score_saturation( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_slots_behind_cap( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_small );
  test_pool_exhaustion( t_wksp_small.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_add_null_key( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_remove_null_key( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_remove_unknown_key( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_remove_by_addr_unknown( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_best_empty_selector( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_genesis_cluster_slot( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_invalid_clear_and_best_sentinel( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_ping_preserves_cleared_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_stress );
  test_stress_peer_count( t_wksp_stress.selector, rng, t_wksp_stress.max_peers );

  test_wksp_reinit( &t_wksp_base );
  test_max_high_slot_outlier( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_max_low_slot_outlier( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_all_unknown_slots( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_process_cluster_slot_idempotent( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_full_only_cluster_rescore( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_max_incr_clamped_to_full( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_max_four_distinct( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_dirty_but_max_unchanged( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_noop_readd( t_wksp_base.selector, rng );

  /* Cleanup. */

  fd_rng_delete( fd_rng_leave( rng ) );
  test_wksp_fini( &t_wksp_base );
  test_wksp_fini( &t_wksp_small );
  test_wksp_fini( &t_wksp_stress );

  fd_halt();
  return 0;
}
