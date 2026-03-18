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
   int                    incr_snap_fetch;
   ulong                  seed;
};
typedef struct test_wksp_struct test_wksp_t;

static void
test_wksp_init( fd_wksp_t *   wksp,
                test_wksp_t * t_wksp,
                ulong         max_peers,
                int           incr_snap_fetch,
                ulong         seed ) {
  FD_TEST( t_wksp->selector==NULL );
  FD_TEST( t_wksp->shmem==NULL );
  t_wksp->shmem    = fd_wksp_alloc_laddr( wksp, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( max_peers ), 1UL );
  t_wksp->selector = fd_sspeer_selector_join( fd_sspeer_selector_new( t_wksp->shmem, max_peers, incr_snap_fetch, seed ) );
  FD_TEST( t_wksp->selector );
  t_wksp->max_peers       = max_peers;
  t_wksp->incr_snap_fetch = incr_snap_fetch;
  t_wksp->seed            = seed;
}

static void
test_wksp_reinit( test_wksp_t * t_wksp ) {
  FD_TEST( t_wksp->selector!=NULL );
  FD_TEST( fd_sspeer_selector_delete( fd_sspeer_selector_leave( t_wksp->selector ) )==t_wksp->shmem );
  FD_TEST( fd_sspeer_selector_join( fd_sspeer_selector_new( t_wksp->shmem, t_wksp->max_peers, t_wksp->incr_snap_fetch, t_wksp->seed ) )==t_wksp->selector );
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

  ulong cluster_full_slot = 1000UL;
  ulong cluster_incr_slot = 1500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer and it should be the best peer */
  fd_sspeer_key_t key[1]; FD_TEST( generate_rand_sspeer_key( key, rng, fd_rng_int( rng )&0x1/*is_url*/) );
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 35, 123, 172, 227 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key, addr, 1000UL, 1500UL, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==5UL*1000UL*1000UL );

  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer with better latency at the same slot and it should be
     the best peer */
  fd_sspeer_key_t key2[1]; FD_TEST( generate_rand_sspeer_key( key2, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr2 = { .addr = FD_IP4_ADDR( 35, 123, 172, 228 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key2, addr2, 1000UL, 1500UL, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer with the same latency but lagging slots behind */
  fd_sspeer_key_t key3[1]; FD_TEST( generate_rand_sspeer_key( key3, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr3 = { .addr = FD_IP4_ADDR( 35, 123, 172, 229 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key3, addr3, 1000UL, 1400UL, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL + 100UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  FD_TEST( 3UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 3UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  cluster_incr_slot = 1600UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  /* Add a peer that is slightly slower but caught up in slots */
  fd_sspeer_key_t key4[1]; FD_TEST( generate_rand_sspeer_key( key4, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr4 = { .addr = FD_IP4_ADDR( 35, 123, 172, 230 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key4, addr4, 1000UL, 1600UL, 3UL*1000UL*1000UL + 75UL*1000UL )==3UL*1000UL*1000UL + 75UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3UL*1000UL*1000UL + 75UL*1000UL );

  FD_TEST( 4UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 4UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a fast peer that doesn't have resolved slots */
  fd_sspeer_key_t key5[1]; FD_TEST( generate_rand_sspeer_key( key5, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr5 = { .addr = FD_IP4_ADDR( 35, 123, 172, 231 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key5, addr5, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL + 1000UL*1000UL*1000UL);
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3UL*1000UL*1000UL + 75UL*1000UL );

  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Test incremental peer selection */
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3UL*1000UL*1000UL + 75UL*1000UL );

  cluster_incr_slot = 1700UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  /* Add a peer that is fast and at the highest slot but not building
     off full slot, which makes it an invalid incremental peer */
  fd_sspeer_key_t key6[1]; FD_TEST( generate_rand_sspeer_key( key6, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr6 = { .addr = FD_IP4_ADDR( 35, 123, 172, 232 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key6, addr6, 900UL, 1700UL, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3UL*1000UL*1000UL + 75UL*1000UL + 100UL*1000UL );

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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t key_pub_A[1]; FD_TEST( generate_rand_sspeer_key( key_pub_A, rng, 0 ) );
  fd_sspeer_key_t key_pub_B[1]; FD_TEST( generate_rand_sspeer_key( key_pub_B, rng, 0 ) );
  fd_sspeer_key_t key_url_A[1]; FD_TEST( generate_rand_sspeer_key( key_url_A, rng, 1 ) );
  fd_sspeer_key_t key_url_B[1]; FD_TEST( generate_rand_sspeer_key( key_url_B, rng, 1 ) );
  fd_ip4_port_t addr0; FD_TEST( generate_rand_addr_non_zero( &addr0, rng ) );
  /* This is a test, but in reality resolved_addr should match addr0. */
  fd_sspeer_key_t key_url_C[1]; *key_url_C = *key_url_A; key_url_C->url.resolved_addr.l = (key_url_A->url.resolved_addr.l ^ 2UL) | 1UL;

  /* Add peers with same addr, same full_slot and incr_slot. */

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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A;  FD_TEST( generate_rand_addr_non_zero( &addr_A,  rng ) );
  fd_ip4_port_t addr_A1; FD_TEST( generate_rand_addr_non_zero( &addr_A1, rng ) );
  fd_ip4_port_t addr_B;  FD_TEST( generate_rand_addr_non_zero( &addr_B,  rng ) );

  /* Add 2 peers change the addr of one of them. */

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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_D[1]; FD_TEST( generate_rand_sspeer_key( key_D, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_E[1]; FD_TEST( generate_rand_sspeer_key( key_E, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_AB; FD_TEST( generate_rand_addr_non_zero( &addr_AB, rng ) );
  fd_ip4_port_t addr_CD; FD_TEST( generate_rand_addr_non_zero( &addr_CD, rng ) );
  fd_ip4_port_t addr_E;  FD_TEST( generate_rand_addr_non_zero( &addr_E,  rng ) );
  fd_ip4_port_t addr_X;  FD_TEST( generate_rand_addr_non_zero( &addr_X,  rng ) );

  /* Add 5 peers: pairs AB, CD and single E. */

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

  /* Verify hashes are preserved after update_on_ping.  Add a peer with
     explicit hashes, update latency via ping, and confirm hashes are
     unchanged. */
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
test_update_on_resolve( fd_sspeer_selector_t * selector,
                        fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing update on_resolve" ));

  ulong cluster_full_slot = 5000UL;
  ulong cluster_incr_slot = 5500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, 1/*is_url*/ ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, 1/*is_url*/ ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Add 2 peers and update gradually. */

  /* ... peer A latency 3us, expected best score 3e6 (the expected
     score must not match the default one). */
  FD_TEST( add_peer( selector, key_A, addr_A, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )!=3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, NULL,  cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_ERR_NULL_KEY );
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_B, cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_ERR_NOT_FOUND );
  FD_TEST(fd_sspeer_selector_update_on_resolve( selector, key_A, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, NULL, NULL )==FD_SSPEER_UPDATE_SUCCESS  );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );
  /* full_slot==UNKNOWN with incr_slot!=UNKNOWN is now rejected
     (an incremental slot requires a known full slot). */
  FD_TEST(fd_sspeer_selector_update_on_resolve( selector, key_A, FD_SSPEER_SLOT_UNKNOWN, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_ERR_INVALID_ARG  );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );
  FD_TEST(fd_sspeer_selector_update_on_resolve( selector, key_A, cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_SUCCESS  );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3UL*1000UL*1000UL );

  /* ... peer B latency 2us, expected best score 2e6 (the expected
     score must not match the default one). */
  FD_TEST( add_peer( selector, key_B, addr_B, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )!=2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3UL*1000UL*1000UL );
  FD_TEST(fd_sspeer_selector_update_on_resolve( selector, key_B, cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_SUCCESS  );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Cleanup and verification. */
  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST(fd_sspeer_selector_update_on_resolve( selector, key_A, cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_ERR_NOT_FOUND );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST(fd_sspeer_selector_update_on_resolve( selector, key_B, cluster_full_slot, cluster_incr_slot, NULL, NULL )==FD_SSPEER_UPDATE_ERR_NOT_FOUND );
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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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

  /* Add both peers with valid addresses. */
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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  /* Two HTTP servers with same hostname but different resolved_addr. */
  fd_sspeer_key_t key_url_A[1]; FD_TEST( generate_rand_sspeer_key( key_url_A, rng, 1 ) );
  fd_sspeer_key_t key_url_B[1]; *key_url_B = *key_url_A; key_url_B->url.resolved_addr.l = (key_url_A->url.resolved_addr.l ^ 2UL) | 1UL;
  fd_ip4_port_t addr_A = key_url_A->url.resolved_addr;
  fd_ip4_port_t addr_B = key_url_B->url.resolved_addr;

  /* Add both peers with valid addresses. */
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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_N; FD_TEST( generate_rand_addr_non_zero( &addr_N, rng ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Add peer A with valid incremental. */
  FD_TEST( add_peer( selector, key_A, addr_N, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
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
     be preserved (slot-based clearing only clears when incr_slot <
     full_slot). */
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

  /* Clear incremental by advancing full_slot past the peer's incr_slot.
     Peer has incr_slot=8500, new full_slot=8501 > 8500, so the
     incremental is genuinely stale and should be cleared. */
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

  /* Now clear with full_slot one past incr_slot: incr_slot (8500) <
     full_slot (8501), genuinely stale. */
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

  /* Re-add peer A with a valid incremental slot.  This verifies the
     full transition cycle: has-incremental -> clear -> has-incremental. */
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
     be preserved (not overwritten) and the incr_hash should be updated.
     No slot-based clearing because full_slot==UNKNOWN. */
  uchar new_incr_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( new_incr_hash, 0xEE, FD_HASH_FOOTPRINT );
  FD_TEST( fd_sspeer_selector_add( selector, key_A, addr_A, FD_SSPEER_LATENCY_UNKNOWN,
                                   FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN,
                                   NULL, new_incr_hash )!=FD_SSPEER_SCORE_INVALID );

  /* The peer's existing full_hash should be preserved (full_hash was
     NULL so no overwrite), and incr_hash should be updated. */
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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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

  /* Peer A should be a valid incremental candidate. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Call update_on_resolve with full_hash non-NULL and incr_hash NULL,
     using the SAME full_slot.  Because the peer's incr_slot (8800) >=
     full_slot (8700), the incremental is not stale and is preserved. */
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_A,
                                                 cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                                 full_hash, NULL )==FD_SSPEER_UPDATE_SUCCESS );

  /* Peer A should STILL be a valid incremental candidate (not stale). */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* Now advance full_slot past the peer's incr_slot so the slot-based
     clear fires.  new_full_slot (8801) > incr_slot (8800). */
  ulong new_full_slot = cluster_incr_slot + 1UL;
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_A,
                                                 new_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                                 full_hash, NULL )==FD_SSPEER_UPDATE_SUCCESS );

  /* Peer A should no longer be an incremental candidate. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( !best.addr.l );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Peer A should still be valid for full selection with cleared
     incremental (incr_slot==FD_SSPEER_SLOT_UNKNOWN, incr_hash zeroed). */
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
test_cluster_slot_incremental( fd_sspeer_selector_t * selector,
                               fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing cluster slot incremental" ));

  ulong cluster_full_slot = 9000UL;
  ulong cluster_incr_slot = 9500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Add two peers with valid incrementals at the cluster slot. */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_incr_slot, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, cluster_incr_slot, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );

  /* Peer A is the best incremental candidate. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* A newer full_slot arrives with no incremental.  The cluster full
     slot advances but incremental is preserved (not reset). */
  fd_sspeer_selector_process_cluster_slot( selector, 9001UL, FD_SSPEER_SLOT_UNKNOWN );

  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==9001UL );
  FD_TEST( cs.incremental==cluster_incr_slot );

  /* Peers still have incr_slot==9500 so they are still valid
     incremental candidates for base_slot 9000.  Cluster incremental
     is preserved at 9500, so slots_behind==0 and score==latency. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* A subsequent observation with a higher incremental advances it. */
  fd_sspeer_selector_process_cluster_slot( selector, 9001UL, 9600UL );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==9001UL );
  FD_TEST( cs.incremental==9600UL );

  /* Now peers are 100 slots behind (9600-9500). */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 100UL*1000UL );

  /* Advance full past incremental (9600) to 10000 with no new
     incremental.  The cluster incremental is invalidated (set to
     FD_SSPEER_SLOT_UNKNOWN).  All peers must be rescored: peers with
     valid incr_slot now fall back to comparing full_slot against the
     cluster full slot.  Peers have full_slot=9000, so
     slots_behind = 10000-9000 = 1000. */
  fd_sspeer_selector_process_cluster_slot( selector, 10000UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==10000UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Peers still have incr_slot==9500 so they are still incremental
     candidates for base_slot 9000.  Score: latency + 1000*1000. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2UL*1000UL*1000UL + 1000UL*1000UL );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  /* Full selection falls back to full_slot comparison when
     cluster.incremental == FD_SSPEER_SLOT_UNKNOWN.
     Same score as incremental. */
  FD_TEST( best.score==2UL*1000UL*1000UL + 1000UL*1000UL );

  /* Re-establish cluster incremental.  Peers should be rescored back
     to using incremental slot difference. */
  fd_sspeer_selector_process_cluster_slot( selector, 10000UL, 10000UL );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==10000UL );
  FD_TEST( cs.incremental==10000UL );

  /* Peers are now 500 slots behind (10000-9500).
     Score = 2_000_000 + 500*1000 = 2_500_000. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 500UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_slot_zero( fd_sspeer_selector_t * selector,
                fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing slot zero" ));

  /* full_slot==0 and incr_slot==0 are valid slot values (e.g. genesis).
     Set (0, 1) so the peer at incr_slot=0 is one slot behind. */
  fd_sspeer_selector_process_cluster_slot( selector, 0UL, 1UL );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Peer at full_slot=0, incr_slot=0, latency 2ms.  Cluster is at
     (0, 1), which means the peer is 1 slot behind.  Then the score is
     2_000_000 + 1*1000 = 2_001_000. */
  FD_TEST( add_peer( selector, key_A, addr_A, 0UL, 0UL, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL + 1000UL );

  /* Full selection: peer should be valid and best. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==0UL );
  FD_TEST( best.incr_slot==0UL );
  FD_TEST( best.score==2UL*1000UL*1000UL + 1000UL );

  /* Incremental selection with base_slot=0: peer's full_slot==0
     matches base_slot, and incr_slot==0 != FD_SSPEER_SLOT_UNKNOWN. */
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==0UL );
  FD_TEST( best.incr_slot==0UL );
  FD_TEST( best.score==2UL*1000UL*1000UL + 1000UL );

  /* Peer with full_slot==0, incr_slot==FD_SSPEER_SLOT_UNKNOWN: valid
     for full but NOT for incremental selection.  full_slot uses the
     full cluster slot branch: slots_behind = cluster_full(0) - 0 = 0.
     score = 3_000_000. */
  FD_TEST( add_peer( selector, key_B, addr_B, 0UL, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 1000UL );
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==0UL );

  /* Score with incr_slot=0 when cluster has advanced.  Re-add peer A
     to observe the rescored value via the add_peer return. */
  fd_sspeer_selector_process_cluster_slot( selector, 0UL, 100UL );
  FD_TEST( add_peer( selector, key_A, addr_A, 0UL, 0UL, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL + 100UL*1000UL );

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

  /* Score is never FD_SSPEER_SCORE_INVALID: verify the cap prevents
     confusion with the "no peer" sentinel. */
  FD_TEST( score!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( FD_SSPEER_SCORE_MAX<FD_SSPEER_SCORE_INVALID );

  /* Establish a cluster with both full and incremental slots. */
  ulong cluster_full_slot = 10000UL;
  ulong cluster_incr_slot = 10500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  /* Normal score, no overflow: peer at cluster slot, latency 5ms.
     score = 5_000_000 + 0 = 5_000_000. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10500UL, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Slots-behind penalty: peer incr_slot 100 behind cluster.
     score = 5_000_000 + 100*1000 = 5_100_000. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10400UL, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL + 100UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Default latency (FD_SSPEER_LATENCY_UNKNOWN input): peer at cluster slot.
     score = DEFAULT_PEER_LATENCY = 100_000_000. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10500UL, FD_SSPEER_LATENCY_UNKNOWN )==100UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Default latency + slot-behind penalty combined: peer has unknown
     latency and incr_slot 100 behind cluster.
     score = DEFAULT_PEER_LATENCY + 100*1000 = 100_100_000. */
  FD_TEST( add_peer( selector, key, addr, 10000UL, 10400UL, FD_SSPEER_LATENCY_UNKNOWN )==100UL*1000UL*1000UL + 100UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Unresolved full slot: peer has FD_SSPEER_SLOT_UNKNOWN for both slots.
     slots_behind = DEFAULT_SLOTS_BEHIND = 1_000_000.
     score = 5_000_000 + 1_000_000*1000 = 1_005_000_000. */
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )==5UL*1000UL*1000UL + 1000UL*1000UL*1000UL );
  fd_sspeer_selector_remove( selector, key );

  /* Unresolved full slot with valid incr_slot:
     full_slot==FD_SSPEER_SLOT_UNKNOWN with incr_slot!=UNKNOWN is now
     rejected (an incremental slot requires a known full slot). */
  FD_TEST( add_peer( selector, key, addr, FD_SSPEER_SLOT_UNKNOWN, 10500UL, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );

  /* Score saturation: peer's full_slot is far behind a very high cluster
     full slot.  slots_behind = (ULONG_MAX-1) - 0 = ULONG_MAX-1, which
     causes sat_mul(1000, ULONG_MAX-1) to overflow, then sat_add also
     overflows, and the result is clamped to FD_SSPEER_SCORE_MAX. */
  fd_sspeer_selector_process_cluster_slot( selector, ULONG_MAX-1UL, ULONG_MAX-1UL );
  FD_TEST( add_peer( selector, key, addr, 0UL, FD_SSPEER_SLOT_UNKNOWN, 5UL*1000UL*1000UL )==FD_SSPEER_SCORE_MAX );
  fd_sspeer_selector_remove( selector, key );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cluster_slot_monotonicity( fd_sspeer_selector_t * selector_incr,
                                fd_sspeer_selector_t * selector_full ) {
  FD_LOG_NOTICE(( "testing cluster slot monotonicity" ));

  /* Incremental mode (incremental_snapshot_fetch=1).
     Use slot values higher than any previous test to avoid
     monotonicity rejection from prior cluster slot state. */

  /* Establish baseline: full=20000, incr=20200. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20000UL, 20200UL );
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20000UL );
  FD_TEST( cs.incremental==20200UL );

  /* Both FD_SSPEER_SLOT_UNKNOWN => no-op. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20000UL );
  FD_TEST( cs.incremental==20200UL );

  /* full_slot==FD_SSPEER_SLOT_UNKNOWN with valid incr_slot => no-op. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, FD_SSPEER_SLOT_UNKNOWN, 99999UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20000UL );
  FD_TEST( cs.incremental==20200UL );

  /* incr_slot==stored incr (20200), same full => rejected (no forward
     progress on either axis). */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20000UL, 20200UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20000UL );
  FD_TEST( cs.incremental==20200UL );

  /* incr_slot==stored incr (20200), but full advances (20050 > 20000):
     accepted because the full slot has made forward progress. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20050UL, 20200UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20050UL );
  FD_TEST( cs.incremental==20200UL );

  /* incr_slot < stored incr => rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20050UL, 20199UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20050UL );
  FD_TEST( cs.incremental==20200UL );

  /* incr_slot > stored incr => accepted. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20050UL, 20201UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20050UL );
  FD_TEST( cs.incremental==20201UL );

  /* Advance full with incr==FD_SSPEER_SLOT_UNKNOWN.  Full advances but
     incremental is preserved (not reset). */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20150UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20150UL );
  FD_TEST( cs.incremental==20201UL );

  /* incr==FD_SSPEER_SLOT_UNKNOWN, full<=stored full => rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20150UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20150UL );
  FD_TEST( cs.incremental==20201UL );

  /* incr==FD_SSPEER_SLOT_UNKNOWN, full<stored full => rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20149UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20150UL );
  FD_TEST( cs.incremental==20201UL );

  /* incr_slot==stored incr, full<=stored full => rejected (no forward
     progress). */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20150UL, 20201UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20150UL );
  FD_TEST( cs.incremental==20201UL );

  /* incr_slot < stored incr => rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20150UL, 20200UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20150UL );
  FD_TEST( cs.incremental==20201UL );

  /* incr_slot > stored incr => accepted. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20150UL, 20202UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20150UL );
  FD_TEST( cs.incremental==20202UL );

  /* Advance full past incremental with incr==FD_SSPEER_SLOT_UNKNOWN.
     The stored incremental (20202) is now stale because the full slot
     (20300) advanced past it.  It must be invalidated. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20300UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20300UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Re-establish incremental after invalidation. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20300UL, 20400UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20300UL );
  FD_TEST( cs.incremental==20400UL );

  /* full_slot regression with valid incr_slot: rejected.  Even though
     incr_slot (20500) advances past stored incremental (20400),
     full_slot (20200) is less than stored full (20300), so the update
     must be rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20200UL, 20500UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20300UL );
  FD_TEST( cs.incremental==20400UL );

  /* full_slot regression with valid incr_slot, stored incr unknown:
     rejected.  First invalidate the stored incremental by advancing
     full past it. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20500UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20500UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  fd_sspeer_selector_process_cluster_slot( selector_incr, 20400UL, 20600UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20500UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  /* Re-establish for subsequent tests. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20500UL, 20600UL );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20500UL );
  FD_TEST( cs.incremental==20600UL );

  /* Advance full to exactly the incremental slot with
     incr==FD_SSPEER_SLOT_UNKNOWN.  incr==full is not stale
     (incremental is at the same slot), so incremental is preserved. */
  fd_sspeer_selector_process_cluster_slot( selector_incr, 20600UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_incr );
  FD_TEST( cs.full==20600UL );
  FD_TEST( cs.incremental==20600UL );

  /* Full-only mode (incremental_snapshot_fetch=0). */

  /* Establish baseline: full=500. */
  fd_sspeer_selector_process_cluster_slot( selector_full, 500UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_full );
  FD_TEST( cs.full==500UL );

  /* full<=stored full => rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_full, 500UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_full );
  FD_TEST( cs.full==500UL );

  /* full<stored full => rejected. */
  fd_sspeer_selector_process_cluster_slot( selector_full, 499UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_full );
  FD_TEST( cs.full==500UL );

  /* full>stored full => accepted. */
  fd_sspeer_selector_process_cluster_slot( selector_full, 501UL, FD_SSPEER_SLOT_UNKNOWN );
  cs = fd_sspeer_selector_cluster_slot( selector_full );
  FD_TEST( cs.full==501UL );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_pool_exhaustion( fd_sspeer_selector_t * selector,
                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing pool exhaustion" ));

  ulong cluster_full = 1000UL;
  ulong cluster_incr = 1500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full, cluster_incr );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, 0 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, 0 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, 0 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_C; FD_TEST( generate_rand_addr_non_zero( &addr_C, rng ) );

  /* Fill to max capacity. */
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

  /* Adding with NULL key should return FD_SSPEER_SCORE_INVALID and not modify state. */

  FD_TEST( add_peer( selector, NULL, *addr_A, 100UL, 200UL, 1UL*1000UL*1000UL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a valid peer, then try NULL key again to confirm no corruption. */

  fd_sspeer_key_t key_A[1];
  FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );

  ulong cluster_full_slot = 100UL;
  ulong cluster_incr_slot = 200UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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
test_best_incremental_on_full_only_selector( fd_sspeer_selector_t * selector,
                                             fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing best incremental on full-only selector" ));

  /* The selector was created with incr_snap_fetch=0 (full-only mode).
     Verify that fd_sspeer_selector_best(selector, 1, base_slot) still
     works correctly.  The incremental flag in best() filters by peer
     attributes (full_slot==base_slot && incr_slot!=FD_SSPEER_SLOT_UNKNOWN),
     it does NOT depend on the selector's incremental_snapshot_fetch
     setting. */

  ulong cluster_full_slot = 30000UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_C[1]; FD_TEST( generate_rand_sspeer_key( key_C, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );
  fd_ip4_port_t addr_C; FD_TEST( generate_rand_addr_non_zero( &addr_C, rng ) );

  /* Peer A: has incremental.  Peer B: no incremental.  Peer C: has
     incremental at a different base slot. */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_full_slot + 500UL, 3UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  FD_TEST( add_peer( selector, key_C, addr_C, cluster_full_slot - 1UL, cluster_full_slot + 400UL, 1UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* Full selection: peer C has the lowest score.  Cluster incremental
     is UNKNOWN so all peers with incr_slot fall back to the full_slot
     comparison.  Peer C: latency=1ms, slots_behind=1 (30000-29999),
     score = 1_000_000 + 1_000 = 1_001_000.  Peer B: latency=2ms,
     slots_behind=0, score = 2_000_000.  Peer A: latency=3ms,
     slots_behind=0, score = 3_000_000. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_C.l );
  FD_TEST( best.score==1UL*1000UL*1000UL + 1UL*1000UL );

  /* Incremental selection with the right base_slot: only peer A
     qualifies (peer B has no incr, peer C has a different full_slot). */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_full_slot + 500UL );

  /* Incremental selection with a base_slot that no peer matches. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot + 999UL );
  FD_TEST( best.addr.l==0UL );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );

  /* Incremental selection with peer C's base_slot. */
  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot - 1UL );
  FD_TEST( best.addr.l==addr_C.l );
  FD_TEST( best.full_slot==cluster_full_slot - 1UL );
  FD_TEST( best.incr_slot==cluster_full_slot + 400UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  fd_sspeer_selector_remove( selector, key_C );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_ping_preserves_cleared_incremental( fd_sspeer_selector_t * selector,
                                         fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing ping preserves cleared incremental" ));

  /* Verify that update_on_ping does NOT restore stale incremental data
     after a peer's incremental was cleared via slot-based clearing.

     The update_on_ping codepath passes NULL, NULL for hashes and
     FD_SSPEER_SLOT_UNKNOWN for both slots.  In fd_sspeer_selector_update,
     since full_slot==UNKNOWN, no slot-based clearing fires and the
     existing incr_slot/incr_hash are preserved (already cleared).
     So the peer's incr_slot and incr_hash should remain as they were
     (cleared to FD_SSPEER_SLOT_UNKNOWN and zeroed, respectively). */

  ulong cluster_full_slot = 31000UL;
  ulong cluster_incr_slot = 31500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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

  /* Peer A should be a valid incremental candidate. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 1, cluster_full_slot );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( fd_memeq( best.incr_hash, incr_hash, FD_HASH_FOOTPRINT ) );

  /* Clear the peer's incremental via slot-based clearing.  Advance
     full_slot past incr_slot: new_full_slot (31501) > incr_slot
     (31500), so the incremental is stale and will be cleared. */
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

  /* The peer's incr_slot should still be FD_SSPEER_SLOT_UNKNOWN and
     incr_hash should still be zeroed. */
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( fd_memeq( best.incr_hash, zeroed_hash, FD_HASH_FOOTPRINT ) );
  /* full_hash should be preserved through the ping. */
  FD_TEST( fd_memeq( best.full_hash, full_hash, FD_HASH_FOOTPRINT ) );
  /* Latency should have updated. */
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

  /* Stress the selector with max_peers=32.  Try to add 34 peers
     (exceeding capacity by 2) to exercise pool exhaustion, then
     remove and re-add peers to verify the maps and treap stay
     consistent under churn. */

  ulong const MAX_PEERS = 32UL;
  FD_TEST( MAX_PEERS==max_peers );
  ulong const TRY_CNT   = 34UL;

  ulong cluster_full_slot = 50000UL;
  ulong cluster_incr_slot = 50500UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  fd_sspeer_key_t keys[ 34 ];
  fd_ip4_port_t   addrs[ 34 ];

  /* Try to add 34 peers.  The first 32 should succeed, the remaining
     2 should be rejected (pool exhaustion). */

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

    /* Remove the overflow peer and half the original peers (note:
       best_full_idx==0 was already removed, so i==0 is a no-op). */

    fd_sspeer_selector_remove( selector, &keys[ overflow_idx ] );
  }
  for( ulong i=0UL; i<MAX_PEERS; i+=2UL ) {
    fd_sspeer_selector_remove( selector, &keys[ i ] );
  }

  /* 31 peers before the loop (32 - best_full + overflow - overflow).
     Loop touches 16 even indices but best_full_idx==0 was already
     removed, so only 15 actual removals => 16 remaining (odd indices). */

  ulong remaining = fd_sspeer_selector_peer_map_by_key_ele_cnt( selector );
  FD_TEST( remaining==16UL );
  FD_TEST( remaining==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  if( remaining>0UL ) {
    FD_TEST( best.addr.l!=0UL );
    FD_TEST( best.score!=FD_SSPEER_SCORE_INVALID );
  }

  /* Advance the cluster slot and verify rescoring. */

  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot + 100UL, cluster_incr_slot + 100UL );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  if( remaining>0UL ) {
    FD_TEST( best.addr.l!=0UL );
    FD_TEST( best.score!=FD_SSPEER_SCORE_INVALID );
  }

  /* Re-add removed peers to fill back to capacity. */

  for( ulong i=0UL; i<MAX_PEERS; i+=2UL ) {
    ulong lat = (i + 1UL) * 1000UL * 1000UL;
    ulong inc = i % 2UL == 0UL
                ? cluster_incr_slot + 100UL - (i % 10UL)
                : FD_SSPEER_SLOT_UNKNOWN;
    add_peer( selector, &keys[ i ], addrs[ i ], cluster_full_slot + 100UL, inc, lat );
  }

  FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( MAX_PEERS==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Verify incremental selection still works. */

  best = fd_sspeer_selector_best( selector, 1, cluster_full_slot + 100UL );
  if( best.addr.l ) {
    FD_TEST( best.full_slot==cluster_full_slot + 100UL );
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
  FD_LOG_NOTICE(( "testing genesis cluster slot (0, 0)" ));

  /* Verify that process_cluster_slot(0, 0) succeeds from the initial
     state {full=0, incremental=FD_SSPEER_SLOT_UNKNOWN}.  This is the
     genesis case where both the full and incremental snapshots are at
     slot 0. */
  fd_sscluster_slot_t cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==FD_SSPEER_SLOT_UNKNOWN );

  fd_sspeer_selector_process_cluster_slot( selector, 0UL, 0UL );
  cs = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs.full==0UL );
  FD_TEST( cs.incremental==0UL );

  /* Verify scoring when cluster.incremental == cluster.full == 0.
     Peer with incr_slot=0: slots_behind = 0.  Score = latency.
     Peer with incr_slot=FD_SSPEER_SLOT_UNKNOWN: uses full branch,
     slots_behind = 0.  Score = latency. */
  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  FD_TEST( add_peer( selector, key_A, addr_A, 0UL, 0UL,        2UL*1000UL*1000UL )==2UL*1000UL*1000UL );
  FD_TEST( add_peer( selector, key_B, addr_B, 0UL, FD_SSPEER_SLOT_UNKNOWN,  3UL*1000UL*1000UL )==3UL*1000UL*1000UL );

  /* Peer A has lower score, so it's best for full selection. */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Peer A is the only incremental candidate (B has
     incr_slot==FD_SSPEER_SLOT_UNKNOWN). */
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.incr_slot==0UL );
  FD_TEST( best.score==2UL*1000UL*1000UL );

  /* Advance cluster to (0, 5).  Peer A is now 5 slots behind.
     Score = 2_000_000 + 5*1000 = 2_005_000. */
  fd_sspeer_selector_process_cluster_slot( selector, 0UL, 5UL );
  best = fd_sspeer_selector_best( selector, 1, 0UL );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 5UL*1000UL );

  /* Cleanup */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cluster_slot_rescore_full_only( fd_sspeer_selector_t * selector,
                                     fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing cluster slot rescore full only" ));

  ulong cluster_full_slot = 1000UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN );

  fd_sspeer_key_t key_A[1]; FD_TEST( generate_rand_sspeer_key( key_A, rng, fd_rng_uint( rng )&0x1 ) );
  fd_sspeer_key_t key_B[1]; FD_TEST( generate_rand_sspeer_key( key_B, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_A; FD_TEST( generate_rand_addr_non_zero( &addr_A, rng ) );
  fd_ip4_port_t addr_B; FD_TEST( generate_rand_addr_non_zero( &addr_B, rng ) );

  /* Peer A at cluster slot, peer B 2 slots behind.
     A: slots_behind=0, score=3_000_000.
     B: slots_behind=2, score=2_000_000 + 2*1000 = 2_002_000. */
  FD_TEST( add_peer( selector, key_A, addr_A, 1000UL, FD_SSPEER_SLOT_UNKNOWN, 3UL*1000UL*1000UL )==3UL*1000UL*1000UL );
  FD_TEST( add_peer( selector, key_B, addr_B,  998UL, FD_SSPEER_SLOT_UNKNOWN, 2UL*1000UL*1000UL )==2UL*1000UL*1000UL + 2UL*1000UL );

  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 2UL*1000UL );

  /* Advance cluster full slot.  All peers should be rescored.
     A: slots_behind=100, score=3_000_000 + 100*1000 = 3_100_000.
     B: slots_behind=102, score=2_000_000 + 102*1000 = 2_102_000. */
  fd_sspeer_selector_process_cluster_slot( selector, 1100UL, FD_SSPEER_SLOT_UNKNOWN );

  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.score==2UL*1000UL*1000UL + 102UL*1000UL );

  /* Cleanup. */
  fd_sspeer_selector_remove( selector, key_A );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_invalid_clear_and_best_sentinel( fd_sspeer_selector_t * selector,
                                      fd_rng_t *             rng ) {
  FD_LOG_NOTICE(( "testing invalid clear and best sentinel" ));

  ulong cluster_full_slot = 9500UL;
  ulong cluster_incr_slot = 9600UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

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

  /* full_hash set, incr_hash NULL, incr_slot != FD_SSPEER_SLOT_UNKNOWN
     is now valid (slot-based clearing handles the decision).  The
     update should succeed because the existing peer's incr_slot (9600)
     >= full_slot (9500), so the incremental is preserved. */
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_A,
                                                 cluster_full_slot, FD_SSPEER_SLOT_UNKNOWN,
                                                 full_hash, NULL )==FD_SSPEER_UPDATE_SUCCESS );

  /* Peer A should be unaffected (incremental preserved). */
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( fd_memeq( best.full_hash, full_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( fd_memeq( best.incr_hash, incr_hash, FD_HASH_FOOTPRINT ) );

  /* full_slot==UNKNOWN with incr_slot!=UNKNOWN is invalid.  add() for
     a new peer with this combination must be rejected. */
  fd_sspeer_key_t key_new[1]; FD_TEST( generate_rand_sspeer_key( key_new, rng, fd_rng_uint( rng )&0x1 ) );
  fd_ip4_port_t addr_new; FD_TEST( generate_rand_addr_non_zero( &addr_new, rng ) );
  FD_TEST( fd_sspeer_selector_add( selector, key_new, addr_new, 2UL*1000UL*1000UL,
                                   FD_SSPEER_SLOT_UNKNOWN, cluster_incr_slot,
                                   NULL, NULL )==FD_SSPEER_SCORE_INVALID );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* update_on_resolve with full_slot==UNKNOWN and incr_slot!=UNKNOWN
     on an existing peer with known full_slot succeeds because the
     effective full_slot is the peer's stored value (not UNKNOWN). */
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_A,
                                                 FD_SSPEER_SLOT_UNKNOWN, cluster_incr_slot,
                                                 NULL, incr_hash )==FD_SSPEER_UPDATE_SUCCESS );

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

  /* update_on_resolve with incr_slot < full_slot must be rejected. */
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_A,
                                                 200UL, 100UL,
                                                 full_hash, incr_hash )==FD_SSPEER_UPDATE_ERR_INVALID_ARG );
  best = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );

  /* process_cluster_slot with incr_slot < full_slot should be silently
     rejected (cluster slot unchanged). */
  fd_sscluster_slot_t cs_before = fd_sspeer_selector_cluster_slot( selector );
  fd_sspeer_selector_process_cluster_slot( selector, 50000UL, 40000UL );
  fd_sscluster_slot_t cs_after = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs_before.full==cs_after.full );
  FD_TEST( cs_before.incremental==cs_after.incremental );

  /* incr_slot == full_slot boundary (non-genesis). */

  /* add() for a new peer with incr_slot == full_slot must be accepted. */
  FD_TEST( add_peer( selector, key_new, addr_new, 500UL, 500UL, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_remove( selector, key_new );

  /* add() updating an existing peer with incr_slot == full_slot must
     be accepted. */
  FD_TEST( add_peer( selector, key_A, addr_A, 500UL, 500UL, 5UL*1000UL*1000UL )!=FD_SSPEER_SCORE_INVALID );

  /* update_on_resolve with incr_slot == full_slot must be accepted. */
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_A,
                                                 600UL, 600UL,
                                                 full_hash, incr_hash )==FD_SSPEER_UPDATE_SUCCESS );

  /* process_cluster_slot with incr_slot == full_slot must be accepted. */
  fd_sspeer_selector_process_cluster_slot( selector, 60000UL, 60000UL );
  fd_sscluster_slot_t cs_eq = fd_sspeer_selector_cluster_slot( selector );
  FD_TEST( cs_eq.full==60000UL );
  FD_TEST( cs_eq.incremental==60000UL );

  /* Cleanup. */
  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST( !fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( !fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  uint rng_seed = fd_env_strip_cmdline_uint( &argc, &argv, "--seed", NULL, 3714951721/* arbitrary seed, reproducible CI */ );
  if( FD_UNLIKELY( !rng_seed ) ) rng_seed = (uint)fd_log_wallclock(); /* random seed, used for development */
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, rng_seed, 0UL ) );
  FD_LOG_NOTICE(( "rng seed %u", rng_seed ));

  /* Initialize and verify. */

  FD_TEST( wksp );
  test_wksp_t t_wksp_base  = {0};
  test_wksp_t t_wksp_full  = {0};
  test_wksp_t t_wksp_small = {0};
  test_wksp_t t_wksp_stress= {0};

  test_wksp_init( wksp,
                  &t_wksp_base,
                  65536UL/*max_peers*/,
                  1/*incr_snap_fetch*/,
                  fd_rng_ulong( rng )/*seed*/ );

  test_wksp_init( wksp,
                  &t_wksp_full,
                  4UL/*max_peers*/,
                  0/*incr_snap_fetch*/,
                  fd_rng_ulong( rng )/*seed*/ );

  test_wksp_init( wksp,
                  &t_wksp_small,
                  2UL/*max_peers*/,
                  1/*incr_snap_fetch*/,
                  fd_rng_ulong( rng )/*seed*/ );

  test_wksp_init( wksp,
                  &t_wksp_stress,
                  32UL/*max_peers*/,
                  1/*incr_snap_fetch*/,
                  fd_rng_ulong( rng )/*seed*/ );

  verify_initial_cluster_slot( t_wksp_base.selector );
  verify_initial_cluster_slot( t_wksp_full.selector );
  verify_initial_cluster_slot( t_wksp_small.selector );
  verify_initial_cluster_slot( t_wksp_stress.selector );

  /* Subtests.  To make them independent from each other, the test
     workspaces need to be re-initialized before usage.  This is because
     the cluster slot can only increase monotonically over time. */

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
  test_update_on_resolve( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_address_zero( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_duplicate_hostnames( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_add_clears_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_on_resolve_clears_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_cluster_slot_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_score_saturation( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_wksp_reinit( &t_wksp_full );
  test_cluster_slot_monotonicity( t_wksp_base.selector, t_wksp_full.selector );

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

  test_wksp_reinit( &t_wksp_full );
  test_cluster_slot_rescore_full_only( t_wksp_full.selector, rng );

  test_wksp_reinit( &t_wksp_full );
  test_best_incremental_on_full_only_selector( t_wksp_full.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_invalid_clear_and_best_sentinel( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_base );
  test_ping_preserves_cleared_incremental( t_wksp_base.selector, rng );

  test_wksp_reinit( &t_wksp_stress );
  test_stress_peer_count( t_wksp_stress.selector, rng, t_wksp_stress.max_peers );

  /* Cleanup. */

  fd_rng_delete( fd_rng_leave( rng ) );
  test_wksp_fini( &t_wksp_base );
  test_wksp_fini( &t_wksp_full );
  test_wksp_fini( &t_wksp_small );
  test_wksp_fini( &t_wksp_stress );

  fd_halt();
  return 0;
}
