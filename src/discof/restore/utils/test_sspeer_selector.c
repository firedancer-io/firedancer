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
  FD_TEST( add_peer( selector, key, addr, 1000UL, 1500UL, 5L*1000L*1000L )==5UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==5L*1000L*1000L );

  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 1UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer with better latency at the same slot and it should be
     the best peer */
  fd_sspeer_key_t key2[1]; FD_TEST( generate_rand_sspeer_key( key2, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr2 = { .addr = FD_IP4_ADDR( 35, 123, 172, 228 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key2, addr2, 1000UL, 1500UL, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3L*1000L*1000L );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a peer with the same latency but lagging slots behind */
  fd_sspeer_key_t key3[1]; FD_TEST( generate_rand_sspeer_key( key3, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr3 = { .addr = FD_IP4_ADDR( 35, 123, 172, 229 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key3, addr3, 1000UL, 1400UL, 3L*1000L*1000L )==3UL*1000UL*1000UL + 100UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1500UL );
  FD_TEST( best.score==3L*1000L*1000L );

  FD_TEST( 3UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 3UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  cluster_incr_slot = 1600UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  /* Add a peer that is slightly slower but caught up in slots */
  fd_sspeer_key_t key4[1]; FD_TEST( generate_rand_sspeer_key( key4, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr4 = { .addr = FD_IP4_ADDR( 35, 123, 172, 230 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key4, addr4, 1000UL, 1600UL, 3L*1000L*1000L + 75L*1000L )==3UL*1000UL*1000UL + 75UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L );

  FD_TEST( 4UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 4UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a fast peer that doesn't have resolved slots */
  fd_sspeer_key_t key5[1]; FD_TEST( generate_rand_sspeer_key( key5, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr5 = { .addr = FD_IP4_ADDR( 35, 123, 172, 231 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key5, addr5, ULONG_MAX, ULONG_MAX, 2L*1000L*1000L )==2UL*1000UL*1000UL + 1000UL*1000UL*1000UL);
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L );

  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Test incremental peer selection */
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L );

  cluster_incr_slot = 1700UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_full_slot, cluster_incr_slot );

  /* Add a peer that is fast and at the highest slot but not building
     off full slot, which makes it invalid an incremental peer */
  fd_sspeer_key_t key6[1]; FD_TEST( generate_rand_sspeer_key( key6, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr6 = { .addr = FD_IP4_ADDR( 35, 123, 172, 232 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key6, addr6, 900UL, 1700UL, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1600UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L + 100UL*1000UL );

  FD_TEST( 6UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 6UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add a fast incremental peer that is caught up to the cluster slot */
  fd_sspeer_key_t key7[1]; FD_TEST( generate_rand_sspeer_key( key7, rng, fd_rng_int( rng )&0x1/*is_url*/ ) );
  fd_ip4_port_t addr7 = { .addr = FD_IP4_ADDR( 35, 123, 172, 233 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( add_peer( selector, key7, addr7, 1000UL, 1700UL, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr7.l );
  FD_TEST( best.full_slot==1000UL );
  FD_TEST( best.incr_slot==1700UL );
  FD_TEST( best.score==2L*1000L*1000L );

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
  fd_sspeer_key_t key_url_C[1]; *key_url_C = *key_url_A; key_url_C->url.resolved_addr.l = ~key_url_A->url.resolved_addr.l;

  /* Add peers with same addr, same full_slot and incr_slot. */

  /* ... pubkey peer, latency 2us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_pub_A, addr0, cluster_full_slot, cluster_incr_slot, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... pubkey peer, latency 3us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_pub_B, addr0, cluster_full_slot, cluster_incr_slot, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... url peer, latency 4us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_url_A, addr0, cluster_full_slot, cluster_incr_slot, 4L*1000L*1000L )==4UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... url peer, latency 5us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_url_B, addr0, cluster_full_slot, cluster_incr_slot, 5L*1000L*1000L )==5UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... url peer, latency 1us, expected best score 1e6. */
  FD_TEST( add_peer( selector, key_url_C, addr0, cluster_full_slot, cluster_incr_slot, 1L*1000L*1000L )==1UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr0.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==1L*1000L*1000L );

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
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_incr_slot, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... peer B, latency 3us, expected best score 2e6. */
  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, cluster_incr_slot, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... peer A, new addr, latency 4us, expected best score 3e6 */
  FD_TEST( add_peer( selector, key_A, addr_A1, cluster_full_slot, cluster_incr_slot, 4L*1000L*1000L )==4UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3L*1000L*1000L );

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

  /* Add 5 peers: pairs AB, CD and single E. */

  /* ... peers A and B, latency 2us, expected best score 2e6 (pair AB). */
  FD_TEST( add_peer( selector, key_A, addr_AB, cluster_full_slot, cluster_incr_slot, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  FD_TEST( add_peer( selector, key_B, addr_AB, cluster_full_slot, cluster_incr_slot, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... peers C and D, latency 3us, expected best score 2e6 (pair AB). */
  FD_TEST( add_peer( selector, key_C, addr_CD, cluster_full_slot, cluster_incr_slot, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  FD_TEST( add_peer( selector, key_D, addr_CD, cluster_full_slot, cluster_incr_slot, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... peers E, latency 4us, expected best score 2e6 (pair AB). */
  FD_TEST( add_peer( selector, key_E, addr_E, cluster_full_slot, cluster_incr_slot, 4L*1000L*1000L )==4UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* ... update addr_AB to 5us, expected best score 3e6 (pair CD). */
  FD_TEST( 2UL==fd_sspeer_selector_update_on_ping( selector, addr_AB, 5L*1000L*1000L ) );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_CD.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3L*1000L*1000L );

  /* ... update addr_CD to 6us, expected best score 4e6 (single E). */
  FD_TEST( 2UL==fd_sspeer_selector_update_on_ping( selector, addr_CD, 6L*1000L*1000L ) );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_E.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==4L*1000L*1000L );

  /* ... update addr_E to 7us, expected best score 5e6 (pair AB). */
  FD_TEST( 1UL==fd_sspeer_selector_update_on_ping( selector, addr_E, 7L*1000L*1000L ) );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_AB.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==5L*1000L*1000L );

  /* Verify how many peers were added to selector. */
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 5UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Cleanup */
  fd_sspeer_selector_remove_by_addr( selector, addr_AB );
  fd_sspeer_selector_remove_by_addr( selector, addr_CD );
  fd_sspeer_selector_remove_by_addr( selector, addr_E  );
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

  /* ... peer A latency 3us, expected best score 3e6 (the expected score must not match the default one). */
  FD_TEST( add_peer( selector, key_A, addr_A, ULONG_MAX, ULONG_MAX, 3L*1000L*1000L )!=3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==ULONG_MAX );
  FD_TEST( best.incr_slot==ULONG_MAX );
  FD_TEST( best.score==ULONG_MAX );
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, NULL,  cluster_full_slot, cluster_incr_slot, NULL, NULL )==-1 );
  FD_TEST( fd_sspeer_selector_update_on_resolve( selector, key_B, cluster_full_slot, cluster_incr_slot, NULL, NULL )==-2 );
  FD_TEST (fd_sspeer_selector_update_on_resolve( selector, key_A, ULONG_MAX, ULONG_MAX, NULL, NULL )==0  );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==ULONG_MAX );
  FD_TEST( best.incr_slot==ULONG_MAX );
  FD_TEST( best.score==ULONG_MAX );
  FD_TEST (fd_sspeer_selector_update_on_resolve( selector, key_A, ULONG_MAX, cluster_incr_slot, NULL, NULL )==0  );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( !best.addr.l );
  FD_TEST( best.full_slot==ULONG_MAX );
  FD_TEST( best.incr_slot==ULONG_MAX );
  FD_TEST( best.score==ULONG_MAX );
  FD_TEST (fd_sspeer_selector_update_on_resolve( selector, key_A, cluster_full_slot, cluster_incr_slot, NULL, NULL )==0  );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3L*1000L*1000L );

  /* ... peer B latency 2us, expected best score 2e6 (the expected score must not match the default one). */
  FD_TEST( add_peer( selector, key_B, addr_B, ULONG_MAX, ULONG_MAX, 2L*1000L*1000L )!=2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3L*1000L*1000L );
  FD_TEST (fd_sspeer_selector_update_on_resolve( selector, key_B, cluster_full_slot, cluster_incr_slot, NULL, NULL )==0  );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  /* Cleanup and verification. */
  fd_sspeer_selector_remove( selector, key_A );
  FD_TEST (fd_sspeer_selector_update_on_resolve( selector, key_A, cluster_full_slot, cluster_incr_slot, NULL, NULL )==-2 );
  fd_sspeer_selector_remove( selector, key_B );
  FD_TEST (fd_sspeer_selector_update_on_resolve( selector, key_B, cluster_full_slot, cluster_incr_slot, NULL, NULL )==-2 );
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
  FD_TEST( add_peer( selector, key_A, addr_0, cluster_full_slot, cluster_incr_slot, 1L*1000L*1000L )==ULONG_MAX );
  FD_TEST( add_peer( selector, key_B, addr_0, cluster_full_slot, cluster_incr_slot, 1L*1000L*1000L )==ULONG_MAX );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 0UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Add both peers with valid addresses. */
  FD_TEST( add_peer( selector, key_A, addr_A, cluster_full_slot, cluster_incr_slot, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3L*1000L*1000L );

  FD_TEST( add_peer( selector, key_B, addr_B, cluster_full_slot, cluster_incr_slot, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_key_ele_cnt( selector ) );
  FD_TEST( 2UL==fd_sspeer_selector_peer_map_by_addr_ele_cnt( selector ) );

  /* Try to add both peers with addr_0. Selector state must not change. */
  FD_TEST( add_peer( selector, key_A, addr_0, cluster_full_slot, cluster_incr_slot, 1L*1000L*1000L )==ULONG_MAX );
  FD_TEST( add_peer( selector, key_B, addr_0, cluster_full_slot, cluster_incr_slot, 1L*1000L*1000L )==ULONG_MAX );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

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
  fd_sspeer_key_t key_url_B[1]; *key_url_B = *key_url_A; key_url_B->url.resolved_addr.l = key_url_A->url.resolved_addr.l ^ 1UL;
  fd_ip4_port_t addr_A = key_url_A->url.resolved_addr;
  fd_ip4_port_t addr_B = key_url_B->url.resolved_addr;

  /* Add both peers with valid addresses. */
  FD_TEST( add_peer( selector, key_url_A, addr_A, cluster_full_slot, cluster_incr_slot, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_A.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==3L*1000L*1000L );

  FD_TEST( add_peer( selector, key_url_B, addr_B, cluster_full_slot, cluster_incr_slot, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr_B.l );
  FD_TEST( best.full_slot==cluster_full_slot );
  FD_TEST( best.incr_slot==cluster_incr_slot );
  FD_TEST( best.score==2L*1000L*1000L );

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

  FD_TEST( wksp );
  void *                 shmem    = fd_wksp_alloc_laddr( wksp, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( 65535UL ), 1UL );
  fd_sspeer_selector_t * selector = fd_sspeer_selector_join( fd_sspeer_selector_new( shmem, 65535UL, 1, fd_rng_ulong( rng )/*seed*/ ) );
  FD_TEST( selector );

  test_basic_peer_selection( selector, rng );

  test_duplicate_peers( selector, rng );

  test_peer_addr_change( selector, rng );

  test_update_on_ping( selector, rng );

  test_update_on_resolve( selector, rng );

  test_address_zero( selector, rng );

  test_duplicate_hostnames( selector, rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_wksp_free_laddr( fd_sspeer_selector_delete( fd_sspeer_selector_leave( selector ) ) );
  return 0;
}
