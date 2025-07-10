#include "fd_repair_ledger.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/net/fd_net_headers.h"

#include <stdarg.h>

/* Helper function to create and setup a repair ledger */
fd_repair_ledger_t *
setup_repair_ledger( fd_wksp_t * wksp, ulong seed, ulong timeout_ns ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_repair_ledger_align(), fd_repair_ledger_footprint(), 1UL );
  FD_TEST( mem );
  fd_repair_ledger_t * ledger = fd_repair_ledger_join( fd_repair_ledger_new( mem, seed, timeout_ns ) );
  FD_TEST( ledger );
  return ledger;
}

/* create pubkeys */
fd_pubkey_t
make_pubkey( uchar val ) {
  fd_pubkey_t key;
  memset( &key, 0, sizeof(key) );
  key.key[0] = val;
  return key;
}

/*  create IP addresses */
fd_ip4_port_t
make_ip4_port( uint ip, ushort port ) {
  fd_ip4_port_t ip4;
  ip4.addr = ip;
  ip4.port = port;
  return ip4;
}

void test_repair_ledger_cleanup( fd_repair_ledger_t * ledger ) {
  fd_wksp_free_laddr( fd_repair_ledger_delete( fd_repair_ledger_leave( ledger ) ) );
  FD_LOG_NOTICE(( "Peer selection test passed" ));
}

/* basic peer operations: add, query, remove */
void
test_repair_ledger_peer_basic( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing basic peer operations" ));
  
  fd_repair_ledger_t * ledger = setup_repair_ledger( wksp, 42UL, 1000000000UL );
  
  /* initial state */
  FD_TEST( fd_repair_ledger_peer_cnt( ledger ) == 0UL );
  
  /* create peer data */
  fd_pubkey_t peer1_key = make_pubkey( 1 );
  fd_pubkey_t peer2_key = make_pubkey( 2 );
  fd_ip4_port_t peer1_ip = make_ip4_port( 0x7F000001, 8080 ); /* 127.0.0.1:8080 */
  fd_ip4_port_t peer2_ip = make_ip4_port( 0x7F000002, 8081 ); /* 127.0.0.2:8081 */
  long current_time = 1000000000L;
  
  /* adding peers */
  fd_repair_ledger_peer_t * peer1 = fd_repair_ledger_peer_add( ledger, &peer1_key, peer1_ip, current_time );
  FD_TEST( peer1 );
  FD_TEST( fd_repair_ledger_peer_cnt( ledger ) == 1UL );
  FD_TEST( peer1->ip4.addr == peer1_ip.addr );
  FD_TEST( peer1->ip4.port == peer1_ip.port );
  FD_TEST( peer1->last_recv == current_time );
  FD_TEST( peer1->num_inflight_req == 0UL );
  
  fd_repair_ledger_peer_t * peer2 = fd_repair_ledger_peer_add( ledger, &peer2_key, peer2_ip, current_time );
  FD_TEST( peer2 );
  FD_TEST( fd_repair_ledger_peer_cnt( ledger ) == 2UL );
  
  /* querying peers */
  fd_repair_ledger_peer_t * found1 = fd_repair_ledger_peer_query( ledger, &peer1_key );
  FD_TEST( found1 );
  FD_TEST( found1 == peer1 );
  FD_TEST( !memcmp( &found1->key, &peer1_key, sizeof(fd_pubkey_t) ) );
  
  fd_repair_ledger_peer_t * found2 = fd_repair_ledger_peer_query( ledger, &peer2_key );
  FD_TEST( found2 );
  FD_TEST( found2 == peer2 );
  
  /* querying non-existent peer */
  fd_pubkey_t nonexistent_key = make_pubkey( 99 );
  fd_repair_ledger_peer_t * not_found = fd_repair_ledger_peer_query( ledger, &nonexistent_key );
  FD_TEST( !not_found );
  
  fd_repair_ledger_peer_t * test = fd_repair_ledger_peer_query( ledger, &peer1_key );
  FD_TEST( test );
  FD_TEST( test == peer1 );
  FD_TEST( test->num_inflight_req == 0UL );

  /* adding duplicate peer (should update existing) */
  fd_ip4_port_t peer1_new_ip = make_ip4_port( 0x7F000003, 9090 );
  long new_time = current_time + 1000000L;
  fd_repair_ledger_peer_t * peer1_updated = fd_repair_ledger_peer_add( ledger, &peer1_key, peer1_new_ip, new_time );
  FD_TEST( peer1_updated );
  FD_TEST( peer1_updated == peer1 ); /* Should be same object */
  FD_TEST( fd_repair_ledger_peer_cnt( ledger ) == 2UL ); /* Count shouldn't change */
  FD_TEST( peer1_updated->ip4.addr == peer1_new_ip.addr );
  FD_TEST( peer1_updated->last_recv == new_time );

  test = fd_repair_ledger_peer_query( ledger, &peer1_key );
  FD_TEST( test );
  FD_TEST( test == peer1 );
  FD_TEST( test->num_inflight_req == 0UL );
  
  /* removing peers */
  fd_repair_ledger_peer_t * remove_result = fd_repair_ledger_peer_remove( ledger, &peer1_key );
  FD_TEST( remove_result != NULL );
  FD_TEST( fd_repair_ledger_peer_cnt( ledger ) == 1UL );
  
  /* querying removed peer */
  fd_repair_ledger_peer_t * removed = fd_repair_ledger_peer_query( ledger, &peer1_key );
  FD_TEST( !removed );
  
  /* removing non-existent peer */
  fd_repair_ledger_peer_t * remove_result2 = fd_repair_ledger_peer_remove( ledger, &nonexistent_key );
  FD_TEST( remove_result2 == NULL );
  
  /* cleanup */
  test_repair_ledger_cleanup( ledger );
}

/* basic request operations: insert, query, remove */
void
test_repair_ledger_req_basic( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing basic request operations" ));
  
  fd_repair_ledger_t * ledger = setup_repair_ledger( wksp, 42UL, 1000000000UL );
  
  /* initial state */
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 0UL );
  
  /* add a peer first (required for requests) */
  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  long current_time = 1000000000L;
  fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_add( ledger, &peer_key, peer_ip, current_time );
  FD_TEST( peer );
  
  /* inserting requests */
  ulong nonce1 = 12345UL;
  ulong nonce2 = 67890UL;
  ulong timestamp = 1000000000UL;
  ulong slot = 100UL;
  ulong shred_idx = 5UL;
  uint req_type = FD_REPAIR_KIND_SHRED_REQ;
  
  fd_repair_ledger_req_t * req1 = fd_repair_ledger_req_insert( ledger, nonce1, timestamp, 
                                                               &peer_key, peer_ip, slot, shred_idx, req_type );
  FD_TEST( req1 );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 1UL );
  FD_TEST( req1->nonce == nonce1 );
  FD_TEST( req1->timestamp_ns == timestamp );
  FD_TEST( req1->slot == slot );
  FD_TEST( req1->shred_idx == shred_idx );
  FD_TEST( req1->req_type == req_type );
  FD_TEST( !memcmp( &req1->pubkey, &peer_key, sizeof(fd_pubkey_t) ) );
  
  fd_repair_ledger_req_t * req2 = fd_repair_ledger_req_insert( ledger, nonce2, timestamp + 1000000UL,
                                                               &peer_key, peer_ip, slot + 1, shred_idx + 1, req_type );
  FD_TEST( req2 );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 2UL );
  
  /* querying requests */
  fd_repair_ledger_req_t * found1 = fd_repair_ledger_req_query( ledger, nonce1 );
  FD_TEST( found1 );
  FD_TEST( found1 == req1 );
  FD_TEST( found1->nonce == nonce1 );
  
  fd_repair_ledger_req_t * found2 = fd_repair_ledger_req_query( ledger, nonce2 );
  FD_TEST( found2 );
  FD_TEST( found2 == req2 );
  
  /* querying non-existent request */
  fd_repair_ledger_req_t * not_found = fd_repair_ledger_req_query( ledger, 99999UL );
  FD_TEST( !not_found );
  
  /* inserting duplicate nonce (should fail) */
  fd_repair_ledger_req_t * duplicate = fd_repair_ledger_req_insert( ledger, nonce1, timestamp,
                                                                   &peer_key, peer_ip, slot, shred_idx, req_type );
  FD_TEST( !duplicate );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 2UL ); /* Count shouldn't change */
  
  /* oldest/newest requests */
  fd_repair_ledger_req_t const * oldest = fd_repair_ledger_req_oldest( ledger );
  FD_TEST( oldest );
  FD_TEST( oldest->nonce == nonce1 ); /* First inserted should be oldest */
  
  fd_repair_ledger_req_t const * newest = fd_repair_ledger_req_newest( ledger );
  FD_TEST( newest );
  FD_TEST( newest->nonce == nonce2 ); /* Last inserted should be newest */
  
  /* removing requests */
  int remove_result = fd_repair_ledger_req_remove( ledger, nonce1 );
  FD_TEST( remove_result == 0 );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 1UL );
  
  /* querying removed request */
  fd_repair_ledger_req_t * removed = fd_repair_ledger_req_query( ledger, nonce1 );
  FD_TEST( !removed );
  
  /* removing non-existent request */
  int remove_result2 = fd_repair_ledger_req_remove( ledger, 99999UL );
  FD_TEST( remove_result2 == -1 );
  
  /* cleanup */
  test_repair_ledger_cleanup( ledger );
}

/* Request expiration functionality */
void
test_repair_ledger_req_expire( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing request expiration" ));
  
  ulong timeout_ns = 1000000000UL; /* 1 second timeout */
  fd_repair_ledger_t * ledger = setup_repair_ledger( wksp, 42UL, timeout_ns );
  
  /* Add a peer first */
  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  long current_time = 1000000000L;
  fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_add( ledger, &peer_key, peer_ip, current_time );
  FD_TEST( peer );
  
  /* Insert requests at different times */
  ulong base_time = 1000000000UL;
  ulong nonce1 = 1UL;
  ulong nonce2 = 2UL;
  ulong nonce3 = 3UL;
  
  /* Request 1: expire */
  fd_repair_ledger_req_t * req1 = fd_repair_ledger_req_insert( ledger, nonce1, base_time,
                                                               &peer_key, peer_ip, 100UL, 0UL, FD_REPAIR_KIND_SHRED_REQ );
  FD_TEST( req1 );
  
  /* Request 2: expire */
  fd_repair_ledger_req_t * req2 = fd_repair_ledger_req_insert( ledger, nonce2, base_time + 500000000UL,
                                                               &peer_key, peer_ip, 101UL, 0UL, FD_REPAIR_KIND_SHRED_REQ );
  FD_TEST( req2 );
  
  /* Request 3: not expire */
  fd_repair_ledger_req_t * req3 = fd_repair_ledger_req_insert( ledger, nonce3, base_time + 1500000000UL,
                                                               &peer_key, peer_ip, 102UL, 0UL, FD_REPAIR_KIND_SHRED_REQ );
  FD_TEST( req3 );
  
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 3UL );
  
  /* Test expiration at a time that should expire first two requests */
  ulong expire_time = base_time + 2000000000UL; /* 2 seconds after base_time */
  ulong expired_count = fd_repair_ledger_req_expire( ledger, expire_time );
  
  FD_TEST( expired_count == 2UL );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 1UL );
  
  /* Check that third request remains */
  FD_TEST( !fd_repair_ledger_req_query( ledger, nonce1 ) );
  FD_TEST( !fd_repair_ledger_req_query( ledger, nonce2 ) );
  FD_TEST( fd_repair_ledger_req_query( ledger, nonce3 ) );
  
  /* Test expiration when no requests should expire */
  ulong no_expire_count = fd_repair_ledger_req_expire( ledger, expire_time );
  FD_TEST( no_expire_count == 0UL );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 1UL );
  
  /* Test expiration that removes all remaining requests */
  ulong expire_all_time = base_time + 3000000000UL; /* 3 seconds after base_time */
  ulong all_expired_count = fd_repair_ledger_req_expire( ledger, expire_all_time );
  FD_TEST( all_expired_count == 1UL );
  FD_TEST( fd_repair_ledger_req_cnt( ledger ) == 0UL );
  
  /* Test expiration on empty ledger */
  ulong empty_expire_count = fd_repair_ledger_req_expire( ledger, expire_all_time );
  FD_TEST( empty_expire_count == 0UL );
  
  /* Cleanup */
  test_repair_ledger_cleanup( ledger );
}

/* Test peer selection functionality */
void
test_repair_ledger_peer_selection( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing peer selection" ));
  
  fd_repair_ledger_t * ledger = setup_repair_ledger( wksp, 42UL, 1000000000UL );
  
  /* Add multiple peers */
  long current_time = 1000000000L;
  fd_pubkey_t peer_keys[5];
  for( uint i = 0; i < 5; i++ ) {
    peer_keys[i] = make_pubkey( (uchar)(i + 1) );
    fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001 + i, (ushort)(8080UL + i) );
    fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_add( ledger, &peer_keys[i], peer_ip, current_time );
    FD_TEST( peer );
  }
  
  FD_TEST( fd_repair_ledger_peer_cnt( ledger ) == 5UL );
  
  /* Test selecting peers */
  fd_pubkey_t * selected_peers[3];
  fd_repair_ledger_select_peers( ledger, 3, selected_peers );
  
  /* Verify we got 3 different peers */
  FD_TEST( selected_peers[0] != selected_peers[1] );
  FD_TEST( selected_peers[1] != selected_peers[2] );
  FD_TEST( selected_peers[0] != selected_peers[2] );
  
  /* Test selecting more peers */
  fd_pubkey_t * more_selected[3];
  fd_repair_ledger_select_peers( ledger, 3, more_selected );
  
  /* Cleanup */
  test_repair_ledger_cleanup( ledger );
}

/* Test peer update functionality */
void
test_repair_ledger_peer_update( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing peer update" ));
  
  fd_repair_ledger_t * ledger = setup_repair_ledger( wksp, 42UL, 1000000000UL );
  
  /* Add peer */
  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  long current_time = 1000000000L;
  fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_add( ledger, &peer_key, peer_ip, current_time );
  FD_TEST( peer );
  
  /* Test updating peer receive */
  long update_time = current_time + 1000000L;
  fd_repair_ledger_peer_t * updated_peer = fd_repair_ledger_peer_update( ledger, &peer_key, peer_ip, 1, update_time );
  FD_TEST( updated_peer );
  FD_TEST( updated_peer == peer );
  FD_TEST( updated_peer->last_recv == update_time );
  
  /* Test updating peer send */
  long send_time = update_time + 1000000L;
  fd_repair_ledger_peer_t * sent_peer = fd_repair_ledger_peer_update( ledger, &peer_key, peer_ip, 0, send_time );
  FD_TEST( sent_peer );
  FD_TEST( sent_peer == peer );
  
  /* Test updating on onon-existent peer */
  fd_pubkey_t nonexistent_key = make_pubkey( 99 );
  fd_repair_ledger_peer_t * not_found = fd_repair_ledger_peer_update( ledger, &nonexistent_key, peer_ip, 1, send_time );
  FD_TEST( !not_found );
  
  /* Cleanup */
  test_repair_ledger_cleanup( ledger );
}

/* Test repair ledger verification */
void
test_repair_ledger_verify( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing repair ledger verification" ));
  
  fd_repair_ledger_t * ledger = setup_repair_ledger( wksp, 42UL, 1000000000UL );
  
  /* Test verification empty ledger */
  int verify_result = fd_repair_ledger_verify( ledger );
  FD_TEST( verify_result == 0 );
  
  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  long current_time = 1000000000L;
  fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_add( ledger, &peer_key, peer_ip, current_time );
  FD_TEST( peer );
  
  fd_repair_ledger_req_t * req = fd_repair_ledger_req_insert( ledger, 12345UL, 1000000000UL,
                                                             &peer_key, peer_ip, 100UL, 0UL, FD_REPAIR_KIND_SHRED_REQ );
  FD_TEST( req );
  
  /* Test verification with data */
  verify_result = fd_repair_ledger_verify( ledger );
  FD_TEST( verify_result == 0 );
  
  /* Test verification with NULL ledger */
  verify_result = fd_repair_ledger_verify( NULL );
  FD_TEST( verify_result == -1 );
  
  /* Cleanup */
  test_repair_ledger_cleanup( ledger );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  /* Run all tests */
  test_repair_ledger_peer_basic( wksp );
  test_repair_ledger_req_basic( wksp );
  test_repair_ledger_req_expire( wksp );
  test_repair_ledger_peer_selection( wksp );
  test_repair_ledger_peer_update( wksp );
  test_repair_ledger_verify( wksp );

  FD_LOG_NOTICE(( "All repair ledger tests passed!" ));

  fd_wksp_delete_anonymous( wksp );
  fd_halt();
  return 0;
}
