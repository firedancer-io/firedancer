#include "fd_recorder.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/net/fd_net_headers.h"

#include <stdarg.h>

fd_recorder_t *
setup_recorder( fd_wksp_t * wksp, ulong seed, ulong timeout_ns ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_recorder_align(), fd_recorder_footprint(), 1UL );
  FD_TEST( mem );
  fd_recorder_t * ledger = fd_recorder_join( fd_recorder_new( mem, seed, timeout_ns ) );
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

void test_recorder_cleanup( fd_recorder_t * ledger ) {
  fd_wksp_free_laddr( fd_recorder_delete( fd_recorder_leave( ledger ) ) );
  FD_LOG_NOTICE(( "Test passed" ));
}

/* basic peer operations: add, query, remove */
void
test_recorder_peer_basic( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing basic peer operations" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 1000000000UL );

  FD_TEST( fd_recorder_peer_cnt( ledger ) == 0UL );

  fd_pubkey_t peer1_key = make_pubkey( 1 );
  fd_pubkey_t peer2_key = make_pubkey( 2 );
  fd_ip4_port_t peer1_ip = make_ip4_port( 0x7F000001, 8080 );
  fd_ip4_port_t peer2_ip = make_ip4_port( 0x7F000002, 8081 );

  /* adding peers */
  fd_recorder_peer_t * peer1 = fd_recorder_peer_add( ledger, &peer1_key, peer1_ip );
  FD_TEST( peer1 );
  FD_TEST( fd_recorder_peer_cnt( ledger ) == 1UL );
  FD_TEST( peer1->ip4.addr == peer1_ip.addr );
  FD_TEST( peer1->ip4.port == peer1_ip.port );
  FD_TEST( peer1->inflight_to_peer_cnt == 0UL );

  fd_recorder_peer_t * peer2 = fd_recorder_peer_add( ledger, &peer2_key, peer2_ip );
  FD_TEST( peer2 );
  FD_TEST( fd_recorder_peer_cnt( ledger ) == 2UL );

  /* querying peers */
  fd_recorder_peer_t * found1 = fd_recorder_peer_query( ledger, &peer1_key );
  FD_TEST( found1 );
  FD_TEST( found1 == peer1 );
  FD_TEST( !memcmp( &found1->key, &peer1_key, sizeof(fd_pubkey_t) ) );

  fd_recorder_peer_t * found2 = fd_recorder_peer_query( ledger, &peer2_key );
  FD_TEST( found2 );
  FD_TEST( found2 == peer2 );

  /* non-added peer */
  fd_pubkey_t nonexistent_key = make_pubkey( 99 );
  fd_recorder_peer_t * nonexistent_peer = fd_recorder_peer_query( ledger, &nonexistent_key );
  FD_TEST( !nonexistent_peer );

  fd_recorder_peer_t * test = fd_recorder_peer_query( ledger, &peer1_key );
  FD_TEST( test );
  FD_TEST( test == peer1 );
  FD_TEST( test->inflight_to_peer_cnt == 0UL );

  /* adding duplicate peer (should update existing) */
  fd_ip4_port_t peer1_new_ip = make_ip4_port( 0x7F000003, 9090 );
  fd_recorder_peer_t * peer1_updated = fd_recorder_peer_add( ledger, &peer1_key, peer1_new_ip );
  FD_TEST( peer1_updated );
  FD_TEST( peer1_updated == peer1 );
  FD_TEST( fd_recorder_peer_cnt( ledger ) == 2UL );

  FD_TEST( peer1_updated->ip4.addr == peer1_new_ip.addr );

  test = fd_recorder_peer_query( ledger, &peer1_key );
  FD_TEST( test );
  FD_TEST( test == peer1 );
  FD_TEST( test->inflight_to_peer_cnt == 0UL );

  /* removing peers */
  fd_recorder_peer_t * remove_result = fd_recorder_peer_remove( ledger, &peer1_key);
  FD_TEST( remove_result != NULL );
  FD_TEST( fd_recorder_peer_cnt( ledger ) == 1UL );

  /* querying removed peer */
  fd_recorder_peer_t * removed = fd_recorder_peer_query( ledger, &peer1_key );
  FD_TEST( !removed );

  /* removing non-existent peer */
  fd_recorder_peer_t * remove_result2 = fd_recorder_peer_remove( ledger, &nonexistent_key);
  FD_TEST( remove_result2 == NULL );

  test_recorder_cleanup( ledger );
}

/* Basic request operations: insert, query, remove */
void
test_recorder_req_basic( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing basic request operations" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 1000000000UL );

  /* initial state */
  FD_TEST( fd_recorder_req_cnt( ledger ) == 0UL );

  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_key, peer_ip );
  FD_TEST( peer );

  /* inserting requests */
  ulong nonce1 = 12345UL;
  ulong nonce2 = 67890UL;
  ulong timestamp = 1000000000UL;
  ulong slot = 100UL;
  ulong shred_idx = 5UL;
  fd_recorder_req_t * req1 = fd_recorder_req_insert( ledger, nonce1, timestamp, &peer_key, peer_ip, slot, shred_idx );

  FD_TEST( req1 );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 1UL );
  FD_TEST( req1->nonce == nonce1 );
  FD_TEST( req1->timestamp_ns == timestamp );
  FD_TEST( req1->slot == slot );
  FD_TEST( req1->shred_idx == shred_idx );
  FD_TEST( !memcmp( &req1->pubkey, &peer_key, sizeof(fd_pubkey_t) ) );

  fd_recorder_req_t * req2 = fd_recorder_req_insert( ledger, nonce2, timestamp + 1000000UL, &peer_key, peer_ip, slot + 1, shred_idx + 1 );
  FD_TEST( req2 );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 2UL );

  /* querying requests */
  fd_recorder_req_t * found1 = fd_recorder_req_query( ledger, nonce1 );
  FD_TEST( found1 );
  FD_TEST( found1 == req1 );
  FD_TEST( found1->nonce == nonce1 );

  fd_recorder_req_t * found2 = fd_recorder_req_query( ledger, nonce2 );
  FD_TEST( found2 );
  FD_TEST( found2 == req2 );

  /* querying non-existent request */
  fd_recorder_req_t * not_found = fd_recorder_req_query( ledger, 99999UL );
  FD_TEST( !not_found );

  /* inserting another request with different nonce */
  ulong nonce3 = 54321UL;
  fd_recorder_req_t * req3 = fd_recorder_req_insert( ledger, nonce3, timestamp + 2000000UL, &peer_key, peer_ip, slot + 2, shred_idx + 2 );

  FD_TEST( req3 );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 3UL );

  /* oldest/newest requests */
  fd_recorder_req_t const * oldest = fd_recorder_req_oldest( ledger );
  FD_TEST( oldest );
  FD_TEST( oldest->nonce == nonce1 );

  fd_recorder_req_t const * newest = fd_recorder_req_newest( ledger );
  FD_TEST( newest );
  FD_TEST( newest->nonce == nonce3 );

  int remove_result = fd_recorder_req_remove( ledger, nonce1, 1);
  FD_TEST( remove_result == 0 );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 2UL );

  /* querying removed request */
  fd_recorder_req_t * removed = fd_recorder_req_query( ledger, nonce1 );
  FD_TEST( !removed );

  int remove_result2 = fd_recorder_req_remove( ledger, 99999UL, 1);
  FD_TEST( remove_result2 == -1 );

  test_recorder_cleanup( ledger );
}

/* Request expiration functionality */
void
test_recorder_req_expire( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing request expiration" ));

  ulong timeout_ns = 1000000000UL; /* 1 second timeout */
  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, timeout_ns );

  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_key, peer_ip );
  FD_TEST( peer );

  ulong base_time = 1000000000UL;
  ulong nonce1 = 1UL;
  ulong nonce2 = 2UL;
  ulong nonce3 = 3UL;

  /* Request 1: expire */
  fd_recorder_req_t * req1 = fd_recorder_req_insert( ledger, nonce1, base_time,
                                                               &peer_key, peer_ip, 100UL, 0UL );
  FD_TEST( req1 );

  /* Request 2: expire */
  fd_recorder_req_t * req2 = fd_recorder_req_insert( ledger, nonce2, base_time + 500000000UL,
                                                               &peer_key, peer_ip, 101UL, 0UL );
  FD_TEST( req2 );

  /* Request 3: not expire */
  fd_recorder_req_t * req3 = fd_recorder_req_insert( ledger, nonce3, base_time + 1500000000UL,
                                                               &peer_key, peer_ip, 102UL, 0UL );
  FD_TEST( req3 );

  FD_TEST( fd_recorder_req_cnt( ledger ) == 3UL );

  /* Test expiration at a time that should expire first two requests */
  ulong expire_time = base_time + 2000000000UL; /* 2 seconds after base_time */
  ulong expired_count = fd_recorder_req_expire( ledger, expire_time, 1);

  FD_TEST( expired_count == 2UL );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 1UL );

  FD_TEST( !fd_recorder_req_query( ledger, nonce1 ) );
  FD_TEST( !fd_recorder_req_query( ledger, nonce2 ) );
  FD_TEST( fd_recorder_req_query( ledger, nonce3 ) );

  /* Test expiration when no requests should expire */
  ulong no_expire_count = fd_recorder_req_expire( ledger, expire_time, 1);
  FD_TEST( no_expire_count == 0UL );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 1UL );

  /* Test expiration that removes all remaining requests */
  ulong expire_all_time = base_time + 3000000000UL; /* 3 seconds after base_time */
  ulong all_expired_count = fd_recorder_req_expire( ledger, expire_all_time, 1);
  FD_TEST( all_expired_count == 1UL );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 0UL );

  ulong empty_expire_count = fd_recorder_req_expire( ledger, expire_all_time, 1);
  FD_TEST( empty_expire_count == 0UL );

  test_recorder_cleanup( ledger );
}

/* Test peer selection functionality */
void
test_recorder_peer_selection( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing peer selection" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 1000000000UL );

  fd_pubkey_t peer_keys[5];
  for( uint i = 0; i < 5; i++ ) {
    peer_keys[i] = make_pubkey( (uchar)(i + 1) );
    fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001 + i, (ushort)(8080UL + i) );
    fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_keys[i], peer_ip );
    FD_TEST( peer );
  }

  FD_TEST( fd_recorder_peer_cnt( ledger ) == 5UL );

  /* Test selecting peers */
  fd_pubkey_t * selected_peers[3];
  for( uint i=0; i<3; i++ ) {
    selected_peers[i] = fd_recorder_select_peer( ledger );
  }

  /* Verify we got 3 different peers */
  FD_TEST( selected_peers[0] != selected_peers[1] );
  FD_TEST( selected_peers[1] != selected_peers[2] );
  FD_TEST( selected_peers[0] != selected_peers[2] );

  fd_pubkey_t * more_selected[3];
  for( uint i=0; i<3; i++ ) {
    more_selected[i] = fd_recorder_select_peer( ledger );
    FD_TEST( more_selected[i] );
  }

  test_recorder_cleanup( ledger );
}

/* Test peer update functionality */
void
test_recorder_peer_update( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing peer update" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 1000000000UL );

  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  long current_time = 1000000000L;
  fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_key, peer_ip );
  FD_TEST( peer );

  /* Add a request first so we have inflight requests to track */
  fd_recorder_req_t * req = fd_recorder_req_insert( ledger, 12345UL, (ulong)current_time, &peer_key, peer_ip, 100UL, 0UL );
  FD_TEST( req );
  FD_TEST( peer->inflight_to_peer_cnt == 1UL );

  long update_time = current_time + 1000000L;
  fd_recorder_peer_t * updated_peer = fd_recorder_peer_update( ledger, &peer_key, peer_ip, 1, (ulong)current_time, (ulong)update_time );
  FD_TEST( updated_peer );
  FD_TEST( updated_peer == peer );
  FD_TEST( updated_peer->ewma_hr == 1.0 );
  FD_TEST( updated_peer->inflight_to_peer_cnt == 0UL );

  fd_recorder_req_t * req2 = fd_recorder_req_insert( ledger, 12346UL, (ulong)current_time, &peer_key, peer_ip, 101UL, 1UL );
  FD_TEST( req2 );
  FD_TEST( peer->inflight_to_peer_cnt == 1UL );

  /* Test updating peer send */
  long send_time = update_time + 1000000L;
  fd_recorder_peer_t * sent_peer = fd_recorder_peer_update( ledger, &peer_key, peer_ip, 0, (ulong)current_time, (ulong)send_time );
  FD_TEST( sent_peer );
  FD_TEST( sent_peer == peer );
  FD_TEST( sent_peer->ewma_hr > 0.89 && sent_peer->ewma_hr < 0.91 );
  FD_TEST( sent_peer->inflight_to_peer_cnt == 0UL );

  /* Test updating on onon-existent peer */
  fd_pubkey_t nonexistent_key = make_pubkey( 99 );
  fd_recorder_peer_t * not_found = fd_recorder_peer_update( ledger, &nonexistent_key, peer_ip, 1, (ulong)send_time, (ulong)current_time );
  FD_TEST( !not_found );

  test_recorder_cleanup( ledger );
}

/* Test repair ledger verification */
void
test_recorder_verify( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing repair ledger verification" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 1000000000UL );

  int verify_result = fd_recorder_verify( ledger );
  FD_TEST( verify_result == 0 );

  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_key, peer_ip );
  FD_TEST( peer );

  fd_recorder_req_t * req = fd_recorder_req_insert( ledger, 12345UL, 1000000000UL,
                                                             &peer_key, peer_ip, 100UL, 0UL );
  FD_TEST( req );

  verify_result = fd_recorder_verify( ledger );
  FD_TEST( verify_result == 0 );

  verify_result = fd_recorder_verify( NULL );
  FD_TEST( verify_result == -1 );

  test_recorder_cleanup( ledger );
}

/* Test filling up the request map/deque with many requests */
void
test_recorder_many_requests( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing many requests (fill map/deque)" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 10000000000UL ); /* 10 second timeout */

  ulong num_peers = 10;
  fd_pubkey_t peer_keys[10];

  for( ulong i = 0; i < num_peers; i++ ) {
    peer_keys[i] = make_pubkey( (uchar)(i + 1) );
    fd_ip4_port_t peer_ip = make_ip4_port( (uint)(0x7F000001 + i), (ushort)(8080 + i) );
    fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_keys[i], peer_ip );
    FD_TEST( peer );
  }

  FD_TEST( fd_recorder_peer_cnt( ledger ) == num_peers );

  /* Insert many requests */
  ulong num_requests = 1000; /* Test with 1000 requests */
  ulong base_time = 1000000000UL;

  for( ulong i = 0; i < num_requests; i++ ) {
    ulong nonce = i + 1000;
    ulong peer_idx = i % num_peers;
    fd_ip4_port_t peer_ip = make_ip4_port( (uint)(0x7F000001 + peer_idx), (ushort)(8080 + peer_idx) );

    fd_recorder_req_t * req = fd_recorder_req_insert(
      ledger, nonce, base_time + i * 1000000UL, /* Spread timestamps */
      &peer_keys[peer_idx], peer_ip,
      100UL + i, /* Different slots */
      i % 10     /* Different shred indices */
    );
    FD_TEST( req );
    FD_TEST( req->nonce == nonce );
  }

  FD_TEST( fd_recorder_req_cnt( ledger ) == num_requests );
  FD_LOG_NOTICE(( "Successfully inserted %lu requests", num_requests ));

  /* Verify we can query all requests */
  for( ulong i = 0; i < num_requests; i++ ) {
    ulong nonce = i + 1000;
    fd_recorder_req_t * req = fd_recorder_req_query( ledger, nonce );
    FD_TEST( req );
    FD_TEST( req->nonce == nonce );
  }

  fd_recorder_req_t const * oldest = fd_recorder_req_oldest( ledger );
  fd_recorder_req_t const * newest = fd_recorder_req_newest( ledger );
  FD_TEST( oldest );
  FD_TEST( newest );
  FD_TEST( oldest->nonce == 1000 );
  FD_TEST( newest->nonce == 1000 + num_requests - 1 );

  /* Remove all requests */
  for( ulong i = 0; i < num_requests; i++ ) {
    ulong nonce = i + 1000;
    int result = fd_recorder_req_remove( ledger, nonce, 1 );
    FD_TEST( result == 0 );
  }

  FD_TEST( fd_recorder_req_cnt( ledger ) == 0UL );
  FD_LOG_NOTICE(( "Successfully removed all %lu requests", num_requests ));

  test_recorder_cleanup( ledger );
}

/* Test out of order response handling */
void
test_recorder_out_of_order_response( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing out of order response handling" ));

  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, 5000000000UL ); /* 5 second timeout */

  /* Add peers */
  ulong num_peers = 3;
  fd_pubkey_t peer_keys[3];

  for( ulong i = 0; i < num_peers; i++ ) {
    peer_keys[i] = make_pubkey( (uchar)(i + 1) );
    fd_ip4_port_t peer_ip = make_ip4_port( (uint)(0x7F000001 + i), (ushort)(8080 + i) );
    fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_keys[i], peer_ip );
    FD_TEST( peer );
  }

  /* Insert requests in order: nonce 100, 101, 102, 103, 104 */
  ulong base_time = 1000000000UL;
  ulong nonces[5] = {100, 101, 102, 103, 104};

  for( ulong i = 0; i < 5; i++ ) {
    ulong peer_idx = i % num_peers;
    fd_ip4_port_t peer_ip = make_ip4_port( (uint)(0x7F000001 + peer_idx), (ushort)(8080 + peer_idx) );

    fd_recorder_req_t * req = fd_recorder_req_insert(
      ledger, nonces[i], base_time + i * 100000000UL, /* 100ms apart */
      &peer_keys[peer_idx], peer_ip,
      200UL + i, i
    );
    FD_TEST( req );
  }

  FD_TEST( fd_recorder_req_cnt( ledger ) == 5UL );

  fd_recorder_req_t const * oldest = fd_recorder_req_oldest( ledger );
  FD_TEST( oldest );
  FD_TEST( oldest->nonce == 100 );

  /* Remove responses out of order: 102, 100, 104, 101, 103 */
  ulong remove_order[5] = {102, 100, 104, 101, 103};

  for( ulong i = 0; i < 5; i++ ) {
    ulong nonce_to_remove = remove_order[i];

    fd_recorder_req_t * req = fd_recorder_req_query( ledger, nonce_to_remove );
    FD_TEST( req );

    int result = fd_recorder_req_remove( ledger, nonce_to_remove, 1 );
    FD_TEST( result == 0 );
    FD_TEST( fd_recorder_req_cnt( ledger ) == (5 - i - 1) );

    fd_recorder_req_t * removed_req = fd_recorder_req_query( ledger, nonce_to_remove );
    FD_TEST( !removed_req );

    FD_LOG_NOTICE(( "Removed request %lu out of order (step %lu/5)", nonce_to_remove, i + 1 ));
  }

  FD_TEST( fd_recorder_req_cnt( ledger ) == 0UL );

  /* Test that we can still add new requests after out-of-order removal */
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  fd_recorder_req_t * new_req = fd_recorder_req_insert(
    ledger, 999UL, base_time + 1000000000UL,
    &peer_keys[0], peer_ip, 300UL, 0UL
  );
  FD_TEST( new_req );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 1UL );

  test_recorder_cleanup( ledger );
}

/* Test that removed requests don't get expired later */
void
test_recorder_removal_vs_expiration( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Testing removal vs expiration interaction" ));

  ulong timeout_ns = 1000000000UL; /* 1 second timeout */
  fd_recorder_t * ledger = setup_recorder( wksp, 42UL, timeout_ns );

  fd_pubkey_t peer_key = make_pubkey( 1 );
  fd_ip4_port_t peer_ip = make_ip4_port( 0x7F000001, 8080 );
  fd_recorder_peer_t * peer = fd_recorder_peer_add( ledger, &peer_key, peer_ip );
  FD_TEST( peer );

  /* Insert 4 requests with old timestamps (all should be expirable) */
  ulong base_time = 1000000000UL;
  ulong nonce1 = 1UL, nonce2 = 2UL, nonce3 = 3UL, nonce4 = 4UL;

  fd_recorder_req_t * req1 = fd_recorder_req_insert( ledger, nonce1, base_time, &peer_key, peer_ip, 100UL, 1UL );
  fd_recorder_req_t * req2 = fd_recorder_req_insert( ledger, nonce2, base_time + 100000000UL, &peer_key, peer_ip, 101UL, 2UL );
  fd_recorder_req_t * req3 = fd_recorder_req_insert( ledger, nonce3, base_time + 200000000UL, &peer_key, peer_ip, 102UL, 3UL );
  fd_recorder_req_t * req4 = fd_recorder_req_insert( ledger, nonce4, base_time + 300000000UL, &peer_key, peer_ip, 103UL, 4UL );

  FD_TEST( req1 && req2 && req3 && req4 );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 4UL );

  ulong initial_handled = ledger->total_handled_requests;
  ulong initial_expired = ledger->total_expired_requests;

  // Remove two requests manually and check that only two remain
  int remove_result1 = fd_recorder_req_remove( ledger, nonce1, 1 );
  int remove_result2 = fd_recorder_req_remove( ledger, nonce3, 1 );
  FD_TEST( remove_result1 == 0 && remove_result2 == 0 );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 2UL );

  FD_TEST( !fd_recorder_req_query( ledger, nonce1 ) );
  FD_TEST( !fd_recorder_req_query( ledger, nonce3 ) );
  FD_TEST( fd_recorder_req_query( ledger, nonce2 ) );
  FD_TEST( fd_recorder_req_query( ledger, nonce4 ) );

  FD_TEST( ledger->total_handled_requests == initial_handled + 2 );
  FD_TEST( ledger->total_expired_requests == initial_expired );

  // expire the remaining requests and check that both are expired
  ulong expire_time = base_time + 2000000000UL;
  ulong expired_count = fd_recorder_req_expire( ledger, expire_time, 0 );

  FD_TEST( expired_count == 2UL );
  FD_TEST( fd_recorder_req_cnt( ledger ) == 0UL );

  // handled unchanged, expired increased by 2
  FD_TEST( ledger->total_handled_requests == initial_handled + 2 );
  FD_TEST( ledger->total_expired_requests == initial_expired + 2 );

  FD_TEST( !fd_recorder_req_query( ledger, nonce1 ) );
  FD_TEST( !fd_recorder_req_query( ledger, nonce2 ) );
  FD_TEST( !fd_recorder_req_query( ledger, nonce3 ) );
  FD_TEST( !fd_recorder_req_query( ledger, nonce4 ) );

  FD_LOG_NOTICE(( "Verified: manually removed requests don't get double-counted as expired" ));

  test_recorder_cleanup( ledger );
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
  test_recorder_peer_basic( wksp );
  test_recorder_req_basic( wksp );
  test_recorder_req_expire( wksp );
  test_recorder_peer_selection( wksp );
  test_recorder_peer_update( wksp );
  test_recorder_verify( wksp );
  test_recorder_many_requests( wksp );
  test_recorder_out_of_order_response( wksp );
  test_recorder_removal_vs_expiration( wksp );

  FD_LOG_NOTICE(( "All repair ledger tests passed!" ));

  fd_wksp_delete_anonymous( wksp );
  fd_halt();
  return 0;
}
