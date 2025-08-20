#include "../fd_flamenco_base.h"
#include "fd_repair.h"
#include "../../util/fd_util.h"
#include <stdlib.h>
#include <string.h>

/* init repair test */
static fd_repair_t *
test_repair_setup( void ) {
  ulong  footprint = fd_repair_footprint();
  void * shmem     = aligned_alloc( fd_repair_align(), footprint );
  FD_TEST( shmem );
  fd_repair_t * repair = fd_repair_join( fd_repair_new( shmem, 14919811UL  ) );
  FD_TEST( repair );
  return repair;
}

/* cleanup repair test*/
static void
test_repair_cleanup( fd_repair_t * repair ) {
  void * shmem = fd_repair_leave( repair );
  fd_repair_delete( shmem );
  free( shmem );
}

/* create a test buffer */
static void
create_test_buffer( uchar * buf, ulong buflen ) {
  for( ulong i = 0; i < buflen; i++ ) {
    buf[i] = (uchar)(i & 0xFF);
  }
}

/* test helper to create a seed generated recipient */
static void
create_test_recipient( fd_pubkey_t * recipient, ulong seed ) {
/* The range of values written to recipient->uc[i] is [0, 255] for
    each i in [0, 31], as each byte is set to (seed + i) & 0xFF. */
  for( uint i = 0; i < 32; i++ ) {
    recipient->uc[i] = (uchar)((seed + i) & 0xFF);
  }
}

/* test helper to add a pending request (similar logic to fd_repair_send_request_async) */
static int
test_add_pending_request( fd_repair_t * repair,
                          ulong         nonce,
                          uchar const * buf,
                          ulong         buflen,
                          ulong         sig_offset,
                          uint          dst_ip_addr,
                          ushort        dst_port,
                          fd_pubkey_t const * recipient ) {
  /* Check if there is any space for a new pending sign request */
  if( FD_UNLIKELY( fd_sign_req_pool_free( repair->sign_req_pool ) == 0 ) ) {
    return -1;
  }

  if( buflen > FD_REPAIR_MAX_SIGN_BUF_SIZE ) {
    return -1;
  }

  fd_repair_pending_sign_req_t * pending = fd_sign_req_pool_ele_acquire( repair->sign_req_pool );
  if( !pending ) {
    return -1;
  }

  pending->nonce       = nonce;
  pending->buflen      = buflen;
  pending->sig_offset  = sig_offset;
  pending->dst_ip_addr = dst_ip_addr;
  pending->dst_port    = dst_port;
  pending->recipient   = *recipient;

  fd_memcpy( pending->buf, buf, buflen );

  /* Add to map */
  fd_sign_req_map_ele_insert( repair->sign_req_map, pending, repair->sign_req_pool );

  return 0;
}

/* basic pending sign request operations (add, find, remove) */
static void
test_pending_sign_requests_basic( void ) {
  FD_LOG_NOTICE(( "Testing basic pending sign request operations" ));

  fd_repair_t * repair = test_repair_setup();

  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == FD_SIGN_REQ_MAX );
  FD_TEST( fd_repair_query_pending_request( repair, 14919811UL ) == NULL );

  uchar test_buf[128];
  create_test_buffer( test_buf, sizeof(test_buf) );
  fd_pubkey_t recipient;
  create_test_recipient( &recipient, 0x1234 );

  ulong nonce = 14919811UL;
  uint dst_ip = 14919811UL;
  ushort dst_port = 8080UL;
  ulong sig_offset = 4;

  int result = test_add_pending_request( repair, nonce, test_buf, sizeof(test_buf),
                                         sig_offset, dst_ip, dst_port, &recipient );
  FD_TEST( result == 0 );
  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == FD_SIGN_REQ_MAX - 1 );

  fd_repair_pending_sign_req_t * pending = fd_repair_query_pending_request( repair, nonce );
  FD_TEST( pending != NULL );
  FD_TEST( pending->nonce == nonce );
  FD_TEST( pending->buflen == sizeof(test_buf) );
  FD_TEST( pending->sig_offset == sig_offset );
  FD_TEST( pending->dst_ip_addr == dst_ip );
  FD_TEST( pending->dst_port == dst_port );
  FD_TEST( memcmp( &pending->recipient, &recipient, sizeof(fd_pubkey_t) ) == 0 );
  FD_TEST( memcmp( pending->buf, test_buf, sizeof(test_buf) ) == 0 );

  result = fd_repair_remove_pending_request( repair, nonce );
  FD_TEST( result == 0 );
  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == FD_SIGN_REQ_MAX );
  FD_TEST( fd_repair_query_pending_request( repair, nonce ) == NULL );

  result = fd_repair_remove_pending_request( repair, nonce );
  FD_TEST( result == -1 );

  test_repair_cleanup( repair );
  FD_LOG_NOTICE(( "Basic pending sign request tests PASS" ));
}

static void
test_pending_sign_requests_multiple( void ) {
  FD_LOG_NOTICE(( "Testing multiple pending sign requests" ));

  fd_repair_t * repair = test_repair_setup();

  const ulong num_requests = 10;
  ulong nonces[num_requests];
  fd_pubkey_t recipients[num_requests];

  for( ulong i = 0; i < num_requests; i++ ) {
    nonces[i] = 1000 + i;
    create_test_recipient( &recipients[i], i );

    uchar test_buf[64];
    create_test_buffer( test_buf, sizeof(test_buf) );

    int result = test_add_pending_request( repair, nonces[i], test_buf, sizeof(test_buf),
                                           4, 0x7F000001, (ushort)(8080 + i), &recipients[i] );
    FD_TEST( result == 0 );
  }

  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == FD_SIGN_REQ_MAX - num_requests );

  for( ulong i = 0; i < num_requests; i++ ) {
    fd_repair_pending_sign_req_t * pending = fd_repair_query_pending_request( repair, nonces[i] );
    FD_TEST( pending != NULL );
    FD_TEST( pending->nonce == nonces[i] );
    FD_TEST( pending->dst_port == (ushort)(8080 + i) );
    FD_TEST( memcmp( &pending->recipient, &recipients[i], sizeof(fd_pubkey_t) ) == 0 );
  }

  for( ulong i = num_requests; i > 0; i-- ) {
    int result = fd_repair_remove_pending_request( repair, nonces[i-1] );
    FD_TEST( result == 0 );

    FD_TEST( fd_repair_query_pending_request( repair, nonces[i-1] ) == NULL );

    for( ulong j = i - 1; j > 0; j-- ) {
      FD_TEST( fd_repair_query_pending_request( repair, nonces[j-1] ) != NULL );
    }
  }

  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == FD_SIGN_REQ_MAX );

  test_repair_cleanup( repair );
  FD_LOG_NOTICE(( "Multiple pending sign request tests PASS" ));
}

/* out-of-order pending sign request operations (change order of add, find, remove)*/
static void
test_pending_sign_requests_out_of_order( void ) {
  FD_LOG_NOTICE(( "Testing out-of-order pending sign request operations" ));

  fd_repair_t * repair = test_repair_setup();

  ulong nonces[] = { 100, 50, 200, 25, 150, 75, 300 };
  const ulong num_requests = sizeof(nonces) / sizeof(nonces[0]);

  for( ulong i = 0; i < num_requests; i++ ) {
    fd_pubkey_t recipient;
    create_test_recipient( &recipient, nonces[i] );

    uchar test_buf[32];
    create_test_buffer( test_buf, sizeof(test_buf) );

    int result = test_add_pending_request( repair, nonces[i], test_buf, sizeof(test_buf),
                                           4, 0x7F000001, 8080, &recipient );
    FD_TEST( result == 0 );
  }

  ulong find_order[] = { 100, 50, 200, 25, 150, 75, 300 };
  const ulong num_finds = sizeof(find_order) / sizeof(find_order[0]);
  for( ulong i = 0; i < num_finds; i++ ) {
    fd_repair_pending_sign_req_t * pending = fd_repair_query_pending_request( repair, find_order[i] );
    FD_TEST( pending != NULL );
    FD_TEST( pending->nonce == find_order[i] );
  }

  ulong removal_order[] = { 200, 25, 300, 50, 75, 100, 150 };
  for( ulong i = 0; i < num_requests; i++ ) {
    int result = fd_repair_remove_pending_request( repair, removal_order[i] );
    FD_TEST( result == 0 );

    FD_TEST( fd_repair_query_pending_request( repair, removal_order[i] ) == NULL );

    for( ulong j = i + 1; j < num_requests; j++ ) {
      FD_TEST( fd_repair_query_pending_request( repair, removal_order[j] ) != NULL );
    }
  }

  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == FD_SIGN_REQ_MAX );

  test_repair_cleanup( repair );
  FD_LOG_NOTICE(( "Out-of-order pending sign request tests PASS" ));
}

/* test edge cases and error conditions */
static void
test_pending_sign_requests_edge_cases( void ) {
  FD_LOG_NOTICE(( "Testing edge cases and error conditions" ));

  fd_repair_t * repair = test_repair_setup();

  fd_pubkey_t recipient;
  create_test_recipient( &recipient, 0x5678 );

  /* zero-length buffer */
  uchar test_buf[1];
  create_test_buffer( test_buf, sizeof(test_buf) );

  int result = test_add_pending_request( repair, 1, test_buf, 0,
                                         0, 14919811UL, 8080, &recipient );
  FD_TEST( result == 0 );

  fd_repair_pending_sign_req_t * pending = fd_repair_query_pending_request( repair, 1 );
  FD_TEST( pending != NULL );
  FD_TEST( pending->buflen == 0 );
  fd_repair_remove_pending_request( repair, 1 );

  /* maximum buffer size */
  uchar max_buf[FD_REPAIR_MAX_SIGN_BUF_SIZE];
  create_test_buffer( max_buf, sizeof(max_buf) );

  result = test_add_pending_request( repair, 2, max_buf, sizeof(max_buf),
                                     4, 14919811UL, 8080, &recipient );
  FD_TEST( result == 0 );

  pending = fd_repair_query_pending_request( repair, 2 );
  FD_TEST( pending != NULL );
  FD_TEST( pending->buflen == FD_REPAIR_MAX_SIGN_BUF_SIZE );
  fd_repair_remove_pending_request( repair, 2 );

  /* oversized buffer */
  uchar oversized_buf[FD_REPAIR_MAX_SIGN_BUF_SIZE + 1];
  result = test_add_pending_request( repair, 3, oversized_buf, sizeof(oversized_buf),
                                     4, 14919811UL, 8080, &recipient );
  FD_TEST( result == -1 );

  /* repeat nonce, will overwrite the first one */
  result = test_add_pending_request( repair, 100, test_buf, sizeof(test_buf),
                                     4, 16120512UL, 8080, &recipient );
  FD_TEST( result == 0 );

  fd_repair_pending_sign_req_t * pending2 = fd_sign_req_pool_ele_acquire( repair->sign_req_pool );
  pending2->nonce = 100;
  pending2->dst_ip_addr = 16120512UL;

  fd_sign_req_map_ele_insert( repair->sign_req_map, pending2, repair->sign_req_pool );

  FD_TEST( fd_repair_query_pending_request( repair, 100 )->dst_ip_addr == 16120512UL );

  fd_repair_remove_pending_request( repair, 100 );

  test_repair_cleanup( repair );
  FD_LOG_NOTICE(( "Edge case tests PASS" ));
}

/* pool exhaustion, and cleanup */
static void
test_pending_sign_requests_pool_exhaustion( void ) {
  FD_LOG_NOTICE(( "Testing pool exhaustion" ));

  fd_repair_t * repair = test_repair_setup();

  fd_pubkey_t recipient;
  create_test_recipient( &recipient, 0x9ABC );
  uchar test_buf[32];
  create_test_buffer( test_buf, sizeof(test_buf) );

  /* reach pool limit*/
  for( ulong i = 0; i < FD_SIGN_REQ_MAX; i++ ) {
    int result = test_add_pending_request( repair, i, test_buf, sizeof(test_buf),
                                           4, 0x7F000001, 8080, &recipient );
    FD_TEST( result == 0 );
  }

  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == 0 );

  /* try to add one more thiis should fail */
  int result = test_add_pending_request( repair, FD_SIGN_REQ_MAX,
                                         test_buf, sizeof(test_buf),
                                         4, 0x7F000001, 8080, &recipient );
  FD_TEST( result == -1 );

  /* remove and readd requests, should be able to add again */
  for( ulong i = 0; i < 10; i++ ) {
    result = fd_repair_remove_pending_request( repair, i );
    FD_TEST( result == 0 );
  }

  FD_TEST( fd_sign_req_pool_free( repair->sign_req_pool ) == 10 );

  for( ulong i = 0; i < 5; i++ ) {
    result = test_add_pending_request( repair, FD_SIGN_REQ_MAX + i,
                                       test_buf, sizeof(test_buf),
                                       4, 0x7F000001, 8080, &recipient );
    FD_TEST( result == 0 );
  }

  test_repair_cleanup( repair );
  FD_LOG_NOTICE(( "Pool exhaustion tests PASS" ));
}

/* multiple data test */
static void
test_pending_sign_requests_multiple_data( void ) {
  FD_LOG_NOTICE(( "Testing multiple data" ));

  fd_repair_t * repair = test_repair_setup();

  struct {
    ulong nonce;
    uchar pattern;
    ulong buflen;
    uint ip;
    ushort port;
    ulong sig_offset;
  } test_cases[] = {
    { 1, 0x00, 16, 0x7F000001, 8001, 0 },
    { 2, 0xFF, 32, 0xC0A80101, 8002, 4 },
    { 3, 0xAA, 64, 0x08080808, 8003, 8 },
    { 4, 0x55, 128, 0x01010101, 8004, 16 }
  };

  const ulong num_cases = sizeof(test_cases) / sizeof(test_cases[0]);

  for( ulong i = 0; i < num_cases; i++ ) {
    uchar test_buf[128];
    memset( test_buf, test_cases[i].pattern, test_cases[i].buflen );

    fd_pubkey_t recipient;
    create_test_recipient( &recipient, test_cases[i].nonce );

    int result = test_add_pending_request( repair, test_cases[i].nonce,
                                           test_buf, test_cases[i].buflen,
                                           test_cases[i].sig_offset,
                                           test_cases[i].ip,
                                           test_cases[i].port,
                                           &recipient );
    FD_TEST( result == 0 );
  }

  for( ulong i = 0; i < num_cases; i++ ) {
    fd_repair_pending_sign_req_t * pending = fd_repair_query_pending_request( repair, test_cases[i].nonce );
    FD_TEST( pending != NULL );

    FD_TEST( pending->nonce == test_cases[i].nonce );
    FD_TEST( pending->buflen == test_cases[i].buflen );
    FD_TEST( pending->sig_offset == test_cases[i].sig_offset );
    FD_TEST( pending->dst_ip_addr == test_cases[i].ip );
    FD_TEST( pending->dst_port == test_cases[i].port );

    for( ulong j = 0; j < test_cases[i].buflen; j++ ) {
      FD_TEST( pending->buf[j] == test_cases[i].pattern );
    }

    fd_pubkey_t expected_recipient;
    create_test_recipient( &expected_recipient, test_cases[i].nonce );
    FD_TEST( memcmp( &pending->recipient, &expected_recipient, sizeof(fd_pubkey_t) ) == 0 );
  }

  test_repair_cleanup( repair );
  FD_LOG_NOTICE(( "Multiple data tests PASS" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing fd_repair pending sign request functions" ));
  test_pending_sign_requests_basic();
  test_pending_sign_requests_multiple();
  test_pending_sign_requests_out_of_order();
  test_pending_sign_requests_edge_cases();
  test_pending_sign_requests_pool_exhaustion();
  test_pending_sign_requests_multiple_data();

  FD_LOG_NOTICE(( "All pending sign request tests PASS" ));

  fd_halt();
  return 0;
}
