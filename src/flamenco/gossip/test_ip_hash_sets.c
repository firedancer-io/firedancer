#include "fd_gossip_msg_parse.c"

void
test_ipv4_hash_set( void ) {
  /* Test IPv4 hash set functionality */
  ipv4_entry_t ipv4_map[ ipv4_set_slot_cnt() ];
  ipv4_set_new( ipv4_map );

  /* Test inserting unique IPv4 addresses (excluding 0.0.0.0) */
  uint ip1 = 0x08080808U; /* 8.8.8.8 */
  uint ip2 = 0x08080404U; /* 8.8.4.4 */
  uint ip3 = 0xC0A80001U; /* 192.168.0.1 */

  ipv4_entry_t * result1 = ipv4_set_insert( ipv4_map, ip1 );
  ipv4_entry_t * result2 = ipv4_set_insert( ipv4_map, ip2 );
  ipv4_entry_t * result3 = ipv4_set_insert( ipv4_map, ip3 );

  FD_TEST( result1 != NULL );
  FD_TEST( result2 != NULL );
  FD_TEST( result3 != NULL );
  FD_TEST( result1->ip4_addr == ip1 );
  FD_TEST( result2->ip4_addr == ip2 );
  FD_TEST( result3->ip4_addr == ip3 );

  /* Test duplicate rejection */
  ipv4_entry_t * duplicate1 = ipv4_set_insert( ipv4_map, ip1 );
  ipv4_entry_t * duplicate2 = ipv4_set_insert( ipv4_map, ip2 );

  FD_TEST( duplicate1 == NULL );
  FD_TEST( duplicate2 == NULL );

  /* Test query functionality */
  ipv4_entry_t * found1 = ipv4_set_query( ipv4_map, ip1, NULL );
  ipv4_entry_t * found2 = ipv4_set_query( ipv4_map, ip2, NULL );
  ipv4_entry_t * not_found = ipv4_set_query( ipv4_map, 0x01010101U, NULL );

  FD_TEST( found1 != NULL );
  FD_TEST( found2 != NULL );
  FD_TEST( not_found == NULL );
  FD_TEST( found1->ip4_addr == ip1 );
  FD_TEST( found2->ip4_addr == ip2 );

  /* Note: 0.0.0.0 (0U) is handled separately with a flag in the actual parser */
}

void
test_ipv6_hash_set( void ) {
  /* Test IPv6 hash set functionality with full 128-bit keys */
  ipv6_entry_t ipv6_map[ ipv6_set_slot_cnt() ];
  ipv6_set_new( ipv6_map );

  /* Test inserting unique IPv6 addresses using full 128-bit keys */
  fd_gossip_view_ipv6_addr_t ip6_1 = { .hi = 0x20010db800000000UL, .lo = 0x0000000000000001UL };
  fd_gossip_view_ipv6_addr_t ip6_2 = { .hi = 0x20010db800000000UL, .lo = 0x0000000000000002UL };
  fd_gossip_view_ipv6_addr_t ip6_3 = { .hi = 0xfe80000000000000UL, .lo = 0x0000000000000001UL };

  ipv6_entry_t * result1 = ipv6_set_insert( ipv6_map, ip6_1 );
  ipv6_entry_t * result2 = ipv6_set_insert( ipv6_map, ip6_2 );
  ipv6_entry_t * result3 = ipv6_set_insert( ipv6_map, ip6_3 );

  FD_TEST( result1 != NULL );
  FD_TEST( result2 != NULL );
  FD_TEST( result3 != NULL );
  FD_TEST( result1->ip6.hi == ip6_1.hi && result1->ip6.lo == ip6_1.lo );
  FD_TEST( result2->ip6.hi == ip6_2.hi && result2->ip6.lo == ip6_2.lo );
  FD_TEST( result3->ip6.hi == ip6_3.hi && result3->ip6.lo == ip6_3.lo );

  /* Test duplicate rejection */
  ipv6_entry_t * duplicate1 = ipv6_set_insert( ipv6_map, ip6_1 );
  ipv6_entry_t * duplicate2 = ipv6_set_insert( ipv6_map, ip6_2 );

  FD_TEST( duplicate1 == NULL );
  FD_TEST( duplicate2 == NULL );

  /* Test query functionality */
  ipv6_entry_t * found1 = ipv6_set_query( ipv6_map, ip6_1, NULL );
  ipv6_entry_t * found2 = ipv6_set_query( ipv6_map, ip6_2, NULL );
  fd_gossip_view_ipv6_addr_t not_found_key = { .hi = 0x1234567890abcdefUL, .lo = 0xfedcba0987654321UL };
  ipv6_entry_t * not_found = ipv6_set_query( ipv6_map, not_found_key, NULL );

  FD_TEST( found1 != NULL );
  FD_TEST( found2 != NULL );
  FD_TEST( not_found == NULL );
  FD_TEST( found1->ip6.hi == ip6_1.hi && found1->ip6.lo == ip6_1.lo );
  FD_TEST( found2->ip6.hi == ip6_2.hi && found2->ip6.lo == ip6_2.lo );

  /* Test collision avoidance - addresses with same XOR but different hi/lo should be distinct */
  fd_gossip_view_ipv6_addr_t collision_test1 = { .hi = 0x1111111111111111UL, .lo = 0x2222222222222222UL };
  fd_gossip_view_ipv6_addr_t collision_test2 = { .hi = 0x2222222222222222UL, .lo = 0x1111111111111111UL };
  /* These have the same XOR: 0x1111111111111111 ^ 0x2222222222222222 == 0x2222222222222222 ^ 0x1111111111111111 */

  ipv6_entry_t * collision_result1 = ipv6_set_insert( ipv6_map, collision_test1 );
  ipv6_entry_t * collision_result2 = ipv6_set_insert( ipv6_map, collision_test2 );

  FD_TEST( collision_result1 != NULL );
  FD_TEST( collision_result2 != NULL );
  FD_TEST( collision_result1 != collision_result2 ); /* Should be different entries */

  /* Note: :: (all zeros) is handled separately with a flag in the actual parser */
}

void
test_hash_function_quality( void ) {
  /* Test that hash functions produce different values for different inputs */
  uint ip1 = 0x08080808U;
  uint ip2 = 0x08080404U;
  uint ip3 = 0xC0A80001U;

  uint hash1 = fd_uint_hash( ip1 );
  uint hash2 = fd_uint_hash( ip2 );
  uint hash3 = fd_uint_hash( ip3 );

  /* Hashes should be different for different IPs */
  FD_TEST( hash1 != hash2 );
  FD_TEST( hash1 != hash3 );
  FD_TEST( hash2 != hash3 );

  /* Same input should produce same hash */
  FD_TEST( fd_uint_hash( ip1 ) == hash1 );
  FD_TEST( fd_uint_hash( ip2 ) == hash2 );

  /* Test IPv6 hash function */
  ulong ip6_1 = 0x20010db800000001UL;
  ulong ip6_2 = 0x20010db800000002UL;

  uint hash6_1 = (uint)fd_ulong_hash( ip6_1 );
  uint hash6_2 = (uint)fd_ulong_hash( ip6_2 );

  FD_TEST( hash6_1 != hash6_2 );
  FD_TEST( (uint)fd_ulong_hash( ip6_1 ) == hash6_1 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_ipv4_hash_set();
  test_ipv6_hash_set();
  test_hash_function_quality();
  return 0;
}
