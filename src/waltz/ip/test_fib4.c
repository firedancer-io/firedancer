#include "fd_fib4_private.h"
#define _POSIX_C_SOURCE 200809L /* fmemopen */
#include "fd_fib4.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib1_mem[ 1<<18 ];

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib2_mem[ 1<<18 ];

#if FD_HAS_HOSTED
#include <stdio.h>

static void
test_fib_print( fd_fib4_t const * fib,
                char const *      actual ) {
  static char dump_buf[ 8192 ];
  FILE * dump = fmemopen( dump_buf, sizeof(dump_buf), "w" );
  FD_TEST( 0==fd_fib4_fprintf( fib, dump ) );
  ulong sz = (ulong)ftell( dump );
  fclose( dump );

  if( FD_UNLIKELY( sz!=strlen( actual ) || 0!=strncmp( dump_buf, actual, sz ) ) ) {
    fwrite( dump_buf, 1, sz, stderr );
    fflush( stderr );
    FD_LOG_ERR(( "FAIL: fd_fib4_fprintf(fib) != expected" ));
  }
}

#else /* !FD_HAS_HOSTED */

#define test_fib_print(...)

#endif


void
test_fib4_hmap_precedence( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );

  uint target_ip = FD_IP4_ADDR( 10,0,0,100 );

  /* Add a broad route in routing table */
  fd_fib4_hop_t route_hop = {
    .ip4_src = FD_IP4_ADDR( 10,0,0,2 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 1,
    .ip4_gw  = FD_IP4_ADDR( 10,0,0,1 )
  };
  FD_TEST( fd_fib4_insert( fib, FD_IP4_ADDR( 10,0,0,0 ), 24, 100, &route_hop ) );

  /* Verify broad route works */
  fd_fib4_hop_t lookup_hop;
  fd_fib4_lookup( fib, &lookup_hop, target_ip, 0 );
  FD_TEST( lookup_hop.rtype == route_hop.rtype );
  FD_TEST( lookup_hop.if_idx == route_hop.if_idx );

  /* Add specific host route in hashmap */
  fd_fib4_hop_t hmap_hop = {
    .ip4_src = FD_IP4_ADDR( 10,0,0,3 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 2,
    .ip4_gw  = FD_IP4_ADDR( 10,0,0,2 )
  };
  FD_TEST( fd_fib4_insert( fib, target_ip, 32, 0, &hmap_hop ) );

  /* Hashmap entry should take precedence */
  fd_fib4_lookup( fib, &lookup_hop, target_ip, 0 );
  FD_TEST( lookup_hop.rtype == hmap_hop.rtype );
  FD_TEST( lookup_hop.if_idx == hmap_hop.if_idx );
  FD_TEST( lookup_hop.ip4_gw == hmap_hop.ip4_gw );

  /* Other IPs in the subnet should still use routing table */
  uint other_ip = FD_IP4_ADDR( 10,0,0,101 );
  fd_fib4_lookup( fib, &lookup_hop, other_ip, 0 );
  FD_TEST( lookup_hop.rtype == route_hop.rtype );
  FD_TEST( lookup_hop.if_idx == route_hop.if_idx );
}

void
test_fib4_hmap_capacity( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );

  fd_fib4_hop_t hop = {
    .ip4_src = FD_IP4_ADDR( 10,0,0,2 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 1,
    .ip4_gw  = FD_IP4_ADDR( 10,0,0,1 )
  };

  /* Fill hashmap to capacity */
  ulong hmap_max  = fd_fib4_peer_max( fib );
  ulong table_max = fd_fib4_max( fib );
  uint ip_base    = FD_IP4_ADDR( 192,168,1,1 );

  for( ulong i = 0; i < hmap_max ; i++ ) {
    uint ip = ip_base + (uint)i;
    FD_TEST( fd_fib4_insert( fib, ip, 32, 0, &hop ) );
  }

  /*Try to insert one more - should fail. fd_fib4_insert should log warnings */
  uint overflow_ip = ip_base + (uint)hmap_max;
  FD_TEST( fd_fib4_insert( fib, overflow_ip, 32, 0, &hop )==0 );

  /* Insert to route table */
  for( ulong i = 0; i < table_max-1 ; i++ ) {
    uint ip = (ip_base + (uint)hmap_max + (uint)i) & 31;
    FD_TEST( fd_fib4_insert( fib, ip, 31, 0, &hop ) );

    fd_fib4_hop_t lookup_hop;
    fd_fib4_lookup( fib, &lookup_hop, ip, 0 );
    FD_TEST( lookup_hop.rtype  == hop.rtype );
    FD_TEST( lookup_hop.if_idx == hop.if_idx );
    FD_TEST( lookup_hop.ip4_gw == hop.ip4_gw );
  }
  /*Try to insert one more - should fail. fd_fib4_insert should log warnings */
  overflow_ip = ip_base + (uint)hmap_max + (uint)table_max;
  FD_TEST( fd_fib4_insert( fib, overflow_ip, 31, 0, &hop )==0 );

  /* Verify all inserted routes are still accessible */
  fd_fib4_hop_t lookup_hop;
  for( ulong i = 0; i < hmap_max - 1; i++ ) {
    uint ip = ip_base + (uint)i;
    fd_fib4_lookup( fib, &lookup_hop, ip, 0 );
    FD_TEST( lookup_hop.rtype  == hop.rtype );
    FD_TEST( lookup_hop.if_idx == hop.if_idx );
    FD_TEST( lookup_hop.ip4_gw == hop.ip4_gw );
  }

  /* Verify that the not inserted routes can't be found */
  fd_fib4_lookup( fib, &lookup_hop, ip_base + (uint)hmap_max, 0 );
  FD_TEST( lookup_hop.rtype  == FD_FIB4_RTYPE_THROW );
  fd_fib4_lookup( fib, &lookup_hop, (ip_base + (uint)hmap_max + (uint)table_max) & 31, 0 );
  FD_TEST( lookup_hop.rtype  == FD_FIB4_RTYPE_THROW );
}

void
test_fib4_hmap_edge_cases( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );

  fd_fib4_hop_t hop = {
    .ip4_src = FD_IP4_ADDR( 255,255,255,255 ),
    .rtype = FD_FIB4_RTYPE_UNICAST,
    .if_idx = 1
  };

  /* Test with special IP addresses */
  uint special_ips[] = {
    FD_IP4_ADDR( 255,255,255,255 ),
    FD_IP4_ADDR( 127,0,0,1 ),
    FD_IP4_ADDR( 224,0,0,1 ),
    FD_IP4_ADDR( 169,254,1,1 ),
  };

  for( ulong i = 0; i < sizeof(special_ips)/sizeof(special_ips[0]); i++ ) {
    FD_TEST( fd_fib4_insert( fib, special_ips[i], 32, 0, &hop ) );

    fd_fib4_hop_t lookup_hop;
    fd_fib4_lookup( fib, &lookup_hop, special_ips[i], 0 );
    FD_TEST( lookup_hop.rtype == hop.rtype );
    FD_TEST( lookup_hop.if_idx == hop.if_idx );
  }
}

void
test_fib4_hmap_duplicates( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );
  FD_TEST( fd_fib4_cnt( fib )==1 );

  uint ip = FD_IP4_ADDR( 192,168,1,100 );

  fd_fib4_hop_t hop1 = {
    .ip4_src = FD_IP4_ADDR( 192,168,1,2 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 1,
    .ip4_gw  = FD_IP4_ADDR( 192,168,1,1 )
  };

  fd_fib4_hop_t hop2 = {
    .ip4_src = FD_IP4_ADDR( 192,168,1,3 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 2,
    .ip4_gw  = FD_IP4_ADDR( 192,168,1,2 )
  };

  /* Insert first hop */
  FD_TEST( fd_fib4_insert( fib, ip, 32, 0, &hop1 ) );

  /* Verify first hop */
  fd_fib4_hop_t lookup_hop;
  fd_fib4_lookup( fib, &lookup_hop, ip, 0 );
  FD_TEST( lookup_hop.ip4_src == hop1.ip4_src );
  FD_TEST( lookup_hop.if_idx  == hop1.if_idx  );
  FD_TEST( lookup_hop.ip4_gw  == hop1.ip4_gw  );

  /* Insert duplicate - should update existing entry */
  FD_TEST( fd_fib4_insert( fib, ip, 32, 0, &hop2 ) );

  /* Verify second hop overwrote first */
  fd_fib4_lookup( fib, &lookup_hop, ip, 0 );
  FD_TEST( lookup_hop.ip4_src == hop2.ip4_src );
  FD_TEST( lookup_hop.if_idx  == hop2.if_idx  );
  FD_TEST( lookup_hop.ip4_gw  == hop2.ip4_gw  );
}

void
test_fib4_hmap_clear( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );

  fd_fib4_hop_t hop = {
    .ip4_src = FD_IP4_ADDR( 192,168,1,3 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 1
  };

  /* Add entries to both hashmap and routing table */
  uint hmap_ip = FD_IP4_ADDR( 10,0,0,1 );
  FD_TEST( fd_fib4_insert( fib, hmap_ip, 32, 0, &hop ) );

  uint route_ip = FD_IP4_ADDR( 192,168,0,0 );
  FD_TEST( fd_fib4_insert( fib, route_ip, 24, 0, &hop ) );

  /* Verify entries exist */
  fd_fib4_hop_t lookup_hop;
  fd_fib4_lookup( fib, &lookup_hop, hmap_ip, 0 );
  FD_TEST( lookup_hop.ip4_src == hop.ip4_src );
  FD_TEST( lookup_hop.rtype   == hop.rtype );

  fd_fib4_lookup( fib, &lookup_hop, FD_IP4_ADDR( 192,168,0,100 ), 0 );
  FD_TEST( lookup_hop.ip4_src == hop.ip4_src );
  FD_TEST( lookup_hop.rtype   == hop.rtype );

  /* Clear and verify both are gone */
  fd_fib4_clear( fib );

  fd_fib4_lookup( fib, &lookup_hop, hmap_ip, 0 );
  FD_TEST( lookup_hop.rtype == FD_FIB4_RTYPE_THROW );

  fd_fib4_lookup( fib, &lookup_hop, FD_IP4_ADDR( 192,168,0,100 ), 0 );
  FD_TEST( lookup_hop.rtype == FD_FIB4_RTYPE_THROW );
}

void
test_fib4_hmap_counts( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );

  ulong initial_cnt = fd_fib4_cnt( fib );

  fd_fib4_hop_t hop = {
    .ip4_src = FD_IP4_ADDR( 192,168,1,3 ),
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .if_idx  = 1 };

  /* Add some hashmap entries */
  uint ip1 = FD_IP4_ADDR( 10,0,0,1 );
  uint ip2 = FD_IP4_ADDR( 10,0,0,2 );
  FD_TEST( fd_fib4_insert( fib, ip1, 32, 0, &hop ) );
  FD_TEST( fd_fib4_insert( fib, ip2, 32, 0, &hop ) );

  /* Count should include hashmap entries */
  FD_TEST( fd_fib4_cnt( fib ) == initial_cnt + 2 );

  /* Add a routing table entry */
  FD_TEST( fd_fib4_insert( fib, FD_IP4_ADDR( 192,168,0,0 ), 24, 0, &hop ) );

  /* Count should include both hashmap and routing table entries */
  FD_TEST( fd_fib4_cnt( fib ) == initial_cnt + 3 );
}

void
test_fib4_hmap_basic_insert( fd_fib4_t * fib ) {
  FD_TEST( fib );

  fd_fib4_clear( fib );

  FD_TEST( fd_fib4_cnt( fib )==1 );
  fd_fib4_hop_t hop1 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,161 )};
  fd_fib4_hop_t hop2 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,162 )} ;
  fd_fib4_hop_t hop3 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,163 )};
  fd_fib4_hop_t hop4 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,1 )};
  fd_fib4_hop_t hop5 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,2 )};
  fd_fib4_hop_t hop6 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=1, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };

  uint ip_dst1 = FD_IP4_ADDR( 192,0,2,160   );
  uint ip_dst2 = FD_IP4_ADDR( 192,0,2,165  );
  uint ip_dst3 = FD_IP4_ADDR( 192,0,2,191   );
  uint ip_dst4 = FD_IP4_ADDR( 127,0,0,0   );
  uint ip_dst5 = FD_IP4_ADDR( 127,0,0,1   );
  uint ip_dst6 = FD_IP4_ADDR( 127,0,255,255 );

  fd_fib4_hop_t hop;

  FD_TEST( fd_fib4_lookup( fib, &hop, ip_dst1, 0 )->rtype==FD_FIB4_RTYPE_THROW );

  FD_TEST( fd_fib4_insert( fib, ip_dst1, 32, 0, &hop1 ) );
  FD_TEST( fd_fib4_insert( fib, ip_dst2, 32, 0, &hop2 ) );
  FD_TEST( fd_fib4_insert( fib, ip_dst3, 32, 0, &hop3 ) );
  FD_TEST( fd_fib4_insert( fib, ip_dst4, 32, 0, &hop4 ) );
  FD_TEST( fd_fib4_insert( fib, ip_dst5, 32, 0, &hop5 ) );
  FD_TEST( fd_fib4_insert( fib, ip_dst6, 32, 0, &hop6 ) );

  fd_fib4_lookup( fib, &hop, ip_dst1, 0 );
  FD_TEST( hop.rtype==hop1.rtype );
  FD_TEST( hop.if_idx==hop1.if_idx );
  FD_TEST( hop.ip4_src==hop1.ip4_src );

  fd_fib4_lookup( fib, &hop, ip_dst2, 0 );
  FD_TEST( hop.rtype==hop2.rtype );
  FD_TEST( hop.if_idx==hop2.if_idx );
  FD_TEST( hop.ip4_src==hop2.ip4_src );

  fd_fib4_lookup( fib, &hop, ip_dst3, 0 );
  FD_TEST( hop.rtype==hop3.rtype );
  FD_TEST( hop.if_idx==hop3.if_idx );
  FD_TEST( hop.ip4_src==hop3.ip4_src );

  fd_fib4_lookup( fib, &hop, ip_dst4, 0 );
  FD_TEST( hop.rtype==hop4.rtype );
  FD_TEST( hop.if_idx==hop4.if_idx );
  FD_TEST( hop.ip4_src==hop4.ip4_src );

  fd_fib4_lookup( fib, &hop, ip_dst5, 0 );
  FD_TEST( hop.rtype==hop5.rtype );
  FD_TEST( hop.if_idx==hop5.if_idx );
  FD_TEST( hop.ip4_src==hop5.ip4_src );

  fd_fib4_lookup( fib, &hop, ip_dst6, 0 );
  FD_TEST( hop.rtype==hop6.rtype );
  FD_TEST( hop.if_idx==hop6.if_idx );
  FD_TEST( hop.ip4_src==hop6.ip4_src );
}

void
test_fib4_mix( fd_fib4_t * fib ) {
  FD_TEST( fib );
  fd_fib4_clear( fib );

  fd_fib4_hop_t default_hop = {
    .rtype = FD_FIB4_RTYPE_UNICAST,
    .if_idx = 1,
    .ip4_gw = FD_IP4_ADDR( 10,0,0,1 )
  };

  fd_fib4_hop_t subnet_hop = {
    .rtype = FD_FIB4_RTYPE_UNICAST,
    .if_idx = 2,
    .ip4_gw = FD_IP4_ADDR( 10,0,1,1 )
  };

  fd_fib4_hop_t host_hop = {
    .rtype = FD_FIB4_RTYPE_UNICAST,
    .if_idx = 3,
    .ip4_gw = FD_IP4_ADDR( 10,0,1,254 )
  };

  FD_TEST( fd_fib4_insert( fib, 0, 0, 100, &default_hop ) );  // default route
  FD_TEST( fd_fib4_insert( fib, FD_IP4_ADDR( 10,0,1,0 ), 24, 50, &subnet_hop) );  // subnet route

  uint target_ip = FD_IP4_ADDR( 10,0,1,100 );

  fd_fib4_hop_t lookup_hop;
  fd_fib4_lookup( fib, &lookup_hop, target_ip, 0 );
  FD_TEST( lookup_hop.if_idx == subnet_hop.if_idx );

  FD_TEST( fd_fib4_insert( fib, target_ip, 32, 0, &host_hop ) );
  fd_fib4_lookup( fib, &lookup_hop, target_ip, 0 );
  FD_TEST( lookup_hop.if_idx == host_hop.if_idx );

  uint other_ip = FD_IP4_ADDR( 10,0,1,101 );
  fd_fib4_lookup( fib, &lookup_hop, other_ip, 0 );
  FD_TEST( lookup_hop.if_idx == subnet_hop.if_idx );

  uint outside_ip = FD_IP4_ADDR( 192,168,1,1 );
  fd_fib4_lookup( fib, &lookup_hop, outside_ip, 0 );
  FD_TEST( lookup_hop.if_idx == default_hop.if_idx );
}


void
test_fib4_hmap( fd_fib4_t * fib ) {

  test_fib4_hmap_basic_insert( fib );

  test_fib4_hmap_capacity( fib );

  test_fib4_hmap_precedence( fib );

  test_fib4_hmap_edge_cases( fib );

  test_fib4_hmap_duplicates( fib );

  test_fib4_hmap_clear( fib );

  test_fib4_hmap_counts( fib );

  test_fib4_mix( fib );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_ulong_is_aligned( (ulong)fib1_mem, fd_fib4_align() ) );

  // Test fib4_footprint
  FD_TEST(  fd_fib4_footprint( 1UL, 1UL ) );
  FD_TEST(  fd_fib4_footprint( 1UL, 3UL ) );
  FD_TEST(  fd_fib4_footprint( 1UL, 4UL ) );
  FD_TEST( !fd_fib4_footprint( 0UL, 1UL ) );
  FD_TEST( !fd_fib4_footprint( 1UL, 0UL ) );
  FD_TEST( !fd_fib4_footprint( 1UL, 0UL ) );
  FD_TEST( 1UL==fd_fib4_hmap_get_lock_cnt( 16UL ) );
  FD_TEST( 3UL==fd_fib4_hmap_get_lock_cnt( 48UL ) );

  FD_TEST( fd_fib4_footprint( 16UL, 16UL )<=sizeof(fib1_mem) );
  fd_fib4_t * fib_local = fd_fib4_join( fd_fib4_new( fib1_mem, 16UL, 16UL, 123456UL ) );
  fd_fib4_t * fib_main  = fd_fib4_join( fd_fib4_new( fib2_mem, 16UL, 16UL, 123456UL ) );
  fd_fib4_hop_t candidate[2];

  /* Ensure empty FIB returns THROW */

  FD_TEST( fd_fib4_lookup( fib_local, candidate, 0x12345678, 0 )->rtype==FD_FIB4_RTYPE_THROW );

  /* Simple production scenario

     # ip route list table local
     broadcast 192.0.2.160     dev bond0 proto kernel scope link src 192.0.2.165
     local     192.0.2.0       dev bond0 proto kernel scope host src 192.0.2.165
     broadcast 192.0.2.191     dev bond0 proto kernel scope link src 192.0.2.165
     broadcast 127.0.0.0       dev lo    proto kernel scope link src 127.0.0.1
     local     127.0.0.0/8     dev lo    proto kernel scope host src 127.0.0.1
     local     127.0.0.1       dev lo    proto kernel scope host src 127.0.0.1
     broadcast 127.255.255.255 dev lo    proto kernel scope link src 127.0.0.1

     # ip route list table main
     default        via 192.0.2.161 dev bond0 proto dhcp              src 192.0.2.165 metric 300
     192.0.2.160/27                 dev bond0 proto kernel scope link src 192.0.2.165 metric 300 */

  fd_fib4_clear( fib_local );
  FD_TEST( fd_fib4_cnt( fib_local )==1 );
  fd_fib4_hop_t hop1 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  fd_fib4_hop_t hop2 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_LOCAL,     .if_idx=6, .scope=254, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  fd_fib4_hop_t hop3 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  fd_fib4_hop_t hop4 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=1, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };
  fd_fib4_hop_t hop5 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_LOCAL,     .if_idx=1, .scope=254, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };
  fd_fib4_hop_t hop6 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_LOCAL,     .if_idx=1, .scope=254, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };
  fd_fib4_hop_t hop7 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=1, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };

  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 192,0,2,160   ), 32, 0, &hop1 ) );  // fib4 hashmap
  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 192,0,2,165   ), 32, 0, &hop2 ) );
  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 192,0,2,191   ), 32, 0, &hop3 ) );
  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,0,0     ), 30, 0, &hop4 ) );
  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,0,0     ),  8, 0, &hop5 ) );
  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,0,1     ), 32, 0, &hop6 ) );   // fib4 hashmap
  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,255,255 ), 30, 0, &hop7 ) );

  FD_TEST( fd_fib4_cnt( fib_local )==8 );

  test_fib_print( fib_local,
    "throw default metric 4294967295\n"
    "broadcast 127.0.0.0/30 dev 1 scope link src 127.0.0.1\n"
    "local 127.0.0.0/8 dev 1 scope host src 127.0.0.1\n"
    "broadcast 127.0.255.255/30 dev 1 scope link src 127.0.0.1\n"
    "local 192.0.2.165/32 dev 6 scope host src 192.0.2.165\n"
    "broadcast 192.0.2.191/32 dev 6 scope link src 192.0.2.165\n"
    "local 127.0.0.1/32 dev 1 scope host src 127.0.0.1\n"
    "broadcast 192.0.2.160/32 dev 6 scope link src 192.0.2.165\n" );

  fd_fib4_clear( fib_main );
  FD_TEST( fd_fib4_cnt( fib_main )==1 );
  fd_fib4_hop_t hop8 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_gw=FD_IP4_ADDR( 192,0,2,161 ), .if_idx=6,             .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  fd_fib4_hop_t hop9 = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_UNICAST,                                     .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };

  FD_TEST( fd_fib4_insert( fib_main, FD_IP4_ADDR( 0,0,0,0     ),  0, 300, &hop8 ) );
  FD_TEST( fd_fib4_insert( fib_main, FD_IP4_ADDR( 192,0,2,161 ), 27, 300, &hop9 ) );

  test_fib_print( fib_main,
    "throw default metric 4294967295\n"
    "default via 192.0.2.161 dev 6 src 192.0.2.165 metric 300\n"
    "192.0.2.161/27 dev 6 scope link src 192.0.2.165 metric 300\n" );

# define QUERY(ip) fd_fib4_hop_or( fd_fib4_lookup( fib_local, candidate+0, FD_IP4_ADDR ip, 0 ), fd_fib4_lookup( fib_main, candidate+1, FD_IP4_ADDR ip, 0 ) )
  fd_fib4_hop_t const * next;

  /* $ ip route get 127.0.0.1
     local 127.0.0.1 dev lo src 127.0.0.1 */
  next = QUERY(( 127,0,0,1 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_LOCAL );
  FD_TEST( next->if_idx==1 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 127,0,0,1 ) );

  /* $ ip route get 192.0.2.160
     broadcast 192.0.2.160 dev bond0 src 192.0.2.165 */
  next = QUERY(( 192,0,2,160 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_BROADCAST );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

  /* $ ip route get 192.0.2.161
     192.0.2.161 dev bond0 src 192.0.2.165 */
  next = QUERY(( 192,0,2,161 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_UNICAST );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

  /* $ ip route get 192.0.2.191
     broadcast 192.0.2.191 dev bond0 src 192.0.2.165 */
  next = QUERY(( 192,0,2,191 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_BROADCAST );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

  /* $ ip route get 8.8.8.8
     8.8.8.8 via 192.0.2.161 dev bond0 src 192.0.2.165 */
  next = QUERY(( 8,8,8,8 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_UNICAST );
  FD_TEST( next->ip4_gw==FD_IP4_ADDR( 192,0,2,161 ) );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

# undef QUERY

  /* Clear again */
  fd_fib4_clear( fib_main );
  FD_TEST( fd_fib4_lookup( fib_local, candidate, 0x12345678, 0 )->rtype==FD_FIB4_RTYPE_THROW );

  /* Test the fib4 hmap */
  test_fib4_hmap( fib_main );
  test_fib4_hmap( fib_main );   // test again

  fd_fib4_delete( fd_fib4_leave( fib_local ) );
  fd_fib4_delete( fd_fib4_leave( fib_main  ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
