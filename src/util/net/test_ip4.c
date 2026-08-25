#include "../fd_util.h"
#include "fd_ip4.h"

FD_STATIC_ASSERT( FD_IP4_HDR_TOS_PREC_INTERNETCONTROL==(uchar)0xc0, unit_test );

FD_STATIC_ASSERT( FD_IP4_HDR_FRAG_OFF_RF  ==(ushort)0x8000, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_FRAG_OFF_DF  ==(ushort)0x4000, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_FRAG_OFF_MF  ==(ushort)0x2000, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_FRAG_OFF_MASK==(ushort)0x1fff, unit_test );

FD_STATIC_ASSERT( FD_IP4_HDR_PROTOCOL_IP4 ==(uchar) 0, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_PROTOCOL_ICMP==(uchar) 1, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_PROTOCOL_IGMP==(uchar) 2, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_PROTOCOL_TCP ==(uchar) 6, unit_test );
FD_STATIC_ASSERT( FD_IP4_HDR_PROTOCOL_UDP ==(uchar)17, unit_test );

FD_STATIC_ASSERT( FD_IP4_OPT_RA ==(uchar)148, unit_test );
FD_STATIC_ASSERT( FD_IP4_OPT_EOL==(uchar)  0, unit_test );

FD_STATIC_ASSERT( alignof(fd_ip4_hdr_t)== 2UL, unit_test );
FD_STATIC_ASSERT( sizeof (fd_ip4_hdr_t)==20UL, unit_test );


static void
test_cstr_to_ip4_addr( void ) {
  uint ip;
  FD_TEST( fd_cstr_to_ip4_addr( "",                           &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "0",                          &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "0.0",                        &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "0.0.0",                      &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "0.0.0.0",                    &ip )==1  ); FD_TEST( ip==0x00000000 );
  // FIXME FD_TEST( fd_cstr_to_ip4_addr( "0.0.0.0.",                   &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "127.0.0.1",                  &ip )==1  ); FD_TEST( ip==0x0100007F );
  FD_TEST( fd_cstr_to_ip4_addr( "255.255.255.255",            &ip )==1  ); FD_TEST( ip==0xffffffff );
  FD_TEST( fd_cstr_to_ip4_addr( "256.255.255.255",            &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "255.256.255.255",            &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "255.255.256.255",            &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "255.255.255.256",            &ip )==0  );
  FD_TEST( fd_cstr_to_ip4_addr( "36893488147419103232.0.0.0", &ip )==0  );
}

static void
test_ip4_addr_is_public( void ) {
  // Public addresses should return 1 for fd_ip4_addr_is_public
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(  8,   8,   8,   8) ) == 1 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR( 74, 125, 224,  72) ) == 1 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(  1,   1,   1,   1) ) == 1 );

  // Private addresses should return 0 for fd_ip4_addr_is_public
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR( 10,   0,   0,   1) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(172,  16,   0,   1) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192, 168,   1,   1) ) == 0 );

  // Loopback address should also return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(127,   0,   0,   1) ) == 0 );

  // "This network" 0.0.0.0/8 (RFC 791) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(  0,   0,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(  0,   0,   0,   1) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(  0, 255, 255, 255) ) == 0 );

  // More private addresses tests
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR( 10,   0,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR( 10, 255, 255, 255) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(172,  16,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(172,  31, 255, 255) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192, 168,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192, 168, 255, 255) ) == 0 );

  // Link-local addresses (169.254.0.0/16) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(169, 254,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(169, 254,   1,   1) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(169, 254, 255, 255) ) == 0 );

  // CGNAT addresses (100.64.0.0/10) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(100,  64,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(100, 100, 100, 100) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(100, 127, 255, 255) ) == 0 );

  // Boundary: just outside CGNAT should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(100, 128,   0,   0) ) == 1 );

  // Boundary: just outside link-local should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(169, 253, 255, 255) ) == 1 );

  // Reserved 240.0.0.0 – 255.255.255.254 should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(240,   0,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(250,   1,   2,   3) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(255, 255, 255, 254) ) == 0 );

  // Broadcast is not caught by fd_ip4_addr_is_public (use fd_ip4_addr_is_bcast)
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(255, 255, 255, 255) ) == 1 );

  // Boundary: just below reserved should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(239, 255, 255, 255) ) == 1 );

  // Boundary: just above "this network" should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(  1,   0,   0,   0) ) == 1 );

  // Documentation addresses (RFC 5737) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   2,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   2, 255) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(198,  51, 100,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(198,  51, 100, 255) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(203,   0, 113,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(203,   0, 113, 255) ) == 0 );

  // Benchmarking addresses (RFC 2544) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(198,  18,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(198,  19, 255, 255) ) == 0 );

  // Boundary: just outside documentation/benchmarking should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   3,   0) ) == 1 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(198,  20,   0,   0) ) == 1 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(203,   0, 114,   0) ) == 1 );

  // IETF Protocol Assignments (192.0.0.0/24, RFC 6890) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   0, 128) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   0, 255) ) == 0 );

  // Boundary: just outside IETF Protocol Assignments should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,   0,   1,   0) ) == 1 );

  // 6to4 Relay Anycast (192.88.99.0/24, RFC 7526) should return 0
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,  88,  99,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,  88,  99,   1) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,  88,  99, 255) ) == 0 );

  // Boundary: just outside 6to4 Relay Anycast should return 1
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,  88,  98, 255) ) == 1 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192,  88, 100,   0) ) == 1 );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->tos         ) )== 1UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->net_tot_len ) )== 2UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->net_id      ) )== 4UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->net_frag_off) )== 6UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->ttl         ) )== 8UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->protocol    ) )== 9UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->check       ) )==10UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->saddr_c     ) )==12UL );
  FD_TEST( (ulong)( &(((fd_ip4_hdr_t *)NULL)->daddr_c     ) )==16UL );

  uint ip4_addr_ucast = FD_IP4_ADDR(  1,  2,  3,  4); FD_TEST( ip4_addr_ucast==0x04030201U );
  uint ip4_addr_mcast = FD_IP4_ADDR(239, 17, 34, 51); FD_TEST( ip4_addr_mcast==0x332211efU );
  uint ip4_addr_bcast = FD_IP4_ADDR(255,255,255,255); FD_TEST( ip4_addr_bcast==0xffffffffU );

  FD_LOG_NOTICE(( "Test ip4 addr fmt: " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( ip4_addr_ucast ) ));

  FD_TEST( !fd_ip4_addr_is_mcast( ip4_addr_ucast ) ); FD_TEST( !fd_ip4_addr_is_bcast( ip4_addr_ucast ) );
  FD_TEST(  fd_ip4_addr_is_mcast( ip4_addr_mcast ) ); FD_TEST( !fd_ip4_addr_is_bcast( ip4_addr_mcast ) );
  FD_TEST( !fd_ip4_addr_is_mcast( ip4_addr_bcast ) ); FD_TEST(  fd_ip4_addr_is_bcast( ip4_addr_bcast ) );

  /* FIXME: TEST FD_IP4_HDR_NET_FRAG_OFF_IS_UNFRAGMENTED */
  /* FIXME: TEST FD_IP4_HDR_CHECK */
  /* FIXME: TEST FD_IP4_HDR_CHECK_FAST */

  test_cstr_to_ip4_addr();
  test_ip4_addr_is_public();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

