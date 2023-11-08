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

FD_STATIC_ASSERT( sizeof(fd_ip4_hdr_t)==20UL, unit_test );


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

  // More private addresses tests
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR( 10,   0,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR( 10, 255, 255, 255) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(172,  16,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(172,  31, 255, 255) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192, 168,   0,   0) ) == 0 );
  FD_TEST( fd_ip4_addr_is_public( FD_IP4_ADDR(192, 168, 255, 255) ) == 0 );
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

