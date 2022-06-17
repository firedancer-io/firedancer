#include "../fd_util.h"
#include "fd_eth.h"

FD_STATIC_ASSERT( FD_ETH_HDR_TYPE_IP  ==(ushort)0x0800, unit_test );
FD_STATIC_ASSERT( FD_ETH_HDR_TYPE_ARP ==(ushort)0x0806, unit_test );
FD_STATIC_ASSERT( FD_ETH_HDR_TYPE_VLAN==(ushort)0x8100, unit_test );

FD_STATIC_ASSERT( FD_ETH_FCS_APPEND_SEED==0U, unit_test );

FD_STATIC_ASSERT( FD_ETH_PAYLOAD_MAX    ==1500UL, unit_test );
FD_STATIC_ASSERT( FD_ETH_PAYLOAD_MIN_RAW==  46UL, unit_test );
FD_STATIC_ASSERT( FD_ETH_PAYLOAD_MIN( 0)==  46UL, unit_test );
FD_STATIC_ASSERT( FD_ETH_PAYLOAD_MIN( 1)==  42UL, unit_test );
FD_STATIC_ASSERT( FD_ETH_PAYLOAD_MIN( 2)==  38UL, unit_test );
FD_STATIC_ASSERT( FD_ETH_PAYLOAD_MIN(11)==   2UL, unit_test );

FD_STATIC_ASSERT( sizeof(fd_eth_hdr_t )==14UL, unit_test );
FD_STATIC_ASSERT( sizeof(fd_vlan_tag_t)== 4UL, unit_test );

static uchar const frame[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x50,
  0xb6, 0x07, 0x86, 0x5a, 0x08, 0x06, 0x00, 0x01,
  0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x50,
  0xb6, 0x07, 0x86, 0x5a, 0xc0, 0xa8, 0x64, 0x01,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0xa8,
  0x64, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  TEST( (ulong)( &(((fd_eth_hdr_t *)NULL)->dst     ) )== 0UL );
  TEST( (ulong)( &(((fd_eth_hdr_t *)NULL)->src     ) )== 6UL );
  TEST( (ulong)( &(((fd_eth_hdr_t *)NULL)->net_type) )==12UL );

  TEST( (ulong)( &(((fd_vlan_tag_t *)NULL)->net_vid ) )==0UL );
  TEST( (ulong)( &(((fd_vlan_tag_t *)NULL)->net_type) )==2UL );

  uchar src[6];
  src[0] = (uchar)0x00; src[1] = (uchar)0x11; src[2] = (uchar)0x22;
  src[3] = (uchar)0x33; src[4] = (uchar)0x44; src[5] = (uchar)0x55;
  TEST( !fd_eth_mac_is_mcast    ( src ) );
  TEST( !fd_eth_mac_is_local    ( src ) );
  TEST( !fd_eth_mac_is_bcast    ( src ) );
  TEST( !fd_eth_mac_is_ip4_mcast( src ) );
  FD_LOG_NOTICE(( "Testing eth mac fmt: " FD_ETH_MAC_FMT, FD_ETH_MAC_FMT_ARGS( src ) ));

  TEST( fd_eth_mac_ip4_mcast( src, 0x332211efU /* 239.17.34.51 */ )==src );
  TEST( src[0]==(uchar)0x01 ); TEST( src[1]==(uchar)0x00 ); TEST( src[2]==(uchar)0x5e );
  TEST( src[3]==(uchar)0x11 ); TEST( src[4]==(uchar)0x22 ); TEST( src[5]==(uchar)0x33 );
  TEST(  fd_eth_mac_is_mcast    ( src ) );
  TEST( !fd_eth_mac_is_local    ( src ) );
  TEST( !fd_eth_mac_is_bcast    ( src ) );
  TEST(  fd_eth_mac_is_ip4_mcast( src ) );

  ulong frame_sz = sizeof(frame);
  uint  fcs_exp  = 0x47ed1e58U;
  uint  fcs;
  TEST( fd_eth_fcs( frame, frame_sz )==fcs_exp );

  fcs = fd_eth_fcs( frame, 10UL );
  fcs = fd_eth_fcs_append( fcs, frame+10UL, frame_sz-10UL );
  TEST( fcs==fcs_exp );

  fcs = FD_ETH_FCS_APPEND_SEED;
  fcs = fd_eth_fcs_append( fcs, frame,      10UL          );
  fcs = fd_eth_fcs_append( fcs, frame+10UL, frame_sz-10UL );
  TEST( fcs==fcs_exp );

  uchar dst[6];
  TEST( fd_eth_mac_bcast( dst )==dst );
  TEST( dst[0]==(uchar)0xff ); TEST( dst[1]==(uchar)0xff ); TEST( dst[2]==(uchar)0xff );
  TEST( dst[3]==(uchar)0xff ); TEST( dst[4]==(uchar)0xff ); TEST( dst[5]==(uchar)0xff );
  TEST(  fd_eth_mac_is_mcast    ( dst ) );
  TEST(  fd_eth_mac_is_local    ( dst ) );
  TEST(  fd_eth_mac_is_bcast    ( dst ) );
  TEST( !fd_eth_mac_is_ip4_mcast( dst ) );

  TEST( fd_eth_mac_cpy( dst, src )==dst );
  TEST( !memcmp( dst, src, 6UL ) );

  fd_vlan_tag_t tag[1];
  TEST( fd_vlan_tag( tag, (ushort)1234, FD_ETH_HDR_TYPE_IP )==tag );
  TEST( fd_ushort_bswap( tag->net_vid  )==(ushort)1234 );
  TEST( fd_ushort_bswap( tag->net_type )==FD_ETH_HDR_TYPE_IP );
  
# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

