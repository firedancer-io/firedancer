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

static void
test_cstr_to_mac_addr( void ) {

  uchar mac[ 6 ]={0};
# define MAC_OK(str,num) FD_TEST( fd_ulong_bswap( fd_ulong_load_6( fd_cstr_to_mac_addr( str, mac ) )>>16UL ) )
# define MAC_FAIL(str)   FD_TEST( !fd_cstr_to_mac_addr( str, mac ) );

  MAC_OK( "01:34:56:78:9a:bc",  0x013456789abc );
  MAC_OK( "12:34:56:78:9a:bc",  0x123456789abc );
  MAC_OK( "12:34:56:78:9a:Bc",  0x123456789abc );
  MAC_OK( "12:34:56:78:9a:bcd", 0x123456789abc );

  /* Test invalid char and truncated string */

  for( ulong i=0UL; i<15UL; i++ ) {
    char str[ 18UL ]="12:34:56:78:9a:bc";
    for( int j=1; j<'0'; j++ ) {
      str[ i ] = (char)j;
      MAC_FAIL( str );
    }
    for( int j='\0'; j<'0'; j++ ) {
      str[ i ] = (char)j;
      MAC_FAIL( str );
    }
    for( int j=';'; j<'A'; j++ ) {
      str[ i ] = (char)j;
      MAC_FAIL( str );
    }
    for( int j='G'; j<'a'; j++ ) {
      str[ i ] = (char)j;
      MAC_FAIL( str );
    }
    for( int j='g'; j<0xff; j++ ) {
      str[ i ] = (char)j;
      MAC_FAIL( str );
    }
  }

  /* Test invalid separator */

  MAC_FAIL( "12034:56:78:9a:bc" );
  MAC_FAIL( "12:34056:78:9a:bc" );
  MAC_FAIL( "12:34:56078:9a:bc" );
  MAC_FAIL( "12:34:56:7809a:bc" );
  MAC_FAIL( "12:34:56:78:9a0bc" );

  /* Test unexpected separator */

  MAC_FAIL( ":2:34:56:78:9a:bc" );
  MAC_FAIL( "1::34:56:78:9a:bc" );
  MAC_FAIL( "12::4:56:78:9a:bc" );
  MAC_FAIL( "12:3::56:78:9a:bc" );
  MAC_FAIL( "12:34::6:78:9a:bc" );
  MAC_FAIL( "12:34:5::78:9a:bc" );
  MAC_FAIL( "12:34:56::8:9a:bc" );
  MAC_FAIL( "12:34:56:7::9a:bc" );
  MAC_FAIL( "12:34:56:78::a:bc" );
  MAC_FAIL( "12:34:56:78:9::bc" );
  MAC_FAIL( "12:34:56:78:9a::c" );
  MAC_FAIL( "12:34:56:78:9a:b:" );

}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( (ulong)( &(((fd_eth_hdr_t *)NULL)->dst     ) )== 0UL );
  FD_TEST( (ulong)( &(((fd_eth_hdr_t *)NULL)->src     ) )== 6UL );
  FD_TEST( (ulong)( &(((fd_eth_hdr_t *)NULL)->net_type) )==12UL );

  FD_TEST( (ulong)( &(((fd_vlan_tag_t *)NULL)->net_vid ) )==0UL );
  FD_TEST( (ulong)( &(((fd_vlan_tag_t *)NULL)->net_type) )==2UL );

  uchar src[6];
  src[0] = (uchar)0x00; src[1] = (uchar)0x11; src[2] = (uchar)0x22;
  src[3] = (uchar)0x33; src[4] = (uchar)0x44; src[5] = (uchar)0x55;
  FD_TEST( !fd_eth_mac_is_mcast    ( src ) );
  FD_TEST( !fd_eth_mac_is_local    ( src ) );
  FD_TEST( !fd_eth_mac_is_bcast    ( src ) );
  FD_TEST( !fd_eth_mac_is_ip4_mcast( src ) );
  FD_LOG_NOTICE(( "Testing eth mac fmt: " FD_ETH_MAC_FMT, FD_ETH_MAC_FMT_ARGS( src ) ));

  FD_TEST( fd_eth_mac_ip4_mcast( src, 0x332211efU /* 239.17.34.51 */ )==src );
  FD_TEST( src[0]==(uchar)0x01 ); FD_TEST( src[1]==(uchar)0x00 ); FD_TEST( src[2]==(uchar)0x5e );
  FD_TEST( src[3]==(uchar)0x11 ); FD_TEST( src[4]==(uchar)0x22 ); FD_TEST( src[5]==(uchar)0x33 );
  FD_TEST(  fd_eth_mac_is_mcast    ( src ) );
  FD_TEST( !fd_eth_mac_is_local    ( src ) );
  FD_TEST( !fd_eth_mac_is_bcast    ( src ) );
  FD_TEST(  fd_eth_mac_is_ip4_mcast( src ) );

  ulong frame_sz = sizeof(frame);
  uint  fcs_exp  = 0x47ed1e58U;
  uint  fcs;
  FD_TEST( fd_eth_fcs( frame, frame_sz )==fcs_exp );

  fcs = fd_eth_fcs( frame, 10UL );
  fcs = fd_eth_fcs_append( fcs, frame+10UL, frame_sz-10UL );
  FD_TEST( fcs==fcs_exp );

  fcs = FD_ETH_FCS_APPEND_SEED;
  fcs = fd_eth_fcs_append( fcs, frame,      10UL          );
  fcs = fd_eth_fcs_append( fcs, frame+10UL, frame_sz-10UL );
  FD_TEST( fcs==fcs_exp );

  uchar dst[6];
  FD_TEST( fd_eth_mac_bcast( dst )==dst );
  FD_TEST( dst[0]==(uchar)0xff ); FD_TEST( dst[1]==(uchar)0xff ); FD_TEST( dst[2]==(uchar)0xff );
  FD_TEST( dst[3]==(uchar)0xff ); FD_TEST( dst[4]==(uchar)0xff ); FD_TEST( dst[5]==(uchar)0xff );
  FD_TEST(  fd_eth_mac_is_mcast    ( dst ) );
  FD_TEST(  fd_eth_mac_is_local    ( dst ) );
  FD_TEST(  fd_eth_mac_is_bcast    ( dst ) );
  FD_TEST( !fd_eth_mac_is_ip4_mcast( dst ) );

  FD_TEST( fd_eth_mac_cpy( dst, src )==dst );
  FD_TEST( !memcmp( dst, src, 6UL ) );

  fd_vlan_tag_t tag[1];
  FD_TEST( fd_vlan_tag( tag, (ushort)1234, FD_ETH_HDR_TYPE_IP )==tag );
  FD_TEST( fd_ushort_bswap( tag->net_vid  )==(ushort)1234 );
  FD_TEST( fd_ushort_bswap( tag->net_type )==FD_ETH_HDR_TYPE_IP );

  test_cstr_to_mac_addr();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

