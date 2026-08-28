#include "../fd_util.h"
#include "fd_udp.h"
#include "fd_net_headers.h"
#include <stddef.h> /* offsetof */

FD_STATIC_ASSERT( alignof(fd_udp_hdr_t)==2UL, unit_test );
FD_STATIC_ASSERT( sizeof (fd_udp_hdr_t)==8UL, unit_test );

FD_STATIC_ASSERT( alignof(fd_ip4_udp_hdrs_t)== 2UL, unit_test );
FD_STATIC_ASSERT( sizeof (fd_ip4_udp_hdrs_t)==42UL, unit_test );
FD_STATIC_ASSERT( offsetof(fd_ip4_udp_hdrs_t, eth)== 0UL, unit_test );
FD_STATIC_ASSERT( offsetof(fd_ip4_udp_hdrs_t, ip4)==14UL, unit_test );
FD_STATIC_ASSERT( offsetof(fd_ip4_udp_hdrs_t, udp)==34UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->net_sport) )==0UL );
  FD_TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->net_dport) )==2UL );
  FD_TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->net_len  ) )==4UL );
  FD_TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->check    ) )==6UL );
  FD_TEST( (ulong)(  (((fd_udp_hdr_t *)NULL)->uc       ) )==0UL );

  FD_TEST( !fd_ip4_udp_hdr_strip( NULL, 0UL, NULL, NULL, NULL, NULL, NULL ) );

  uchar short_packet[ sizeof(fd_eth_hdr_t) ] = {0};
  FD_TEST( !fd_ip4_udp_hdr_strip( short_packet, sizeof(short_packet), NULL, NULL, NULL, NULL, NULL ) );

  fd_ip4_udp_hdrs_t malformed[1];
  for( uint ihl=0U; ihl<5U; ihl++ ) {
    memset( malformed, 0, sizeof(malformed) );
    fd_ip4_hdr_t * ip4 = malformed->ip4;
    ip4->verihl = FD_IP4_VERIHL( 4U, ihl );
    fd_udp_hdr_t * udp = (fd_udp_hdr_t *)( malformed->uc + sizeof(fd_eth_hdr_t) + 4UL*ihl );
    udp->net_len = fd_ushort_bswap( (ushort)sizeof(fd_udp_hdr_t) );
    FD_TEST( !fd_ip4_udp_hdr_strip( malformed->uc, sizeof(malformed->uc), NULL, NULL, NULL, NULL, NULL ) );
  }

  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, 0UL, 0U, 0U );

  uchar *        payload    = NULL;
  ulong          payload_sz = ULONG_MAX;
  fd_eth_hdr_t * eth        = NULL;
  fd_ip4_hdr_t * ip4        = NULL;
  fd_udp_hdr_t * udp        = NULL;
  FD_TEST( fd_ip4_udp_hdr_strip( hdrs->uc, sizeof(hdrs->uc), &payload, &payload_sz, &eth, &ip4, &udp ) );
  FD_TEST( payload==(hdrs->uc + sizeof(hdrs->uc)) );
  FD_TEST( !payload_sz );
  FD_TEST( eth==hdrs->eth );
  FD_TEST( ip4==hdrs->ip4 );
  FD_TEST( udp==hdrs->udp );

  /* FIXME: TEST FD_IP4_UDP_CHECK */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
