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

  /* FIXME: TEST FD_IP4_UDP_CHECK */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

