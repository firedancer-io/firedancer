#include "../fd_util.h"
#include "fd_udp.h"

FD_STATIC_ASSERT( sizeof(fd_udp_hdr_t)==8UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->net_sport) )==0UL );
  TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->net_dport) )==2UL );
  TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->net_len  ) )==4UL );
  TEST( (ulong)( &(((fd_udp_hdr_t *)NULL)->check    ) )==6UL );
  TEST( (ulong)(  (((fd_udp_hdr_t *)NULL)->u        ) )==0UL );

  /* FIXME: TEST FD_IP4_UDP_CHECK */

# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

