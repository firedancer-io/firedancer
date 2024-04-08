#include "../fd_util.h"
#include "fd_igmp.h"

FD_STATIC_ASSERT( FD_IGMP_TYPE_QUERY    ==(uchar)0x11, unit_test );
FD_STATIC_ASSERT( FD_IGMP_TYPE_V1_REPORT==(uchar)0x12, unit_test );
FD_STATIC_ASSERT( FD_IGMP_TYPE_V2_REPORT==(uchar)0x16, unit_test );
FD_STATIC_ASSERT( FD_IGMP_TYPE_V2_LEAVE ==(uchar)0x17, unit_test );

FD_STATIC_ASSERT( sizeof(fd_igmp_t    )== 8UL, unit_test );
FD_STATIC_ASSERT( sizeof(fd_ip4_igmp_t)==32UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( (ulong)( &(((fd_igmp_t *)NULL)->type ) )==0UL );
  FD_TEST( (ulong)( &(((fd_igmp_t *)NULL)->resp ) )==1UL );
  FD_TEST( (ulong)( &(((fd_igmp_t *)NULL)->check) )==2UL );
  FD_TEST( (ulong)( &(((fd_igmp_t *)NULL)->group) )==4UL );
  FD_TEST( (ulong)(  (((fd_igmp_t *)NULL)->u    ) )==0UL );

  FD_TEST( (ulong)( ((fd_ip4_igmp_t *)NULL)->ip4  )== 0UL );
  FD_TEST( (ulong)( ((fd_ip4_igmp_t *)NULL)->opt  )==20UL );
  FD_TEST( (ulong)( ((fd_ip4_igmp_t *)NULL)->igmp )==24UL );

  /* FIXME: TEST FD_IGMP_CHECK */
  /* FIXME: TEST FD_IP4_IGMP */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

