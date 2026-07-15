#define _POSIX_C_SOURCE 200809L /* fmemopen */

#include "fd_netdev_tbl.h"
#include "../../util/fd_util.h"

#include <stdio.h>

static uchar __attribute__((aligned(FD_NETDEV_TBL_ALIGN))) tbl_mem[ 4096 ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong footprint = fd_netdev_tbl_footprint( 3UL, 1UL );
  FD_TEST( footprint<=sizeof(tbl_mem) );
  FD_TEST( fd_netdev_tbl_new( tbl_mem, 3UL, 1UL )==tbl_mem );

  fd_netdev_tbl_join_t tbl[1];
  FD_TEST( fd_netdev_tbl_join( tbl, tbl_mem )==tbl );
  tbl->hdr->dev_cnt = 3U;
  tbl->dev_tbl[0] = (fd_netdev_t) {
    .if_idx      = 2U,
    .name        = "eth2",
    .mtu         = 1500U,
    .oper_status = FD_OPER_STATUS_UP,
  };
  tbl->dev_tbl[1] = (fd_netdev_t) {
    .if_idx      = 42U,
    .name        = "eth42",
    .mtu         = 9000U,
    .oper_status = FD_OPER_STATUS_DOWN,
  };
  tbl->dev_tbl[2] = (fd_netdev_t) {
    .if_idx = 99U,
    .name   = "hidden",
  };

  char buf[ 1024 ] = {0};
  FILE * file = fmemopen( buf, sizeof(buf), "w" );
  FD_TEST( file );
  FD_TEST( !fd_netdev_tbl_fprintf( tbl, file ) );
  FD_TEST( !fclose( file ) );

  FD_TEST( strstr( buf, "2: eth2:" )==buf );
  FD_TEST( strstr( buf, "\n42: eth42:" ) );
  FD_TEST( !strstr( buf, "0: eth2:" ) );
  FD_TEST( !strstr( buf, "\n1: eth42:" ) );
  FD_TEST( !strstr( buf, "hidden" ) );

  FD_TEST( fd_netdev_tbl_leave( tbl )==tbl );
  FD_TEST( fd_netdev_tbl_delete( tbl_mem )==tbl_mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
