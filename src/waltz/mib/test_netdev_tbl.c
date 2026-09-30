#define _POSIX_C_SOURCE 200809L /* fmemopen */

#include "fd_netdev_tbl.h"
#include "../../util/fd_util.h"

#include <stdio.h>

static uchar __attribute__((aligned(FD_NETDEV_TBL_ALIGN))) tbl_mem[ 4096 ];
static uchar __attribute__((aligned(FD_NETDEV_TBL_ALIGN))) dst_mem[ 4096 ];

/* fd_netdev_tbl_refresh copies only a published change: not an
   unpublished write, not mid-write, not an unchanged table. */

static void
test_refresh( fd_netdev_tbl_join_t * src ) {
  FD_TEST( fd_netdev_tbl_new( dst_mem, 3UL, 1UL )==dst_mem );
  fd_netdev_tbl_join_t dst[1];
  FD_TEST( fd_netdev_tbl_join( dst, dst_mem )==dst );

  ulong seq = fd_netdev_tbl_copy( dst, src );
  FD_TEST( !(seq&1UL) && seq==atomic_load( &src->hdr->seqlock ) );
  FD_TEST( !fd_netdev_tbl_refresh( dst, src, &seq ) );           /* unchanged */

  src->dev_tbl[0].mtu = 9000U;                                   /* unpublished write */
  FD_TEST( !fd_netdev_tbl_refresh( dst, src, &seq ) && dst->dev_tbl[0].mtu==1500U );
  fd_seqlock_write_lock( &src->hdr->seqlock );                   /* write in progress */
  FD_TEST( !fd_netdev_tbl_refresh( dst, src, &seq ) && dst->dev_tbl[0].mtu==1500U );
  fd_seqlock_write_unlock( &src->hdr->seqlock );
  FD_TEST( fd_netdev_tbl_refresh( dst, src, &seq ) && dst->dev_tbl[0].mtu==9000U );
  FD_TEST( seq==atomic_load( &src->hdr->seqlock ) );

  dst->dev_tbl[0].mtu = 0U;                                      /* no change since: no copy */
  FD_TEST( !fd_netdev_tbl_refresh( dst, src, &seq ) && dst->dev_tbl[0].mtu==0U );
  src->dev_tbl[0].mtu = 1500U;

  FD_TEST( fd_netdev_tbl_leave( dst )==dst );
  FD_TEST( fd_netdev_tbl_delete( dst_mem )==dst_mem );
}

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

  test_refresh( tbl );

  FD_TEST( fd_netdev_tbl_leave( tbl )==tbl );
  FD_TEST( fd_netdev_tbl_delete( tbl_mem )==tbl_mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
