#include <stdio.h>
#include "fd_netdev_netlink.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong dev_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--dev-cnt",  NULL, 256UL );
  ulong bond_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--bond-cnt", NULL,   4UL );

  if( FD_UNLIKELY( !dev_cnt  ) ) FD_LOG_ERR(( "unsupported --dev-cnt"  ));
  if( FD_UNLIKELY( !bond_cnt ) ) FD_LOG_ERR(( "unsupported --bond-cnt" ));

  int is_anon;
  fd_wksp_t * wksp = fd_wksp_from_env( &argc, &argv, "normal", 4096UL, "wksp", 0UL, &is_anon );
  FD_TEST( wksp );

  ulong tbl_fp = fd_netdev_tbl_footprint( dev_cnt, bond_cnt );
  if( FD_UNLIKELY( !tbl_fp ) ) {
    FD_LOG_ERR(( "Invalid --dev-cnt or --page-cnt" ));
  }
  void * tbl_mem = fd_wksp_alloc_laddr( wksp, fd_netdev_tbl_align(), tbl_fp, 1UL );
  FD_TEST( tbl_mem );

  FD_TEST( fd_netdev_tbl_new( tbl_mem, dev_cnt, bond_cnt )==tbl_mem );
  fd_netdev_tbl_join_t tbl[1];
  FD_TEST( fd_netdev_tbl_join( tbl, tbl_mem )==tbl );

  fd_netlink_t _netlink[1];
  fd_netlink_t * netlink = fd_netlink_init( _netlink, 42U );
  FD_TEST( netlink );

  int ld_err = fd_netdev_netlink_load_table( tbl, netlink );
  if( FD_UNLIKELY( ld_err ) ) {
    FD_LOG_WARNING(( "Failed to load interfaces (error code %i)", ld_err ));
  }
  FD_LOG_NOTICE(( "Dumping interface table" ));
  fd_log_flush();
  fd_netdev_tbl_fprintf( tbl, stderr );
  fflush( stderr );

  fd_netlink_fini( netlink );
  fd_netdev_tbl_leave( tbl );
  fd_wksp_free_laddr( fd_netdev_tbl_delete( tbl_mem ) );
  if( is_anon ) fd_wksp_delete_anon( wksp );
  else          fd_wksp_detach( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
