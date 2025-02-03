#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../funk/fd_funk.h"

/* fd_backtest_ctl provides useful script utilities for recovering
   blockstore and funk from a previous live run.

   For example, you can properly checkpt the existing blockstore under
   /mnt/.fd/.gigantic/fd1_bstore.wksp into a checkpt file.

   Example usage:

   ./build/native/gcc/bin/fd_backtest_ctl \
      --blockstore-checkpt /data/chali/blockstore.checkpt \
      --funk-checkpt /data/chali/funk.checkpt

   SLOTS=$(echo /dev/shm/incremental-snapshot-* | grep -oP '\d+-\d+') \
   ./build/native/gcc/bin/fd_backtest_ctl \
      --blockstore-checkpt /data/chali/$SLOTS-blockstore.checkpt \
      --funk-checkpt /data/chali/$SLOTS-funk.checkpt
   
   */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * blockstore_checkpt = fd_env_strip_cmdline_cstr( &argc,
                                                               &argv,
                                                               "--blockstore-checkpt",
                                                               NULL,
                                                               NULL );
  char const * funk_checkpt       = fd_env_strip_cmdline_cstr( &argc,
                                                         &argv,
                                                         "--funk-checkpt",
                                                         NULL,
                                                         NULL );

  fd_wksp_t * blockstore_wksp = fd_wksp_attach( "fd1_bstore.wksp" );
  FD_TEST( blockstore_wksp );
  fd_wksp_tag_query_info_t blockstore_info;
  ulong                    blockstore_tag = FD_BLOCKSTORE_MAGIC;
  FD_TEST( fd_wksp_tag_query( blockstore_wksp, &blockstore_tag, 1, &blockstore_info, 1 ) > 0 );
  void * blockstore_mem        = fd_wksp_laddr_fast( blockstore_wksp, blockstore_info.gaddr_lo );
  fd_blockstore_t * blockstore = fd_blockstore_join( blockstore_mem );
  FD_TEST( blockstore );
  FD_TEST( !fd_wksp_checkpt( blockstore_wksp, blockstore_checkpt, 0666, 0, NULL ) );

  fd_wksp_t * funk_wksp = fd_wksp_attach( "fd1_funk.wksp" );
  FD_TEST( funk_wksp );
  fd_wksp_tag_query_info_t funk_info;
  ulong                    funk_tag = FD_FUNK_MAGIC;
  FD_TEST( fd_wksp_tag_query( funk_wksp, &funk_tag, 1, &funk_info, 1 ) > 0 );
  void *      funk_mem = fd_wksp_laddr_fast( funk_wksp, funk_info.gaddr_lo );
  fd_funk_t * funk     = fd_funk_join( funk_mem );
  FD_TEST( funk );
  FD_TEST( !fd_wksp_checkpt( funk_wksp, funk_checkpt, 0666, 0, NULL ) );

  fd_halt();
  return 0;
}
