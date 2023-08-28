#include "../../util/fd_util.h"
#include "fd_mvcc.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_mvcc_t mvcc = { .version = 0 };
  FD_TEST( fd_mvcc_begin_read( &mvcc ) == 0 );
  FD_TEST( fd_mvcc_end_read( &mvcc ) == 0 );

  FD_TEST( fd_mvcc_begin_write( &mvcc ) == 0 );
  FD_TEST( fd_mvcc_begin_read( &mvcc ) == 1 );
  FD_TEST( fd_mvcc_end_read( &mvcc ) == 1 );
  FD_TEST( fd_mvcc_end_write( &mvcc ) == 1 );

  FD_TEST( fd_mvcc_begin_read( &mvcc ) == 2 );
  FD_TEST( fd_mvcc_begin_write( &mvcc ) == 2 );
  FD_TEST( fd_mvcc_end_read( &mvcc ) == 3 );
  FD_TEST( fd_mvcc_end_write( &mvcc ) == 3 );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
