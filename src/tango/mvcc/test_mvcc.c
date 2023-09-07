#include "../../util/fd_util.h"
#include "fd_mvcc.h"

FD_STATIC_ASSERT( FD_MVCC_ALIGN          ==128UL, unit_test );
FD_STATIC_ASSERT( FD_MVCC_FOOTPRINT( 0UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_MVCC_FOOTPRINT(64UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_MVCC_FOOTPRINT(65UL)==256UL, unit_test );

FD_STATIC_ASSERT( FD_MVCC_APP_ALIGN==64UL, unit_test );

#define APP_MIN (32UL)
#define APP_MAX (192UL)
uchar __attribute__((aligned(FD_MVCC_ALIGN))) shmem[ FD_MVCC_FOOTPRINT( APP_MAX ) ];

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong app_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--app-sz", NULL,  192UL );

  if( FD_UNLIKELY( app_sz<APP_MIN     ) ) FD_LOG_ERR(( "app_sz should be at least %lu for this unit test", APP_MIN ));
  if( FD_UNLIKELY( app_sz>APP_MAX     ) ) FD_LOG_ERR(( "increase APP_MAX for this app_sz"  ));

  FD_TEST( !fd_mvcc_footprint( ULONG_MAX ) );

  FD_TEST( fd_mvcc_align()            ==FD_MVCC_ALIGN               );
  FD_TEST( fd_mvcc_footprint( app_sz )==FD_MVCC_FOOTPRINT( app_sz ) );

  void * shmvcc = fd_mvcc_new( shmem, app_sz); FD_TEST( shmvcc );
  fd_mvcc_t * mvcc = fd_mvcc_join( shmvcc );   FD_TEST( mvcc );

  FD_TEST( fd_mvcc_app_sz( mvcc )==app_sz );
  uchar *       app       = (uchar       *)fd_mvcc_app_laddr( mvcc );
  uchar const * app_const = (uchar const *)fd_mvcc_app_laddr_const( mvcc );
  FD_TEST( (ulong)app==(ulong)app_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)app, FD_MVCC_APP_ALIGN ) );

  FD_TEST( fd_mvcc_version_query( mvcc ) == 0 );
  FD_TEST( fd_mvcc_version_query( mvcc ) == 0 );

  fd_mvcc_begin_write( mvcc );
  FD_TEST( fd_mvcc_version_query( mvcc ) == 1 );
  FD_TEST( fd_mvcc_version_query( mvcc ) == 1 );
  fd_mvcc_end_write( mvcc );

  FD_TEST( fd_mvcc_version_query( mvcc ) == 2 );
  fd_mvcc_begin_write( mvcc );
  FD_TEST( fd_mvcc_version_query( mvcc ) == 3 );
  fd_mvcc_end_write( mvcc );
  FD_TEST( fd_mvcc_version_query( mvcc ) == 4 );

  FD_TEST( fd_mvcc_leave( mvcc )==shmvcc );
  FD_TEST( fd_mvcc_delete( shmvcc )==shmem );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
