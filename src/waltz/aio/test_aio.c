#include "fd_aio.h"
#include "../../util/fd_util.h"

FD_STATIC_ASSERT( FD_AIO_SUCCESS           == 0,                           unit_test );
FD_STATIC_ASSERT( FD_AIO_ERR_INVAL         ==-1,                           unit_test );
FD_STATIC_ASSERT( FD_AIO_ERR_AGAIN         ==-2,                           unit_test );
FD_STATIC_ASSERT( FD_AIO_PKT_INFO_ALIGN    ==alignof( fd_aio_pkt_info_t ), unit_test );
FD_STATIC_ASSERT( FD_AIO_PKT_INFO_FOOTPRINT==sizeof ( fd_aio_pkt_info_t ), unit_test );
FD_STATIC_ASSERT( FD_AIO_PKT_INFO_BUF_MAX  ==4096UL,                       unit_test );

static struct {
  void *                    ctx;
  fd_aio_pkt_info_t const * batch;
  ulong                     batch_cnt;
  ulong *                   opt_batch_idx;
} send_expected;

static int   send_retval;

static int
test_aio_send_func( void *                    ctx,
                    fd_aio_pkt_info_t const * batch,
                    ulong                     batch_cnt,
                    ulong *                   opt_batch_idx,
                    int                       flush ) {
  (void)flush;
  FD_TEST( ctx          ==send_expected.ctx           );
  FD_TEST( batch        ==send_expected.batch         );
  FD_TEST( batch_cnt    ==send_expected.batch_cnt     );
  FD_TEST( opt_batch_idx==send_expected.opt_batch_idx );
  return send_retval;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_aio_t _aio[1];

  /* Test various error handling */

  FD_TEST( fd_aio_new      ( NULL, NULL, test_aio_send_func )==NULL ); /* NULL shmem     */
  FD_TEST( fd_aio_new      ( _aio, NULL, NULL               )==NULL ); /* NULL send_func */
  FD_TEST( fd_aio_join     ( NULL )                          ==NULL );
  FD_TEST( fd_aio_leave    ( NULL )                          ==NULL );
  FD_TEST( fd_aio_delete   ( NULL )                          ==NULL );
  FD_TEST( fd_aio_ctx      ( NULL )                          ==NULL );
  FD_TEST( fd_aio_send_func( NULL )                          ==NULL );

  int err;
  err = FD_AIO_SUCCESS;   FD_LOG_NOTICE(( "FD_AIO_SUCCESS   (%i-%s)", err, fd_aio_strerror( err ) ));
  err = FD_AIO_ERR_INVAL; FD_LOG_NOTICE(( "FD_AIO_ERR_INVAL (%i-%s)", err, fd_aio_strerror( err ) ));
  err = FD_AIO_ERR_AGAIN; FD_LOG_NOTICE(( "FD_AIO_ERR_AGAIN (%i-%s)", err, fd_aio_strerror( err ) ));
  err = 1;                FD_LOG_NOTICE(( "unknown          (%i-%s)", err, fd_aio_strerror( err ) ));

  /* Simple test */

  void *     ctx   = (void *)0x1234UL;
  void *     shaio = fd_aio_new( _aio, ctx, test_aio_send_func ); FD_TEST( shaio );
  fd_aio_t * aio   = fd_aio_join( shaio );                        FD_TEST( aio );
  
  FD_TEST( fd_aio_ctx      ( aio )==ctx                );
  FD_TEST( fd_aio_send_func( aio )==test_aio_send_func );

  fd_aio_pkt_info_t batch[1];
  ulong             batch_idx;

  send_expected.ctx           = ctx;
  send_expected.batch         = batch;
  send_expected.batch_cnt     = 1UL;
  send_expected.opt_batch_idx = &batch_idx;
  send_retval                 = FD_AIO_ERR_INVAL;

  FD_TEST( fd_aio_send( aio, batch, 1UL, &batch_idx, 1 )==FD_AIO_ERR_INVAL );

  FD_TEST( fd_aio_leave ( aio   )==shaio        );
  FD_TEST( fd_aio_delete( shaio )==(void *)_aio );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

