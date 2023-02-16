#include "fd_aio.h"
#include "../../util/fd_util.h"

FD_STATIC_ASSERT( alignof( fd_aio_buf_t )==FD_AIO_BUF_ALIGN,     alignment     );
FD_STATIC_ASSERT( sizeof ( fd_aio_buf_t )==FD_AIO_BUF_FOOTPRINT, alignment );

static struct {
  void *         ctx;
  fd_aio_buf_t * batch;
  ulong          batch_cnt;
} recv_expected;

static ulong recv_retval;

static ulong
test_aio_recv( void *         ctx,
               fd_aio_buf_t * batch,
               ulong          batch_cnt ) {
  FD_TEST( ctx      ==recv_expected.ctx       );
  FD_TEST( batch    ==recv_expected.batch     );
  FD_TEST( batch_cnt==recv_expected.batch_cnt );
  return recv_retval;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_aio_t _aio[1];

  /* Test failure cases for fd_aio_new */

  FD_TEST( fd_aio_new( NULL, NULL, test_aio_recv )==NULL ); /* NULL mem  */
  FD_TEST( fd_aio_new( _aio, NULL, NULL          )==NULL ); /* NULL recv */

  /* Test fd_aio */

  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, (void *)0x1234UL, test_aio_recv ) );
  FD_TEST( aio );

  FD_TEST( (ulong)aio      ==(ulong)_aio   );
  FD_TEST( (ulong)aio->ctx ==0x1234UL      );
  FD_TEST(        aio->recv==test_aio_recv );

  FD_TEST( fd_aio_delete( fd_aio_leave( aio ) ) );

  /* Test fd_aio callback */

  fd_aio_buf_t batch[ 2UL ] = {0};

  recv_expected.ctx       = (void *)0x2345UL;
  recv_expected.batch     = batch;
  recv_expected.batch_cnt = 2UL;
  recv_retval             = 1UL;

  aio = fd_aio_join( fd_aio_new( _aio, (void *)0x2345UL, test_aio_recv ) );
  FD_TEST( aio );
  FD_TEST( fd_aio_send( aio, batch, 2UL )==1UL );
  FD_TEST( fd_aio_delete( fd_aio_leave( aio ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
