/* test_xdp_unit: Unit tests for xdp modules.
   Runs on non-hosted targets. */

#include "fd_xdp.h"
#include "fd_xsk_private.h"
#include "fd_xsk_aio_private.h"
#include "../../util/fd_util.h"


FD_STATIC_ASSERT( alignof(fd_xsk_frame_meta_t)==alignof(fd_aio_buf_t), alignment );
FD_STATIC_ASSERT( alignof(fd_xsk_frame_meta_t)>=8UL,                      alignment );


int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_xsk_aio_align()==32UL                         );
  FD_TEST( fd_xsk_aio_align()==alignof(fd_xsk_aio_t)        );
  FD_TEST( fd_xsk_aio_align()>=alignof(fd_xsk_frame_meta_t) );
  FD_TEST( fd_xsk_aio_align()>=alignof(fd_aio_buf_t)     );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}

