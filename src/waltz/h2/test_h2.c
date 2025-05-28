#include "../../util/fd_util.h"

#include "test_hpack.c"
#if FD_HAS_HOSTED
#include "test_h2_rbuf.c"
#endif
#include "test_h2_hdr_match.c"
#include "test_h2_conn.c"
#include "test_h2_proto.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing hpack" ));
  test_hpack();

#if FD_HAS_HOSTED
  FD_LOG_NOTICE(( "Testing h2_buf" ));
  test_h2_rbuf( rng );
#endif

  FD_LOG_NOTICE(( "Testing h2_hdr_match" ));
  test_h2_hdr_match();

  FD_LOG_NOTICE(( "Testing h2_conn" ));
  test_h2_conn();

  FD_LOG_NOTICE(( "Testing h2_proto" ));
  test_h2_proto();

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
