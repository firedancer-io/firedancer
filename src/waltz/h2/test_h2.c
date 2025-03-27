#include "../../util/fd_util.h"

#include "test_hpack.c"
#include "test_h2_rbuf.c"
#include "test_h2_hdr_match.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing hpack" ));
  test_hpack();

  FD_LOG_NOTICE(( "Testing h2_buf" ));
  test_h2_rbuf( rng );

  FD_LOG_NOTICE(( "Testing h2_hdr_match" ));
  test_h2_hdr_match();

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
