#include "../../util/fd_util.h"
#include "../../util/tmpl/fd_unit_test.c"

static fd_rng_t rng[1];

#include "test_hpack.c"
#if FD_HAS_HOSTED
#include "test_h2_rbuf.c"
#endif
#include "test_h2_server_sequences.c"
#include "test_h2_hdr_match.c"
#include "test_h2_conn.c"
#include "test_h2_proto.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0U, 0UL ) ) );

  fd_unit_tests( argc, argv );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
