#include "../../util/tmpl/fd_unit_test.c"
#include "../../util/fd_util.h"
#include "test_slow_inflight.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
