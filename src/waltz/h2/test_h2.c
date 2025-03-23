#include "../../util/fd_util.h"

#include "test_hpack.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing hpack" ));
  test_hpack();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
