#include "test_pb_encode.c"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_pb_encode();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
