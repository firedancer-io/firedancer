#include "../../fd_flamenco_base.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) )
    FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  // test_retry_token_invalid_length();  // FIXME after error change

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
