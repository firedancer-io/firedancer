/* Unit tests for epoch boundary reward calculations (partitioned rewards,
   inflation, stake/vote reward math).  Scaffold — add cases here. */

#include "fd_rewards.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* TODO: exercise fd_begin_partitioned_rewards, inflation helpers, etc. */
  FD_TEST( 1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
