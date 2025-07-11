#include "test_sysvar_cache.c"
#include "test_sysvar_epoch_schedule.c"
#include "test_sysvar_rent.c"
#include "test_sysvar_slot_history.c"
#include "../../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_sysvar_cache();
  test_sysvar_epoch_schedule();
  test_sysvar_rent();
  test_sysvar_slot_history();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
