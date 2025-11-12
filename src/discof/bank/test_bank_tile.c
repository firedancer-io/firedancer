#include "../../util/fd_util.h"
#include "../../util/tile/fd_tile.h"

#include "fd_bank_tile_test.h"

FD_TL ulong fd_tile_private_stack0 = 0UL;
FD_TL ulong fd_tile_private_stack1 = 0UL;

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_bank_tile_test_bundle_ctx_visibility();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
