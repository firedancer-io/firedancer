#include "fd_sysvar_stake_history.h"
#include "../../types/fd_types.h"

FD_IMPORT_BINARY( example_stake_history, "src/flamenco/runtime/sysvar/test_sysvar_stake_history.bin" );

static void
test_sysvar_stake_history_bounds( void ) {
  FD_TEST( example_stake_history_sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = {
    .data    = example_stake_history,
    .dataend = example_stake_history + example_stake_history_sz
  };
  ulong obj_sz = 0UL;
  FD_TEST( fd_stake_history_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_STAKE_HISTORY_FOOTPRINT );
  FD_TEST( fd_stake_history_align()==FD_SYSVAR_STAKE_HISTORY_ALIGN );
}

static void
test_sysvar_stake_history( void ) {
  test_sysvar_stake_history_bounds();
  /* FIXME more tests here ... */
}
