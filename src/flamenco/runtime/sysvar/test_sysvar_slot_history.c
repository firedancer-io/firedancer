#include "fd_sysvar_slot_history.h"
#include "../../types/fd_types.h"

FD_IMPORT_BINARY( example_slot_history, "src/flamenco/runtime/sysvar/test_sysvar_slot_history.bin" );

static void
test_sysvar_slot_history_bounds( void ) {
  FD_TEST( example_slot_history_sz==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = {
    .data    = example_slot_history,
    .dataend = example_slot_history + example_slot_history_sz
  };
  ulong obj_sz = 0UL;
  FD_TEST( fd_slot_history_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_SLOT_HISTORY_FOOTPRINT );
  FD_TEST( fd_slot_history_align()==FD_SYSVAR_SLOT_HISTORY_ALIGN );
}

static void
test_sysvar_slot_history( void ) {
  test_sysvar_slot_history_bounds();
  /* FIXME more tests here ... */
}
