#include "fd_sysvar_slot_hashes.h"
#include "../../types/fd_types.h"

FD_IMPORT_BINARY( example_slot_hashes, "src/flamenco/runtime/sysvar/test_sysvar_slot_hashes.bin" );

static void
test_sysvar_slot_hashes_bounds( void ) {
  FD_TEST( example_slot_hashes_sz==FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = {
    .data    = example_slot_hashes,
    .dataend = example_slot_hashes + example_slot_hashes_sz
  };
  ulong obj_sz = 0UL;
  FD_TEST( fd_slot_hashes_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_SLOT_HASHES_FOOTPRINT );
  FD_TEST( fd_slot_hashes_align()==FD_SYSVAR_SLOT_HASHES_ALIGN );
}

static void
test_sysvar_slot_hashes( void ) {
  test_sysvar_slot_hashes_bounds();
  /* FIXME more tests here ... */
}
