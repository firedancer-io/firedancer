#include "fd_sysvar_recent_hashes.h"
#include "../../types/fd_types.h"

FD_IMPORT_BINARY( example_recent_hashes, "src/flamenco/runtime/sysvar/test_sysvar_recent_hashes.bin" );

static void
test_sysvar_recent_hashes_bounds( void ) {
  FD_TEST( example_recent_hashes_sz==FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = {
    .data    = example_recent_hashes,
    .dataend = example_recent_hashes + example_recent_hashes_sz
  };
  ulong obj_sz = 0UL;
  FD_TEST( fd_recent_block_hashes_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_RECENT_HASHES_FOOTPRINT );
  FD_TEST( fd_recent_block_hashes_align()==FD_SYSVAR_RECENT_HASHES_ALIGN );
}

static void
test_sysvar_recent_hashes( void ) {
  test_sysvar_recent_hashes_bounds();
  /* FIXME more tests here ... */
}
