#include "fd_sysvar_slot_hashes.h"

FD_IMPORT_BINARY( example_slot_hashes, "src/flamenco/runtime/sysvar/test_sysvar_slot_hashes.bin" );

static void
test_sysvar_slot_hashes( void ) {
  FD_TEST( example_slot_hashes_sz==FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
  FD_TEST( fd_sysvar_slot_hashes_validate( example_slot_hashes, example_slot_hashes_sz ) );

  fd_slot_hashes_view_t view[1];
  FD_TEST( fd_sysvar_slot_hashes_view( view, example_slot_hashes, example_slot_hashes_sz ) );
  FD_TEST( view->cnt==FD_SYSVAR_SLOT_HASHES_CAP );

  FD_TEST( !fd_sysvar_slot_hashes_validate( NULL, 0 ) );
  FD_TEST( !fd_sysvar_slot_hashes_validate( example_slot_hashes, 4 ) );
}
