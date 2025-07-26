#include "fd_sysvar_recent_hashes.h"

FD_IMPORT_BINARY( example_recent_hashes, "src/flamenco/runtime/sysvar/test_sysvar_recent_hashes.bin" );

static void
test_sysvar_recent_hashes_bounds( void ) {
  FD_TEST( FD_SYSVAR_RECENT_HASHES_BINCODE_SZ==6008 );
}

static void
test_sysvar_recent_hashes( void ) {
  test_sysvar_recent_hashes_bounds();
  /* FIXME more tests here ... */
}
