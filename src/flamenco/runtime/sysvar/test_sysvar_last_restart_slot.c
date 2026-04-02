#include "fd_sysvar_last_restart_slot.h"
#include "../../types/fd_types.h"

static void
test_sysvar_last_restart_slot_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x28, 0xbe, 0xb0, 0x0e, 0x00, 0x00, 0x00, 0x00
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ );
}

static void
test_sysvar_last_restart_slot( void ) {
  test_sysvar_last_restart_slot_bounds();
  /* FIXME more tests here ... */
}
