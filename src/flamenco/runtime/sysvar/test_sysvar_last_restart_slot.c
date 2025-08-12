#include "fd_sysvar_last_restart_slot.h"
#include "../../types/fd_types.h"

static void
test_sysvar_last_restart_slot_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x28, 0xbe, 0xb0, 0x0e, 0x00, 0x00, 0x00, 0x00
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = { .data=data, .dataend=data+sizeof(data) };
  ulong obj_sz = 0UL;
  FD_TEST( fd_sol_sysvar_last_restart_slot_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT );
  FD_TEST( fd_sol_sysvar_last_restart_slot_align()==FD_SYSVAR_LAST_RESTART_SLOT_ALIGN );
}

static void
test_sysvar_last_restart_slot( void ) {
  test_sysvar_last_restart_slot_bounds();
  /* FIXME more tests here ... */
}
