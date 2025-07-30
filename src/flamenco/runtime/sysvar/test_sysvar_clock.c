#include "fd_sysvar_clock.h"
#include "../../types/fd_types.h"

static void
test_sysvar_clock_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0xef, 0x04, 0x28, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x55, 0x95, 0x7d, 0x68, 0x00, 0x00, 0x00, 0x00,
    0x35, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x36, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x87, 0x3a, 0x7f, 0x68, 0x00, 0x00, 0x00, 0x00
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_CLOCK_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = { .data=data, .dataend=data+sizeof(data) };
  ulong obj_sz = 0UL;
  FD_TEST( fd_sol_sysvar_clock_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_CLOCK_FOOTPRINT );
  FD_TEST( fd_sol_sysvar_clock_align()==FD_SYSVAR_CLOCK_ALIGN );
}

static void
test_sysvar_clock( void ) {
  test_sysvar_clock_bounds();
  /* FIXME more tests here ... */
}
