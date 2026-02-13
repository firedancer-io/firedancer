#include "fd_pb_less.h"
#include "../../util/log/fd_log.h"

static void
test_pb_simple( void ) {
  static uchar scratch[256];
  static uchar const msg[] = { 0x08, 0x96, 0x01 };
  fd_pb_less_t * less = fd_pb_less_parse( scratch, sizeof(scratch), msg, sizeof(msg) );
  FD_TEST( less );
  FD_TEST( fd_pb_get_int32( less, 1, -1 )==150 );
  FD_TEST( fd_pb_get_int32( less, 2, -1 )==-1 );
}

static void
test_pb_less( void ) {
  test_pb_simple();
}
