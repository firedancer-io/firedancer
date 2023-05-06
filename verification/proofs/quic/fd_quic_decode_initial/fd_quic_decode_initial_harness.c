#include <util/fd_util_base.h>
#include <tango/quic/fd_quic_proto.h>

#define SIZE 1500UL

void harness(void)
{
  uchar *buf[SIZE];
  fd_quic_initial_t initial = {0};

  fd_quic_decode_initial( &initial, buf, SIZE );
}
