#include <assert.h>
#include <malloc.h>
#include <util/fd_util_base.h>
#include <tango/quic/fd_quic_proto.h>

void harness(void)
{
  uint size;
  __CPROVER_assume(size <= 1500);
  uchar *buf = malloc(size);

  if (buf != NULL) {
    fd_quic_initial_t initial;

    ulong byte_cnt = fd_quic_decode_initial( &initial, buf, size );

    if (byte_cnt != FD_QUIC_PARSE_FAIL) {
      assert(byte_cnt <= size);

      assert(initial.hdr_form <= 1);
      assert(initial.fixed_bit <= 1);
      assert(initial.long_packet_type <= 4);
      assert(initial.reserved_bits <= 4);
      assert(initial.pkt_number_len <= 4);

      assert(initial.dst_conn_id_len <= 20);
      assert(initial.src_conn_id_len <= 20);
      assert(initial.len < (1UL << 62));
    }
  }
}
