#include "fd_pb_gen.h"

static void
test_pb_gen_packed_overflow( void ) {
  static uchar spad_mem[ 4096 ] __attribute__((aligned(FD_SPAD_ALIGN)));
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, sizeof(spad_mem)-sizeof(fd_spad_t) ) );
  FD_TEST( spad );
  fd_spad_push( spad );

  /* field 1, packed varints [1, 2] */
  static uchar const packed_ok[] = { 0x0a, 0x02, 0x01, 0x02 };
  /* field 1, packed varint with tenth byte >1 (overflows 64 bits) */
  static uchar const packed_overflow[] = { 0x0a, 0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
  /* field 1, packed varint truncated */
  static uchar const packed_eof[] = { 0x0a, 0x01, 0x80 };

  fd_pb_inbuf_t in[1];
  fd_pb_tlv_t   tlv[1];
  ulong *       arr;
  uint          cnt;

  arr = NULL; cnt = 0U;
  fd_pb_inbuf_init( in, packed_ok, sizeof(packed_ok) );
  FD_TEST( fd_pb_tlv_read( in, tlv ) );
  FD_TEST( fd_pb_dec_repeated( in, tlv, spad, FD_PB_GEN_UINT64, &arr, &cnt ) );
  FD_TEST( cnt==2U && arr[0]==1UL && arr[1]==2UL );
  FD_TEST( !fd_pb_inbuf_sz( in ) );

  arr = NULL; cnt = 0U;
  fd_pb_inbuf_init( in, packed_overflow, sizeof(packed_overflow) );
  FD_TEST( fd_pb_tlv_read( in, tlv ) );
  FD_TEST( !fd_pb_dec_repeated( in, tlv, spad, FD_PB_GEN_UINT64, &arr, &cnt ) );

  arr = NULL; cnt = 0U;
  fd_pb_inbuf_init( in, packed_eof, sizeof(packed_eof) );
  FD_TEST( fd_pb_tlv_read( in, tlv ) );
  FD_TEST( !fd_pb_dec_repeated( in, tlv, spad, FD_PB_GEN_UINT64, &arr, &cnt ) );

  fd_spad_pop( spad );
  fd_spad_delete( fd_spad_leave( spad ) );
}

static void
test_pb_gen( void ) {
  test_pb_gen_packed_overflow();
}
