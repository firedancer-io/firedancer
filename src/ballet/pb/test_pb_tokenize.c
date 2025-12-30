#include "fd_pb_tokenize.h"

static void
test_pb_tokenize1( void ) {
  static uchar encoded[] = {
    0x08, 0x96, 0x01,                         /* field 1, varint 150 */
    0x12, 0x07,                               /* field 2, length 7 */
    0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, /* "testing" */
    0x1a, 0x03,                               /* field 3, submsg length 3 */
    0x20, 0x97, 0x01,                         /* field 4, varint 151 */
    0x2d, 0x03, 0x02, 0x01, 0xf0,             /* field 5, fixed32 */
    0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x80 /* field 6, fixed64 */
  };

# define EXPECT_TLV( in, ... ) do {           \
    fd_pb_tlv_t expected = __VA_ARGS__;       \
    fd_pb_tlv_t actual;                       \
    FD_TEST( fd_pb_read_tlv( in, &actual ) ); \
    if( FD_UNLIKELY( !fd_memeq( &expected, &actual, sizeof(fd_pb_tlv_t) ) ) ) { \
      FD_LOG_HEXDUMP_NOTICE(( "exp", &expected, sizeof(fd_pb_tlv_t) ));\
      FD_LOG_HEXDUMP_ERR   (( "act", &actual,   sizeof(fd_pb_tlv_t) ));\
    }                                                                  \
  } while(0)

  fd_pb_inbuf_t inbuf[1];
  fd_pb_inbuf_init( inbuf, encoded, sizeof(encoded) );
  EXPECT_TLV( inbuf, { .wire_type=FD_PB_WIRE_TYPE_VARINT, .field_id=1, .varint=150 } );
  EXPECT_TLV( inbuf, { .wire_type=FD_PB_WIRE_TYPE_LEN,    .field_id=2, .len   =  7 } );
  fd_pb_inbuf_skip( inbuf, 7 );
  EXPECT_TLV( inbuf, { .wire_type=FD_PB_WIRE_TYPE_LEN,    .field_id=3, .len   =  3 } );
  EXPECT_TLV( inbuf, { .wire_type=FD_PB_WIRE_TYPE_VARINT, .field_id=4, .varint=151 } );
  EXPECT_TLV( inbuf, { .wire_type=FD_PB_WIRE_TYPE_I32,    .field_id=5, .i64=0xf0010203 } );
  EXPECT_TLV( inbuf, { .wire_type=FD_PB_WIRE_TYPE_I64,    .field_id=6, .i64=0x8007060504030201UL } );
}

static void
test_pb_tokenize( void ) {
  test_pb_tokenize1();
}
