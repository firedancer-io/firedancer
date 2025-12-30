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
test_pb_corrupt( void ) {
  static uchar const tag_oob[] = { 0xff, 0xff, 0xff, 0xff, 0x7f }; /* tag>UINT_MAX */
  static uchar const tag_mega[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }; /* tag>ULONG_MAX */
  static uchar const tag_eof[] = { 0x80 };
  static uchar const wire_type_invalid[] = { 0x03, 0x00 };
  static uchar const varint_mega[] = { 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
  static uchar const varint_eof[] = { 0x08, 0x80 };
  static uchar const i32_eof[] = { 0x0d, 0x01, 0x02 };
  static uchar const i64_eof[] = { 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
  static struct { uchar const * p; ulong sz; } corrupt_cases[] = {
    { tag_oob,           sizeof(tag_oob)               },
    { tag_mega,          sizeof(tag_mega)              },
    { tag_eof,           sizeof(tag_eof)               },
    { wire_type_invalid, sizeof(wire_type_invalid)     },
    { varint_mega,       sizeof(varint_mega)           },
    { varint_eof,        sizeof(varint_eof)            },
    { i32_eof,           sizeof(i32_eof)               },
    { i64_eof,           sizeof(i64_eof)               },
    {0}
  };
  for( ulong i=0; corrupt_cases[i].p; i++ ) {
    fd_pb_inbuf_t inbuf[1];
    fd_pb_inbuf_init( inbuf, corrupt_cases[i].p, corrupt_cases[i].sz );
    fd_pb_tlv_t tlv;
    FD_TEST( !fd_pb_read_tlv( inbuf, &tlv ) );
  }
}

static void
test_pb_tokenize( void ) {
  test_pb_tokenize1();
  test_pb_corrupt();
}
