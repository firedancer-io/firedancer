#include "fd_pb_encode.h"

/* Test all examples from the Protobuf encoding guide documentation */

/* https://protobuf.dev/programming-guides/encoding/#simple */

static void
test_pb_encode_doc_simple( void ) {
  uchar buf[ 32 ];
  fd_pb_encoder_t enc_[1];
  fd_pb_encoder_t * enc = fd_pb_encoder_init( enc_, buf, sizeof(buf) );
  FD_TEST( enc==enc_ );
  FD_TEST( fd_pb_push_int32( enc, 1U, 150 ) );
  static uchar const expected[3] = { 0x08, 0x96, 0x01 };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )==enc_             );
  FD_TEST( fd_memeq( buf, expected, 3UL ) );
}

/* https://protobuf.dev/programming-guides/encoding/#length-types */

static void
test_pb_encode_doc_length_types( void ) {
  uchar buf[ 32 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_cstr( enc, 2U, "testing" ) );
  static uchar const expected[] = {
    0x12, 0x07,
    0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) ) );
}

/* https://protobuf.dev/programming-guides/encoding/#embedded */

static void
test_pb_encode_doc_embedded( void ) {
  uchar buf[ 32 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_submsg_open( enc, 3 ) );
  FD_TEST( fd_pb_push_int32( enc, 1U, 150 ) );
  FD_TEST( fd_pb_submsg_close( enc ) );
  static uchar const expected[] = {
    0x1a,
    /* fd_pb_encode's submessage length prefixes are inefficient */
    0x83, 0x80, 0x80, 0x80, 0x00,
    0x08, 0x96, 0x01
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) ) );
}

/* https://protobuf.dev/programming-guides/encoding/#repeated */

static void
test_pb_encode_doc_repeated( void ) {
  uchar buf[ 32 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_cstr( enc, 4U, "hello" ) );
  int const e[3] = { 1U, 2U, 3U };
  FD_TEST( fd_pb_push_packed_int32( enc, 6U, e, 3 ) );
  static uchar const expected[] = {
    0x22, 0x05,
    0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x32, 0x83, 0x80, 0x80, 0x80, 0x00,
    0x01, 0x02, 0x03
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) ) );
}

static ulong
read_varint( uchar const * p,
             ulong         sz ) {
  FD_TEST( sz );
  ulong var   = 0UL;
  int   shift = 0;
  for( ulong i=0UL;; i++ ) {
    FD_TEST( i<10 && i<sz ); /* overlong varint */
    /* FIXME check if one bits are shifted out of bounds */
    var |= (ulong)( p[i] & 0x7f ) << shift;
    shift += 7;
    if( !( p[i] & 0x80 ) ) return var;
  }
}

static void
test_pb_encode_bool( void ) {
  /* correctness */

  uchar buf[ 32 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_bool( enc, 1, 0 ) );
  FD_TEST( fd_pb_push_bool( enc, 2, 1 ) );
  FD_TEST( fd_pb_push_bool( enc, 3, 2 ) );
  static uchar const expected[] = {
    0x08, 0x00,
    0x10, 0x01,
    0x18, 0x01
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );
  FD_TEST( read_varint( expected+0, 1 )==0x08 );
  FD_TEST( read_varint( expected+1, 1 )==0x00 );
  FD_TEST( read_varint( expected+2, 1 )==0x10 );
  FD_TEST( read_varint( expected+3, 1 )==0x01 );
  FD_TEST( read_varint( expected+4, 1 )==0x18 );
  FD_TEST( read_varint( expected+5, 1 )==0x01 );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 5 ) );
  FD_TEST( !fd_pb_push_bool( enc, 1, 0 ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 6 ) );
  FD_TEST( fd_pb_push_bool( enc, 1, 0 ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_int32( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_int32( enc,  1, 0          ) );
  FD_TEST( fd_pb_push_int32( enc,  2, 0x0000007f ) );
  FD_TEST( fd_pb_push_int32( enc,  3, 0x00000080 ) );
  FD_TEST( fd_pb_push_int32( enc,  4, 0x00003fff ) );
  FD_TEST( fd_pb_push_int32( enc,  5, 0x00004000 ) );
  FD_TEST( fd_pb_push_int32( enc,  6, 0x001fffff ) );
  FD_TEST( fd_pb_push_int32( enc,  7, 0x00200000 ) );
  FD_TEST( fd_pb_push_int32( enc,  8, 0x0fffffff ) );
  FD_TEST( fd_pb_push_int32( enc,  9, 0x10000000 ) );
  FD_TEST( fd_pb_push_int32( enc, 10, INT_MAX    ) );
  FD_TEST( fd_pb_push_int32( enc, 11, -1         ) );
  FD_TEST( fd_pb_push_int32( enc, 12, INT_MIN    ) );
  static uchar const expected[] = {
    0x08, 0x00,
    0x10, 0x7f,
    0x18, 0x80, 0x01,
    0x20, 0xff, 0x7f,
    0x28, 0x80, 0x80, 0x01,
    0x30, 0xff, 0xff, 0x7f,
    0x38, 0x80, 0x80, 0x80, 0x01,
    0x40, 0xff, 0xff, 0xff, 0x7f,
    0x48, 0x80, 0x80, 0x80, 0x80, 0x01,
    0x50, 0xff, 0xff, 0xff, 0xff, 0x07,
    0x58, 0xff, 0xff, 0xff, 0xff, 0x0f,
    0x60, 0x80, 0x80, 0x80, 0x80, 0x08
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );
  FD_TEST( read_varint( expected+ 0, 1 )==      0x08 );
  FD_TEST( read_varint( expected+ 1, 1 )==0x00000000 );
  FD_TEST( read_varint( expected+ 2, 1 )==      0x10 );
  FD_TEST( read_varint( expected+ 3, 1 )==0x0000007f );
  FD_TEST( read_varint( expected+ 4, 1 )==      0x18 );
  FD_TEST( read_varint( expected+ 5, 2 )==0x00000080 );
  FD_TEST( read_varint( expected+ 7, 1 )==      0x20 );
  FD_TEST( read_varint( expected+ 8, 2 )==0x00003fff );
  FD_TEST( read_varint( expected+10, 1 )==      0x28 );
  FD_TEST( read_varint( expected+11, 3 )==0x00004000 );
  FD_TEST( read_varint( expected+14, 1 )==      0x30 );
  FD_TEST( read_varint( expected+15, 3 )==0x001fffff );
  FD_TEST( read_varint( expected+18, 1 )==      0x38 );
  FD_TEST( read_varint( expected+19, 4 )==0x00200000 );
  FD_TEST( read_varint( expected+23, 1 )==      0x40 );
  FD_TEST( read_varint( expected+24, 4 )==0x0fffffff );
  FD_TEST( read_varint( expected+28, 1 )==      0x48 );
  FD_TEST( read_varint( expected+29, 5 )==0x10000000 );
  FD_TEST( read_varint( expected+34, 1 )==      0x50 );
  FD_TEST( read_varint( expected+35, 5 )==0x7fffffff );
  FD_TEST( read_varint( expected+40, 1 )==      0x58 );
  FD_TEST( read_varint( expected+41, 5 )==0xffffffff );
  FD_TEST( read_varint( expected+46, 1 )==      0x60 );
  FD_TEST( read_varint( expected+47, 5 )==0x80000000 );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 9 ) );
  FD_TEST( !fd_pb_push_int32( enc, 1U, 1 ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 10 ) );
  FD_TEST( fd_pb_push_int32( enc, 1U, 1 ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_int32_sz5( void ) {
  /* correctness */

  uchar buf[ 60 ];
  FD_TEST( fd_pb_append_varint32_sz5( buf+ 0, 0          )==buf+ 5 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+ 5, 0x0000007f )==buf+10 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+10, 0x00000080 )==buf+15 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+15, 0x00003fff )==buf+20 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+20, 0x00004000 )==buf+25 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+25, 0x001fffff )==buf+30 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+30, 0x00200000 )==buf+35 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+35, 0x0fffffff )==buf+40 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+40, 0x10000000 )==buf+45 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+45, 0x7fffffff )==buf+50 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+50, 0xffffffff )==buf+55 );
  FD_TEST( fd_pb_append_varint32_sz5( buf+55, 0x80000000 )==buf+60 );
  static uchar const expected[] = {
    0x80, 0x80, 0x80, 0x80, 0x00,
    0xff, 0x80, 0x80, 0x80, 0x00,
    0x80, 0x81, 0x80, 0x80, 0x00,
    0xff, 0xff, 0x80, 0x80, 0x00,
    0x80, 0x80, 0x81, 0x80, 0x00,
    0xff, 0xff, 0xff, 0x80, 0x00,
    0x80, 0x80, 0x80, 0x81, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x00,
    0x80, 0x80, 0x80, 0x80, 0x01,
    0xff, 0xff, 0xff, 0xff, 0x07,
    0xff, 0xff, 0xff, 0xff, 0x0f,
    0x80, 0x80, 0x80, 0x80, 0x08
  };
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) ) );
  FD_TEST( read_varint( expected+ 0, 5 )==0x00000000 );
  FD_TEST( read_varint( expected+ 5, 5 )==0x0000007f );
  FD_TEST( read_varint( expected+10, 5 )==0x00000080 );
  FD_TEST( read_varint( expected+15, 5 )==0x00003fff );
  FD_TEST( read_varint( expected+20, 5 )==0x00004000 );
  FD_TEST( read_varint( expected+25, 5 )==0x001fffff );
  FD_TEST( read_varint( expected+30, 5 )==0x00200000 );
  FD_TEST( read_varint( expected+35, 5 )==0x0fffffff );
  FD_TEST( read_varint( expected+40, 5 )==0x10000000 );
  FD_TEST( read_varint( expected+45, 5 )==0x7fffffff );
  FD_TEST( read_varint( expected+50, 5 )==0xffffffff );
  FD_TEST( read_varint( expected+55, 5 )==0x80000000 );
}

static void
test_pb_encode_sint32( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_sint32( enc, 1,       0 ) );
  FD_TEST( fd_pb_push_sint32( enc, 2,      -1 ) );
  FD_TEST( fd_pb_push_sint32( enc, 3,       1 ) );
  FD_TEST( fd_pb_push_sint32( enc, 4,      -2 ) );
  FD_TEST( fd_pb_push_sint32( enc, 5, INT_MAX ) );
  FD_TEST( fd_pb_push_sint32( enc, 6, INT_MIN ) );
  static uchar const expected[] = {
    0x08, 0x00,
    0x10, 0x01,
    0x18, 0x02,
    0x20, 0x03,
    0x28, 0xfe, 0xff, 0xff, 0xff, 0x0f,
    0x30, 0xff, 0xff, 0xff, 0xff, 0x0f
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 9 ) );
  FD_TEST( !fd_pb_push_sint32( enc, 1U, 1 ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 10 ) );
  FD_TEST( fd_pb_push_sint32( enc, 1U, 1 ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_uint32( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_uint32( enc, 1,          0U ) );
  FD_TEST( fd_pb_push_uint32( enc, 2,          1U ) );
  FD_TEST( fd_pb_push_uint32( enc, 3,          2U ) );
  FD_TEST( fd_pb_push_uint32( enc, 4,          3U ) );
  FD_TEST( fd_pb_push_uint32( enc, 5, UINT_MAX-1U ) );
  FD_TEST( fd_pb_push_uint32( enc, 6, UINT_MAX    ) );
  static uchar const expected[] = {
    0x08, 0x00,
    0x10, 0x01,
    0x18, 0x02,
    0x20, 0x03,
    0x28, 0xfe, 0xff, 0xff, 0xff, 0x0f,
    0x30, 0xff, 0xff, 0xff, 0xff, 0x0f
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 9 ) );
  FD_TEST( !fd_pb_push_uint32( enc, 1U, 1U ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 10 ) );
  FD_TEST( fd_pb_push_uint32( enc, 1U, 1U ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );

  /* packed */

  uint num[8] = { 1U, 2U, 3U, 4U, 5U, 6U, 7U, UINT_MAX };
  FD_TEST( fd_pb_encoder_init( enc, buf, 18UL ) );
  FD_TEST( fd_pb_push_packed_uint32( enc, 1, num, 8 ) );
  uchar const packed[] = {
    0x0a, 0x8c, 0x80, 0x80, 0x80, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xff, 0xff, 0xff, 0xff, 0x0f
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf            );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(packed) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                 );
  FD_TEST( fd_memeq( buf, packed, sizeof(packed) )     );

  /* packed bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 9UL ) );
  FD_TEST( !fd_pb_push_packed_uint32( enc, 1, num, 0 ) );  /* oversz header */
  FD_TEST( fd_pb_encoder_init( enc, buf, 17UL ) );
  FD_TEST( !fd_pb_push_packed_uint32( enc, 1, num, 8 ) );  /* oversz data */
}

static void
test_pb_encode_int64( void ) {
  /* correctness */

  uchar buf[ 256 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_int64( enc,  1, 0                   ) );
  FD_TEST( fd_pb_push_int64( enc,  2, 0x000000000000007fL ) ); /*  7 bits */
  FD_TEST( fd_pb_push_int64( enc,  3, 0x0000000000000080L ) );
  FD_TEST( fd_pb_push_int64( enc,  4, 0x0000000000003fffL ) ); /* 14 bits */
  FD_TEST( fd_pb_push_int64( enc,  5, 0x0000000000004000L ) );
  FD_TEST( fd_pb_push_int64( enc,  6, 0x00000000001fffffL ) ); /* 21 bits */
  FD_TEST( fd_pb_push_int64( enc,  7, 0x0000000000200000L ) );
  FD_TEST( fd_pb_push_int64( enc,  8, 0x000000000fffffffL ) ); /* 28 bits */
  FD_TEST( fd_pb_push_int64( enc,  9, 0x0000000010000000L ) );
  FD_TEST( fd_pb_push_int64( enc, 10, INT_MAX             ) );
  FD_TEST( fd_pb_push_int64( enc, 11, 0x00000007ffffffffL ) ); /* 35 bits */
  FD_TEST( fd_pb_push_int64( enc, 12, 0x0000000800000000L ) );
  FD_TEST( fd_pb_push_int64( enc, 13, 0x000003ffffffffffL ) ); /* 42 bits */
  FD_TEST( fd_pb_push_int64( enc, 14, 0x0000040000000000L ) );
  FD_TEST( fd_pb_push_int64( enc, 15, 0x0001ffffffffffffL ) ); /* 49 bits */
  FD_TEST( fd_pb_push_int64( enc, 16, 0x0002000000000000L ) );
  FD_TEST( fd_pb_push_int64( enc, 17, 0x00ffffffffffffffL ) ); /* 56 bits */
  FD_TEST( fd_pb_push_int64( enc, 18, 0x0100000000000000L ) );
  FD_TEST( fd_pb_push_int64( enc, 19, LONG_MAX            ) ); /* 63 bits */
  FD_TEST( fd_pb_push_int64( enc, 20, LONG_MIN            ) );
  FD_TEST( fd_pb_push_int64( enc, 21, -1L                 ) ); /* 64 bits */
  static uchar const expected[] = {
    0x08,       0x00,
    0x10,       0x7f,
    0x18,       0x80, 0x01,
    0x20,       0xff, 0x7f,
    0x28,       0x80, 0x80, 0x01,
    0x30,       0xff, 0xff, 0x7f,
    0x38,       0x80, 0x80, 0x80, 0x01,
    0x40,       0xff, 0xff, 0xff, 0x7f,
    0x48,       0x80, 0x80, 0x80, 0x80, 0x01,
    0x50,       0xff, 0xff, 0xff, 0xff, 0x07,
    0x58,       0xff, 0xff, 0xff, 0xff, 0x7f,
    0x60,       0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
    0x68,       0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    0x70,       0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
    0x78,       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    0x80, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
    0x88, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    0x90, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
    0x98, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    0xa0, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
    0xa8, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );
  FD_TEST( read_varint( expected+  0, 1 )==                0x08 );
  FD_TEST( read_varint( expected+  1, 1 )==0x0000000000000000UL );
  FD_TEST( read_varint( expected+  2, 1 )==                0x10 );
  FD_TEST( read_varint( expected+  3, 1 )==0x000000000000007fUL );
  FD_TEST( read_varint( expected+  4, 1 )==                0x18 );
  FD_TEST( read_varint( expected+  5, 2 )==0x0000000000000080UL );
  FD_TEST( read_varint( expected+  7, 1 )==                0x20 );
  FD_TEST( read_varint( expected+  8, 2 )==0x0000000000003fffUL );
  FD_TEST( read_varint( expected+ 10, 1 )==                0x28 );
  FD_TEST( read_varint( expected+ 11, 3 )==0x0000000000004000UL );
  FD_TEST( read_varint( expected+ 14, 1 )==                0x30 );
  FD_TEST( read_varint( expected+ 15, 3 )==0x00000000001fffffUL );
  FD_TEST( read_varint( expected+ 18, 1 )==                0x38 );
  FD_TEST( read_varint( expected+ 19, 4 )==0x0000000000200000UL );
  FD_TEST( read_varint( expected+ 23, 1 )==                0x40 );
  FD_TEST( read_varint( expected+ 24, 4 )==0x000000000fffffffUL );
  FD_TEST( read_varint( expected+ 28, 1 )==                0x48 );
  FD_TEST( read_varint( expected+ 29, 5 )==0x0000000010000000UL );
  FD_TEST( read_varint( expected+ 34, 1 )==                0x50 );
  FD_TEST( read_varint( expected+ 35, 5 )==0x000000007fffffffUL );
  FD_TEST( read_varint( expected+ 40, 1 )==                0x58 );
  FD_TEST( read_varint( expected+ 41, 6 )==0x00000007ffffffffUL );
  FD_TEST( read_varint( expected+ 46, 1 )==                0x60 );
  FD_TEST( read_varint( expected+ 47, 6 )==0x0000000800000000UL );
  FD_TEST( read_varint( expected+ 53, 1 )==                0x68 );
  FD_TEST( read_varint( expected+ 54, 7 )==0x000003ffffffffffUL );
  FD_TEST( read_varint( expected+ 60, 1 )==                0x70 );
  FD_TEST( read_varint( expected+ 61, 7 )==0x0000040000000000UL );
  FD_TEST( read_varint( expected+ 68, 1 )==                0x78 );
  FD_TEST( read_varint( expected+ 69, 8 )==0x0001ffffffffffffUL );
  FD_TEST( read_varint( expected+ 76, 2 )==                0x80 );
  FD_TEST( read_varint( expected+ 78, 8 )==0x0002000000000000UL );
  FD_TEST( read_varint( expected+ 86, 2 )==                0x88 );
  FD_TEST( read_varint( expected+ 88, 8 )==0x00ffffffffffffffUL );
  FD_TEST( read_varint( expected+ 96, 2 )==                0x90 );
  FD_TEST( read_varint( expected+ 98, 9 )==0x0100000000000000UL );
  FD_TEST( read_varint( expected+107, 2 )==                0x98 );
  FD_TEST( read_varint( expected+109, 9 )==0x7fffffffffffffffUL );
  FD_TEST( read_varint( expected+118, 2 )==                0xa0 );
  FD_TEST( read_varint( expected+120,10 )==0x8000000000000000UL );
  FD_TEST( read_varint( expected+130, 2 )==                0xa8 );
  FD_TEST( read_varint( expected+132,10 )==0xffffffffffffffffUL );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 14 ) );
  FD_TEST( !fd_pb_push_int64( enc, 1U, 1L ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 15 ) );
  FD_TEST( fd_pb_push_int64( enc, 1U, 1L ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_sint64( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_sint64( enc, 1,       0L ) );
  FD_TEST( fd_pb_push_sint64( enc, 2,      -1L ) );
  FD_TEST( fd_pb_push_sint64( enc, 3,       1L ) );
  FD_TEST( fd_pb_push_sint64( enc, 4,      -2L ) );
  FD_TEST( fd_pb_push_sint64( enc, 5, LONG_MAX ) );
  FD_TEST( fd_pb_push_sint64( enc, 6, LONG_MIN ) );
  static uchar const expected[] = {
    0x08, 0x00,
    0x10, 0x01,
    0x18, 0x02,
    0x20, 0x03,
    0x28, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 14 ) );
  FD_TEST( !fd_pb_push_sint64( enc, 1U, 1L ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 15 ) );
  FD_TEST( fd_pb_push_sint64( enc, 1U, 1L ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_uint64( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_uint64( enc, 1,           0UL ) );
  FD_TEST( fd_pb_push_uint64( enc, 2,           1UL ) );
  FD_TEST( fd_pb_push_uint64( enc, 3,           2UL ) );
  FD_TEST( fd_pb_push_uint64( enc, 4,           3UL ) );
  FD_TEST( fd_pb_push_uint64( enc, 5, ULONG_MAX-1UL ) );
  FD_TEST( fd_pb_push_uint64( enc, 6, ULONG_MAX     ) );
  static uchar const expected[] = {
    0x08, 0x00,
    0x10, 0x01,
    0x18, 0x02,
    0x20, 0x03,
    0x28, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 14 ) );
  FD_TEST( !fd_pb_push_uint64( enc, 1U, 1UL ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 15 ) );
  FD_TEST( fd_pb_push_uint64( enc, 1U, 1UL ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_fixed32( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_fixed32( enc,  1, 0          ) );
  FD_TEST( fd_pb_push_fixed32( enc,  2, 0xc3a3ed90 ) );
  FD_TEST( fd_pb_push_fixed32( enc,  3, 0xffffffff ) );
  static uchar const expected[] = {
    0x0d, 0x00, 0x00, 0x00, 0x00,
    0x15, 0x90, 0xed, 0xa3, 0xc3,
    0x1d, 0xff, 0xff, 0xff, 0xff
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 8 ) );
  FD_TEST( !fd_pb_push_fixed32( enc, 1U, 1 ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 9 ) );
  FD_TEST( fd_pb_push_fixed32( enc, 1U, 1 ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==5 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_fixed64( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_fixed64( enc,  1, 0UL                  ) );
  FD_TEST( fd_pb_push_fixed64( enc,  2, 0x98268d2bf52e7617UL ) );
  FD_TEST( fd_pb_push_fixed64( enc,  3, 0xffffffffffffffffUL ) );
  static uchar const expected[] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x17, 0x76, 0x2e, 0xf5, 0x2b, 0x8d, 0x26, 0x98,
    0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 8 ) );
  FD_TEST( !fd_pb_push_fixed32( enc, 1U, 1 ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 9 ) );
  FD_TEST( fd_pb_push_fixed32( enc, 1U, 1 ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==5 );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_float( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_float( enc, 1, 0.0f    ) );
  FD_TEST( fd_pb_push_float( enc, 2, 1.0f    ) );
  FD_TEST( fd_pb_push_float( enc, 3, 2.0f    ) );
  FD_TEST( fd_pb_push_float( enc, 4, 0.5f    ) );
  FD_TEST( fd_pb_push_float( enc, 5, FLT_MIN ) );
  FD_TEST( fd_pb_push_float( enc, 6, FLT_MAX ) );
  static uchar const expected[] = {
    0x0d, 0x00, 0x00, 0x00, 0x00,
    0x15, 0x00, 0x00, 0x80, 0x3f,
    0x1d, 0x00, 0x00, 0x00, 0x40,
    0x25, 0x00, 0x00, 0x00, 0x3f,
    0x2d, 0x00, 0x00, 0x80, 0x00,
    0x35, 0xff, 0xff, 0x7f, 0x7f
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 8 ) );
  FD_TEST( !fd_pb_push_float( enc, 1U, 1.0f ) ); /* no space */
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 9 ) );
  FD_TEST( fd_pb_push_float( enc, 1U, 1.0f ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==5 );
  FD_TEST( fd_pb_encoder_fini( enc ) );

  /* packed */

  float num[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
  FD_TEST( fd_pb_encoder_init( enc, buf, 18UL ) );
  FD_TEST( fd_pb_push_packed_float( enc, 1, num, 4 ) );
  uchar const packed[] = {
    0x0a, 0x10,
    0x00, 0x00, 0x80, 0x3f,
    0x00, 0x00, 0x00, 0x40,
    0x00, 0x00, 0x40, 0x40,
    0x00, 0x00, 0x80, 0x40
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf            );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(packed) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                 );
  FD_TEST( fd_memeq( buf, packed, sizeof(packed) )     );

  /* packed bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 14UL ) );
  FD_TEST( !fd_pb_push_packed_float( enc, 1, num, 0 ) );  /* oversz header */
  FD_TEST( fd_pb_encoder_init( enc, buf, 17UL ) );
  FD_TEST( !fd_pb_push_packed_float( enc, 1, num, 4 ) );  /* oversz data */
}

#if FD_HAS_DOUBLE
static void
test_pb_encode_double( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_double( enc, 1, 0.0     ) );
  FD_TEST( fd_pb_push_double( enc, 2, 1.0     ) );
  FD_TEST( fd_pb_push_double( enc, 3, 2.0     ) );
  FD_TEST( fd_pb_push_double( enc, 4, 0.5     ) );
  FD_TEST( fd_pb_push_double( enc, 5, DBL_MIN ) );
  FD_TEST( fd_pb_push_double( enc, 6, DBL_MAX ) );
  static uchar const expected[] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f,
    0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x3f,
    0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x31, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xef, 0x7f
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 12 ) );
  FD_TEST( !fd_pb_push_double( enc, 1U, 1.0 ) );
  FD_TEST( fd_pb_encoder_fini( enc ) );

  FD_TEST( fd_pb_encoder_init( enc, buf, 13 ) );
  FD_TEST( fd_pb_push_double( enc, 1U, 1.0 ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==9 );
  FD_TEST( fd_pb_encoder_fini( enc ) );

  /* packed */

  double num[3] = { 1.0, 2.0, 3.0 };
  FD_TEST( fd_pb_encoder_init( enc, buf, 26UL ) );
  FD_TEST( fd_pb_push_packed_double( enc, 1, num, 3 ) );
  uchar const packed[] = {
    0x0a, 0x18,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf            );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(packed) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                 );
  FD_TEST( fd_memeq( buf, packed, sizeof(packed) )     );

  /* packed bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 14UL ) );
  FD_TEST( !fd_pb_push_packed_double( enc, 1, num, 0 ) );  /* oversz header */
  FD_TEST( fd_pb_encoder_init( enc, buf, 25UL ) );
  FD_TEST( !fd_pb_push_packed_double( enc, 1, num, 3 ) );  /* oversz data */
}
#endif

static void
test_pb_encode_bytes( void ) {
  /* correctness */

  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  FD_TEST( fd_pb_push_bytes( enc, 1, NULL, 0 ) );
  FD_TEST( fd_pb_push_bytes( enc, 2, (uchar const *)"hello", 5 ) );
  static uchar const expected[] = {
    0x0a, 0x00,
    0x12, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini  ( enc )                   );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );

  /* bounds checks */

  FD_TEST( fd_pb_encoder_init( enc, buf, 9UL ) );
  FD_TEST( !fd_pb_push_bytes( enc, 1U, NULL, 0UL ) );
  FD_TEST( fd_pb_encoder_init( enc, buf, 10UL ) );
  FD_TEST( !fd_pb_push_bytes( enc, 1U, NULL, UINT_MAX+1UL ) );
  FD_TEST( fd_pb_encoder_init( enc, buf, 10UL ) );
  FD_TEST( fd_pb_push_bytes( enc, 1U, NULL, 0UL ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==2UL );
  FD_TEST( fd_pb_encoder_fini( enc ) );
  FD_TEST( fd_pb_encoder_init( enc, buf, 10UL ) );
  FD_TEST( !fd_pb_push_bytes( enc, 1U, "a", 1UL ) );
  FD_TEST( fd_pb_encoder_init( enc, buf, 11UL ) );
  FD_TEST( fd_pb_push_bytes( enc, 1U, "a", 1UL ) );
  FD_TEST( fd_pb_encoder_out_sz( enc )==3UL );
  FD_TEST( fd_pb_encoder_fini( enc ) );
}

static void
test_pb_encode_nested( void ) {
  ulong const depth = 16UL;
  uchar buf[ 128 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  for( ulong i=0UL; i<depth; i++ ) {
    FD_TEST( fd_pb_submsg_open( enc, 1U ) );
  }
  fd_pb_push_cstr( enc, 2U, "deep" );
  for( ulong i=0UL; i<depth; i++ ) {
    FD_TEST( fd_pb_submsg_close( enc ) );
  }

  static uchar const expected[] = {
    0x0a, 0xe0, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xda, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xd4, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xce, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xc8, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xc2, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xbc, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xb6, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xb0, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xaa, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0xa4, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0x9e, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0x98, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0x92, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0x8c, 0x80, 0x80, 0x80, 0x00,
    0x0a, 0x86, 0x80, 0x80, 0x80, 0x00,
    0x12, 0x04, 0x64, 0x65, 0x65, 0x70
  };
  FD_TEST( fd_pb_encoder_out   ( enc )==buf              );
  FD_TEST( fd_pb_encoder_out_sz( enc )==sizeof(expected) );
  FD_TEST( fd_pb_encoder_fini( enc ) );
  FD_TEST( fd_memeq( buf, expected, sizeof(expected) )   );
}

static void
test_pb_encode_nested_overflow( void ) {
  ulong const depth = FD_PB_ENCODER_DEPTH_MAX;
  static uchar buf[ FD_PB_ENCODER_DEPTH_MAX*16 ];
  fd_pb_encoder_t enc[1];
  FD_TEST( fd_pb_encoder_init( enc, buf, sizeof(buf) ) );
  for( ulong i=0UL; i<depth; i++ ) {
    FD_TEST( fd_pb_submsg_open( enc, 1U ) );
  }
  FD_TEST( !fd_pb_submsg_open( enc, 1U ) ); /* overflow */
}

static void
test_pb_encode( void ) {
  test_pb_encode_doc_simple();
  test_pb_encode_doc_length_types();
  test_pb_encode_doc_embedded();
  test_pb_encode_doc_repeated();
  test_pb_encode_bool();
  test_pb_encode_int32();
  test_pb_encode_int32_sz5();
  test_pb_encode_sint32();
  test_pb_encode_uint32();
  test_pb_encode_int64();
  test_pb_encode_sint64();
  test_pb_encode_uint64();
  test_pb_encode_fixed32();
  test_pb_encode_fixed64();
  test_pb_encode_float();
# if FD_HAS_DOUBLE
  test_pb_encode_double();
# endif
  test_pb_encode_bytes();
  test_pb_encode_nested();
  test_pb_encode_nested_overflow();
}
