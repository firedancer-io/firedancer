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
  uchar const expected[3] = { 0x08, 0x96, 0x01 };
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
  uchar const expected[] = {
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
  uchar const expected[] = {
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
  uchar const expected[] = {
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
  uchar const expected[] = {
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
  uchar const expected[] = {
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
  uchar const expected[] = {
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
test_pb_encode( void ) {
  test_pb_encode_doc_simple();
  test_pb_encode_doc_length_types();
  test_pb_encode_doc_embedded();
  test_pb_encode_doc_repeated();
  test_pb_encode_bool();
  test_pb_encode_int32();
  test_pb_encode_sint32();
}
