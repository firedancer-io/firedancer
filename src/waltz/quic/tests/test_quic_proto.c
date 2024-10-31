#include "../fd_quic_common.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "../templ/fd_quic_parse_util.h"

/* Test the varint parser generator */

void
test_varint_min_sz( void ) {
  for( ulong j=0UL; j<0x40UL; j++ ) {
    FD_TEST( fd_quic_varint_min_sz( j )==1UL );
  }
  for( ulong j=0x40UL; j<0x4000UL; j++ ) {
    FD_TEST( fd_quic_varint_min_sz( j )==2UL );
  }
  for( ulong j=0x4000UL; j<0x40000000UL; j++ ) {
    FD_TEST( fd_quic_varint_min_sz( j )==4UL );
  }
  for( ulong j=0x40000000UL; j<0x50000000UL; j++ ) {
    FD_TEST( fd_quic_varint_min_sz( j )==8UL );
  }
  for( ulong j=0x3fffffff00000000UL; j<=0x3fffffffffffffffUL; j++ ) {
    FD_TEST( fd_quic_varint_min_sz( j )==8UL );
  }
  /* out of bounds cases */
  FD_TEST( fd_quic_varint_min_sz( 0x40000000000000UL )==8UL );
  FD_TEST( fd_quic_varint_min_sz( 0x80000000000000UL )==8UL );
  FD_TEST( fd_quic_varint_min_sz( 0xffffffffffffffUL )==8UL );
}

#define VARINT_TEST()                    \
  FD_TEMPL_DEF_STRUCT_BEGIN(varint_test) \
    FD_TEMPL_MBR_ELEM_VARINT( i, ulong ) \
  FD_TEMPL_DEF_STRUCT_END(varint_test)

#include "../templ/fd_quic_defs.h"
VARINT_TEST()
#include "../templ/fd_quic_undefs.h"

#include "../templ/fd_quic_encoders.h"
VARINT_TEST()
#include "../templ/fd_quic_undefs.h"

#include "../templ/fd_quic_parsers.h"
VARINT_TEST()
#include "../templ/fd_quic_undefs.h"

#undef VARINT_TEST

static void
test_varint_encode( void ) {
  uchar buf[8];
  fd_quic_varint_test_t v = {0};
  for( ulong j=0; j<=7; j++ ) {
    FD_TEST( fd_quic_encode_varint_test( buf, j, &v )==FD_QUIC_ENCODE_FAIL );
  }

  v.i = 0UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==1UL );
  FD_TEST( buf[0]==0x00 );

  v.i = 1UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==1UL );
  FD_TEST( buf[0]==0x01 );

  v.i = 63UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==1UL );
  FD_TEST( buf[0]==0x3f );

  v.i = 64UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==2UL );
  FD_LOG_HEXDUMP_NOTICE(( "buf", buf, 2 ));
  FD_TEST( buf[0]==0x40 && buf[1]==0x40 );

  v.i = 0x3fffUL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==2UL );
  FD_TEST( buf[0]==0x7f && buf[1]==0xff );

  v.i = 0x4000UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==4UL );
  FD_TEST( buf[0]==0x80 && buf[1]==0x00 && buf[2]==0x40 && buf[3]==0x00 );

  v.i = 0x807060;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==4UL );
  FD_TEST( buf[0]==0x80 && buf[1]==0x80 && buf[2]==0x70 && buf[3]==0x60 );

  v.i = 0x3fffffff;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==4UL );
  FD_TEST( buf[0]==0xbf && buf[1]==0xff && buf[2]==0xff && buf[3]==0xff );

  v.i = 0x40000000;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xc0 && buf[1]==0x00 && buf[2]==0x00 && buf[3]==0x00 &&
           buf[4]==0x40 && buf[5]==0x00 && buf[6]==0x00 && buf[7]==0x00 );

  v.i = 0x0001020304050607UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xc0 && buf[1]==0x01 && buf[2]==0x02 && buf[3]==0x03 &&
           buf[4]==0x04 && buf[5]==0x05 && buf[6]==0x06 && buf[7]==0x07 );

  v.i = 0x2fffffffffffffffUL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xef && buf[1]==0xff && buf[2]==0xff && buf[3]==0xff &&
           buf[4]==0xff && buf[5]==0xff && buf[6]==0xff && buf[7]==0xff );

  v.i = 0x3fffffffffffffffUL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xff && buf[1]==0xff && buf[2]==0xff && buf[3]==0xff &&
           buf[4]==0xff && buf[5]==0xff && buf[6]==0xff && buf[7]==0xff );

  /* Truncate oversize numbers */
  v.i = 0x4000000000000000UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xc0 && buf[1]==0x00 && buf[2]==0x00 && buf[3]==0x00 &&
           buf[4]==0x00 && buf[5]==0x00 && buf[6]==0x00 && buf[7]==0x00 );

  v.i = 0x8000000000000000UL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xc0 && buf[1]==0x00 && buf[2]==0x00 && buf[3]==0x00 &&
           buf[4]==0x00 && buf[5]==0x00 && buf[6]==0x00 && buf[7]==0x00 );

  v.i = 0xffffffffffffffffUL;
  FD_TEST( fd_quic_encode_varint_test( buf, sizeof(buf), &v )==8UL );
  FD_TEST( buf[0]==0xff && buf[1]==0xff && buf[2]==0xff && buf[3]==0xff &&
           buf[4]==0xff && buf[5]==0xff && buf[6]==0xff && buf[7]==0xff );
}

static void
test_varint_parse( void ) {
  fd_quic_varint_test_t v = {0};
  FD_TEST( fd_quic_decode_varint_test( &v, NULL, 0UL )==FD_QUIC_PARSE_FAIL );

  do {
    uchar buf[1] = {0x00};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 1UL )==1UL );
    FD_TEST( v.i==0UL );
  } while(0);

  do {
    uchar buf[1] = {0x01};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 1UL )==1UL );
    FD_TEST( v.i==1UL );
  } while(0);

  do {
    uchar buf[1] = {0x3f};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 1UL )==1UL );
    FD_TEST( v.i==63UL );
  } while(0);

  do {
    uchar buf[1] = {0x40};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 1UL )==FD_QUIC_PARSE_FAIL );
  } while(0);

  do {
    uchar buf[2] = {0x40, 0x00};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 2UL )==2UL );
    FD_TEST( v.i==0UL );
  } while(0);

  do {
    uchar buf[2] = {0x40, 0x40};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 2UL )==2UL );
    FD_TEST( v.i==64UL );
  } while(0);

  do {
    uchar buf[2] = {0x7f, 0xff};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 2UL )==2UL );
    FD_TEST( v.i==0x3fffUL );
  } while(0);

  do {
    uchar buf[2] = {0x80, 0x00};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 2UL )==FD_QUIC_PARSE_FAIL );
  } while(0);

  do {
    uchar buf[4] = {0x80, 0x00, 0x00, 0x00};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 3UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 4UL )==4UL );
    FD_TEST( v.i==0 );
  } while(0);

  do {
    uchar buf[4] = {0x80, 0x80, 0x70, 0x60};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 3UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 4UL )==4UL );
    FD_TEST( v.i==0x00807060 );
  } while(0);

  do {
    uchar buf[4] = {0xbf, 0xff, 0xff, 0xff};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 4UL )==4UL );
    FD_TEST( v.i==0x3fffffff );
  } while(0);

  do {
    uchar buf[4] = {0xc0, 0x00, 0x00, 0x00};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 4UL )==FD_QUIC_PARSE_FAIL );
  } while(0);

  do {
    uchar buf[8] = {0xc0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 1UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 2UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 3UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 4UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 5UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 6UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 7UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 8UL )==8UL );
    FD_TEST( v.i==0x0001020304050607UL );
  } while(0);

  do {
    uchar buf[8] = {0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 8UL )==8UL );
    FD_TEST( v.i==0x2fffffffffffffffUL );
  } while(0);

  do {
    uchar buf[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    FD_TEST( fd_quic_decode_varint_test( &v, buf, 8UL )==8UL );
    FD_TEST( v.i==0x3fffffffffffffffUL );
  } while(0);
}

/* Test packet number handling */

void
test_pktnum_parse( void ) {
  uchar buf[4] = {0x01, 0x02, 0x03, 0x04}; /* big endian */
  FD_TEST( fd_quic_pktnum_decode( buf, 1UL )==      0x01 );
  FD_TEST( fd_quic_pktnum_decode( buf, 2UL )==    0x0102 );
  FD_TEST( fd_quic_pktnum_decode( buf, 3UL )==  0x010203 );
  FD_TEST( fd_quic_pktnum_decode( buf, 4UL )==0x01020304 );
}

/* Test crypto frame parser */

uchar raw_crypto_frame[] =
"\x06\x00\x41\x79\x01\x00\x01\x75\x03\x03\x6f\x2d\xa1\x28\xdd\x7e"
"\xff\xa9\x8c\x1c\xe4\x84\x55\x04\xa2\xcc\xc6\x35\x46\xfa\xfa\xfa"
"\x47\xa3\xf7\xff\x2a\xaa\x7f\xa4\x28\x0b\x00\x00\x06\x13\x02\x13"
"\x01\x13\x03\x01\x00\x01\x46\x00\x33\x00\xa7\x00\xa5\x00\x17\x00"
"\x41\x04\x6d\x7d\xad\xed\xf2\x09\x94\x79\x7a\xe9\x3c\xce\x69\x55"
"\xc0\xca\x94\xd7\x0c\xbe\x06\xd3\x35\x2c\xfa\x09\xda\x7e\xd7\x8e"
"\xda\x0b\x99\xb4\x31\xba\x1e\x52\x9c\x9c\xaf\xc5\x16\xcb\x7d\xb5"
"\xf5\x14\x3f\xaf\x26\x3e\x0a\x0d\x85\x54\x9f\x64\x38\x75\x12\xe7"
"\x23\xad\x00\x1d\x00\x20\x0f\x3d\x20\xaa\x73\x05\xad\x27\x77\x35"
"\xa3\xd8\xe2\x34\xf4\xab\x55\x06\xb9\x1e\x3e\xaf\x5b\x6d\x48\x6b"
"\x6b\x16\xde\x4b\x50\x7a\x00\x1e\x00\x38\x16\xe8\xe2\x5d\x14\x8d"
"\x2c\x81\xc4\x42\xf7\x3e\x6e\x55\x6b\x94\xf3\x5e\x91\x5b\xcf\xe8"
"\x31\x21\x2b\xb5\xef\x50\x51\xca\xf0\xa8\x36\xe3\xd0\xf3\xfe\x3a"
"\xda\xab\x58\xc0\xca\x33\xb2\xd8\x99\x6f\xfc\x87\x92\x1c\xc6\xce"
"\x86\x2a\x00\x2b\x00\x03\x02\x03\x04\x00\x0d\x00\x0e\x00\x0c\x08"
"\x04\x04\x03\x04\x01\x02\x01\x08\x07\x08\x08\x00\x0a\x00\x08\x00"
"\x06\x00\x17\x00\x1d\x00\x1e\x00\x2d\x00\x02\x01\x01\x00\x00\x00"
"\x0e\x00\x0c\x00\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00"
"\x10\x00\x1d\x00\x1b\x02\x68\x33\x05\x68\x33\x2d\x33\x32\x05\x68"
"\x33\x2d\x33\x31\x05\x68\x33\x2d\x33\x30\x05\x68\x33\x2d\x32\x39"
"\x00\x39\x00\x39\x01\x04\x80\x00\xea\x60\x04\x04\x80\x10\x00\x00"
"\x05\x04\x80\x10\x00\x00\x06\x04\x80\x10\x00\x00\x07\x04\x80\x10"
"\x00\x00\x08\x02\x40\x80\x09\x02\x40\x80\x0a\x01\x03\x0b\x01\x19"
"\x0e\x01\x08\x0f\x08\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";

void
test_crypto_frame( void ) {
  fd_quic_common_frag_t common_frag[1];
  fd_quic_crypto_frame_t crypto_frame[1];

  uchar * cur_ptr = raw_crypto_frame;
  ulong  cur_sz  = sizeof( raw_crypto_frame ) - 1; /* account for NUL byte */

  ulong rc = fd_quic_decode_common_frag( common_frag, cur_ptr, cur_sz );
  FD_TEST( rc!=FD_QUIC_PARSE_FAIL );

  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_crypto_frame( crypto_frame, cur_ptr, cur_sz );
  FD_TEST( rc!=FD_QUIC_PARSE_FAIL );

  FD_LOG_INFO(( "parsed crypto_frame" ));
  fd_quic_dump_struct_common_frag( common_frag );
  fd_quic_dump_struct_crypto_frame( crypto_frame );

  /* check footprints */
  FD_LOG_INFO(( "crypto_frame footprint: %lu",
                (ulong)fd_quic_encode_footprint_crypto_frame( crypto_frame ) ));

  /* adjust and try again */
  crypto_frame->length -= 100;
  FD_LOG_INFO(( "crypto_frame after subtracting 100 in length:" ));
  FD_LOG_INFO(( "crypto_frame footprint: %lu",
                (ulong)fd_quic_encode_footprint_crypto_frame( crypto_frame ) ));

  crypto_frame->length += 100;

  /* now try encoding */
  uchar buf[4096];

  rc = fd_quic_encode_crypto_frame( buf, sizeof( buf ), crypto_frame );
  FD_TEST( rc!=FD_QUIC_PARSE_FAIL );

  FD_LOG_HEXDUMP_INFO(( "encoded", buf, rc ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_varint_min_sz();
  test_varint_encode();
  test_varint_parse();
  test_pktnum_parse();
  test_crypto_frame();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

