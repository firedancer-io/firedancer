#include "fd_der.h"
#include "../../util/fd_util.h"
#include <string.h>

static void
test_read_tl( void ) {
  FD_LOG_NOTICE(( "Testing fd_der_read_tl" ));

  /* Short-form length */
  {
    uchar buf[] = { 0x02, 0x03, 0xAA, 0xBB, 0xCC };
    fd_der_cursor_t c = { .p = buf, .end = buf + sizeof(buf) };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == 0 );
    FD_TEST( tag == 0x02 );
    FD_TEST( len == 3 );
    FD_TEST( c.p == buf + 2 );
  }

  /* Zero-length content */
  {
    uchar buf[] = { 0x05, 0x00 };  /* NULL */
    fd_der_cursor_t c = { .p = buf, .end = buf + sizeof(buf) };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == 0 );
    FD_TEST( tag == 0x05 );
    FD_TEST( len == 0 );
    FD_TEST( c.p == buf + 2 );
  }

  /* Multi-byte length (1 extra byte) */
  {
    uchar buf[132];
    buf[0] = 0x04;        /* OCTET STRING */
    buf[1] = 0x81;        /* 1 length byte follows */
    buf[2] = 0x80;        /* 128 bytes */
    memset( buf + 3, 0x42, 128 );
    fd_der_cursor_t c = { .p = buf, .end = buf + 131 };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == 0 );
    FD_TEST( tag == 0x04 );
    FD_TEST( len == 128 );
    FD_TEST( c.p == buf + 3 );
  }

  /* Multi-byte length (2 extra bytes) */
  {
    uchar big_buf[260];
    big_buf[0] = 0x30; big_buf[1] = 0x82; big_buf[2] = 0x01; big_buf[3] = 0x00;
    memset( big_buf + 4, 0, 256 );
    fd_der_cursor_t c = { .p = big_buf, .end = big_buf + 260 };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == 0 );
    FD_TEST( tag == 0x30 );
    FD_TEST( len == 256 );
    FD_TEST( c.p == big_buf + 4 );
  }

  /* Empty buffer */
  {
    fd_der_cursor_t c = { .p = NULL, .end = NULL };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == -1 );
  }

  /* Truncated: tag only, no length */
  {
    uchar buf[] = { 0x02 };
    fd_der_cursor_t c = { .p = buf, .end = buf + 1 };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == -1 );
  }

  /* Content exceeds buffer */
  {
    uchar buf[] = { 0x02, 0x05, 0xAA };  /* says 5 bytes but only 1 available */
    fd_der_cursor_t c = { .p = buf, .end = buf + 3 };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == -1 );
  }

  /* Invalid multi-byte length: 0 extra bytes (0x80 = indefinite, not valid in DER) */
  {
    uchar buf[] = { 0x30, 0x80 };
    fd_der_cursor_t c = { .p = buf, .end = buf + 2 };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == -1 );
  }

  /* Invalid multi-byte length: >4 extra bytes */
  {
    uchar buf[] = { 0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05 };
    fd_der_cursor_t c = { .p = buf, .end = buf + sizeof(buf) };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == -1 );
  }

  /* Truncated multi-byte length */
  {
    uchar buf[] = { 0x30, 0x82, 0x01 };  /* says 2 length bytes but only 1 */
    fd_der_cursor_t c = { .p = buf, .end = buf + 3 };
    int tag; ulong len;
    FD_TEST( fd_der_read_tl( &c, &tag, &len ) == -1 );
  }
}

/* Test fd_der_int_to_fixed *******************************************/

static void
test_int_to_fixed( void ) {
  FD_LOG_NOTICE(( "Testing fd_der_int_to_fixed" ));

  /* Normal: 32-byte integer, no padding */
  {
    uchar in[32]; memset( in, 0xAB, 32 );
    uchar out[32];
    FD_TEST( fd_der_int_to_fixed( in, 32, out, 32 ) == 0 );
    FD_TEST( 0 == memcmp( out, in, 32 ) );
  }

  /* Short integer: right-justified, zero-padded */
  {
    uchar in[] = { 0x01, 0x02 };
    uchar out[4];
    FD_TEST( fd_der_int_to_fixed( in, 2, out, 4 ) == 0 );
    uchar expected[] = { 0x00, 0x00, 0x01, 0x02 };
    FD_TEST( 0 == memcmp( out, expected, 4 ) );
  }

  /* 33 bytes with 0x00 prefix gives us 32 bytes */
  {
    uchar in[33]; in[0] = 0x00; memset( in + 1, 0xCD, 32 );
    uchar out[32];
    FD_TEST( fd_der_int_to_fixed( in, 33, out, 32 ) == 0 );
    FD_TEST( 0 == memcmp( out, in + 1, 32 ) );
  }

  /* Leading zero required but missing */
  {
    uchar in[33]; in[0] = 0x01; memset( in + 1, 0xCD, 32 );
    uchar out[32];
    FD_TEST( fd_der_int_to_fixed( in, 33, out, 32 ) == -1 );
  }

  /* Too long: 34 bytes for 32-byte output */
  {
    uchar in[34]; memset( in, 0x01, 34 );
    uchar out[32];
    FD_TEST( fd_der_int_to_fixed( in, 34, out, 32 ) == -1 );
  }

  /* Empty integer */
  {
    uchar out[32];
    FD_TEST( fd_der_int_to_fixed( (uchar const *)"", 0, out, 32 ) == -1 );
  }

  /* Single byte */
  {
    uchar in[] = { 0x42 };
    uchar out[32];
    FD_TEST( fd_der_int_to_fixed( in, 1, out, 32 ) == 0 );
    FD_TEST( out[31] == 0x42 );
    for( int i = 0; i < 31; i++ ) FD_TEST( out[i] == 0x00 );
  }
}

/* Parse SEQUENCE { INTEGER, INTEGER } and return r/s values */
static int
parse_two_ints( uchar const * buf, ulong buf_sz,
                uchar const ** r_ptr, ulong * r_len,
                uchar const ** s_ptr, ulong * s_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, *r_ptr, *r_len );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, *s_ptr, *s_len );
  FD_DER_LEAVE( c );
  return 0;
}

static void
test_enter_leave( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_ENTER / FD_DER_LEAVE" ));

  /* Valid SEQUENCE { INTEGER 0x01, INTEGER 0x02 } */
  {
    uchar buf[] = {
      0x30, 0x06,           /* SEQUENCE, len=6 */
      0x02, 0x01, 0x01,     /* INTEGER 1 */
      0x02, 0x01, 0x02,     /* INTEGER 2 */
    };
    uchar const * r; ulong r_len;
    uchar const * s; ulong s_len;
    FD_TEST( parse_two_ints( buf, sizeof(buf), &r, &r_len, &s, &s_len ) == 0 );
    FD_TEST( r_len == 1 && r[0] == 0x01 );
    FD_TEST( s_len == 1 && s[0] == 0x02 );
  }

  /* Wrong outer tag */
  {
    uchar buf[] = { 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    uchar const * r; ulong r_len; uchar const * s; ulong s_len;
    FD_TEST( parse_two_ints( buf, sizeof(buf), &r, &r_len, &s, &s_len ) == -1 );
  }

  /* Truncated: SEQUENCE says 6 bytes but only 4 available */
  {
    uchar buf[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02 };
    uchar const * r; ulong r_len; uchar const * s; ulong s_len;
    FD_TEST( parse_two_ints( buf, sizeof(buf), &r, &r_len, &s, &s_len ) == -1 );
  }

  /* Extra trailing data inside SEQUENCE (LEAVE checks exact consumption) */
  {
    uchar buf[] = {
      0x30, 0x07,           /* SEQUENCE, len=7 */
      0x02, 0x01, 0x01,     /* INTEGER 1 */
      0x02, 0x01, 0x02,     /* INTEGER 2 */
      0xFF,                 /* extra byte inside SEQUENCE */
    };
    uchar const * r; ulong r_len; uchar const * s; ulong s_len;
    FD_TEST( parse_two_ints( buf, sizeof(buf), &r, &r_len, &s, &s_len ) == -1 );
  }

  /* Empty buffer */
  {
    uchar const * r; ulong r_len; uchar const * s; ulong s_len;
    FD_TEST( parse_two_ints( (uchar const *)"", 0, &r, &r_len, &s, &s_len ) == -1 );
  }
}

/* Test FD_DER_SKIP / FD_DER_SKIP_IF */

static int
parse_skip_optional_then_int( uchar const * buf, ulong buf_sz,
                              uchar const ** val, ulong * val_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );
    FD_DER_SKIP_IF( c, FD_DER_TAG_CONTEXT(0) );  /* optional [0] */
    FD_DER_READ( c, FD_DER_TAG_INTEGER, *val, *val_len );
  FD_DER_LEAVE( c );
  return 0;
}

static void
test_skip( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_SKIP / FD_DER_SKIP_IF" ));

  /* With optional [0] present */
  {
    uchar buf[] = {
      0x30, 0x08,
      0xA0, 0x03, 0x02, 0x01, 0x03,  /* [0] EXPLICIT { INTEGER 3 } */
      0x02, 0x01, 0x42,              /* INTEGER 0x42 */
    };
    uchar const * val; ulong val_len;
    FD_TEST( parse_skip_optional_then_int( buf, sizeof(buf), &val, &val_len ) == 0 );
    FD_TEST( val_len == 1 && val[0] == 0x42 );
  }

  /* Without optional [0] */
  {
    uchar buf[] = {
      0x30, 0x03,
      0x02, 0x01, 0x42,
    };
    uchar const * val; ulong val_len;
    FD_TEST( parse_skip_optional_then_int( buf, sizeof(buf), &val, &val_len ) == 0 );
    FD_TEST( val_len == 1 && val[0] == 0x42 );
  }
}

/* Test FD_DER_READ_BITS */

static int
parse_bit_string( uchar const * buf, ulong buf_sz,
                  uchar const ** bits, ulong * bits_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_READ_BITS( c, *bits, *bits_len );
  return 0;
}

static void
test_read_bits( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_READ_BITS" ));

  /* Valid BIT STRING with 0 unused bits */
  {
    uchar buf[] = { 0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    uchar const * bits; ulong bits_len;
    FD_TEST( parse_bit_string( buf, sizeof(buf), &bits, &bits_len ) == 0 );
    FD_TEST( bits_len == 4 );
    FD_TEST( bits[0] == 0xDE && bits[3] == 0xEF );
  }

  /* BIT STRING with non-zero unused bits (rejected) */
  {
    uchar buf[] = { 0x03, 0x03, 0x04, 0xDE, 0xAD };
    uchar const * bits; ulong bits_len;
    FD_TEST( parse_bit_string( buf, sizeof(buf), &bits, &bits_len ) == -1 );
  }

  /* Empty BIT STRING (just unused-bits byte) */
  {
    uchar buf[] = { 0x03, 0x01, 0x00 };
    uchar const * bits; ulong bits_len;
    FD_TEST( parse_bit_string( buf, sizeof(buf), &bits, &bits_len ) == 0 );
    FD_TEST( bits_len == 0 );
  }

  /* Zero-length BIT STRING which has no unused-bits byte. */
  {
    uchar buf[] = { 0x03, 0x00 };
    uchar const * bits; ulong bits_len;
    FD_TEST( parse_bit_string( buf, sizeof(buf), &bits, &bits_len ) == -1 );
  }
}

/* Test FD_DER_READ_RAW */

static int
parse_raw_sequence( uchar const * buf, ulong buf_sz,
                    uchar const ** raw_ptr, ulong * raw_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_READ_RAW( c, FD_DER_TAG_SEQUENCE, *raw_ptr, *raw_len );
  return 0;
}

static void
test_read_raw( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_READ_RAW" ));

  uchar buf[] = {
    0x30, 0x03, 0x01, 0x02, 0x03,   /* SEQUENCE { 01 02 03 } */
  };
  uchar const * raw_ptr; ulong raw_len;
  FD_TEST( parse_raw_sequence( buf, sizeof(buf),
                               &raw_ptr, &raw_len ) == 0 );
  FD_TEST( raw_ptr == buf );
  FD_TEST( raw_len == 5 );
}

/* Test FD_DER_READ_TIME */

static int
parse_time( uchar const * buf, ulong buf_sz,
            uchar const ** t_ptr, ulong * t_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_READ_TIME( c, *t_ptr, *t_len );
  return 0;
}

static void
test_read_time( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_READ_TIME" ));

  /* UTCTime */
  {
    uchar buf[] = { 0x17, 0x0D, '2', '5', '0', '1', '0', '1',
                    '0', '0', '0', '0', '0', '0', 'Z' };
    uchar const * t; ulong t_len;
    FD_TEST( parse_time( buf, sizeof(buf), &t, &t_len ) == 0 );
    FD_TEST( t_len == 13 );
  }

  /* GeneralizedTime */
  {
    uchar buf[] = { 0x18, 0x0F, '2', '0', '2', '5', '0', '1', '0', '1',
                    '0', '0', '0', '0', '0', '0', 'Z' };
    uchar const * t; ulong t_len;
    FD_TEST( parse_time( buf, sizeof(buf), &t, &t_len ) == 0 );
    FD_TEST( t_len == 15 );
  }

  /* Wrong tag (INTEGER instead of time) */
  {
    uchar buf[] = { 0x02, 0x01, 0x00 };
    uchar const * t; ulong t_len;
    FD_TEST( parse_time( buf, sizeof(buf), &t, &t_len ) == -1 );
  }
}

/* Test FD_DER_PEEK_TAG / FD_DER_PEEK_TAG_OR */

static int
parse_peek( uchar const * buf, ulong buf_sz, int * out_tag ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_PEEK_TAG( c, *out_tag );
  return 0;
}

static void
test_peek( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_PEEK_TAG / FD_DER_PEEK_TAG_OR" ));

  /* Normal peek */
  {
    uchar buf[] = { 0x30, 0x00 };
    int tag;
    FD_TEST( parse_peek( buf, sizeof(buf), &tag ) == 0 );
    FD_TEST( tag == 0x30 );
  }

  /* Peek on empty cursor fails */
  {
    int tag;
    FD_TEST( parse_peek( (uchar const *)"", 0, &tag ) == -1 );
  }

  /* PEEK_TAG_OR with default */
  {
    uchar buf[] = { 0x02 };
    fd_der_cursor_t c = { .p = buf, .end = buf + 1 };
    int tag;
    FD_DER_PEEK_TAG_OR( c, tag, 0xFF );
    FD_TEST( tag == 0x02 );

    fd_der_cursor_t c2 = { .p = buf, .end = buf };  /* empty */
    FD_DER_PEEK_TAG_OR( c2, tag, 0xFF );
    FD_TEST( tag == 0xFF );
  }
}

/* Test nested ENTER/LEAVE (2 levels deep) */

static int
parse_nested( uchar const * buf, ulong buf_sz,
              uchar const ** val, ulong * val_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );         /* outer */
    FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );        /* inner */
      FD_DER_READ( c, FD_DER_TAG_INTEGER, *val, *val_len );
    FD_DER_LEAVE( c );
  FD_DER_LEAVE( c );
  return 0;
}

static void
test_nested( void ) {
  FD_LOG_NOTICE(( "Testing nested FD_DER_ENTER / FD_DER_LEAVE" ));

  uchar buf[] = {
    0x30, 0x05,             /* outer SEQUENCE */
    0x30, 0x03,             /* inner SEQUENCE */
    0x02, 0x01, 0x42,       /* INTEGER 0x42 */
  };
  uchar const * val; ulong val_len;
  FD_TEST( parse_nested( buf, sizeof(buf), &val, &val_len ) == 0 );
  FD_TEST( val_len == 1 && val[0] == 0x42 );
}

/* Test LEAVE_RELAXED */

static int
parse_relaxed( uchar const * buf, ulong buf_sz,
               uchar const ** val, ulong * val_len ) {
  FD_DER_CURSOR_FROM_BUF( c, buf, buf_sz );
  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, *val, *val_len );
  FD_DER_LEAVE_RELAXED( c );  /* ignore trailing data inside SEQUENCE */
  return 0;
}

static void
test_leave_relaxed( void ) {
  FD_LOG_NOTICE(( "Testing FD_DER_LEAVE_RELAXED" ));

  uchar buf[] = {
    0x30, 0x06,
    0x02, 0x01, 0x42,       /* INTEGER 0x42 */
    0x02, 0x01, 0x99,       /* extra INTEGER ignored by relax. */
  };
  uchar const * val; ulong val_len;
  FD_TEST( parse_relaxed( buf, sizeof(buf), &val, &val_len ) == 0 );
  FD_TEST( val_len == 1 && val[0] == 0x42 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_read_tl();
  test_int_to_fixed();
  test_enter_leave();
  test_skip();
  test_read_bits();
  test_read_raw();
  test_read_time();
  test_peek();
  test_nested();
  test_leave_relaxed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
