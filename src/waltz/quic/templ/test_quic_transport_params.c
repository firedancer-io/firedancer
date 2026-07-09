#include "../../../util/fd_util.h"
#include "../fd_quic_conn_id.h"
#include "../fd_quic_enum.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "fd_quic_transport_params.h"

static int
preferred_address_equal( fd_quic_preferred_address_t const * p1,
                         fd_quic_preferred_address_t const * p2 ) {
  return
    ( 0==memcmp( p1->ipv4_address, p2->ipv4_address, sizeof(p1->ipv4_address) ) ) &
    (            p1->ipv4_port   ==p2->ipv4_port                                ) &
    ( 0==memcmp( p1->ipv6_address, p2->ipv6_address, sizeof(p1->ipv6_address) ) ) &
    (            p1->ipv6_port   ==p2->ipv6_port                                ) &
    (            p1->conn_id_len ==p2->conn_id_len                              ) &
    ( 0==memcmp( p1->conn_id,      p2->conn_id,      p1->conn_id_len          ) ) &
    ( 0==memcmp( p1->reset_token,  p2->reset_token,  sizeof(p1->reset_token)  ) );
}

static void
test_preferred_address( void ) {

  fd_quic_preferred_address_t preferred_address = {
    .ipv4_address = { 0x01, 0x02, 0x03, 0x04 },
    .ipv4_port    = 0x0506,
    .ipv6_address = { 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                      0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
    .ipv6_port    = 0x1718,
    .conn_id_len  = 20,
    .conn_id      = { 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                      0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                      0x27, 0x28, 0x29, 0x2a },
    .reset_token  = { 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
                      0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a }
  };
  uchar encoded[ FD_QUIC_PREFERRED_ADDRESS_SZ_MAX ];

  ulong encoded_sz = fd_quic_encode_preferred_address( encoded, sizeof(encoded), &preferred_address );
  FD_TEST( encoded_sz == FD_QUIC_PREFERRED_ADDRESS_SZ_MAX );

  static uchar expected_0[61] = {
    /* ipv4_address */
    0x01, 0x02, 0x03, 0x04,
    /* ipv4_port */
    0x05, 0x06,
    /* ipv6_address */
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    /* ipv6_port */
    0x17, 0x18,
    /* conn_id_len */
    20,
    /* conn_id */
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x28, 0x29, 0x2a,
    /* reset_token */
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a
  };
  FD_TEST( encoded_sz==sizeof(expected_0) && 0==memcmp( encoded, expected_0, sizeof(expected_0) ) );

  fd_quic_preferred_address_t decoded;
  FD_TEST( fd_quic_decode_preferred_address( &decoded, encoded, encoded_sz )==encoded_sz );
  FD_TEST( preferred_address_equal( &decoded, &preferred_address ) );

  preferred_address.conn_id_len = 0;
  encoded_sz = fd_quic_encode_preferred_address( encoded, sizeof(encoded), &preferred_address );
  FD_TEST( encoded_sz!=FD_QUIC_ENCODE_FAIL );

  static uchar expected_1[41] = {
    /* ipv4_address */
    0x01, 0x02, 0x03, 0x04,
    /* ipv4_port */
    0x05, 0x06,
    /* ipv6_address */
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    /* ipv6_port */
    0x17, 0x18,
    /* conn_id_len */
    0,
    /* reset_token */
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a
  };
  FD_TEST( encoded_sz==sizeof(expected_1) && 0==memcmp( encoded, expected_1, sizeof(expected_1) ) );
  FD_TEST( fd_quic_decode_preferred_address( &decoded, encoded, encoded_sz )==encoded_sz );
  FD_TEST( preferred_address_equal( &decoded, &preferred_address ) );

}

/* test_max_size crafts the largest possible transport parameter object.
   Use every single option and fill in the largest possible value. */

static void
test_max_size( void ) {

  fd_quic_transport_params_t params = {
    /* 0x00 */
    .original_destination_connection_id_present = 1,
    .original_destination_connection_id_len     = FD_QUIC_MAX_CONN_ID_SZ,

    /* 0x01 */
    .max_idle_timeout_ms_present = 1,
    .max_idle_timeout_ms         = (1UL<<62)-1,

    /* 0x02 */
    .stateless_reset_token_present = 1,
    .stateless_reset_token_len     = 16,

    /* 0x03 */
    .max_udp_payload_size_present = 1,
    .max_udp_payload_size         = 65527, /* theoretically up to 2^62-1, but not semantically valid */

    /* 0x04 */
    .initial_max_data_present                    = 1,
    .initial_max_data                            = (1UL<<62)-1,
    /* 0x05 */
    .initial_max_stream_data_bidi_local_present  = 1,
    .initial_max_stream_data_bidi_local          = (1UL<<62)-1,
    /* 0x06 */
    .initial_max_stream_data_bidi_remote_present = 1,
    .initial_max_stream_data_bidi_remote         = (1UL<<62)-1,
    /* 0x07 */
    .initial_max_stream_data_uni_present         = 1,
    .initial_max_stream_data_uni                 = (1UL<<62)-1,
    /* 0x08 */
    .initial_max_streams_bidi_present            = 1,
    .initial_max_streams_bidi                    = (1UL<<60), /* theoretically up to 2^62-1, but not valid */
    /* 0x09 */
    .initial_max_streams_uni_present             = 1,
    .initial_max_streams_uni                     = (1UL<<60), /* theoretically up to 2^62-1, but not valid */

    /* 0x0a */
    .ack_delay_exponent_present = 1,
    .ack_delay_exponent         = 20,

    /* 0x0b */
    .max_ack_delay_present = 1,
    .max_ack_delay         = (1UL<<14)-1,

    /* 0x0c */
    .disable_active_migration_present = 1,

    /* 0x0d */
    .preferred_address_present = 1,
    .preferred_address_len     = FD_QUIC_PREFERRED_ADDRESS_SZ_MAX,

    /* 0x0e */
    .active_connection_id_limit_present = 1,
    .active_connection_id_limit         = (1UL<<62)-1,

    /* 0x0f */
    .initial_source_connection_id_present = 1,
    .initial_source_connection_id_len     = FD_QUIC_MAX_CONN_ID_SZ,

    /* 0x10 */
    .retry_source_connection_id_present = 1,
    .retry_source_connection_id_len     = FD_QUIC_MAX_CONN_ID_SZ
  };

  uchar buf[4096];
  ulong sz = fd_quic_encode_transport_params( buf, sizeof(buf), &params );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  FD_LOG_NOTICE(( "Largest RFC 9000 transport parameter blob: %lu bytes", sz ));

}

/* test_grease ensures that the decoder skips unknown transport params.

   RFC 9000 Section 7.4.2. New Transport Parameters:
   > New transport parameters can be used to negotiate new protocol
   > behavior. An endpoint MUST ignore transport parameters that it does
   > not support. */

static void
test_grease( void ) {

  static uchar const unknown_params[] = {
    /* Unknown transport param */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ID */
    0x40, 0x00, /* length (64 bytes) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    /* Known zero length param */
    0x0c, 0x00
  };

  fd_quic_transport_params_t params = {0};
  FD_TEST(  0==fd_quic_decode_transport_params( &params, unknown_params, sizeof(unknown_params)-2 ) );
  FD_TEST( -1==fd_quic_decode_transport_params( &params, unknown_params, sizeof(unknown_params)-1 ) );
  FD_TEST( params.disable_active_migration_present==0 );
  FD_TEST(  0==fd_quic_decode_transport_params( &params, unknown_params, sizeof(unknown_params)   ) );
  FD_TEST( params.disable_active_migration_present==1 );

}

/* Test Case 1: Valid max_idle_timeout values */
static void
test_max_idle_timeout_valid( void ) {
  FD_LOG_NOTICE(( "test_max_idle_timeout_valid" ));

  fd_quic_transport_params_t params_in[1];
  fd_quic_transport_params_t params_out[1];
  uchar buf[512];

  /* Test valid values: 0, 1, typical value, max */
  ulong test_values[] = { 0UL, 1UL, 30000UL, FD_QUIC_VARINT_MAX };

  for( ulong i = 0; i < sizeof(test_values) / sizeof(test_values[0]); i++ ) {
    fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
    params_in->max_idle_timeout_ms = test_values[i];
    params_in->max_idle_timeout_ms_present = 1;

    ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
    FD_TEST( len != FD_QUIC_ENCODE_FAIL );

    fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
    int ret = fd_quic_decode_transport_params( params_out, buf, len );
    FD_TEST( ret == 0 );
    FD_TEST( params_out->max_idle_timeout_ms_present == 1 );
    FD_TEST( params_out->max_idle_timeout_ms == test_values[i] );
  }
}

/* Test Case 2: Valid and invalid max_udp_payload_size values */
static void
test_max_udp_payload_size_bounds( void ) {
  FD_LOG_NOTICE(( "test_max_udp_payload_size_bounds" ));

  fd_quic_transport_params_t params_in[1];
  fd_quic_transport_params_t params_out[1];
  uchar buf[512];

  /* Test valid minimum value (1200) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_udp_payload_size = 1200UL;
  params_in->max_udp_payload_size_present = 1;
  ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  int ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->max_udp_payload_size_present == 1 );
  FD_TEST( params_out->max_udp_payload_size == 1200UL );

  /* Test valid typical value (65527) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_udp_payload_size = 65527UL;
  params_in->max_udp_payload_size_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->max_udp_payload_size_present == 1 );
  FD_TEST( params_out->max_udp_payload_size == 65527UL );

  /* Test invalid value below minimum (1199) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_udp_payload_size = 1199UL;
  params_in->max_udp_payload_size_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */

  /* Test invalid value (0) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_udp_payload_size = 0UL;
  params_in->max_udp_payload_size_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */
}

/* Test Case 3: ack_delay_exponent bounds (max 20) */
static void
test_ack_delay_exponent_bounds( void ) {
  FD_LOG_NOTICE(( "test_ack_delay_exponent_bounds" ));

  fd_quic_transport_params_t params_in[1];
  fd_quic_transport_params_t params_out[1];
  uchar buf[512];

  /* Test valid values 0-20 */
  for( ulong value = 0; value <= 20; value++ ) {
    fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
    params_in->ack_delay_exponent = value;
    params_in->ack_delay_exponent_present = 1;
    ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
    FD_TEST( len != FD_QUIC_ENCODE_FAIL );
    fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
    int ret = fd_quic_decode_transport_params( params_out, buf, len );
    FD_TEST( ret == 0 );
    FD_TEST( params_out->ack_delay_exponent_present == 1 );
    FD_TEST( params_out->ack_delay_exponent == value );
  }

  /* Test invalid value (21) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->ack_delay_exponent = 21UL;
  params_in->ack_delay_exponent_present = 1;
  ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  int ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */

  /* Test invalid value (100) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->ack_delay_exponent = 100UL;
  params_in->ack_delay_exponent_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */
}

/* Test Case 4: max_ack_delay bounds (max 2^14-1 = 16383) */
static void
test_max_ack_delay_bounds( void ) {
  FD_LOG_NOTICE(( "test_max_ack_delay_bounds" ));

  fd_quic_transport_params_t params_in[1];
  fd_quic_transport_params_t params_out[1];
  uchar buf[512];

  /* Test valid minimum value (0) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_ack_delay = 0UL;
  params_in->max_ack_delay_present = 1;
  ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  int ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->max_ack_delay_present == 1 );
  FD_TEST( params_out->max_ack_delay == 0UL );

  /* Test valid typical value (25) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_ack_delay = 25UL;
  params_in->max_ack_delay_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->max_ack_delay_present == 1 );
  FD_TEST( params_out->max_ack_delay == 25UL );

  /* Test valid maximum value (16383) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_ack_delay = 16383UL;
  params_in->max_ack_delay_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->max_ack_delay_present == 1 );
  FD_TEST( params_out->max_ack_delay == 16383UL );

  /* Test invalid value (16384 = 2^14) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_ack_delay = 16384UL;
  params_in->max_ack_delay_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */

  /* Test invalid value (1000000) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->max_ack_delay = 1000000UL;
  params_in->max_ack_delay_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */
}

/* Test Case 5: Stream count bounds (max 2^60-1) */
static void
test_stream_count_bounds( void ) {
  FD_LOG_NOTICE(( "test_stream_count_bounds" ));

  fd_quic_transport_params_t params_in[1];
  fd_quic_transport_params_t params_out[1];
  uchar buf[512];

  /* Test initial_max_streams_bidi with valid values */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->initial_max_streams_bidi = 0UL;
  params_in->initial_max_streams_bidi_present = 1;
  ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  int ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->initial_max_streams_bidi_present == 1 );
  FD_TEST( params_out->initial_max_streams_bidi == 0UL );

  /* Test with typical value */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->initial_max_streams_bidi = 100UL;
  params_in->initial_max_streams_bidi_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->initial_max_streams_bidi_present == 1 );
  FD_TEST( params_out->initial_max_streams_bidi == 100UL );

  /* Test with maximum valid value (2^60) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  ulong max_stream_count = FD_QUIC_STREAM_COUNT_MAX;
  params_in->initial_max_streams_bidi = max_stream_count;
  params_in->initial_max_streams_bidi_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->initial_max_streams_bidi_present == 1 );
  FD_TEST( params_out->initial_max_streams_bidi == max_stream_count );

  /* Test with invalid value (2^60 + 1) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  ulong invalid_stream_count = FD_QUIC_STREAM_COUNT_MAX + 1;
  params_in->initial_max_streams_bidi = invalid_stream_count;
  params_in->initial_max_streams_bidi_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */

  /* Test initial_max_streams_uni with valid value */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->initial_max_streams_uni = 100UL;
  params_in->initial_max_streams_uni_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->initial_max_streams_uni_present == 1 );
  FD_TEST( params_out->initial_max_streams_uni == 100UL );

  /* Test initial_max_streams_uni with invalid value (2^61) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  ulong very_large_count = (1UL << 61);
  params_in->initial_max_streams_uni = very_large_count;
  params_in->initial_max_streams_uni_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */
}

/* Test Case 6: active_connection_id_limit bounds (min 2) */
static void
test_active_connection_id_limit_bounds( void ) {
  FD_LOG_NOTICE(( "test_active_connection_id_limit_bounds" ));

  fd_quic_transport_params_t params_in[1];
  fd_quic_transport_params_t params_out[1];
  uchar buf[512];

  /* Test valid minimum value (2) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->active_connection_id_limit = 2UL;
  params_in->active_connection_id_limit_present = 1;
  ulong len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  int ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->active_connection_id_limit_present == 1 );
  FD_TEST( params_out->active_connection_id_limit == 2UL );

  /* Test valid typical value (8) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->active_connection_id_limit = 8UL;
  params_in->active_connection_id_limit_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == 0 );
  FD_TEST( params_out->active_connection_id_limit_present == 1 );
  FD_TEST( params_out->active_connection_id_limit == 8UL );

  /* Test invalid value below minimum (0) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->active_connection_id_limit = 0UL;
  params_in->active_connection_id_limit_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */

  /* Test invalid value (1) */
  fd_memset( params_in, 0, sizeof(fd_quic_transport_params_t) );
  params_in->active_connection_id_limit = 1UL;
  params_in->active_connection_id_limit_present = 1;
  len = fd_quic_encode_transport_params( buf, sizeof(buf), params_in );
  FD_TEST( len != FD_QUIC_ENCODE_FAIL );
  fd_memset( params_out, 0, sizeof(fd_quic_transport_params_t) );
  ret = fd_quic_decode_transport_params( params_out, buf, len );
  FD_TEST( ret == -1 );  /* bounds check failure in decoder */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_preferred_address();
  test_max_size();
  test_grease();
  test_max_idle_timeout_valid();
  test_max_udp_payload_size_bounds();
  test_ack_delay_exponent_bounds();
  test_max_ack_delay_bounds();
  test_stream_count_bounds();
  test_active_connection_id_limit_bounds();

  fd_quic_dump_transport_param_desc( stdout );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

