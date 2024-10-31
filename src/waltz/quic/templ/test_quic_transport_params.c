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
    .max_idle_timeout_present = 1,
    .max_idle_timeout         = (1UL<<62)-1,

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
    .initial_max_streams_bidi                    = (1UL<<62)-1,
    /* 0x09 */
    .initial_max_streams_uni_present             = 1,
    .initial_max_streams_uni                     = (1UL<<62)-1,

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_preferred_address();
  test_max_size();
  test_grease();

  fd_quic_dump_transport_param_desc( stdout );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

