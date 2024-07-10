#include "../../../util/fd_util.h"
#include "../fd_quic_enum.h"
#include "../fd_quic_proto.h"
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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_preferred_address();

  fd_quic_dump_transport_param_desc( stdout );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

