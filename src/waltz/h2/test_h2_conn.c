#include "fd_h2_callback.h"
#include "fd_h2_conn.h"

static void
test_h2_client_handshake( fd_h2_config_t * config ) {
  uchar scratch[256];
  uchar rbuf_rx_b[128];
  uchar rbuf_tx_b[128];

  fd_h2_conn_t conn[1];
  FD_TEST( fd_h2_conn_init_client( conn, config )==conn );
  conn->self_settings.initial_window_size    = 65535U;
  conn->self_settings.max_frame_size         = 16384U;
  conn->self_settings.max_header_list_size   =  4096U;
  conn->self_settings.max_concurrent_streams =   128U;
  conn->settings_timeout                     =  1000L;

  /* Verify that the client initiates the conn */

  FD_TEST( conn->action == 0                               );
  FD_TEST( conn->state  == FD_H2_CONN_STATE_CLIENT_INITIAL );

  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );
  fd_h2_tx_control( conn, rbuf_tx, 1L );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==69 );
  uchar * hello = fd_h2_rbuf_pop( rbuf_tx, scratch, 69 );
  FD_TEST( fd_memeq( hello, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 ) );
  static uchar const settings_frame_expected[ 45 ] = {
    /* payload size: 24 bytes */
    0x00, 0x00, 0x18,
    /* frame type: SETTINGS */
    0x04,
    /* flags: none */
    0x00,
    /* stream id: 0 */
    0x00, 0x00, 0x00, 0x00,

    /* HEADER_TABLE_SIZE: 0 */
    0x00, 0x01,  0x00, 0x00, 0x00, 0x00,
    /* ENABLE_PUSH: 0 */
    0x00, 0x02,  0x00, 0x00, 0x00, 0x00,
    /* MAX_CONCURRENT_STREAMS: 128 */
    0x00, 0x03,  0x00, 0x00, 0x00, 0x80,
    /* INITIAL_WINDOW_SIZE: 65535 */
    0x00, 0x04,  0x00, 0x00, 0xff, 0xff,
    /* MAX_FRAME_SIZE: 16384 */
    0x00, 0x05,  0x00, 0x00, 0x40, 0x00,
    /* MAX_HEADER_LIST_SIZE: 4096 */
    0x00, 0x06,  0x00, 0x00, 0x10, 0x00
  };
  FD_TEST( fd_memeq( hello+24, settings_frame_expected, sizeof(settings_frame_expected) ) );

  FD_TEST( conn->action == 0                              );
  FD_TEST( conn->state  == FD_H2_CONN_STATE_WAIT_SETTINGS );
  fd_h2_tx_control( conn, rbuf_tx, 1L );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );

  /* Ensure that the handshake timeout fires */

  fd_h2_conn_t conn_timeout[1] = {conn[0]};
  fd_h2_tx_control( conn_timeout, rbuf_tx, 1002L );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==17 );
  uchar * goaway_timeout = fd_h2_rbuf_pop( rbuf_tx, scratch, 17 );
  static uchar const goaway_timeout_expected[ 17 ] __attribute__((unused)) = {
    /* payload size: 24 bytes */
    0x00, 0x00, 0x18,
    /* frame type: GOAWAY */
    0x07,
    /* flags: none */
    0x00,
    /* stream id: 0 */
    0x00, 0x00, 0x00, 0x00,

    /* last stream ID: 0 */
    0x00, 0x00, 0x00, 0x00,
    /* error code: SETTINGS_TIMEOUT */
    0x00, 0x00, 0x00, 0x04
  };
  FD_TEST( fd_memeq( goaway_timeout, goaway_timeout_expected, sizeof(goaway_timeout_expected) ) );
  FD_TEST( conn_timeout->action == 0                     );
  FD_TEST( conn_timeout->state  == FD_H2_CONN_STATE_DEAD );

  /* Send server-side handshake frame */

  static uchar const server_settings[ 45 ] = {
    /* payload size: 24 bytes */
    0x00, 0x00, 0x18,
    /* frame type: SETTINGS */
    0x04,
    /* flags: none */
    0x00,
    /* stream id: 0 */
    0x00, 0x00, 0x00, 0x00,

    /* HEADER_TABLE_SIZE: 2 */
    0x00, 0x01,  0x00, 0x00, 0x00, 0x02,
    /* ENABLE_PUSH: 1 */
    0x00, 0x02,  0x00, 0x00, 0x00, 0x01,
    /* MAX_CONCURRENT_STREAMS: 256 */
    0x00, 0x03,  0x00, 0x00, 0x01, 0x00,
    /* INITIAL_WINDOW_SIZE: 131071 */
    0x00, 0x04,  0x00, 0x01, 0xff, 0xff,
    /* MAX_FRAME_SIZE: 32768 */
    0x00, 0x05,  0x00, 0x00, 0x80, 0x00,
    /* MAX_HEADER_LIST_SIZE: 8192 */
    0x00, 0x06,  0x00, 0x00, 0x20, 0x00
  };
  fd_h2_rbuf_t rbuf_rx[1];
  FD_TEST( fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) )==rbuf_rx );
  fd_h2_rbuf_push( rbuf_rx, server_settings, sizeof(server_settings) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), &fd_h2_callbacks_noop );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==9 );

  static uchar const settings_ack_expected[ 9 ] = {
    /* payload size: 0 bytes */
    0x00, 0x00, 0x00,
    /* frame type: SETTINGS */
    0x04,
    /* flags: ACK */
    0x01,
    /* stream id: 0 */
    0x00, 0x00, 0x00, 0x00
  };
  uchar * settings_ack = fd_h2_rbuf_pop( rbuf_tx, scratch, 9UL );
  FD_TEST( fd_memeq( settings_ack, settings_ack_expected, sizeof(settings_ack_expected) ) );

  FD_TEST( conn->action == 0 );
  FD_TEST( conn->state  == FD_H2_CONN_STATE_ESTABLISHED );
  fd_h2_tx_control( conn, rbuf_tx, 1L );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );
}

static void
test_h2_conn( void ) {
  fd_h2_config_t config = {
    .ns_per_tick      = 1.f,
    .settings_timeout = 1000L
  };
  test_h2_client_handshake( &config );
}
