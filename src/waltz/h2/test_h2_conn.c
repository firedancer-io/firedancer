#include "fd_h2_callback.h"
#include "fd_h2_conn.h"
#include "../../util/sanitize/fd_asan.h"
#include "fd_h2_proto.h"

struct test_h2_callback_rec {
  uint cb_established_cnt;
};

typedef struct test_h2_callback_rec test_h2_callback_rec_t;

static test_h2_callback_rec_t cb_rec;

static void
test_cb_conn_established( fd_h2_conn_t * conn ) {
  (void)conn;
  cb_rec.cb_established_cnt++;
}

/* test_h2_client_handshake exercises various client-side handshake
   state logic.  There are three possible successful client handshake
   sequences:

   Sequence 1:
   - Client: Preface, SETTINGS
   - Server: SETTINGS
   - Client: SETTINGS ACK
   - Server: SETTINGS ACK

   Sequence 3:
   - Client: Preface, SETTINGS
   - Server: SETTINGS ACK
   - Server: SETTINGS
   - Client: SETTINGS ACK */

static void
test_h2_client_handshake( void ) {
  uchar scratch[256];
  uchar rbuf_rx_b[128];
  uchar rbuf_tx_b[128];

  fd_h2_conn_t conn[1];
  FD_TEST( fd_h2_conn_init_client( conn )==conn );
  conn->self_settings.initial_window_size    = 65535U;
  conn->self_settings.max_frame_size         = 16384U;
  conn->self_settings.max_header_list_size   =  4096U;
  conn->self_settings.max_concurrent_streams =   128U;

  fd_h2_callbacks_t cb[1];
  fd_h2_callbacks_init( cb );
  cb->conn_established = test_cb_conn_established;

  /* Verify that the client initiates the conn */

  FD_TEST( conn->flags == FD_H2_CONN_FLAGS_CLIENT_INITIAL );

  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );
  fd_h2_tx_control( conn, rbuf_tx, cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==69 );
  uchar * hello = fd_h2_rbuf_pop( rbuf_tx, scratch, 69 );
  FD_TEST( fd_memeq( hello, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 ) );
  static uchar const settings_frame_expected[ 45 ] = {
    /* payload size: 24 bytes */
    0x00, 0x00, 0x24,
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

  FD_TEST( conn->flags == (FD_H2_CONN_FLAGS_WAIT_SETTINGS_0 | FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0) );
  fd_h2_tx_control( conn, rbuf_tx, cb );
  fd_h2_tx_control( conn, rbuf_tx, cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );

  /* Server: SETTINGS, SETTINGS ACK */

  static uchar const server_settings[ 45 ] = {
    /* payload size: 36 bytes */
    0x00, 0x00, 0x24,
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
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
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

  FD_TEST( conn->flags == FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0 );
  fd_h2_tx_control( conn, rbuf_tx, cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );

  FD_TEST( cb_rec.cb_established_cnt==0 );
  fd_h2_rbuf_push( rbuf_rx, settings_ack_expected, sizeof(settings_ack_expected) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );
  FD_TEST( conn->flags == 0 );
  fd_h2_tx_control( conn, rbuf_tx, cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );
  FD_TEST( cb_rec.cb_established_cnt==1 );

  /* Retry the scenario, but this time:
     Server: SETTINGS ACK, SETTINGS */

  cb_rec.cb_established_cnt = 0;
  FD_TEST( fd_h2_conn_init_client( conn )==conn );
  conn->self_settings.initial_window_size    = 65535U;
  conn->self_settings.max_frame_size         = 16384U;
  conn->self_settings.max_header_list_size   =  4096U;
  conn->self_settings.max_concurrent_streams =   128U;

  /* Pretend we just sent a preface and a settings frame, and are now
     waiting on the server's response */
  conn->flags = FD_H2_CONN_FLAGS_WAIT_SETTINGS_0 | FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0;
  conn->setting_tx = 1;

  fd_h2_rbuf_push( rbuf_rx, settings_ack_expected, sizeof(settings_ack_expected) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );
  FD_TEST( conn->flags == FD_H2_CONN_FLAGS_WAIT_SETTINGS_0 );
  FD_TEST( cb_rec.cb_established_cnt==0 );

  fd_h2_rbuf_push( rbuf_rx, server_settings, sizeof(server_settings) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==9 );
  settings_ack = fd_h2_rbuf_pop( rbuf_tx, scratch, 9UL );
  FD_TEST( fd_memeq( settings_ack, settings_ack_expected, sizeof(settings_ack_expected) ) );
  FD_TEST( conn->flags == 0 );
  FD_TEST( cb_rec.cb_established_cnt==1 );
}

static ulong test_h2_ping_tx_ack_cnt = 0UL;

static void
test_h2_ping_ack( fd_h2_conn_t * conn ) {
  (void)conn;
  test_h2_ping_tx_ack_cnt++;
}

static void
test_h2_ping_tx( void ) {
  fd_h2_conn_t conn[1];
  FD_TEST( fd_h2_conn_init_client( conn )==conn );
  uchar scratch[128];
  conn->self_settings.max_frame_size = sizeof(scratch);

  fd_h2_callbacks_t cb[1];
  fd_h2_callbacks_init( cb );
  cb->ping_ack = test_h2_ping_ack;

  uchar rbuf_tx_b[128] = {0};
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

  /* Too many pending pings */
  conn->ping_tx = UCHAR_MAX;
  FD_TEST( fd_h2_tx_ping( conn, rbuf_tx )==0 );
  conn->ping_tx = 0;

  /* rbuf_tx is full */
  fd_h2_rbuf_push( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b)-sizeof(fd_h2_ping_t)+1 );
  FD_TEST( fd_h2_tx_ping( conn, rbuf_tx )==0 );

  /* Exactly enough space for a ping */
  fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );
  fd_h2_rbuf_push( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b)-sizeof(fd_h2_ping_t) );
  FD_TEST( fd_h2_tx_ping( conn, rbuf_tx )==1 );

  /* Parse ping */
  fd_h2_rbuf_skip( rbuf_tx, sizeof(rbuf_tx_b)-sizeof(fd_h2_ping_t) );
  fd_h2_ping_t ping;
  fd_h2_rbuf_pop_copy( rbuf_tx, &ping, sizeof(fd_h2_ping_t) );
  FD_TEST( ping.hdr.typlen == fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ) );
  FD_TEST( ping.hdr.flags == 0 );
  FD_TEST( ping.hdr.r_stream_id == 0 );
  FD_TEST( ping.payload == 0UL );

  /* Acknowledge ping */
  fd_h2_ping_t ping_ack = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
      .flags       = FD_H2_FLAG_ACK,
      .r_stream_id = 0
    },
    .payload = 0UL
  };

  /* Ensure PING ACK callback is triggered */
  uchar rbuf_rx_b[128] = {0};
  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
  fd_h2_rbuf_push( rbuf_rx, &ping_ack, sizeof(fd_h2_ping_t) );
  FD_TEST( conn->ping_tx==1 );
  FD_TEST( test_h2_ping_tx_ack_cnt==0UL );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
  FD_TEST( conn->ping_tx==0 );
  FD_TEST( test_h2_ping_tx_ack_cnt==1UL );

  /* Unsolicited PING ACKs should be ignored */
  fd_h2_rbuf_push( rbuf_rx, &ping_ack, sizeof(fd_h2_ping_t) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
  FD_TEST( conn->ping_tx==0 );
  FD_TEST( test_h2_ping_tx_ack_cnt==1UL );
}

static void
test_h2_conn( void ) {
  test_h2_client_handshake();
  test_h2_ping_tx();
}
