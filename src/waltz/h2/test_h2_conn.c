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

static void
test_h2_push_settings_max_frame_size( fd_h2_rbuf_t * rbuf,
                                      uint           max_frame_size ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, sizeof(fd_h2_setting_t) ),
    .flags  = 0,
    .r_stream_id = 0
  };
  fd_h2_setting_t setting = {
    .id    = fd_ushort_bswap( FD_H2_SETTINGS_MAX_FRAME_SIZE ),
    .value = fd_uint_bswap( max_frame_size )
  };
  fd_h2_rbuf_push( rbuf, &hdr, sizeof(hdr) );
  fd_h2_rbuf_push( rbuf, &setting, sizeof(setting) );
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

static uint test_conn_final_cnt;
static uint test_conn_final_err;

static void
test_cb_conn_final( fd_h2_conn_t * conn,
                    uint           h2_err,
                    int            closed_by ) {
  (void)conn; (void)closed_by;
  test_conn_final_cnt++;
  test_conn_final_err = h2_err;
}

/* test_h2_buffer_guard exercises the buffer guard at fd_h2_conn.c:671
   and related frame size checks.

   Background: Non-DATA frames are consumed "all or nothing", meaning
   the entire frame (header + payload) must fit in the rx ring buffer
   at once.  If a frame's total size exceeds the buffer capacity, it
   can never be consumed, causing a deadlock.  The buffer guard
   detects this and issues a conn error instead. */

static void
test_h2_buffer_guard( void ) {
  FD_LOG_NOTICE(( "Testing H2 buffer guard" ));

  /* (a) Frame exceeds buffer capacity -> FD_H2_ERR_INTERNAL
     Regression test for the original deadlock bug: a non-DATA frame
     whose total size (header + payload) exceeds the rx buffer capacity
     can never be consumed by the "all or nothing" path.  The buffer
     guard must detect this and issue FD_H2_ERR_INTERNAL. */
  {
    /* Use a 32-byte rx buffer but max_frame_size=64 (misconfigured) */
    uchar rbuf_rx_b[32];
    uchar rbuf_tx_b[256];
    uchar scratch[256];

    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags = 0; /* skip handshake */
    conn->self_settings.max_frame_size = 64U;

    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    test_conn_final_cnt = 0;
    cb->conn_final = test_cb_conn_final;

    fd_h2_rbuf_t rbuf_rx[1];
    fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
    fd_h2_rbuf_t rbuf_tx[1];
    fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

    /* Construct a SETTINGS frame with payload_sz=24 -> tot_sz=33 > 32 */
    fd_h2_frame_hdr_t hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 24UL ),
      .flags       = 0,
      .r_stream_id = 0
    };
    uchar frame[33];
    fd_memcpy( frame, &hdr, sizeof(fd_h2_frame_hdr_t) );
    fd_memset( frame+sizeof(fd_h2_frame_hdr_t), 0, 24 );
    /* Push only what fits in the buffer (32 bytes) */
    fd_h2_rbuf_push( rbuf_rx, frame, 32 );

    ulong lo_before = rbuf_rx->lo_off;
    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

    /* Must have triggered SEND_GOAWAY with INTERNAL error */
    FD_TEST( conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
    FD_TEST( conn->conn_error == FD_H2_ERR_INTERNAL );
    /* rx data not consumed (peeked only) */
    FD_TEST( rbuf_rx->lo_off == lo_before );

    /* Complete the GOAWAY lifecycle */
    fd_h2_tx_control( conn, rbuf_tx, cb );
    FD_TEST( conn->flags & FD_H2_CONN_FLAGS_DEAD );
    FD_TEST( test_conn_final_cnt == 1 );
    FD_TEST( test_conn_final_err == FD_H2_ERR_INTERNAL );

    /* Verify GOAWAY frame was generated */
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx ) == sizeof(fd_h2_goaway_t) );
    fd_h2_goaway_t goaway;
    fd_h2_rbuf_pop_copy( rbuf_tx, &goaway, sizeof(fd_h2_goaway_t) );
    FD_TEST( fd_h2_frame_type( goaway.hdr.typlen ) == FD_H2_FRAME_TYPE_GOAWAY );
    FD_TEST( fd_uint_bswap( goaway.error_code ) == FD_H2_ERR_INTERNAL );
  }

  /* (b) Frame exactly at buffer capacity -> processed normally
     A non-DATA frame whose total size equals the buffer capacity
     should be processed without error. */
  {
    /* Buffer = 45 bytes.  SETTINGS with 6 params = 36 bytes payload.
       tot_sz = 9 + 36 = 45 == bufsz */
    uchar rbuf_rx_b[45];
    uchar rbuf_tx_b[256];
    uchar scratch[256];

    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags = 0; /* skip handshake */
    conn->self_settings.max_frame_size = 64U; /* large enough */

    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    test_conn_final_cnt = 0;
    cb->conn_final = test_cb_conn_final;

    fd_h2_rbuf_t rbuf_rx[1];
    fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
    fd_h2_rbuf_t rbuf_tx[1];
    fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

    /* Server SETTINGS frame: 36 bytes payload (6 params) */
    static uchar const server_settings[45] = {
      0x00, 0x00, 0x24, /* payload size: 36 */
      0x04,             /* SETTINGS */
      0x00,             /* no flags */
      0x00, 0x00, 0x00, 0x00, /* stream 0 */
      /* 6 settings, all valid */
      0x00, 0x01,  0x00, 0x00, 0x00, 0x00,
      0x00, 0x02,  0x00, 0x00, 0x00, 0x00,
      0x00, 0x03,  0x00, 0x00, 0x01, 0x00,
      0x00, 0x04,  0x00, 0x00, 0xff, 0xff,
      0x00, 0x05,  0x00, 0x00, 0x40, 0x00,
      0x00, 0x06,  0x00, 0x00, 0x10, 0x00
    };
    fd_h2_rbuf_push( rbuf_rx, server_settings, sizeof(server_settings) );
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_rx ) == sizeof(rbuf_rx_b) ); /* buffer exactly full */

    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

    /* Frame should be consumed, no conn error */
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_rx ) == 0 );
    FD_TEST( !( conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD) ) );
    FD_TEST( test_conn_final_cnt == 0 );
    /* Should have generated a SETTINGS ACK (header only) */
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx ) == sizeof(fd_h2_frame_hdr_t) );
  }

  /* (c) Frame at max_frame_size+1 -> FD_H2_ERR_FRAME_SIZE fires first
     When max_frame_size is properly clamped to bufsz - sizeof(hdr),
     a frame with payload > max_frame_size should be rejected by the
     FRAME_SIZE check (line 627), not the buffer guard (line 671). */
  {
    uchar rbuf_rx_b[128];
    uchar rbuf_tx_b[256];
    uchar scratch[256];

    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags = 0;
    /* Clamp: max_frame_size = bufsz - hdr_sz = 128 - 9 = 119 */
    conn->self_settings.max_frame_size = (uint)( sizeof(rbuf_rx_b) - sizeof(fd_h2_frame_hdr_t) );

    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    test_conn_final_cnt = 0;
    cb->conn_final = test_cb_conn_final;

    fd_h2_rbuf_t rbuf_rx[1];
    fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
    fd_h2_rbuf_t rbuf_tx[1];
    fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

    /* Frame with payload = max_frame_size + 1 = 120 -> tot_sz = 129 > 128
       But the FRAME_SIZE check at line 627 should catch it first. */
    fd_h2_frame_hdr_t hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 120UL ),
      .flags       = 0,
      .r_stream_id = 0
    };
    /* Only push the header (9 bytes) -- enough for the peek */
    fd_h2_rbuf_push( rbuf_rx, &hdr, sizeof(fd_h2_frame_hdr_t) );

    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

    /* Must be FRAME_SIZE, not INTERNAL */
    FD_TEST( conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
    FD_TEST( conn->conn_error == FD_H2_ERR_FRAME_SIZE );
  }

  /* (d) SEND_GOAWAY terminates fd_h2_rx loop, GOAWAY generated on
     fd_h2_tx_control.  After triggering any conn error, fd_h2_rx must
     stop processing, and the next fd_h2_tx_control must generate a
     GOAWAY with the correct error code, set DEAD, and call conn_final. */
  {
    uchar rbuf_rx_b[128];
    uchar rbuf_tx_b[256];
    uchar scratch[256];

    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags = 0;
    conn->self_settings.max_frame_size = 32U;

    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    test_conn_final_cnt = 0;
    cb->conn_final = test_cb_conn_final;

    fd_h2_rbuf_t rbuf_rx[1];
    fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
    fd_h2_rbuf_t rbuf_tx[1];
    fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

    /* Push a valid PING (17 bytes) followed by a bad frame (payload >
       max_frame_size).  fd_h2_rx should process the PING, then hit
       the FRAME_SIZE error on the second frame and stop. */
    fd_h2_ping_t ping = {
      .hdr = {
        .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
        .flags       = 0,
        .r_stream_id = 0
      },
      .payload = 0UL
    };
    fd_h2_rbuf_push( rbuf_rx, &ping, sizeof(fd_h2_ping_t) );

    /* Bad frame: SETTINGS with payload 33 > max_frame_size=32 */
    fd_h2_frame_hdr_t bad_hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 33UL ),
      .flags       = 0,
      .r_stream_id = 0
    };
    fd_h2_rbuf_push( rbuf_rx, &bad_hdr, sizeof(fd_h2_frame_hdr_t) );

    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

    /* PING was consumed (17 bytes), bad frame header remains (9 bytes) */
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_rx ) == sizeof(fd_h2_frame_hdr_t) );
    FD_TEST( conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
    FD_TEST( conn->conn_error == FD_H2_ERR_FRAME_SIZE );
    /* conn_final not yet called (GOAWAY not sent) */
    FD_TEST( test_conn_final_cnt == 0 );

    /* PING ACK should be in tx buffer (we didn't have ping_tx set,
       so unsolicited ping -> reflected as PING ACK) */
    ulong tx_used_before_goaway = fd_h2_rbuf_used_sz( rbuf_tx );
    FD_TEST( tx_used_before_goaway == sizeof(fd_h2_ping_t) );

    /* Now fd_h2_tx_control sends GOAWAY */
    fd_h2_tx_control( conn, rbuf_tx, cb );
    FD_TEST( conn->flags & FD_H2_CONN_FLAGS_DEAD );
    FD_TEST( test_conn_final_cnt == 1 );
    FD_TEST( test_conn_final_err == FD_H2_ERR_FRAME_SIZE );
    /* PING ACK + GOAWAY in tx buffer */
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx ) == sizeof(fd_h2_ping_t) + sizeof(fd_h2_goaway_t) );

    /* fd_h2_rx returns immediately when DEAD */
    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_rx ) == sizeof(fd_h2_frame_hdr_t) ); /* unchanged */
  }

  /* (e) DATA frame larger than buffer -> incremental path, no INTERNAL
     DATA frames bypass the "all or nothing" path and are processed
     incrementally.  A DATA frame whose total size exceeds the buffer
     should NOT trigger FD_H2_ERR_INTERNAL. */
  {
    uchar rbuf_rx_b[32];
    uchar rbuf_tx_b[256];
    uchar scratch[256];

    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags = 0;
    conn->self_settings.max_frame_size = 64U;

    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    test_conn_final_cnt = 0;
    cb->conn_final = test_cb_conn_final;

    fd_h2_rbuf_t rbuf_rx[1];
    fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
    fd_h2_rbuf_t rbuf_tx[1];
    fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

    /* DATA frame with payload=24 -> tot_sz=33 > bufsz=32
       But DATA takes the incremental path at line 654. */
    fd_h2_frame_hdr_t data_hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_DATA, 24UL ),
      .flags       = 0,
      .r_stream_id = fd_uint_bswap( 1U ) /* stream 1 */
    };
    /* Push header + partial payload (fill 32 byte buffer) */
    fd_h2_rbuf_push( rbuf_rx, &data_hdr, sizeof(fd_h2_frame_hdr_t) );
    uchar payload[23];
    fd_memset( payload, 0x42, sizeof(payload) );
    fd_h2_rbuf_push( rbuf_rx, payload, sizeof(payload) ); /* 9+23=32 */

    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

    /* Should NOT be FD_H2_ERR_INTERNAL.  The DATA frame takes the
       incremental path.  stream_query will return NULL (no stream
       created), resulting in RST_STREAM, which is fine -- the point
       is that it didn't trigger the buffer guard. */
    FD_TEST( conn->conn_error != FD_H2_ERR_INTERNAL );
    FD_TEST( !( conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY ) ||
             conn->conn_error != FD_H2_ERR_INTERNAL );
  }

  FD_LOG_NOTICE(( "test_h2_buffer_guard: pass" ));
}

static void
test_h2_invalid_max_frame_size( void ) {
  static uint const invalid_values[] = {
    0x00003fffU,
    0x01000000U
  };

  uchar scratch [ 128 ];
  uchar rbuf_rx_b[ 128 ];
  uchar rbuf_tx_b[ 128 ];

  fd_h2_callbacks_t cb[1];
  fd_h2_callbacks_init( cb );

  for( ulong i=0UL; i<sizeof(invalid_values)/sizeof(invalid_values[0]); i++ ) {
    fd_h2_conn_t conn[1];
    FD_TEST( fd_h2_conn_init_client( conn )==conn );
    conn->flags = 0;

    fd_h2_rbuf_t rbuf_rx[1];
    fd_h2_rbuf_t rbuf_tx[1];
    fd_h2_rbuf_init( rbuf_rx, rbuf_rx_b, sizeof(rbuf_rx_b) );
    fd_h2_rbuf_init( rbuf_tx, rbuf_tx_b, sizeof(rbuf_tx_b) );

    test_h2_push_settings_max_frame_size( rbuf_rx, invalid_values[i] );
    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

    FD_TEST( !!( conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY ) );
    FD_TEST( conn->conn_error==FD_H2_ERR_PROTOCOL );
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0UL );

    fd_h2_tx_control( conn, rbuf_tx, cb );

    FD_TEST( conn->flags==FD_H2_CONN_FLAGS_DEAD );
    FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==sizeof(fd_h2_goaway_t) );

    fd_h2_goaway_t goaway;
    fd_h2_rbuf_pop_copy( rbuf_tx, &goaway, sizeof(goaway) );
    FD_TEST( fd_h2_frame_type( goaway.hdr.typlen )==FD_H2_FRAME_TYPE_GOAWAY );
    FD_TEST( fd_h2_frame_length( goaway.hdr.typlen )==8U );
    FD_TEST( fd_h2_frame_stream_id( goaway.hdr.r_stream_id )==0U );
    FD_TEST( fd_uint_bswap( goaway.error_code )==FD_H2_ERR_PROTOCOL );
  }
}

static void
test_h2_conn( void ) {
  test_h2_client_handshake();
  test_h2_invalid_max_frame_size();
  test_h2_ping_tx();
  test_h2_buffer_guard();
}
