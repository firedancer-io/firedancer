#include "fd_h2.h"
#include "fd_h2_proto.h"

/* The total size of the SETTINGS frame describing our settings is
   the frame header plus 48 bits for each value. */
FD_STATIC_ASSERT( FD_H2_OUR_SETTINGS_ENCODED_SZ == sizeof(fd_h2_frame_hdr_t) + 6*6, layout );

/* SETTINGS frame and client preface fit into the respond buffer. */
FD_STATIC_ASSERT( FD_H2_CONN_RESPOND_BUFSZ >= 24UL + FD_H2_OUR_SETTINGS_ENCODED_SZ, layout );

static ulong
fd_h2_conn_drain( fd_h2_conn_t * conn,
                  uchar *        buf,
                  ulong          bufsz,
                  long           cur_time ) {
  ulong tot_sz = 0UL;
  for(;;) {
    if( FD_UNLIKELY( tot_sz+64UL > bufsz ) ) FD_LOG_ERR(( "undersz buffer" ));
    ulong res_sz = fd_h2_conn_respond( conn, buf+tot_sz, cur_time );
    if( !res_sz ) break;
    tot_sz += res_sz;
  }
  return tot_sz;
}

static void
test_h2_client_handshake( fd_h2_config_t * config ) {
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

  uchar buf[ 160 ];
  FD_TEST( fd_h2_conn_drain( conn, buf, sizeof(buf), 1UL )==69 );
  FD_TEST( fd_memeq( buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 ) );
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
  FD_TEST( fd_memeq( buf+24, settings_frame_expected, sizeof(settings_frame_expected) ) );

  FD_TEST( conn->action == 0                              );
  FD_TEST( conn->state  == FD_H2_CONN_STATE_WAIT_SETTINGS );
  FD_TEST( fd_h2_conn_drain( conn, buf, sizeof(buf), 1L )==0 );

  /* Ensure that the handshake timeout fires */

  fd_h2_conn_t conn_timeout[1] = {conn[0]};
  FD_TEST( fd_h2_conn_drain( conn_timeout, buf, sizeof(buf), 1002L )==17 );
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
  FD_TEST( fd_memeq( buf, goaway_timeout_expected, sizeof(goaway_timeout_expected) ) );
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
  fd_h2_rbuf_t rbuf[1];
  uchar rbuf_[ 64 ];
  FD_TEST( fd_h2_rbuf_init( rbuf, rbuf_, sizeof(rbuf_) )==rbuf );
  fd_h2_rbuf_push( rbuf, server_settings, sizeof(server_settings) );
  fd_h2_conn_rx_next( conn, rbuf );
}

static void
test_h2_conn( void ) {
  fd_h2_config_t config = {
    .ns_per_tick      = 1.f,
    .ack_backoff      = 1000L,
    .settings_timeout = 1000L
  };
  test_h2_client_handshake( &config );
}
