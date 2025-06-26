#if !FD_HAS_HOSTED

#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED" ));
  fd_halt();
  return 0;
}

#else

#include "fd_grpc_client_private.h"

/* test_grpc_client_mock_conn injects a fake connection state into the
   gRPC client. */

static void
test_grpc_client_mock_conn( fd_grpc_client_t * client ) {
  client->ssl_hs_done = 1;
  client->h2_hs_done  = 1;
  client->conn->flags = 0;
}


static void * g_cb_app_ctx;
static ulong  g_cb_request_ctx;

static ulong g_rx_start_cnt;

static void
cb_rx_start( void * app_ctx,
             ulong  request_ctx ) {
  g_cb_app_ctx     = app_ctx;
  g_cb_request_ctx = request_ctx;
  g_rx_start_cnt++;
}

static ulong g_rx_end_cnt;
static fd_grpc_resp_hdrs_t g_cb_resp_hdrs;

static void
cb_rx_end( void * app_ctx,
           ulong  request_ctx,
           fd_grpc_resp_hdrs_t * resp_hdrs ) {
  g_cb_app_ctx     = app_ctx;
  g_cb_request_ctx = request_ctx;
  g_cb_resp_hdrs   = *resp_hdrs;
  g_rx_end_cnt++;
}

static ulong g_timeout_cnt;

static struct {
  int    deadline_kind;
} g_timeout_details;

static void
cb_rx_timeout( void * app_ctx,
               ulong  request_ctx,
               int    deadline_kind ) {
  g_cb_app_ctx     = app_ctx;
  g_cb_request_ctx = request_ctx;
  g_timeout_details.deadline_kind = deadline_kind;
  g_timeout_cnt++;
}

static void
test_header_deadline( fd_grpc_client_t * client ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  /* Deadline should not fire prior to expiration */
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  long const deadline = 1234L;
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_HEADER, deadline );
  fd_grpc_client_service_streams( client, deadline-1L );
  FD_TEST( client->stream_cnt==1 );

  /* Deadline should deactivate after headers were received */
  fd_grpc_h2_cb_headers( client->conn, &stream->s, NULL, 0UL, FD_H2_FLAG_END_HEADERS );
  fd_grpc_client_service_streams( client, deadline+1L );
  FD_TEST( client->stream_cnt==1 );
  fd_grpc_client_stream_release( client, stream );
  FD_TEST( client->stream_cnt==0 );

  /* Test deadline firing */
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  stream = fd_grpc_client_stream_acquire( client, 0UL );
  ulong const stream_id = stream->s.stream_id;
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_HEADER, deadline );
  FD_TEST( client->stream_cnt==1 );
  fd_grpc_client_service_streams( client, deadline+1L );
  FD_TEST( client->stream_cnt==0 );
  stream = NULL; /* already freed */

  FD_TEST( fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(fd_h2_rst_stream_t) );
  fd_h2_rst_stream_t rst_stream;
  fd_h2_rbuf_pop_copy( client->frame_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
  FD_TEST( rst_stream.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ) );
  FD_TEST( rst_stream.hdr.flags ==0 );
  FD_TEST( fd_uint_bswap( rst_stream.hdr.r_stream_id )==stream_id );
  FD_TEST( fd_uint_bswap( rst_stream.error_code      )==FD_H2_ERR_CANCEL );
}

static void
test_rx_end_deadline( fd_grpc_client_t * client ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  /* Deadline should not fire prior to expiration */
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  long const deadline = 1234L;
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, deadline );
  fd_grpc_client_service_streams( client, deadline-1L );
  FD_TEST( client->stream_cnt==1 );

  /* Deadline should still fire after headers were received */
  fd_grpc_h2_cb_headers( client->conn, &stream->s, NULL, 0UL, FD_H2_FLAG_END_HEADERS );
  fd_grpc_client_service_streams( client, deadline+1L );
  FD_TEST( client->stream_cnt==0 );
}

static void
test_rx_stream_quota( fd_grpc_client_t * client ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  /* Client should replenish receive quota */
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  stream->s.rx_wnd = client->conn->self_settings.initial_window_size / 2 - 1;
  fd_grpc_client_service_streams( client, 0L );

  FD_TEST( fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(fd_h2_window_update_t) );
  fd_h2_window_update_t window_update;
  fd_h2_rbuf_pop_copy( client->frame_tx, &window_update, sizeof(fd_h2_window_update_t) );
  FD_TEST( window_update.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_WINDOW_UPDATE, 4UL ) );
  FD_TEST( window_update.hdr.flags==0 );
  FD_TEST( fd_uint_bswap( window_update.hdr.r_stream_id )==stream->s.stream_id );
  FD_TEST( fd_uint_bswap( window_update.increment )==client->conn->self_settings.initial_window_size / 2 + 2 );
}

static void
test_stream_release( fd_grpc_client_t * client ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  fd_grpc_h2_stream_t * stream0 = fd_grpc_client_stream_acquire( client, 0UL );
  fd_grpc_h2_stream_t * stream1 = fd_grpc_client_stream_acquire( client, 1UL );
  fd_grpc_h2_stream_t * stream2 = fd_grpc_client_stream_acquire( client, 2UL );
  fd_grpc_h2_stream_t * stream3 = fd_grpc_client_stream_acquire( client, 3UL );
  FD_TEST( client->stream_cnt==4 );
  fd_grpc_client_stream_release( client, stream1 );
  FD_TEST( client->stream_cnt==3 );
  FD_TEST( client->stream_ids[ 0 ]==stream0->s.stream_id );
  FD_TEST( client->stream_ids[ 1 ]==stream3->s.stream_id );
  FD_TEST( client->stream_ids[ 2 ]==stream2->s.stream_id );
  fd_grpc_client_stream_release( client, stream2 );
  FD_TEST( client->stream_cnt==2 );
  FD_TEST( client->stream_ids[ 0 ]==stream0->s.stream_id );
  FD_TEST( client->stream_ids[ 1 ]==stream3->s.stream_id );
  fd_grpc_client_stream_release( client, stream0 );
  FD_TEST( client->stream_cnt==1 );
  FD_TEST( client->stream_ids[ 0 ]==stream3->s.stream_id );
  fd_grpc_client_stream_release( client, stream3 );
  FD_TEST( client->stream_cnt==0 );
}

static void
test_rx_headers( fd_grpc_client_t * client ) {
  /* Header-only response */
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  FD_TEST( !stream->hdrs_received );
  stream->hdrs.is_grpc_proto = 1;
  stream->hdrs.h2_status = 200;
  fd_grpc_h2_cb_headers( client->conn, &stream->s, NULL, 0UL, FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM );
  FD_TEST( stream->hdrs_received );
  FD_TEST( g_rx_start_cnt==1 );
  FD_TEST( g_rx_end_cnt  ==1 );
  FD_TEST( client->stream_cnt==0 );

  /* Incomplete header frag */
  stream = fd_grpc_client_stream_acquire( client, 0UL );
  FD_TEST( !stream->hdrs_received );
  fd_grpc_h2_cb_headers( client->conn, &stream->s, NULL, 0UL, 0 );
  FD_TEST( !stream->hdrs_received );
  FD_TEST( g_rx_start_cnt==1 );
  FD_TEST( g_rx_end_cnt  ==1 );
  fd_grpc_client_stream_release( client, stream );

  /* Headers complete, data pending */
  stream = fd_grpc_client_stream_acquire( client, 0UL );
  FD_TEST( !stream->hdrs_received );
  stream->hdrs.is_grpc_proto = 1;
  stream->hdrs.h2_status = 200;
  fd_grpc_h2_cb_headers( client->conn, &stream->s, NULL, 0UL, FD_H2_FLAG_END_HEADERS );
  FD_TEST( stream->hdrs_received );
  FD_TEST( g_rx_start_cnt==2 );
  FD_TEST( g_rx_end_cnt  ==1 );
  fd_grpc_client_stream_release( client, stream );

  /* Corrupt header */
  stream = fd_grpc_client_stream_acquire( client, 0UL );
  FD_TEST( !stream->hdrs_received );
  stream->hdrs.is_grpc_proto = 1;
  stream->hdrs.h2_status = 200;
  fd_grpc_h2_cb_headers( client->conn, &stream->s, "corrupt", 7UL, FD_H2_FLAG_END_HEADERS );
  FD_TEST( g_rx_start_cnt==2 );
  FD_TEST( g_rx_end_cnt  ==2 ); /* FIXME does it make sense to issue rx_end without rx_start? */
  FD_TEST( client->stream_cnt==0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar client_mem[ 131072 ] __attribute__((aligned(128)));
  ulong const buf_max = 4096UL;
  FD_TEST( fd_grpc_client_footprint( buf_max )<=sizeof(client_mem) );

  fd_grpc_client_callbacks_t callbacks = {
    .rx_start   = cb_rx_start,
    .rx_end     = cb_rx_end,
    .rx_timeout = cb_rx_timeout
  };
  fd_grpc_client_metrics_t metrics = {0};
  void * app_ctx = (void *)( 0x1234UL );
  ulong rng_seed = 1UL;
  fd_grpc_client_t * client = fd_grpc_client_new( client_mem, &callbacks, &metrics, app_ctx, buf_max, rng_seed );
  FD_TEST( client );

  test_header_deadline( client );
  test_rx_end_deadline( client );
  test_rx_stream_quota( client );
  test_stream_release ( client );
  test_rx_headers     ( client );

  fd_grpc_client_delete( client );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#endif
