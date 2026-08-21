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
#include "../../util/tmpl/fd_unit_test.c"

typedef struct {
  uchar unused;
} test_empty_msg_t;

#define test_Empty_FIELDLIST(X, a)
#define test_Empty_CALLBACK NULL
#define test_Empty_DEFAULT  NULL
PB_BIND( test_Empty, test_empty_msg_t, AUTO )

static fd_grpc_client_t * client;

/* test_grpc_client_mock_conn injects a fake connection state into the
   gRPC client. */

static void
test_grpc_client_mock_conn( fd_grpc_client_t * client ) {
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

FD_UNIT_TEST( header_deadline ) {
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

FD_UNIT_TEST( rx_end_deadline ) {
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

FD_UNIT_TEST( rx_stream_quota ) {
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

FD_UNIT_TEST( initial_window_update ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  fd_grpc_h2_stream_t * s1 = fd_grpc_client_stream_acquire( client, 0UL );
  fd_grpc_h2_stream_t * s2 = fd_grpc_client_stream_acquire( client, 0UL );

  /* Positive delta grows every active stream and defers tx resumption
     to after fd_h2_rx */
  s1->s.tx_wnd = 100U;
  s2->s.tx_wnd = 200U;
  fd_grpc_h2_initial_window_update( client->conn, 50L );
  FD_TEST( s1->s.tx_wnd==150U && s1->tx_wnd_debt==0L );
  FD_TEST( s2->s.tx_wnd==250U && s2->tx_wnd_debt==0L );
  FD_TEST( client->window_update_pending==1U );
  client->window_update_pending = 0;

  /* Shrink below consumed credit: window 10, delta -20 -> effective -10.
     A WINDOW_UPDATE of 10 must yield effective 0, not 10. */
  s1->s.tx_wnd = 10U;
  s2->s.tx_wnd = 300U;
  fd_grpc_h2_initial_window_update( client->conn, -20L );
  FD_TEST( s1->s.tx_wnd==0U   && s1->tx_wnd_debt==10L );
  FD_TEST( s2->s.tx_wnd==280U && s2->tx_wnd_debt==0L  );
  FD_TEST( client->window_update_pending==0U ); /* no resumption on shrink */

  s1->s.tx_wnd += 10U; /* as fd_h2 does on WINDOW_UPDATE, before the callback */
  fd_grpc_h2_stream_window_update( client->conn, &s1->s, 10U );
  FD_TEST( s1->s.tx_wnd==0U && s1->tx_wnd_debt==0L );

  s1->s.tx_wnd += 25U;
  fd_grpc_h2_stream_window_update( client->conn, &s1->s, 25U );
  FD_TEST( s1->s.tx_wnd==25U && s1->tx_wnd_debt==0L );

  /* A raise past 2^31-1 on any stream is a connection error */
  s2->s.tx_wnd = 0x7fffffffU;
  fd_grpc_h2_initial_window_update( client->conn, 1L );
  FD_TEST( client->conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
  FD_TEST( client->conn->conn_error==FD_H2_ERR_FLOW_CONTROL );
}

FD_UNIT_TEST( stream_release ) {
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

FD_UNIT_TEST( stream_send_state ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  FD_TEST( !fd_grpc_client_request_stream_busy( client ) );

  uchar payload = 0U;
  fd_h2_tx_op_init( client->request_tx_op, &payload, sizeof(payload), 0U );
  FD_TEST( fd_grpc_client_request_stream_busy( client ) );
  *client->request_tx_op = (fd_h2_tx_op_t){0};

  fd_h2_stream_reset( &stream->s, client->conn );
  test_empty_msg_t msg = {0};
  FD_TEST( !fd_grpc_client_stream_send_msg ( client, stream, &test_empty_msg_t_msg, &msg ) );
  FD_TEST( !fd_grpc_client_stream_send_msg1( client, stream, &payload, sizeof(payload) ) );

  stream->s.state = FD_H2_STREAM_STATE_CLOSING_TX;
  FD_TEST( !fd_grpc_client_stream_send_msg ( client, stream, &test_empty_msg_t_msg, &msg ) );
  FD_TEST( !fd_grpc_client_stream_send_msg1( client, stream, &payload, sizeof(payload) ) );

  FD_TEST( fd_h2_rbuf_is_empty( client->frame_tx ) );
  FD_TEST( !client->request_tx_op->chunk_sz );

  fd_grpc_client_stream_release( client, stream );
}

FD_UNIT_TEST( stream_close_state ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1(
      client, "/test", 5UL, 0UL, NULL, 0UL, NULL, 0UL, 1 );
  FD_TEST( stream );
  FD_TEST( stream->s.state==FD_H2_STREAM_STATE_OPEN );
  FD_TEST( client->conn->stream_active_cnt[1]==1U );
  fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );

  uchar payload = 0U;
  FD_TEST( fd_grpc_client_stream_send_msg1( client, stream, &payload, sizeof(payload) ) );
  FD_TEST( !client->request_stream );
  FD_TEST( !client->request_tx_op->chunk_sz );
  fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );

  FD_TEST( fd_grpc_client_stream_close( client, stream ) );
  FD_TEST( stream->s.state==FD_H2_STREAM_STATE_CLOSING_TX );
  fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );

  FD_TEST( !fd_grpc_client_stream_send_msg1( client, stream, &payload, sizeof(payload) ) );
  FD_TEST( !fd_grpc_client_stream_close( client, stream ) );

  fd_h2_stream_rx_data( &stream->s, client->conn, FD_H2_FLAG_END_STREAM );
  FD_TEST( stream->s.state==FD_H2_STREAM_STATE_CLOSED );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
  fd_grpc_client_stream_release( client, stream );
}

FD_UNIT_TEST( rx_headers ) {
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

FD_UNIT_TEST( error_data_end_stream_releases_stream ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 1234UL );
  stream->hdrs.h2_status     = 500U;
  stream->hdrs.is_grpc_proto = 0U;
  fd_h2_stream_close_tx( &stream->s, client->conn );
  fd_h2_stream_rx_data( &stream->s, client->conn, FD_H2_FLAG_END_STREAM );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );

  ulong const rx_start_cnt = g_rx_start_cnt;
  ulong const rx_end_cnt   = g_rx_end_cnt;
  uchar const body[] = { 'o', 'o', 'p', 's' };
  fd_grpc_h2_cb_data( client->conn, &stream->s, body, sizeof(body), FD_H2_FLAG_END_STREAM );

  FD_TEST( g_rx_start_cnt==rx_start_cnt );
  FD_TEST( g_rx_end_cnt  ==rx_end_cnt+1UL );
  FD_TEST( g_cb_request_ctx==1234UL );
  FD_TEST( g_cb_resp_hdrs.h2_status==500U );
  FD_TEST( client->stream_cnt==0UL );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
}

FD_UNIT_TEST( empty_data_end_stream_releases_stream ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 1234UL );
  stream->hdrs.h2_status     = 200U;
  stream->hdrs.is_grpc_proto = 1U;
  fd_h2_stream_close_tx( &stream->s, client->conn );
  fd_h2_stream_rx_data( &stream->s, client->conn, FD_H2_FLAG_END_STREAM );

  ulong const rx_end_cnt = g_rx_end_cnt;
  fd_grpc_h2_cb_data( client->conn, &stream->s, NULL, 0UL, FD_H2_FLAG_END_STREAM );

  FD_TEST( g_rx_end_cnt==rx_end_cnt+1UL );
  FD_TEST( client->stream_cnt==0UL );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
}

FD_UNIT_TEST( grpc_stream_error_releases_h2_quota ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  client->conn->peer_settings.max_concurrent_streams = 1U;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  ulong stream_id = stream->s.stream_id;
  FD_TEST( client->conn->stream_active_cnt[1]==1U );
  FD_TEST( !fd_grpc_client_stream_acquire_is_safe( client ) );

  fd_grpc_h2_cb_headers( client->conn, &stream->s, "corrupt", 7UL, FD_H2_FLAG_END_HEADERS );
  FD_TEST( client->stream_cnt==0UL );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  FD_TEST( g_rx_end_cnt>0UL );

  FD_TEST( fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(fd_h2_rst_stream_t) );
  fd_h2_rst_stream_t rst_stream;
  fd_h2_rbuf_pop_copy( client->frame_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
  FD_TEST( rst_stream.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ) );
  FD_TEST( rst_stream.hdr.flags==0 );
  FD_TEST( fd_uint_bswap( rst_stream.hdr.r_stream_id )==stream_id );
  FD_TEST( fd_uint_bswap( rst_stream.error_code )==FD_H2_ERR_PROTOCOL );

  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  client->conn->peer_settings.max_concurrent_streams = 1U;

  stream = fd_grpc_client_stream_acquire( client, 1UL );
  stream_id = stream->s.stream_id;
  stream->hdrs.h2_status     = 200U;
  stream->hdrs.is_grpc_proto = 1U;
  FD_TEST( client->conn->stream_active_cnt[1]==1U );
  FD_TEST( !fd_grpc_client_stream_acquire_is_safe( client ) );

  fd_grpc_hdr_t hdr = {
    .compressed = 0U,
    .msg_sz     = fd_uint_bswap( (uint)client->frame_rx_buf_max )
  };
  fd_grpc_h2_cb_data( client->conn, &stream->s, &hdr, sizeof(hdr), 0UL );
  FD_TEST( client->stream_cnt==0UL );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );

  FD_TEST( fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(fd_h2_rst_stream_t) );
  fd_h2_rbuf_pop_copy( client->frame_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
  FD_TEST( rst_stream.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ) );
  FD_TEST( rst_stream.hdr.flags==0 );
  FD_TEST( fd_uint_bswap( rst_stream.hdr.r_stream_id )==stream_id );
  FD_TEST( fd_uint_bswap( rst_stream.error_code )==FD_H2_ERR_INTERNAL );
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
  client = fd_grpc_client_new( client_mem, &callbacks, &metrics, app_ctx, buf_max, rng_seed );
  FD_TEST( client );

  fd_unit_tests( argc, argv );

  fd_grpc_client_delete( client );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#endif
