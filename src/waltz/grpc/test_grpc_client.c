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

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

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


static ulong  g_cb_request_ctx;

static ulong g_rx_start_cnt;
static int   g_rx_start_fill_tx;

static void
cb_rx_start( void * app_ctx,
             ulong  request_ctx ) {
  (void)app_ctx;
  g_cb_request_ctx = request_ctx;
  g_rx_start_cnt++;
  while( g_rx_start_fill_tx && fd_h2_rbuf_free_sz( client->frame_tx ) ) fd_h2_rbuf_push( client->frame_tx, "", 1UL );
}

static ulong g_rx_end_cnt;
static int   g_rx_end_fill_tx;
static fd_grpc_resp_hdrs_t g_cb_resp_hdrs;

static void
cb_rx_end( void * app_ctx,
           ulong  request_ctx,
           fd_grpc_resp_hdrs_t * resp_hdrs ) {
  (void)app_ctx;
  g_cb_request_ctx = request_ctx;
  g_cb_resp_hdrs   = *resp_hdrs;
  g_rx_end_cnt++;
  while( g_rx_end_fill_tx && fd_h2_rbuf_free_sz( client->frame_tx ) ) fd_h2_rbuf_push( client->frame_tx, "", 1UL );
}

static ulong g_rx_msg_cnt;
static fd_grpc_h2_stream_t * g_rx_msg_closed_stream;

static void
cb_rx_msg( void *       app_ctx,
           void const * protobuf,
           ulong        protobuf_sz,
           ulong        request_ctx ) {
  (void)app_ctx; (void)protobuf; (void)protobuf_sz; (void)request_ctx;
  g_rx_msg_cnt++;
  if( !g_rx_msg_closed_stream ) return;
  FD_TEST( g_rx_msg_closed_stream->s.state==FD_H2_STREAM_STATE_CLOSED );
  ulong const tx_used = fd_h2_rbuf_used_sz( client->frame_tx );
  ulong const pending = client->request_tx_op->chunk_sz;
  client->conn->tx_wnd = g_rx_msg_closed_stream->s.tx_wnd = 100U;
  fd_h2_tx_op_copy( client->conn, &g_rx_msg_closed_stream->s, client->frame_tx, client->request_tx_op );
  FD_TEST( fd_h2_rbuf_used_sz( client->frame_tx )==tx_used && client->request_tx_op->chunk_sz==pending );
  while( fd_h2_rbuf_free_sz( client->frame_tx ) ) fd_h2_rbuf_push( client->frame_tx, "", 1UL );
}

static int g_rx_timeout_fill_tx;

static struct {
  int    deadline_kind;
  ulong  cnt;
} g_timeout_details;

static void
cb_rx_timeout( void * app_ctx,
               ulong  request_ctx,
               int    deadline_kind ) {
  (void)app_ctx;
  g_cb_request_ctx = request_ctx;
  g_timeout_details.deadline_kind = deadline_kind;
  g_timeout_details.cnt++;
  while( g_rx_timeout_fill_tx && fd_h2_rbuf_free_sz( client->frame_tx ) ) fd_h2_rbuf_push( client->frame_tx, "", 1UL );
}

static void
test_rx_frame( uint          type,
               uint          flags,
               uint          stream_id,
               uchar const * data,
               ulong         data_sz ) {
  fd_h2_tx( client->frame_rx, data, data_sz, type, flags, stream_id );
  fd_h2_rx( client->conn, client->frame_rx, client->frame_tx, client->frame_scratch,
            client->frame_scratch_max, &fd_grpc_client_h2_callbacks );
}

FD_UNIT_TEST( header_deadline ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  client->conn->peer_settings.max_concurrent_streams = 1U;

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
  fd_h2_stream_reset( &stream->s, client->conn );
  fd_grpc_client_stream_release( client, stream );
  FD_TEST( client->stream_cnt==0 );

  /* Test deadline firing */
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  stream = fd_grpc_client_stream_acquire( client, 0UL );
  ulong const stream_id = stream->s.stream_id;
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_HEADER, deadline );
  FD_TEST( client->stream_cnt==1 );
  FD_TEST( !fd_grpc_client_stream_acquire_is_safe( client ) );

  /* Deadlines fire mid field block, but not once the conn is closing */
  uchar const status = 0x88;
  test_rx_frame( FD_H2_FRAME_TYPE_HEADERS, 0U, (uint)stream_id, &status, 1UL );
  client->conn->flags |= FD_H2_CONN_FLAGS_SEND_GOAWAY;
  fd_grpc_client_service_streams( client, deadline+1L );
  FD_TEST( client->stream_cnt==1 );
  client->conn->flags &= (uchar)~FD_H2_CONN_FLAGS_SEND_GOAWAY;

  /* Queue the reset before rx_timeout fills the remaining TX space. */
  static uchar const filler[ 4096 ] = {0};
  ulong const prefix = client->frame_tx_buf_max-sizeof(fd_h2_rst_stream_t);
  fd_h2_rbuf_push( client->frame_tx, filler, prefix );
  g_rx_timeout_fill_tx = 1;
  fd_grpc_client_service_streams( client, deadline+1L );
  g_rx_timeout_fill_tx = 0;
  FD_TEST( client->stream_cnt==0 );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  stream = NULL; /* already freed */

  FD_TEST( !fd_h2_rbuf_free_sz( client->frame_tx ) );
  fd_h2_rbuf_skip( client->frame_tx, prefix );
  fd_h2_rst_stream_t rst_stream;
  fd_h2_rbuf_pop_copy( client->frame_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
  FD_TEST( rst_stream.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ) );
  FD_TEST( rst_stream.hdr.flags ==0 );
  FD_TEST( fd_uint_bswap( rst_stream.hdr.r_stream_id )==stream_id );
  FD_TEST( fd_uint_bswap( rst_stream.error_code      )==FD_H2_ERR_CANCEL );
  /* Late frames for the expired stream are dropped */
  test_rx_frame( FD_H2_FRAME_TYPE_CONTINUATION, FD_H2_FLAG_END_HEADERS, (uint)stream_id, &status, 1UL );
  test_rx_frame( FD_H2_FRAME_TYPE_HEADERS,      FD_H2_FLAG_END_HEADERS, (uint)stream_id, &status, 1UL );
  FD_TEST( !client->conn->flags && !client->conn->conn_error && fd_h2_rbuf_is_empty( client->frame_tx ) );
}

FD_UNIT_TEST( rx_end_deadline ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  client->conn->peer_settings.max_concurrent_streams = 1U;

  /* Deadline should not fire prior to expiration */
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
  fd_h2_stream_close_tx( &stream->s, client->conn );
  long const deadline = 1234L;
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, deadline );
  fd_grpc_client_service_streams( client, deadline-1L );
  FD_TEST( client->stream_cnt==1 );
  FD_TEST( !fd_grpc_client_stream_acquire_is_safe( client ) );

  /* Deadline should still fire after headers were received */
  fd_grpc_h2_cb_headers( client->conn, &stream->s, NULL, 0UL, FD_H2_FLAG_END_HEADERS );
  fd_grpc_client_service_streams( client, deadline+1L );
  FD_TEST( client->stream_cnt==0 );
  FD_TEST( client->conn->stream_active_cnt[1]==0U );
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );

  /* No frames on a stream closed by END_STREAM mid field block */
  fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );
  stream = fd_grpc_client_stream_acquire( client, 0UL );
  fd_h2_stream_close_tx( &stream->s, client->conn );
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, deadline );
  uchar const status = 0x88;
  test_rx_frame( FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_STREAM, stream->s.stream_id, &status, 1UL );
  stream->s.rx_wnd = 0U;
  fd_grpc_client_service_streams( client, deadline-1L );
  fd_grpc_client_service_streams( client, deadline+1L );
  FD_TEST( client->stream_cnt==0 && fd_h2_rbuf_is_empty( client->frame_tx ) );
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

/* END_STREAM on a HEADERS frame continued by CONTINUATION ends the
   request once the field block completes; END_STREAM on CONTINUATION
   is undefined and ignored.  A request the server ends before we
   half-closed it gets RST_STREAM(NO_ERROR), freeing its stream slot.
   c==0: split END_STREAM, c==1: same after we half-closed,
   c==2: DATA END_STREAM, c==3: END_STREAM on CONTINUATION,
   c==4: c==0 with rx_start filling all remaining TX space */

FD_UNIT_TEST( split_end_stream_headers ) {
  static uchar const hdrs[] = {0x88,0x5f,0x10,'a','p','p','l','i','c','a','t','i','o','n','/','g','r','p','c'};
  for( int c=0; c<5; c++ ) {
    fd_grpc_client_reset( client );
    test_grpc_client_mock_conn( client );
    client->conn->peer_settings.max_concurrent_streams = 1U;
    fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 0UL );
    if( c==1 ) fd_h2_stream_close_tx( &stream->s, client->conn );
    g_rx_end_cnt       = 0UL;
    g_rx_start_fill_tx = c==4;
    test_rx_frame( FD_H2_FRAME_TYPE_HEADERS, ( c<2 || c==4 ) ? FD_H2_FLAG_END_STREAM : 0U, 1U, hdrs, 1UL );
    FD_TEST( client->stream_cnt==1UL );
    static uchar const filler[ 4096 ] = {0};
    ulong const tx_prefix = c==4 ? client->frame_tx_buf_max-sizeof(fd_h2_ping_t) : 0UL;
    if( c==4 ) fd_h2_rbuf_push( client->frame_tx, filler, tx_prefix );
    test_rx_frame( FD_H2_FRAME_TYPE_CONTINUATION, FD_H2_FLAG_END_HEADERS|( c==3 ? FD_H2_FLAG_END_STREAM : 0U ),
                   1U, hdrs+1, sizeof(hdrs)-1UL );
    if( c==2 ) test_rx_frame( FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_END_STREAM, 1U, hdrs, 0UL );
    ulong const live = (ulong)( c==3 );
    FD_TEST( !client->conn->conn_error && g_rx_end_cnt==1UL-live );
    FD_TEST( client->stream_cnt==live && client->conn->stream_active_cnt[1]==(uint)live );
    if( c==4 ) fd_h2_rbuf_skip( client->frame_tx, tx_prefix );
    fd_h2_rst_stream_t rst = {0};
    if( c==0 || c==2 || c==4 ) fd_h2_rbuf_pop_copy( client->frame_tx, &rst, sizeof(rst) );
    if( c==4 ) fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );
    FD_TEST( fd_uint_bswap( rst.error_code )==FD_H2_SUCCESS && fd_h2_rbuf_is_empty( client->frame_tx ) );
    FD_TEST( fd_grpc_client_stream_acquire_is_safe( client )==!live );
  }
  g_rx_start_fill_tx = 0;
}

/* A final DATA frame may wrap after a complete message, so its first
   callback can fill TX before the END_STREAM callback.  A pending send
   must not resume after the reset, even when flow-control credit returns. */

FD_UNIT_TEST( data_end_stream_before_callbacks ) {
  static uchar const messages[] = {0,0,0,0,1,'a',0,0,0,0,1,'b'};
  static uchar const request[]  = {0,0,0,0,3,'a','b','c'};
  static uchar const filler[ 4096 ] = {0};
  for( int c=0; c<4; c++ ) {
    fd_grpc_client_reset( client );
    test_grpc_client_mock_conn( client );
    client->conn->peer_settings.max_concurrent_streams = 1U;
    fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, 1UL );
    stream->hdrs.h2_status     = 200U;
    stream->hdrs.is_grpc_proto = 1U;
    g_rx_msg_closed_stream = stream;
    g_rx_msg_cnt           = 0UL;
    g_rx_end_cnt           = 0UL;
    g_rx_end_fill_tx       = 1;

    /* One complete outbound DATA frame precedes the reset.  The rest of
       this request remains parked until the response cancels it. */
    client->conn->tx_wnd = stream->s.tx_wnd = 1U;
    fd_h2_tx_op_init( client->request_tx_op, request, sizeof(request), 0U );
    fd_h2_tx_op_copy( client->conn, &stream->s, client->frame_tx, client->request_tx_op );
    FD_TEST( client->request_tx_op->chunk_sz==sizeof(request)-1UL );
    ulong const tx_prefix = client->frame_tx_buf_max-2UL*sizeof(fd_h2_window_update_t);
    fd_h2_rbuf_push( client->frame_tx, filler, tx_prefix-fd_h2_rbuf_used_sz( client->frame_tx ) );

    if( c==1 ) {
      ulong const offset = client->frame_rx_buf_max-sizeof(fd_h2_frame_hdr_t)-6UL;
      fd_h2_rbuf_push( client->frame_rx, filler, offset );
      fd_h2_rbuf_skip( client->frame_rx, offset );
    }
    uchar response[ sizeof(messages) ];
    memcpy( response, messages, sizeof(messages) );
    ulong response_sz = sizeof(messages);
    if( c>=2 ) {
      ulong const offset = c==2 ? 0UL : 6UL;
      fd_grpc_hdr_t oversized = { .msg_sz = fd_uint_bswap( (uint)client->frame_rx_buf_max ) };
      memcpy( response+offset, &oversized, sizeof(oversized) );
      response_sz = offset+sizeof(oversized);
    }
    test_rx_frame( FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_END_STREAM, stream->s.stream_id, response, response_sz );
    FD_TEST( !client->conn->conn_error && !client->stream_cnt && !client->conn->stream_active_cnt[1] );
    FD_TEST( g_rx_msg_cnt==( c==2 ? 0UL : c==3 ? 1UL : 2UL ) && g_rx_end_cnt==1UL );
    FD_TEST( !client->request_stream && !client->request_tx_op->chunk_sz );

    fd_h2_frame_hdr_t data_hdr;
    fd_h2_rbuf_pop_copy( client->frame_tx, &data_hdr, sizeof(data_hdr) );
    FD_TEST( data_hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_DATA, 1UL ) );
    fd_h2_rbuf_skip( client->frame_tx, tx_prefix-sizeof(data_hdr) );
    fd_h2_rst_stream_t rst;
    fd_h2_rbuf_pop_copy( client->frame_tx, &rst, sizeof(rst) );
    FD_TEST( rst.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ) );
    FD_TEST( fd_uint_bswap( rst.error_code )==( c==2 ? FD_H2_ERR_INTERNAL : FD_H2_SUCCESS ) );
    fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );
    FD_TEST( fd_grpc_client_stream_acquire_is_safe( client ) );
  }
  g_rx_msg_closed_stream = NULL;
  g_rx_end_fill_tx       = 0;
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

  /* Corrupt headers once END_STREAM closed the stream: no RST_STREAM */
  ulong const rx_end_cnt = g_rx_end_cnt;
  stream = fd_grpc_client_stream_acquire( client, 2UL );
  fd_h2_stream_close_tx( &stream->s, client->conn );
  test_rx_frame( FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_STREAM|FD_H2_FLAG_END_HEADERS, stream->s.stream_id, (uchar const *)"corrupt", 7UL );
  FD_TEST( g_rx_end_cnt==rx_end_cnt+1UL && !client->stream_cnt && fd_h2_rbuf_is_empty( client->frame_tx ) );

  /* Zero stream WINDOW_UPDATE: one RST_STREAM, request ended */
  stream = fd_grpc_client_stream_acquire( client, 3UL );
  uint const zero = 0U;
  test_rx_frame( FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, stream->s.stream_id, (uchar const *)&zero, 4UL );
  FD_TEST( g_rx_end_cnt==rx_end_cnt+2UL && !client->stream_cnt && !client->conn->stream_active_cnt[1] && !client->request_stream );
  FD_TEST( !client->conn->conn_error && fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(fd_h2_rst_stream_t) );
  fd_h2_rbuf_pop_copy( client->frame_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
  FD_TEST( fd_uint_bswap( rst_stream.error_code )==FD_H2_ERR_PROTOCOL );
}

FD_UNIT_TEST( tls_socket_eof_disconnects ) {
  fd_grpc_client_reset( client );

  fd_tls_t tls = {0};
  fd_tlsrec_conn_t tls_conn[1];
  fd_tlsrec_conn_init( tls_conn, &tls, 0 );
  tls_conn->hs.base.state = FD_TLS_HS_CONNECTED;

  int sock[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM, 0, sock ) );
  FD_TEST( !close( sock[1] ) );

  int charge_busy = 0;
  FD_TEST( fd_grpc_client_rxtx_tls( client, tls_conn, sock[0], fd_log_wallclock(), &charge_busy )==-1 );
  FD_TEST( !close( sock[0] ) );
}

FD_UNIT_TEST( tls_record_error_disconnects_during_handshake ) {
  fd_grpc_client_reset( client );

  fd_tls_t tls = {0};
  fd_tlsrec_conn_t tls_conn[1];
  fd_tlsrec_conn_init( tls_conn, &tls, 0 );
  tls_conn->hs.base.state = FD_TLS_HS_WAIT_SH;
  FD_TEST( !fd_tlsrec_conn_is_ready( tls_conn ) );
  FD_TEST( !fd_tlsrec_conn_is_failed( tls_conn ) );

  int sock[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM, 0, sock ) );

  uchar const bad_record[] = { FD_TLS_REC_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x00 };
  FD_TEST( write( sock[1], bad_record, sizeof(bad_record) )==(long)sizeof(bad_record) );

  int charge_busy = 0;
  FD_TEST( fd_grpc_client_rxtx_tls( client, tls_conn, sock[0], fd_log_wallclock(), &charge_busy )==-1 );
  FD_TEST( !close( sock[0] ) );
  FD_TEST( !close( sock[1] ) );
}

FD_UNIT_TEST( tls_no_alpn_refuses_h2 ) {
  fd_grpc_client_reset( client );

  fd_tls_t tls = {0};
  fd_tlsrec_conn_t tls_conn[1];
  fd_tlsrec_conn_init( tls_conn, &tls, 0 );
  tls_conn->hs.base.state = FD_TLS_HS_CONNECTED;
  FD_TEST( fd_tlsrec_conn_is_ready( tls_conn ) );
  FD_TEST( !tls_conn->hs.cli.alpn_negotiated );

  int sock[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM, 0, sock ) );

  int charge_busy = 0;
  FD_TEST( fd_grpc_client_rxtx_tls( client, tls_conn, sock[0], fd_log_wallclock(), &charge_busy )==-1 );

  tls_conn->hs.cli.alpn_negotiated = 1;
  FD_TEST( fd_grpc_client_rxtx_tls( client, tls_conn, sock[0], fd_log_wallclock(), &charge_busy )==0 );

  FD_TEST( !close( sock[0] ) );
  FD_TEST( !close( sock[1] ) );
}

/* test_tls_install_keys puts conn into the connected state with the
   given application traffic secrets (RFC 8446 section 7.3), skipping
   the handshake. */

static void
test_tls_install_keys( fd_tlsrec_conn_t * conn,
                       uchar const        write_secret[ static 32 ],
                       uchar const        read_secret [ static 32 ] ) {
  fd_tlsrec_keys_t * keys = &conn->keys[1];
  fd_memcpy( keys->write_secret, write_secret, 32UL );
  fd_memcpy( keys->read_secret,  read_secret,  32UL );
  fd_tls_hkdf_expand_label( keys->write_key, 16UL, keys->write_secret, "key", 3UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( keys->write_iv,  12UL, keys->write_secret, "iv",  2UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( keys->read_key,  16UL, keys->read_secret,  "key", 3UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( keys->read_iv,   12UL, keys->read_secret,  "iv",  2UL, NULL, 0UL );
  fd_aes_gcm_init( &keys->write_gcm, keys->write_key, 16UL, keys->write_iv );
  fd_aes_gcm_init( &keys->read_gcm,  keys->read_key,  16UL, keys->read_iv  );
  conn->read_seq  = 0UL;
  conn->write_seq = 0UL;
  conn->hs.base.state = FD_TLS_HS_CONNECTED;
}

/* A send parked on EAGAIN must not stop RX: a KeyUpdate from the peer
   is processed and its reply is appended behind the parked record. */

FD_UNIT_TEST( tls_rx_continues_while_send_blocked ) {
  fd_grpc_client_reset( client );

  fd_tls_t tls = {0};
  fd_tlsrec_conn_t cli[1];
  fd_tlsrec_conn_t srv[1];
  fd_tlsrec_conn_init( cli, &tls, 0 );
  fd_tlsrec_conn_init( srv, &tls, 1 );
  uchar secret_a[ 32 ]; uchar secret_b[ 32 ];
  for( ulong i=0UL; i<32UL; i++ ) { secret_a[i] = (uchar)(0xa0+i); secret_b[i] = (uchar)(0xb0+i); }
  test_tls_install_keys( cli, secret_a, secret_b );
  test_tls_install_keys( srv, secret_b, secret_a );
  cli->hs.cli.alpn_negotiated = 1;
  FD_TEST( fd_tlsrec_conn_is_ready( cli ) );
  FD_TEST( fd_tlsrec_conn_is_ready( srv ) );

  int sock[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM, 0, sock ) );
  int sndbuf = 4096;
  FD_TEST( !setsockopt( sock[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int) ) );

  /* Fill the socket send buffer so the next send blocks */
  static uchar junk[ 4096 ];
  ulong filled = 0UL;
  for(;;) {
    long n = send( sock[0], junk, sizeof(junk), MSG_NOSIGNAL|MSG_DONTWAIT );
    if( n<0L ) { FD_TEST( errno==EAGAIN || errno==EWOULDBLOCK ); break; }
    filled += (ulong)n;
  }
  FD_TEST( filled );

  /* Park an encrypted record */
  fd_tlsrec_sock_t * tls_sock = client->tls_sock;
  uchar const parked_msg[] = "parked";
  ulong consumed;
  FD_TEST( fd_tlsrec_sock_tx( tls_sock, cli, sock[0], parked_msg, sizeof(parked_msg)-1UL, &consumed )==0 );
  FD_TEST( consumed==sizeof(parked_msg)-1UL );
  ulong parked_sz = tls_sock->tx_sz;
  FD_TEST( parked_sz );
  FD_TEST( fd_grpc_client_tls_tx_pending( client ) );
  FD_TEST( tls_sock->tx_off==0UL );

  /* Peer requests a key update */
  uchar ku[ 64 ];
  ulong ku_sz = sizeof(ku);
  FD_TEST( fd_tlsrec_conn_key_update( srv, ku, &ku_sz, 1 )==FD_TLSREC_SUCCESS );
  FD_TEST( ku_sz );
  FD_TEST( write( sock[1], ku, ku_sz )==(long)ku_sz );

  int charge_busy = 0;
  FD_TEST( fd_grpc_client_rxtx_tls( client, cli, sock[0], fd_log_wallclock(), &charge_busy )==0 );
  FD_TEST( charge_busy );
  FD_TEST( !fd_grpc_client_tls_rx_pending( client ) );
  FD_TEST( tls_sock->tx_off==0UL );
  FD_TEST( tls_sock->tx_sz==parked_sz+ku_sz );
  FD_TEST( !cli->write_seq ); /* rotated */

  /* The peer still is not reading.  A step that moves nothing is not
     busy, even with HTTP/2 output queued behind the parked record;
     otherwise the tile would spin on EAGAIN instead of waiting for
     EPOLLOUT. */
  static uchar const h2_junk[] = "h2";
  fd_h2_rbuf_push( client->frame_tx, h2_junk, sizeof(h2_junk) );
  charge_busy = 0;
  FD_TEST( fd_grpc_client_rxtx_tls( client, cli, sock[0], fd_log_wallclock(), &charge_busy )==0 );
  FD_TEST( !charge_busy );
  FD_TEST( tls_sock->tx_off==0UL );
  FD_TEST( tls_sock->tx_sz==parked_sz+ku_sz );
  FD_TEST( fd_h2_rbuf_used_sz( client->frame_tx )>=sizeof(h2_junk) );

  /* Peer drains; parked record then reply go out in order and decrypt
     under the right keys */
  ulong drained = 0UL;
  while( drained<filled ) {
    long n = recv( sock[1], junk, fd_ulong_min( sizeof(junk), filled-drained ), MSG_DONTWAIT );
    FD_TEST( n>0L );
    drained += (ulong)n;
  }
  FD_TEST( fd_grpc_client_tls_flush( client, sock[0] )==0 );
  FD_TEST( !fd_grpc_client_tls_tx_pending( client ) );

  uchar wire[ 256 ];
  long wire_sz = recv( sock[1], wire, sizeof(wire), MSG_DONTWAIT );
  FD_TEST( wire_sz==(long)( parked_sz+ku_sz ) );

  fd_tlsrec_slice_t wire_slice[1];
  fd_tlsrec_slice_init( wire_slice, wire, (ulong)wire_sz );
  uchar srv_tx[ 64 ]; ulong srv_tx_sz = sizeof(srv_tx);
  uchar app_rx[ 64 ]; ulong app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, wire_slice, srv_tx, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( !srv_tx_sz );
  FD_TEST( app_rx_sz==sizeof(parked_msg)-1UL );
  FD_TEST( !memcmp( app_rx, parked_msg, app_rx_sz ) );
  FD_TEST( !srv->read_seq ); /* rotated by the client's reply */

  /* Next record uses the new client write key */
  uchar const next_msg[] = "after";
  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, (uchar *)next_msg, sizeof(next_msg)-1UL );
  ulong next_sz = sizeof(wire);
  FD_TEST( fd_tlsrec_conn_tx( cli, wire, &next_sz, app_tx )==FD_TLSREC_SUCCESS );
  fd_tlsrec_slice_init( wire_slice, wire, next_sz );
  srv_tx_sz = sizeof(srv_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, wire_slice, srv_tx, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( app_rx_sz==sizeof(next_msg)-1UL );
  FD_TEST( !memcmp( app_rx, next_msg, app_rx_sz ) );

  FD_TEST( !close( sock[0] ) );
  FD_TEST( !close( sock[1] ) );
  fd_grpc_client_reset( client );
}

/* Deadlines fire on time even if frame_tx has no room for RST_STREAM.
   Expired requests get no further callbacks or DATA, and RST_STREAM
   waits for room.  wnd: unrelated stream wanting a WINDOW_UPDATE,
   peer: reset by peer, bad: invalid headers, live: uploading */

FD_UNIT_TEST( request_deadlines_under_tx_backpressure ) {
  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );
  fd_grpc_h2_stream_t * wnd  = fd_grpc_client_stream_acquire( client, 0UL );
  fd_grpc_h2_stream_t * peer = fd_grpc_client_stream_acquire( client, 0UL );
  fd_grpc_h2_stream_t * bad  = fd_grpc_client_stream_acquire( client, 0UL );
  fd_grpc_h2_stream_t * live = fd_grpc_client_stream_acquire( client, 0UL );
  wnd->s.rx_wnd = live->s.rx_wnd = 64U;
  fd_h2_tx_op_init( client->request_tx_op, client->frame_scratch, 1UL, 0U );
  fd_grpc_client_deadline_set( peer, FD_GRPC_DEADLINE_RX_END, 1234L );
  fd_grpc_client_deadline_set( bad,  FD_GRPC_DEADLINE_HEADER, 1234L );
  fd_grpc_client_deadline_set( live, FD_GRPC_DEADLINE_HEADER, 1234L );
  fd_h2_rbuf_push( client->frame_tx, client->frame_scratch, client->frame_tx_buf_max-sizeof(fd_h2_rst_stream_t)+1UL );

  g_rx_end_cnt = g_timeout_details.cnt = 0UL;
  fd_grpc_client_service_streams( client, 1234L );
  FD_TEST( g_timeout_details.cnt==3UL && client->stream_cnt==4UL && client->conn->stream_active_cnt[1]==4U );
  FD_TEST( !client->request_tx_op->chunk_sz && fd_grpc_client_next_deadline( client )==LONG_MAX );

  /* Due once frame_tx has room (unless the conn is closing) */
  fd_h2_rbuf_skip( client->frame_tx, fd_h2_rbuf_used_sz( client->frame_tx ) );
  FD_TEST( !fd_grpc_client_next_deadline( client ) );
  client->conn->flags = FD_H2_CONN_FLAGS_SEND_GOAWAY;
  FD_TEST( fd_grpc_client_next_deadline( client )==LONG_MAX );
  client->conn->flags = 0;
  test_rx_frame( FD_H2_FRAME_TYPE_HEADERS,    FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM, live->s.stream_id, (uchar const *)"\x88", 1UL );
  test_rx_frame( FD_H2_FRAME_TYPE_DATA,       FD_H2_FLAG_END_STREAM,                        peer->s.stream_id, (uchar const *)"", 0UL );
  test_rx_frame( FD_H2_FRAME_TYPE_RST_STREAM, 0U,                                           peer->s.stream_id, (uchar const *)"\0\0\0\0", 4UL );
  test_rx_frame( FD_H2_FRAME_TYPE_HEADERS,    FD_H2_FLAG_END_HEADERS,                       bad->s.stream_id,  (uchar const *)"corrupt", 7UL );
  FD_TEST( !g_rx_end_cnt && client->stream_cnt==2UL && fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(fd_h2_rst_stream_t) );

  fd_grpc_client_service_streams( client, 1235L );
  fd_h2_rst_stream_t tx[3]; /* bad: RST_STREAM(PROTOCOL_ERROR), wnd: WINDOW_UPDATE, live: RST_STREAM(CANCEL) */
  FD_TEST( g_timeout_details.cnt==3UL && fd_grpc_client_next_deadline( client )==LONG_MAX && fd_h2_rbuf_used_sz( client->frame_tx )==sizeof(tx) );
  fd_h2_rbuf_pop_copy( client->frame_tx, tx, sizeof(tx) );
  FD_TEST( tx[2].error_code==fd_uint_bswap( FD_H2_ERR_CANCEL ) );
  FD_TEST( !fd_grpc_client_stream_acquire( client, 0UL )->rst_pending ); /* pool reuse */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar client_mem[ 262144 ] __attribute__((aligned(128)));
  ulong const buf_max = 4096UL;
  FD_TEST( fd_grpc_client_footprint( buf_max )<=sizeof(client_mem) );

  fd_grpc_client_callbacks_t callbacks = {
    .rx_start   = cb_rx_start,
    .rx_msg     = cb_rx_msg,
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
