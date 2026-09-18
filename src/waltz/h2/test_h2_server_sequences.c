#include "fd_h2_callback.h"
#include "fd_h2_conn.h"
#include "fd_h2_stream.h"
#include "fd_h2_tx.h"
#include "fd_hpack_wr.h"

#define TEST_H2_SRV_SEQ_BUF_MAX           512UL
#define TEST_H2_SRV_SEQ_SCRATCH_MAX       512UL
#define TEST_H2_SRV_SEQ_HEADER_MAX        128UL
#define TEST_H2_SRV_SEQ_BODY_MAX          128UL
#define TEST_H2_SRV_SEQ_FRAME_PAYLOAD_MAX 256UL

enum {
  TEST_H2_SRV_SEQ_PAYLOAD_EXACT    = 0,
  TEST_H2_SRV_SEQ_PAYLOAD_EMPTY    = 1,
  TEST_H2_SRV_SEQ_PAYLOAD_NONEMPTY = 2
};

static uchar const TEST_H2_SRV_SEQ_STATUS_200[] = { 0x88 };
static uchar const TEST_H2_SRV_SEQ_OK[] = "OK";

struct test_h2_srv_seq_request {
  uint  stream_id;
  ulong header_sz;
  uchar header[ TEST_H2_SRV_SEQ_HEADER_MAX ];
  ulong body_sz;
  uchar body[ TEST_H2_SRV_SEQ_BODY_MAX ];
};

typedef struct test_h2_srv_seq_request test_h2_srv_seq_request_t;

struct test_h2_srv_seq_request_expect {
  ulong         completed_cnt;
  uint          stream_id;
  uchar const * header;
  ulong         header_sz;
  uchar const * body;
  ulong         body_sz;
};

typedef struct test_h2_srv_seq_request_expect test_h2_srv_seq_request_expect_t;

struct test_h2_srv_seq_fixture {
  fd_h2_stream_t           stream[1];
  fd_h2_tx_op_t            tx_op[1];
  fd_h2_rbuf_t *           rbuf_tx;
  ulong                    conn_established_cnt;
  ulong                    rst_stream_cnt;
  uint                     rst_stream_err;
  int                      rst_stream_closed_by;
  test_h2_srv_seq_request_t current;
  test_h2_srv_seq_request_t last_completed;
  ulong                    request_complete_cnt;
};

typedef struct test_h2_srv_seq_fixture test_h2_srv_seq_fixture_t;

struct test_h2_srv_seq_harness {
  fd_h2_conn_t              conn[1];
  fd_h2_callbacks_t         cb[1];
  fd_h2_rbuf_t              rbuf_rx[1];
  fd_h2_rbuf_t              rbuf_tx[1];
  uchar                     rx_mem[ TEST_H2_SRV_SEQ_BUF_MAX ];
  uchar                     tx_mem[ TEST_H2_SRV_SEQ_BUF_MAX ];
  uchar                     scratch[ TEST_H2_SRV_SEQ_SCRATCH_MAX ];
  test_h2_srv_seq_fixture_t fixture[1];
};

typedef struct test_h2_srv_seq_harness test_h2_srv_seq_harness_t;

static fd_h2_stream_t *
test_h2_srv_seq_stream_create( fd_h2_conn_t * conn,
                               uint           stream_id ) {
  (void)stream_id;
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  fd_h2_stream_t * stream = fixture->stream;
  if( FD_UNLIKELY( stream->stream_id ) ) return NULL;
  fd_h2_stream_init( stream );
  FD_TEST( !fixture->current.stream_id );
  return stream;
}

static fd_h2_stream_t *
test_h2_srv_seq_stream_query( fd_h2_conn_t * conn,
                              uint           stream_id ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  fd_h2_stream_t * stream = fixture->stream;
  if( stream->stream_id!=stream_id ) return NULL;
  return stream;
}

static void
test_h2_srv_seq_response_continue( fd_h2_conn_t * conn ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  fd_h2_stream_t * stream = fixture->stream;
  if( !stream->stream_id ) return;

  fd_h2_tx_op_copy( conn, stream, fixture->rbuf_tx, fixture->tx_op );
  if( stream->state==FD_H2_STREAM_STATE_CLOSED ) {
    fd_memset( fixture->tx_op,  0, sizeof(fixture->tx_op [0]) );
    fd_memset( fixture->stream, 0, sizeof(fixture->stream[0]) );
  }
}

static void
test_h2_srv_seq_response_init( fd_h2_conn_t *   conn,
                               fd_h2_stream_t * stream ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;

  fd_h2_tx( fixture->rbuf_tx,
            TEST_H2_SRV_SEQ_STATUS_200,
            sizeof(TEST_H2_SRV_SEQ_STATUS_200),
            FD_H2_FRAME_TYPE_HEADERS,
            FD_H2_FLAG_END_HEADERS,
            stream->stream_id );

  fd_h2_tx_op_init( fixture->tx_op,
                    TEST_H2_SRV_SEQ_OK,
                    sizeof(TEST_H2_SRV_SEQ_OK)-1UL,
                    FD_H2_FLAG_END_STREAM );
  test_h2_srv_seq_response_continue( conn );
}

static void
test_h2_srv_seq_complete_current( fd_h2_conn_t *   conn,
                                  fd_h2_stream_t * stream ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  fixture->last_completed = fixture->current;
  fixture->request_complete_cnt++;
  FD_TEST( fixture->last_completed.stream_id==stream->stream_id );
  fd_memset( &fixture->current, 0, sizeof(fixture->current) );
  test_h2_srv_seq_response_init( conn, stream );
}

static void
test_h2_srv_seq_conn_established( fd_h2_conn_t * conn ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  fixture->conn_established_cnt++;
}

static void
test_h2_srv_seq_capture( test_h2_srv_seq_request_t * req,
                         uint                        stream_id,
                         void const *                data,
                         ulong                       data_sz,
                         uchar *                     buf,
                         ulong *                     buf_sz,
                         ulong                       buf_max ) {
  if( !req->stream_id ) req->stream_id = stream_id;
  FD_TEST( req->stream_id==stream_id );
  FD_TEST( *buf_sz + data_sz <= buf_max );

  fd_memcpy( buf + *buf_sz, data, data_sz );
  *buf_sz += data_sz;
}

static void
test_h2_srv_seq_capture_payload( fd_h2_conn_t *   conn,
                                 fd_h2_stream_t * stream,
                                 void const *     data,
                                 ulong            data_sz,
                                 ulong            flags,
                                 uchar *          buf,
                                 ulong *          buf_sz,
                                 ulong            buf_max ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  test_h2_srv_seq_request_t * req = &fixture->current;

  test_h2_srv_seq_capture( req, stream->stream_id, data, data_sz, buf, buf_sz, buf_max );

  if( flags & FD_H2_FLAG_END_STREAM ) {
    test_h2_srv_seq_complete_current( conn, stream );
  }
}

static void
test_h2_srv_seq_headers( fd_h2_conn_t *   conn,
                         fd_h2_stream_t * stream,
                         void const *     data,
                         ulong            data_sz,
                         ulong            flags ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  test_h2_srv_seq_request_t * req = &fixture->current;

  test_h2_srv_seq_capture_payload( conn,
                                   stream,
                                   data,
                                   data_sz,
                                   flags,
                                   req->header,
                                   &req->header_sz,
                                   sizeof(req->header) );
}

static void
test_h2_srv_seq_data( fd_h2_conn_t *   conn,
                      fd_h2_stream_t * stream,
                      void const *     data,
                      ulong            data_sz,
                      ulong            flags ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  test_h2_srv_seq_request_t * req = &fixture->current;

  test_h2_srv_seq_capture_payload( conn,
                                   stream,
                                   data,
                                   data_sz,
                                   flags,
                                   req->body,
                                   &req->body_sz,
                                   sizeof(req->body) );
}

static void
test_h2_srv_seq_window_update( fd_h2_conn_t * conn,
                               uint           increment ) {
  (void)increment;
  test_h2_srv_seq_response_continue( conn );
}

static void
test_h2_srv_seq_stream_window_update( fd_h2_conn_t *   conn,
                                      fd_h2_stream_t * stream,
                                      uint             increment ) {
  (void)stream;
  (void)increment;
  test_h2_srv_seq_response_continue( conn );
}

static void
test_h2_srv_seq_rst_stream( fd_h2_conn_t *   conn,
                            fd_h2_stream_t * stream,
                            uint             error_code,
                            int              closed_by ) {
  test_h2_srv_seq_fixture_t * fixture = conn->ctx;
  fixture->rst_stream_cnt++;
  fixture->rst_stream_err       = error_code;
  fixture->rst_stream_closed_by = closed_by;
  fd_memset( fixture->tx_op,   0, sizeof(fixture->tx_op  [0]) );
  fd_memset( fixture->stream,  0, sizeof(fixture->stream [0]) );
  fd_memset( &fixture->current, 0, sizeof(fixture->current) );
  (void)stream;
}

static void
test_h2_srv_seq_fixture_init( test_h2_srv_seq_fixture_t * fixture,
                              fd_h2_conn_t *             conn,
                              fd_h2_callbacks_t *        cb,
                              fd_h2_rbuf_t *             rbuf_tx ) {
  fd_memset( fixture, 0, sizeof(*fixture) );

  fd_h2_conn_init_server( conn );
  conn->self_settings.max_concurrent_streams = 1U;
  conn->ctx = fixture;
  fixture->rbuf_tx = rbuf_tx;

  fd_h2_callbacks_init( cb );
  cb->stream_create        = test_h2_srv_seq_stream_create;
  cb->stream_query         = test_h2_srv_seq_stream_query;
  cb->conn_established     = test_h2_srv_seq_conn_established;
  cb->headers              = test_h2_srv_seq_headers;
  cb->data                 = test_h2_srv_seq_data;
  cb->rst_stream           = test_h2_srv_seq_rst_stream;
  cb->window_update        = test_h2_srv_seq_window_update;
  cb->stream_window_update = test_h2_srv_seq_stream_window_update;
}

static void
test_h2_srv_seq_harness_init( test_h2_srv_seq_harness_t * harness ) {
  fd_memset( harness, 0, sizeof(*harness) );
  fd_h2_rbuf_init( harness->rbuf_rx, harness->rx_mem, sizeof(harness->rx_mem) );
  fd_h2_rbuf_init( harness->rbuf_tx, harness->tx_mem, sizeof(harness->tx_mem) );
  test_h2_srv_seq_fixture_init( harness->fixture, harness->conn, harness->cb, harness->rbuf_tx );
}

static void
test_h2_srv_seq_send_frame( test_h2_srv_seq_harness_t * harness,
                            uint                        frame_type,
                            uint                        frame_flags,
                            uint                        stream_id,
                            void const *                payload,
                            ulong                       payload_sz ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( frame_type, payload_sz ),
    .flags       = (uchar)frame_flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };

  fd_h2_rbuf_push( harness->rbuf_rx, &hdr, sizeof(hdr) );
  if( payload_sz ) fd_h2_rbuf_push( harness->rbuf_rx, payload, payload_sz );
}

static void
test_h2_srv_seq_service_rx( test_h2_srv_seq_harness_t * harness ) {
  fd_h2_rx( harness->conn,
            harness->rbuf_rx,
            harness->rbuf_tx,
            harness->scratch,
            sizeof(harness->scratch),
            harness->cb );
}

static ulong
test_h2_srv_seq_build_request_headers( uchar * out,
                                       ulong   out_max ) {
  fd_h2_rbuf_t rbuf[1];
  fd_h2_rbuf_init( rbuf, out, out_max );

  FD_TEST( fd_hpack_wr_method_post( rbuf ) );
  FD_TEST( fd_hpack_wr_scheme( rbuf, 0 ) );
  FD_TEST( fd_hpack_wr_authority( rbuf, "127.0.0.1", 9UL, 8080U ) );
  FD_TEST( fd_hpack_wr_path( rbuf, "/", 1UL ) );

  return fd_h2_rbuf_used_sz( rbuf );
}

static ulong
test_h2_srv_seq_pop_frame( fd_h2_rbuf_t *   rbuf,
                           fd_h2_frame_hdr_t * hdr,
                           uchar *            payload,
                           ulong              payload_max ) {
  fd_h2_rbuf_pop_copy( rbuf, hdr, sizeof(*hdr) );
  ulong payload_sz = fd_h2_frame_length( hdr->typlen );
  FD_TEST( payload_sz <= payload_max );
  if( payload_sz ) fd_h2_rbuf_pop_copy( rbuf, payload, payload_sz );
  return payload_sz;
}

static void
test_h2_srv_seq_expect_response_frame( test_h2_srv_seq_harness_t * harness,
                                       uint                        frame_type,
                                       uint                        frame_flags,
                                       uint                        stream_id,
                                       uint                        payload_mode,
                                       uchar const *               payload,
                                       ulong                       payload_sz ) {
  fd_h2_frame_hdr_t hdr;
  uchar frame_payload[ TEST_H2_SRV_SEQ_FRAME_PAYLOAD_MAX ];
  ulong frame_payload_sz = test_h2_srv_seq_pop_frame( harness->rbuf_tx,
                                                      &hdr,
                                                      frame_payload,
                                                      sizeof(frame_payload) );

  FD_TEST( fd_h2_frame_type( hdr.typlen )==frame_type );
  FD_TEST( hdr.flags==frame_flags );
  FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==stream_id );

  switch( payload_mode ) {
  case TEST_H2_SRV_SEQ_PAYLOAD_EXACT:
    FD_TEST( frame_payload_sz==payload_sz );
    if( payload_sz ) FD_TEST( fd_memeq( frame_payload, payload, payload_sz ) );
    break;
  case TEST_H2_SRV_SEQ_PAYLOAD_EMPTY:
    FD_TEST( frame_payload_sz==0UL );
    break;
  case TEST_H2_SRV_SEQ_PAYLOAD_NONEMPTY:
    FD_TEST( frame_payload_sz>0UL );
    break;
  default:
    FD_TEST( 0 );
  }
}

static void
test_h2_srv_seq_expect_request( test_h2_srv_seq_harness_t const *       harness,
                                test_h2_srv_seq_request_expect_t const * expected ) {
  test_h2_srv_seq_fixture_t const * fixture = harness->fixture;

  FD_TEST( fixture->conn_established_cnt==1UL );
  FD_TEST( fixture->request_complete_cnt==expected->completed_cnt );
  FD_TEST( fixture->last_completed.stream_id==expected->stream_id );
  FD_TEST( fixture->last_completed.header_sz==expected->header_sz );
  FD_TEST( fd_memeq( fixture->last_completed.header, expected->header, expected->header_sz ) );
  FD_TEST( fixture->last_completed.body_sz==expected->body_sz );
  FD_TEST( fd_memeq( fixture->last_completed.body, expected->body, expected->body_sz ) );
  FD_TEST( !fixture->current.stream_id );
  FD_TEST( fixture->stream->stream_id==0U );
}

static void
test_h2_srv_seq_expect_rx_empty( test_h2_srv_seq_harness_t const * harness ) {
  FD_TEST( fd_h2_rbuf_used_sz( harness->rbuf_rx )==0UL );
}

static void
test_h2_srv_seq_expect_tx_empty( test_h2_srv_seq_harness_t const * harness ) {
  FD_TEST( fd_h2_rbuf_used_sz( harness->rbuf_tx )==0UL );
}

static void
test_h2_srv_seq_handshake( test_h2_srv_seq_harness_t * harness ) {
  fd_h2_tx_control( harness->conn, harness->rbuf_tx, harness->cb );
  FD_TEST( fd_h2_rbuf_used_sz( harness->rbuf_tx )>0UL );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_SETTINGS,
                                         0U,
                                         0U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_NONEMPTY,
                                         NULL,
                                         0UL );
  test_h2_srv_seq_expect_tx_empty( harness );

  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, NULL, 0UL );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_SETTINGS,
                                         FD_H2_FLAG_ACK,
                                         0U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EMPTY,
                                         NULL,
                                         0UL );
  test_h2_srv_seq_expect_tx_empty( harness );

  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_tx_empty( harness );
}

FD_UNIT_TEST( h2_server_stream_accounting ) {
  test_h2_srv_seq_harness_t harness[1];
  uchar request_headers[ TEST_H2_SRV_SEQ_HEADER_MAX ] = {0};
  uchar ping_payload[ 8 ] = { 'p', 'a', 'd', 'p', 'o', 'c', '!', '!' };

  const uchar HELLO[] = "HELLO";
  const uchar WORKS[] = "WORKS";
  const uchar HELLOWORKS[] = "HELLOWORKS";

  ulong request_headers_sz =
    test_h2_srv_seq_build_request_headers( request_headers, sizeof(request_headers) );
  FD_TEST( request_headers_sz>0UL );

  test_h2_srv_seq_request_expect_t request0 = {
    .completed_cnt = 1UL,
    .stream_id     = 33U,
    .header        = request_headers,
    .header_sz     = request_headers_sz,
    .body          = HELLOWORKS,
    .body_sz       = sizeof(HELLOWORKS)-1UL
  };
  test_h2_srv_seq_request_expect_t request1 = {
    .completed_cnt = 2UL,
    .stream_id     = 35U,
    .header        = request_headers,
    .header_sz     = request_headers_sz,
    .body          = HELLOWORKS,
    .body_sz       = sizeof(HELLOWORKS)-1UL
  };

  test_h2_srv_seq_harness_init( harness );

  /* The socket harness would have already consumed the client preface.
     Here we start from the HTTP/2 frame stream: the server emits initial
     SETTINGS, the client sends SETTINGS, then acknowledges the server's
     SETTINGS before opening the first request stream. */
  test_h2_srv_seq_handshake( harness );

  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_HEADERS,
                              FD_H2_FLAG_END_HEADERS,
                              33U,
                              request_headers,
                              request_headers_sz );
  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_DATA,
                              0U,
                              33U,
                              HELLO,
                              sizeof(HELLO)-1UL );
  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_DATA,
                              FD_H2_FLAG_END_STREAM,
                              33U,
                              WORKS,
                              sizeof(WORKS)-1UL );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_request( harness, &request0 );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_HEADERS,
                                         FD_H2_FLAG_END_HEADERS,
                                         33U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EXACT,
                                         TEST_H2_SRV_SEQ_STATUS_200,
                                         sizeof(TEST_H2_SRV_SEQ_STATUS_200) );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_DATA,
                                         FD_H2_FLAG_END_STREAM,
                                         33U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EXACT,
                                         TEST_H2_SRV_SEQ_OK,
                                         sizeof(TEST_H2_SRV_SEQ_OK)-1UL );
  test_h2_srv_seq_expect_tx_empty( harness );

  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_HEADERS,
                              FD_H2_FLAG_END_HEADERS,
                              35U,
                              request_headers,
                              request_headers_sz );
  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_DATA,
                              0U,
                              35U,
                              HELLO,
                              sizeof(HELLO)-1UL );
  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_PING,
                              0U,
                              0U,
                              ping_payload,
                              sizeof(ping_payload) );
  test_h2_srv_seq_send_frame( harness,
                              FD_H2_FRAME_TYPE_DATA,
                              FD_H2_FLAG_END_STREAM,
                              35U,
                              WORKS,
                              sizeof(WORKS)-1UL );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_request( harness, &request1 );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_PING,
                                         FD_H2_FLAG_ACK,
                                         0U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EXACT,
                                         ping_payload,
                                         sizeof(ping_payload) );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_HEADERS,
                                         FD_H2_FLAG_END_HEADERS,
                                         35U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EXACT,
                                         TEST_H2_SRV_SEQ_STATUS_200,
                                         sizeof(TEST_H2_SRV_SEQ_STATUS_200) );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_DATA,
                                         FD_H2_FLAG_END_STREAM,
                                         35U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EXACT,
                                         TEST_H2_SRV_SEQ_OK,
                                         sizeof(TEST_H2_SRV_SEQ_OK)-1UL );
  test_h2_srv_seq_expect_tx_empty( harness );
}

FD_UNIT_TEST( h2_server_conn_window_update_overflow ) {
  test_h2_srv_seq_harness_t harness[1];
  test_h2_srv_seq_harness_init( harness );
  test_h2_srv_seq_handshake( harness );

  uint increment = fd_uint_bswap( 0x7fffffffU-65535U );
  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, 0U, &increment, sizeof(increment) );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_tx_empty( harness );
  FD_TEST( !harness->conn->flags );
  FD_TEST( harness->conn->tx_wnd==0x7fffffffU );

  increment = fd_uint_bswap( 1U );
  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, 0U, &increment, sizeof(increment) );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  FD_TEST( harness->conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
  FD_TEST( harness->conn->conn_error==FD_H2_ERR_FLOW_CONTROL );
  FD_TEST( harness->conn->tx_wnd==0x7fffffffU );

  fd_h2_tx_control( harness->conn, harness->rbuf_tx, harness->cb );
  FD_TEST( harness->conn->flags & FD_H2_CONN_FLAGS_DEAD );
  FD_TEST( fd_h2_rbuf_used_sz( harness->rbuf_tx )==sizeof(fd_h2_goaway_t) );
  fd_h2_goaway_t goaway;
  fd_h2_rbuf_pop_copy( harness->rbuf_tx, &goaway, sizeof(goaway) );
  FD_TEST( fd_h2_frame_type( goaway.hdr.typlen )==FD_H2_FRAME_TYPE_GOAWAY );
  FD_TEST( fd_uint_bswap( goaway.error_code )==FD_H2_ERR_FLOW_CONTROL );
  test_h2_srv_seq_expect_tx_empty( harness );
}

FD_UNIT_TEST( h2_server_stream_error_releases_quota ) {
  test_h2_srv_seq_harness_t harness[1];
  test_h2_srv_seq_harness_init( harness );
  test_h2_srv_seq_handshake( harness );

  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U, NULL, 0UL );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_tx_empty( harness );
  FD_TEST( harness->fixture->stream->stream_id==1U );
  FD_TEST( harness->conn->stream_active_cnt[0]==1U );

  uint increment = fd_uint_bswap( 0x7fffffffU-65535U );
  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, 1U, &increment, sizeof(increment) );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_tx_empty( harness );
  FD_TEST( harness->fixture->stream->stream_id==1U );
  FD_TEST( harness->fixture->stream->tx_wnd==0x7fffffffU );
  FD_TEST( harness->conn->stream_active_cnt[0]==1U );

  increment = fd_uint_bswap( 1U );
  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, 1U, &increment, sizeof(increment) );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  FD_TEST( harness->fixture->rst_stream_cnt==1UL );
  FD_TEST( harness->fixture->rst_stream_err==FD_H2_ERR_FLOW_CONTROL );
  FD_TEST( harness->fixture->rst_stream_closed_by==0 );
  FD_TEST( harness->fixture->stream->stream_id==0U );
  FD_TEST( !harness->conn->flags );
  FD_TEST( harness->conn->tx_wnd==65535U );
  FD_TEST( harness->conn->stream_active_cnt[0]==0U );

  uint rst_err = fd_uint_bswap( FD_H2_ERR_FLOW_CONTROL );
  test_h2_srv_seq_expect_response_frame( harness,
                                         FD_H2_FRAME_TYPE_RST_STREAM,
                                         0U,
                                         1U,
                                         TEST_H2_SRV_SEQ_PAYLOAD_EXACT,
                                         (uchar const *)&rst_err,
                                         sizeof(rst_err) );
  test_h2_srv_seq_expect_tx_empty( harness );

  test_h2_srv_seq_send_frame( harness, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 3U, NULL, 0UL );
  test_h2_srv_seq_service_rx( harness );
  test_h2_srv_seq_expect_rx_empty( harness );
  test_h2_srv_seq_expect_tx_empty( harness );
  FD_TEST( harness->fixture->stream->stream_id==3U );
  FD_TEST( harness->conn->stream_active_cnt[0]==1U );
}

/* The tests below use a second fixture that keeps several streams,
   reassembles field blocks across CONTINUATION frames, and decodes them
   with the connection's HPACK dynamic table. */

#define TEST_H2_SRV2_BUF_MAX    4096UL
#define TEST_H2_SRV2_STREAM_MAX 4UL

struct test_h2_srv2 {
  fd_h2_conn_t      conn[1];
  fd_h2_callbacks_t cb[1];
  fd_h2_rbuf_t      rbuf_rx[1];
  fd_h2_rbuf_t      rbuf_tx[1];
  uchar             rx_mem [ TEST_H2_SRV2_BUF_MAX ];
  uchar             tx_mem [ TEST_H2_SRV2_BUF_MAX ];
  uchar             scratch[ TEST_H2_SRV2_BUF_MAX ];

  fd_h2_stream_t    stream[ TEST_H2_SRV2_STREAM_MAX ];

  uchar             blk    [ TEST_H2_SRV2_BUF_MAX ];
  ulong             blk_len;

  char              hdr_txt[ 1024 ];
  ulong             hdr_txt_len;
  ulong             hdrs_cb_cnt;
  uint              hdr_err;

  ulong             data_sz;
  ulong             rst_cnt;
  uint              rst_err;
  int               rst_closed_by;
  ulong             conn_established_cnt;
  ulong             conn_final_cnt;
  uint              conn_final_err;
};

typedef struct test_h2_srv2 test_h2_srv2_t;

static fd_h2_stream_t *
test_h2_srv2_stream_create( fd_h2_conn_t * conn,
                            uint           stream_id ) {
  (void)stream_id;
  test_h2_srv2_t * ctx = conn->ctx;
  for( ulong i=0UL; i<TEST_H2_SRV2_STREAM_MAX; i++ ) {
    if( !ctx->stream[ i ].stream_id ) return fd_h2_stream_init( ctx->stream+i );
  }
  return NULL;
}

static fd_h2_stream_t *
test_h2_srv2_stream_query( fd_h2_conn_t * conn,
                           uint           stream_id ) {
  test_h2_srv2_t * ctx = conn->ctx;
  for( ulong i=0UL; i<TEST_H2_SRV2_STREAM_MAX; i++ ) {
    if( ctx->stream[ i ].stream_id==stream_id ) return ctx->stream+i;
  }
  return NULL;
}

static void
test_h2_srv2_headers( fd_h2_conn_t *   conn,
                      fd_h2_stream_t * stream,
                      void const *     data,
                      ulong            data_sz,
                      ulong            flags ) {
  (void)stream;
  test_h2_srv2_t * ctx = conn->ctx;
  ctx->hdrs_cb_cnt++;

  /* Reassemble the field block: a single HPACK record may straddle a
     frame boundary. */
  FD_TEST( ctx->blk_len+data_sz <= sizeof(ctx->blk) );
  fd_memcpy( ctx->blk+ctx->blk_len, data, data_sz );
  ctx->blk_len += data_sz;
  if( !( flags & FD_H2_FLAG_END_HEADERS ) ) return;

  fd_hpack_rd_t rd[1];
  if( FD_UNLIKELY( !fd_hpack_rd_init( rd, ctx->blk, ctx->blk_len ) ) ) {
    ctx->hdr_err = FD_H2_ERR_COMPRESSION;
    fd_h2_conn_error( conn, FD_H2_ERR_COMPRESSION );
    return;
  }
  while( !fd_hpack_rd_done( rd ) ) {
    uchar   buf[ 8192 ];
    uchar * bufp = buf;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( rd, hdr, &bufp, buf+sizeof(buf) );
    if( FD_UNLIKELY( err ) ) {
      ctx->hdr_err = err;
      fd_h2_conn_error( conn, err );
      return;
    }
    ulong len = (ulong)hdr->name_len + hdr->value_len + 3UL;
    FD_TEST( ctx->hdr_txt_len+len <= sizeof(ctx->hdr_txt) );
    char * p = ctx->hdr_txt + ctx->hdr_txt_len;
    fd_memcpy( p, hdr->name, hdr->name_len ); p += hdr->name_len;
    *(p++) = ':'; *(p++) = ' ';
    fd_memcpy( p, hdr->value, hdr->value_len ); p += hdr->value_len;
    *(p++) = '\n';
    ctx->hdr_txt_len += len;
  }
  ctx->blk_len = 0UL;
}

static void
test_h2_srv2_data( fd_h2_conn_t *   conn,
                   fd_h2_stream_t * stream,
                   void const *     data,
                   ulong            data_sz,
                   ulong            flags ) {
  (void)stream; (void)data; (void)flags;
  test_h2_srv2_t * ctx = conn->ctx;
  ctx->data_sz += data_sz;
}

static void
test_h2_srv2_rst_stream( fd_h2_conn_t *   conn,
                         fd_h2_stream_t * stream,
                         uint             error_code,
                         int              closed_by ) {
  test_h2_srv2_t * ctx = conn->ctx;
  ctx->rst_cnt++;
  ctx->rst_err       = error_code;
  ctx->rst_closed_by = closed_by;
  fd_memset( stream, 0, sizeof(fd_h2_stream_t) );
}

static void
test_h2_srv2_conn_established( fd_h2_conn_t * conn ) {
  test_h2_srv2_t * ctx = conn->ctx;
  ctx->conn_established_cnt++;
}

static void
test_h2_srv2_conn_final( fd_h2_conn_t * conn,
                         uint           h2_err,
                         int            closed_by ) {
  (void)closed_by;
  test_h2_srv2_t * ctx = conn->ctx;
  ctx->conn_final_cnt++;
  ctx->conn_final_err = h2_err;
}

static void
test_h2_srv2_init( test_h2_srv2_t * ctx ) {
  fd_memset( ctx, 0, sizeof(*ctx) );
  fd_h2_rbuf_init( ctx->rbuf_rx, ctx->rx_mem, sizeof(ctx->rx_mem) );
  fd_h2_rbuf_init( ctx->rbuf_tx, ctx->tx_mem, sizeof(ctx->tx_mem) );
  FD_TEST( fd_h2_conn_init_server( ctx->conn )==ctx->conn );
  ctx->conn->ctx = ctx;

  fd_h2_callbacks_init( ctx->cb );
  ctx->cb->stream_create    = test_h2_srv2_stream_create;
  ctx->cb->stream_query     = test_h2_srv2_stream_query;
  ctx->cb->conn_established = test_h2_srv2_conn_established;
  ctx->cb->conn_final       = test_h2_srv2_conn_final;
  ctx->cb->headers          = test_h2_srv2_headers;
  ctx->cb->data             = test_h2_srv2_data;
  ctx->cb->rst_stream       = test_h2_srv2_rst_stream;
}

static void
test_h2_srv2_send( test_h2_srv2_t * ctx,
                   uint             frame_type,
                   uint             frame_flags,
                   uint             stream_id,
                   void const *     payload,
                   ulong            payload_sz ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( frame_type, payload_sz ),
    .flags       = (uchar)frame_flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( ctx->rbuf_rx, &hdr, sizeof(hdr) );
  if( payload_sz ) fd_h2_rbuf_push( ctx->rbuf_rx, payload, payload_sz );
}

static void
test_h2_srv2_rx( test_h2_srv2_t * ctx ) {
  fd_h2_rx( ctx->conn, ctx->rbuf_rx, ctx->rbuf_tx, ctx->scratch, sizeof(ctx->scratch), ctx->cb );
}

/* test_h2_srv2_pop pops the next frame from the TX buffer. */

static ulong
test_h2_srv2_pop( test_h2_srv2_t *    ctx,
                  fd_h2_frame_hdr_t * hdr,
                  uchar *             payload,
                  ulong               payload_max ) {
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )>=sizeof(*hdr) );
  fd_h2_rbuf_pop_copy( ctx->rbuf_tx, hdr, sizeof(*hdr) );
  ulong payload_sz = fd_h2_frame_length( hdr->typlen );
  FD_TEST( payload_sz<=payload_max );
  if( payload_sz ) fd_h2_rbuf_pop_copy( ctx->rbuf_tx, payload, payload_sz );
  return payload_sz;
}

/* test_h2_srv2_handshake completes the HTTP/2 handshake and returns the
   value the server advertised for SETTINGS_HEADER_TABLE_SIZE. */

static uint
test_h2_srv2_handshake( test_h2_srv2_t * ctx ) {
  fd_h2_frame_hdr_t hdr;
  uchar payload[ 256 ];

  fd_h2_tx_control( ctx->conn, ctx->rbuf_tx, ctx->cb );
  ulong payload_sz = test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_SETTINGS );
  FD_TEST( hdr.flags==0 );
  uint header_table_size = UINT_MAX;
  for( ulong off=0UL; off<payload_sz; off+=sizeof(fd_h2_setting_t) ) {
    fd_h2_setting_t setting = FD_LOAD( fd_h2_setting_t, payload+off );
    if( fd_ushort_bswap( setting.id )==FD_H2_SETTINGS_HEADER_TABLE_SIZE ) {
      header_table_size = fd_uint_bswap( setting.value );
    }
  }
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, NULL, 0UL );
  test_h2_srv2_rx( ctx );
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==0UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_SETTINGS );
  FD_TEST( hdr.flags==FD_H2_FLAG_ACK );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
  test_h2_srv2_rx( ctx );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );
  FD_TEST( ctx->conn_established_cnt==1UL );

  return header_table_size;
}


/* A request field block that adds ':authority: www.example.com' to the
   dynamic table (RFC 7541 Appendix C.3.1, last two records dropped). */
static uchar const test_h2_srv2_req1[] = {
  0x82,                                     /* :method: GET */
  0x41, 0x0f, 'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m'
};

/* A request field block that indexes the entry that req1 added */
static uchar const test_h2_srv2_req2[] = { 0x84, 0xbe };

FD_UNIT_TEST( h2_server_stream_window_refill ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  ctx->conn->self_settings.initial_window_size = 100U;
  test_h2_srv2_handshake( ctx );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  test_h2_srv2_rx( ctx );
  fd_h2_stream_t * stream = test_h2_srv2_stream_query( ctx->conn, 1U );
  FD_TEST( stream && stream->rx_wnd==100U );

  uchar body[ 60 ] = {0};
  fd_h2_frame_hdr_t hdr;
  uchar payload[ 16 ];

  /* Sending more than one initial window worth of data over the life of
     the stream only works if the window is replenished. */
  for( ulong i=0UL; i<4UL; i++ ) {
    test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, 0U, 1U, body, sizeof(body) );
    test_h2_srv2_rx( ctx );
    FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
    FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_WINDOW_UPDATE );
    FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==1U );
    FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==60U );
    FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );
    FD_TEST( stream->rx_wnd==100U );
    FD_TEST( !( ctx->conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD) ) );
  }
  FD_TEST( ctx->data_sz==240UL );
  FD_TEST( ctx->rst_cnt==0UL   );

  /* The final chunk ends the stream, which needs no more credit */
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_END_STREAM, 1U, body, 10UL );
  test_h2_srv2_rx( ctx );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );
  FD_TEST( stream->state==FD_H2_STREAM_STATE_CLOSING_RX );
}

FD_UNIT_TEST( h2_server_conn_window_refund ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  test_h2_srv2_handshake( ctx );

  ctx->conn->rx_wnd_max   = 200U;
  ctx->conn->rx_wnd       = 200U;
  ctx->conn->rx_wnd_wmark = 140U;

  /* Open stream 1 and have the peer reset it, which makes the app
     release the stream object */
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  uint err_code = fd_uint_bswap( FD_H2_ERR_CANCEL );
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_RST_STREAM, 0U, 1U, &err_code, sizeof(err_code) );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->rst_cnt==1UL );
  FD_TEST( !test_h2_srv2_stream_query( ctx->conn, 1U ) );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );

  /* DATA on the released stream still counts against the connection
     window, so the credit has to come back */
  uchar body[ 100 ] = {0};
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, 0U, 1U, body, sizeof(body) );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->conn->rx_wnd==100U );
  FD_TEST( ctx->conn->flags & FD_H2_CONN_FLAGS_WINDOW_UPDATE );
  FD_TEST( ctx->data_sz==0UL );

  fd_h2_frame_hdr_t hdr;
  uchar payload[ 16 ];
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_RST_STREAM );
  FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==1U );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==FD_H2_ERR_STREAM_CLOSED );

  fd_h2_tx_control( ctx->conn, ctx->rbuf_tx, ctx->cb );
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_WINDOW_UPDATE );
  FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==0U );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==100U );
  FD_TEST( ctx->conn->rx_wnd==200U );
}

/* RFC 9113 Section 5.1: a DATA frame on a stream that was never opened
   is a connection error, and RST_STREAM must not be sent for it. */

FD_UNIT_TEST( h2_server_data_on_idle_stream ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  test_h2_srv2_handshake( ctx );

  uchar body[ 8 ] = {0};
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, 0U, 7U, body, sizeof(body) );
  test_h2_srv2_rx( ctx );

  FD_TEST( ctx->conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
  FD_TEST( ctx->conn->conn_error==FD_H2_ERR_PROTOCOL );
  FD_TEST( ctx->rst_cnt==0UL );
  FD_TEST( ctx->data_sz==0UL );
  /* The frame is abandoned rather than consumed */
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_rx )==sizeof(body) );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );

  fd_h2_tx_control( ctx->conn, ctx->rbuf_tx, ctx->cb );
  fd_h2_goaway_t goaway;
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==sizeof(goaway) );
  fd_h2_rbuf_pop_copy( ctx->rbuf_tx, &goaway, sizeof(goaway) );
  FD_TEST( fd_h2_frame_type( goaway.hdr.typlen )==FD_H2_FRAME_TYPE_GOAWAY );
  FD_TEST( fd_uint_bswap( goaway.error_code )==FD_H2_ERR_PROTOCOL );
  FD_TEST( ctx->conn_final_cnt==1UL );

  /* A stream that our own side never opened is idle as well */
  test_h2_srv2_t ctx2[1];
  test_h2_srv2_init( ctx2 );
  test_h2_srv2_handshake( ctx2 );
  test_h2_srv2_send( ctx2, FD_H2_FRAME_TYPE_DATA, 0U, 2U, body, sizeof(body) );
  test_h2_srv2_rx( ctx2 );
  FD_TEST( ctx2->conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY );
  FD_TEST( ctx2->conn->conn_error==FD_H2_ERR_PROTOCOL );
  FD_TEST( fd_h2_rbuf_used_sz( ctx2->rbuf_tx )==0UL );
}

FD_UNIT_TEST( h2_server_padded_data_flow_control ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  test_h2_srv2_handshake( ctx );

  ctx->conn->rx_wnd_max   = 200U;
  ctx->conn->rx_wnd       = 200U;
  ctx->conn->rx_wnd_wmark = 140U;

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  test_h2_srv2_rx( ctx );
  fd_h2_stream_t * stream = test_h2_srv2_stream_query( ctx->conn, 1U );
  FD_TEST( stream );
  uint stream_wnd = stream->rx_wnd;

  /* Pad Length (1) + data (4) + padding (3) all count towards flow
     control, but only the data is delivered */
  static uchar const padded[] = { 0x03, 'd','a','t','a', 0x00, 0x00, 0x00 };
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_PADDED, 1U, padded, sizeof(padded) );
  test_h2_srv2_rx( ctx );

  FD_TEST( ctx->data_sz==4UL );
  FD_TEST( ctx->conn->rx_wnd==200U-8U );
  FD_TEST( stream->rx_wnd==stream_wnd-8U );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_rx )==0UL );
  FD_TEST( !( ctx->conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD) ) );
}

FD_UNIT_TEST( h2_server_rst_stream_both_ways ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  test_h2_srv2_handshake( ctx );

  /* Peer resets the stream */
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->conn->stream_active_cnt[0]==1U );

  uint err_code = fd_uint_bswap( FD_H2_ERR_CANCEL );
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_RST_STREAM, 0U, 1U, &err_code, sizeof(err_code) );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->rst_cnt==1UL                    );
  FD_TEST( ctx->rst_err==FD_H2_ERR_CANCEL       );
  FD_TEST( ctx->rst_closed_by==1                );
  FD_TEST( ctx->conn->stream_active_cnt[0]==0U  );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );

  /* We reset the stream */
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 3U,
                     test_h2_srv2_req2, sizeof(test_h2_srv2_req2) );
  test_h2_srv2_rx( ctx );
  fd_h2_stream_t * stream = test_h2_srv2_stream_query( ctx->conn, 3U );
  FD_TEST( stream && ctx->conn->stream_active_cnt[0]==1U );

  fd_h2_rst_stream( ctx->conn, ctx->rbuf_tx, stream );
  FD_TEST( stream->state==FD_H2_STREAM_STATE_CLOSED );
  FD_TEST( ctx->conn->stream_active_cnt[0]==0U );

  fd_h2_frame_hdr_t hdr;
  uchar payload[ 16 ];
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_RST_STREAM );
  FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==3U );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==FD_H2_ERR_CANCEL );
}

FD_UNIT_TEST( h2_server_refused_stream_continuation ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  ctx->conn->self_settings.max_concurrent_streams = 1U;
  test_h2_srv2_handshake( ctx );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->conn->stream_active_cnt[0]==1U );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );

  /* The second stream is over the limit.  Its field block still spans
     CONTINUATION frames, which must not be mistaken for a protocol
     error. */
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, 0U, 3U, test_h2_srv2_req1, 5UL );
  test_h2_srv2_rx( ctx );

  fd_h2_frame_hdr_t hdr;
  uchar payload[ 16 ];
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_RST_STREAM );
  FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==3U );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==FD_H2_ERR_REFUSED_STREAM );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_CONTINUATION, FD_H2_FLAG_END_HEADERS, 3U,
                     test_h2_srv2_req1+5, sizeof(test_h2_srv2_req1)-5UL );
  test_h2_srv2_rx( ctx );
  FD_TEST( !( ctx->conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD|FD_H2_CONN_FLAGS_CONTINUATION) ) );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_rx )==0UL );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_tx )==0UL );
  FD_TEST( ctx->conn->stream_active_cnt[0]==1U );
}

FD_UNIT_TEST( h2_server_data_flow_control_violation ) {
  test_h2_srv2_t ctx[1];
  test_h2_srv2_init( ctx );
  ctx->conn->self_settings.initial_window_size = 10U;
  test_h2_srv2_handshake( ctx );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->conn->stream_active_cnt[0]==1U );

  /* The peer exceeded the stream receive window.  The stream is closed
     on both sides, which has to release the stream slot. */
  uchar body[ 20 ] = {0};
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, 0U, 1U, body, sizeof(body) );
  test_h2_srv2_rx( ctx );

  FD_TEST( ctx->rst_cnt==1UL                          );
  FD_TEST( ctx->rst_err==FD_H2_ERR_FLOW_CONTROL       );
  FD_TEST( ctx->rst_closed_by==0                      );
  FD_TEST( ctx->conn->stream_active_cnt[0]==0U        );
  FD_TEST( !test_h2_srv2_stream_query( ctx->conn, 1U ) );
  FD_TEST( !( ctx->conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD) ) );
  FD_TEST( fd_h2_rbuf_used_sz( ctx->rbuf_rx )==0UL    );
  FD_TEST( ctx->data_sz==0UL                          );

  fd_h2_frame_hdr_t hdr;
  uchar payload[ 16 ];
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_RST_STREAM );
  FD_TEST( fd_h2_frame_stream_id( hdr.r_stream_id )==1U );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==FD_H2_ERR_FLOW_CONTROL );

  /* DATA after the peer half-closed the stream is a stream error too */
  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_HEADERS,
                     FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM, 3U,
                     test_h2_srv2_req1, sizeof(test_h2_srv2_req1) );
  test_h2_srv2_rx( ctx );
  FD_TEST( test_h2_srv2_stream_query( ctx->conn, 3U ) );
  FD_TEST( ctx->conn->stream_active_cnt[0]==1U );

  test_h2_srv2_send( ctx, FD_H2_FRAME_TYPE_DATA, 0U, 3U, body, 4UL );
  test_h2_srv2_rx( ctx );
  FD_TEST( ctx->rst_cnt==2UL                            );
  FD_TEST( ctx->rst_err==FD_H2_ERR_STREAM_CLOSED        );
  FD_TEST( ctx->rst_closed_by==0                        );
  FD_TEST( ctx->conn->stream_active_cnt[0]==0U          );
  FD_TEST( !( ctx->conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD) ) );
  FD_TEST( test_h2_srv2_pop( ctx, &hdr, payload, sizeof(payload) )==4UL );
  FD_TEST( fd_h2_frame_type( hdr.typlen )==FD_H2_FRAME_TYPE_RST_STREAM );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, payload ) )==FD_H2_ERR_STREAM_CLOSED );
}
