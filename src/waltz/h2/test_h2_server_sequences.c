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
test_h2_server_stream_accounting( void ) {
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
