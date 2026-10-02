#include "fd_h2_callback.h"
#include "fd_h2_conn.h"
#include "../../util/sanitize/fd_asan.h"
#include "fd_h2_proto.h"

struct test_h2_callback_rec {
  uint cb_established_cnt;
};

typedef struct test_h2_callback_rec test_h2_callback_rec_t;

static test_h2_callback_rec_t cb_rec;

struct test_h2_lifecycle_rec {
  fd_h2_stream_t stream;
  uint create_cnt;
  uint rst_cnt;
  uint expected_rst_err;
  ulong data_sz;
  int accept;
  int retain_closed;
  int data_conn_error;
};

static fd_h2_stream_t *
test_h2_stream_query( fd_h2_conn_t * conn, uint stream_id ) {
  /* Both callback records have the stream as their first member. */
  fd_h2_stream_t * stream = conn->ctx;
  return stream->stream_id==stream_id ? stream : NULL;
}

static fd_h2_stream_t *
test_h2_lifecycle_create( fd_h2_conn_t * conn, uint stream_id ) {
  (void)stream_id;
  struct test_h2_lifecycle_rec * rec = conn->ctx;
  rec->create_cnt++;
  return rec->accept ? fd_h2_stream_init( &rec->stream ) : NULL;
}

static void
test_h2_lifecycle_rst( fd_h2_conn_t * conn, fd_h2_stream_t * stream, uint err, int peer ) {
  struct test_h2_lifecycle_rec * rec = conn->ctx;
  FD_TEST( err==(rec->expected_rst_err ? rec->expected_rst_err : FD_H2_ERR_FLOW_CONTROL) && !peer );
  FD_TEST( stream->state==FD_H2_STREAM_STATE_CLOSED );
  rec->rst_cnt++;
  if( !rec->retain_closed ) fd_h2_stream_init( stream );
}

static void
test_h2_lifecycle_data( fd_h2_conn_t * conn, fd_h2_stream_t * stream,
                        void const * data, ulong data_sz, ulong flags ) {
  (void)stream; (void)data; (void)flags;
  struct test_h2_lifecycle_rec * rec = conn->ctx;
  rec->data_sz += data_sz;
  if( rec->data_conn_error ) fd_h2_conn_error( conn, FD_H2_ERR_INTERNAL );
}

FD_UNIT_TEST( h2_peer_stream_roles_and_refusal ) {
  static uchar const status = 0x88;
  uint const increment = fd_uint_bswap( 1U );
  for( uint mode=0U; mode<4U; mode++ ) {
    uchar rx_buf[256], tx_buf[256], scratch[256];
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init( rx, rx_buf, sizeof(rx_buf) );
    fd_h2_rbuf_init( tx, tx_buf, sizeof(tx_buf) );
    fd_h2_conn_t conn[1];
    if( mode<2U ) fd_h2_conn_init_client( conn );
    else fd_h2_conn_init_server( conn );
    conn->flags = 0U;
    conn->allow_server_requests = (uchar)(mode==1U);
    if( mode==2U ) conn->self_settings.max_concurrent_streams = 0U;
    struct test_h2_lifecycle_rec rec = { .accept = mode!=3U };
    conn->ctx = &rec;
    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    cb->stream_query = test_h2_stream_query;
    cb->stream_create = test_h2_lifecycle_create;
    uint id = mode<2U ? 2U : 3U;
    fd_h2_tx( rx, &status, 1UL, FD_H2_FRAME_TYPE_HEADERS,
              mode<2U ? FD_H2_FLAG_END_HEADERS : 0U, id );
    fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), cb );
    if( mode==0U ) {
      FD_TEST( conn->conn_error==FD_H2_ERR_PROTOCOL && !rec.create_cnt && conn->rx_stream_next==2U );
      FD_TEST( fd_h2_rbuf_is_empty(tx) );
      continue;
    }
    FD_TEST( !conn->conn_error && conn->rx_stream_next==id+2U );
    if( mode==1U ) {
      FD_TEST( rec.create_cnt==1U && rec.stream.stream_id==id && conn->stream_active_cnt[0]==1U );
      FD_TEST( fd_h2_rbuf_is_empty(tx) );
      continue;
    }
    FD_TEST( rec.create_cnt==(mode==3U) && !conn->stream_active_cnt[0] );
    FD_TEST( conn->flags==FD_H2_CONN_FLAGS_CONTINUATION && fd_h2_rbuf_used_sz(tx)==sizeof(fd_h2_rst_stream_t) );
    fd_h2_rst_stream_t rst;
    fd_h2_rbuf_pop_copy( tx, &rst, sizeof(rst) );
    FD_TEST( fd_uint_bswap(rst.error_code)==FD_H2_ERR_REFUSED_STREAM );
    fd_h2_tx( rx, NULL, 0UL, FD_H2_FRAME_TYPE_CONTINUATION, FD_H2_FLAG_END_HEADERS, id );
    fd_h2_tx( rx, &status, 1UL, FD_H2_FRAME_TYPE_DATA, 0U, 1U ); /* implicitly closed */
    fd_h2_tx( rx, &status, 1UL, FD_H2_FRAME_TYPE_DATA, 0U, id ); /* refused */
    fd_h2_tx( rx, (uchar const *)&increment, 4UL, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, id );
    fd_h2_tx( rx, &status, 1UL, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, id );
    fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), cb );
    FD_TEST( !conn->conn_error && !conn->flags && conn->rx_wnd==65533U );
    FD_TEST( conn->rx_stream_next==5U && rec.create_cnt==(mode==3U) );
    FD_TEST( fd_h2_rbuf_is_empty(rx) && fd_h2_rbuf_is_empty(tx) );
  }
}

FD_UNIT_TEST( h2_idle_stream_direction ) {
  uint const increment = fd_uint_bswap( 1U );
  uchar const data = 0U;
  for( uint role=0U; role<2U; role++ )
  for( uint frame=0U; frame<3U; frame++ ) {
    uchar rx_buf[128], tx_buf[128], scratch[128];
    fd_h2_conn_t conn[1];
    if( role ) fd_h2_conn_init_server(conn);
    else fd_h2_conn_init_client(conn);
    conn->flags = 0U;
    conn->tx_stream_next += 10U; /* unused peer ID remains below opposite counter */
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init( rx, rx_buf, sizeof(rx_buf) );
    fd_h2_rbuf_init( tx, tx_buf, sizeof(tx_buf) );
    fd_h2_tx( rx, frame ? (uchar const *)&increment : &data, frame ? 4UL : 1UL,
              frame==1U ? FD_H2_FRAME_TYPE_WINDOW_UPDATE : frame==2U ? FD_H2_FRAME_TYPE_RST_STREAM : FD_H2_FRAME_TYPE_DATA,
              0U, conn->rx_stream_next );
    fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), &fd_h2_callbacks_noop );
    FD_TEST( conn->conn_error==FD_H2_ERR_PROTOCOL && fd_h2_rbuf_is_empty(tx) );
  }
}

FD_UNIT_TEST( h2_data_invalid_stream_state ) {
  uchar const payload = 0U;
  uint const states[] = { FD_H2_STREAM_STATE_CLOSING_RX, FD_H2_STREAM_STATE_IDLE, FD_H2_STREAM_STATE_ILLEGAL };
  for( uint i=0U; i<3U; i++ ) {
    uchar rx_buf[128], tx_buf[128], scratch[128];
    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client(conn);
    conn->flags = 0U;
    conn->tx_stream_next = 3U;
    struct test_h2_lifecycle_rec rec = { .expected_rst_err = FD_H2_ERR_STREAM_CLOSED };
    conn->ctx = &rec;
    fd_h2_stream_open(&rec.stream,conn,1U);
    rec.stream.state = (uchar)states[i];
    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init(cb);
    cb->stream_query = test_h2_stream_query;
    cb->rst_stream = test_h2_lifecycle_rst;
    cb->data = test_h2_lifecycle_data;
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init(rx,rx_buf,sizeof(rx_buf));
    fd_h2_rbuf_init(tx,tx_buf,sizeof(tx_buf));
    fd_h2_tx(rx,&payload,1UL,FD_H2_FRAME_TYPE_DATA,0U,1U);
    fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
    if( !i ) {
      FD_TEST( !conn->conn_error && rec.rst_cnt==1U && !rec.data_sz && !conn->stream_active_cnt[1] );
      FD_TEST( fd_h2_rbuf_used_sz(tx)==sizeof(fd_h2_rst_stream_t) );
      fd_h2_tx(rx,&payload,1UL,FD_H2_FRAME_TYPE_DATA,0U,1U);
      fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
      FD_TEST( rec.rst_cnt==1U && !rec.data_sz && fd_h2_rbuf_used_sz(tx)==sizeof(fd_h2_rst_stream_t) );
    } else {
      FD_TEST( conn->conn_error==FD_H2_ERR_PROTOCOL && !rec.rst_cnt && !rec.data_sz && fd_h2_rbuf_is_empty(tx) );
      /* Pending GOAWAY must stop later receives even if the stream can deliver. */
      rec.stream.state = FD_H2_STREAM_STATE_OPEN;
      ulong rx_used = fd_h2_rbuf_used_sz(rx);
      uint rx_wnd = conn->rx_wnd;
      for( uint retry=0U; retry<2U; retry++ ) fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
      FD_TEST( fd_h2_rbuf_used_sz(rx)==rx_used && conn->rx_wnd==rx_wnd && !rec.data_sz );
      FD_TEST( conn->flags==FD_H2_CONN_FLAGS_SEND_GOAWAY && fd_h2_rbuf_is_empty(tx) );
    }
  }
}

FD_UNIT_TEST( h2_data_flow_error_releases_stream ) {
  uchar const payload[16] = { 10U, 1U, 2U, 3U, 4U, 5U };
  for( uint role=0U; role<2U; role++ )
  for( uint retain=0U; retain<2U; retain++ ) {
    uchar rx_buf[128], tx_buf[128], scratch[128];
    fd_h2_conn_t conn[1];
    if( role ) fd_h2_conn_init_server(conn);
    else fd_h2_conn_init_client(conn);
    conn->flags = 0U;
    if( role ) conn->rx_stream_next = 3U;
    else conn->tx_stream_next = 3U;
    struct test_h2_lifecycle_rec rec = { .retain_closed = (int)retain };
    conn->ctx = &rec;
    fd_h2_stream_open( &rec.stream, conn, 1U );
    rec.stream.rx_wnd = 1U;
    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init(cb);
    cb->stream_query = test_h2_stream_query;
    cb->rst_stream = test_h2_lifecycle_rst;
    cb->data = test_h2_lifecycle_data;
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init( rx, rx_buf, sizeof(rx_buf) );
    fd_h2_rbuf_init( tx, tx_buf, sizeof(tx_buf) );
    fd_h2_frame_hdr_t hdr = {
      .typlen = fd_h2_frame_typlen(FD_H2_FRAME_TYPE_DATA,sizeof(payload)),
      .flags = FD_H2_FLAG_PADDED,
      .r_stream_id = fd_uint_bswap(1U)
    };
    fd_h2_rbuf_push(rx,&hdr,sizeof(hdr));
    fd_h2_rbuf_push(rx,payload,3UL); /* two data bytes exceed the stream window */
    fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
    FD_TEST( rec.rst_cnt==1U && !rec.data_sz && !conn->stream_active_cnt[!role] );
    fd_h2_rbuf_push(rx,payload+3,sizeof(payload)-3UL);
    fd_h2_tx(rx,payload,1UL,FD_H2_FRAME_TYPE_DATA,0U,1U);
    fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
    FD_TEST( rec.rst_cnt==1U && !rec.data_sz && conn->rx_wnd==65535U-17U );
    FD_TEST( !conn->conn_error && fd_h2_rbuf_is_empty(rx) && fd_h2_rbuf_used_sz(tx)==sizeof(fd_h2_rst_stream_t) );
  }
}

/* A connection error from the first callback of a DATA chunk that
   wraps the RX buffer suppresses the callback for the tail. */

FD_UNIT_TEST( h2_wrapped_data_after_conn_error ) {
  uchar rx_buf[64], tx_buf[64], scratch[64] = {0};
  fd_h2_rbuf_t rx[1], tx[1];
  fd_h2_rbuf_init( rx, rx_buf, sizeof(rx_buf) );
  fd_h2_rbuf_init( tx, tx_buf, sizeof(tx_buf) );
  fd_h2_rbuf_push( rx, scratch, 50UL );
  fd_h2_rbuf_skip( rx, 50UL );
  fd_h2_tx( rx, scratch, 10UL, FD_H2_FRAME_TYPE_DATA, 0U, 1U ); /* payload at [59,64) and [0,5) */
  fd_h2_conn_t conn[1];
  fd_h2_conn_init_client( conn );
  conn->flags = 0U;
  conn->tx_stream_next = 3U;
  struct test_h2_lifecycle_rec rec = { .data_conn_error = 1 };
  conn->ctx = &rec;
  fd_h2_stream_open( &rec.stream, conn, 1U );
  fd_h2_callbacks_t cb[1];
  fd_h2_callbacks_init( cb );
  cb->stream_query = test_h2_stream_query;
  cb->data = test_h2_lifecycle_data;
  fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), cb );
  FD_TEST( rec.data_sz==5UL && conn->conn_error==FD_H2_ERR_INTERNAL );
}

FD_UNIT_TEST( h2_empty_data_tx_backpressure ) {
  uchar const payload[3] = { 2U, 0U, 0U };
  uchar filler[103] = {0}; /* 25 bytes free, less than DATA's control reserve */
  for( uint padded=0U; padded<2U; padded++ ) {
    uchar rx_buf[128], tx_buf[128], scratch[128];
    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client(conn);
    conn->flags = 0U;
    conn->tx_stream_next = 3U;
    struct test_h2_lifecycle_rec rec = {0};
    conn->ctx = &rec;
    fd_h2_stream_open(&rec.stream,conn,1U);
    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init(cb);
    cb->stream_query = test_h2_stream_query;
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init(rx,rx_buf,sizeof(rx_buf));
    fd_h2_rbuf_init(tx,tx_buf,sizeof(tx_buf));
    fd_h2_rbuf_push(tx,filler,sizeof(filler));
    fd_h2_tx(rx,payload,padded ? sizeof(payload) : 0UL,FD_H2_FRAME_TYPE_DATA,
             FD_H2_FLAG_END_STREAM | (padded ? FD_H2_FLAG_PADDED : 0U),1U);
    ulong rx_used = fd_h2_rbuf_used_sz(rx);
    fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
    FD_TEST( fd_h2_rbuf_used_sz(rx)==rx_used && rec.stream.state==FD_H2_STREAM_STATE_OPEN );
    FD_TEST( conn->rx_wnd==65535U && rec.stream.rx_wnd==65535U );
    fd_h2_rbuf_skip(tx,sizeof(filler));
    fd_h2_rx(conn,rx,tx,scratch,sizeof(scratch),cb);
    FD_TEST( rec.stream.state==FD_H2_STREAM_STATE_CLOSING_RX );
    FD_TEST( conn->rx_wnd==65535U-(padded ? 3U : 0U) && rec.stream.rx_wnd==conn->rx_wnd );
    FD_TEST( !conn->conn_error && fd_h2_rbuf_is_empty(rx) && fd_h2_rbuf_is_empty(tx) );
  }
}

/* Late frames on a released local stream are dropped (RFC 9113
   Section 5.1).  Single-frame field blocks are still HPACK-validated. */

FD_UNIT_TEST( h2_closed_local_headers ) {
  static uchar const status[] = {0x20,0x88}, bad_upd[] = {0x3f,0x88}, wnd_inc[] = {0,0,0,0};
  struct { uchar const * data; uint stream_id; uint err; } const cases[] = {
    { status,  1U, 0U                    }, /* size 0 update */
    { bad_upd, 1U, FD_H2_ERR_COMPRESSION }, /* size>0 update */
    { status,  3U, FD_H2_ERR_PROTOCOL    }  /* never opened */
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    uchar rx_buf[128], tx_buf[128], scratch[128];
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init( rx, rx_buf, sizeof(rx_buf) );
    fd_h2_rbuf_init( tx, tx_buf, sizeof(tx_buf) );
    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags          = 0;
    conn->tx_stream_next = 3U; /* stream 1 was released */
    fd_h2_tx( rx, cases[i].data, 2UL, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, cases[i].stream_id );
    fd_h2_tx( rx, status,  1UL, FD_H2_FRAME_TYPE_DATA,          0U, 1U );
    fd_h2_tx( rx, wnd_inc, 4UL, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, 1U );
    fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), &fd_h2_callbacks_noop );
    FD_TEST( conn->conn_error==cases[i].err );
    if( cases[i].err ) continue;
    /* Late DATA still counts against the connection window */
    FD_TEST( !conn->flags && conn->rx_wnd==65535U-1U );
    FD_TEST( fd_h2_rbuf_is_empty( rx ) && fd_h2_rbuf_is_empty( tx ) );
  }
}

struct test_h2_header_abort_rec {
  fd_h2_stream_t stream;
  fd_h2_rbuf_t * tx;
  uint headers_cnt;
  uint abort_kind; /* 0=none, 1=reset, 2=error */
  int abort_in_callback;
};

static void
test_h2_header_abort( fd_h2_conn_t * conn ) {
  struct test_h2_header_abort_rec * rec = conn->ctx;
  if( rec->abort_kind==1U ) fd_h2_stream_reset( &rec->stream, conn );
  else                    fd_h2_stream_error( &rec->stream, conn, rec->tx, FD_H2_ERR_CANCEL );
}

static void
test_h2_header_abort_headers( fd_h2_conn_t * conn, fd_h2_stream_t * stream,
                              void const * data, ulong data_sz, ulong flags ) {
  (void)stream; (void)data; (void)data_sz; (void)flags;
  struct test_h2_header_abort_rec * rec = conn->ctx;
  rec->headers_cnt++;
  if( rec->headers_cnt==1U && rec->abort_in_callback ) test_h2_header_abort( conn );
}

FD_UNIT_TEST( h2_retained_stream_abort_mid_headers ) {
  struct { uint kind; int in_callback; int end_stream; } const cases[] = {
    { 1U, 0, 0 }, { 2U, 0, 0 }, /* abort between frames */
    { 1U, 1, 0 }, { 2U, 1, 0 }, /* abort from initial HEADERS callback */
    { 0U, 0, 1 },               /* ordinary END_STREAM still delivers CONTINUATION */
    { 2U, 0, 1 }, { 2U, 1, 1 }  /* explicit abort after END_STREAM already closed it */
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ )
  for( uint truncated=0U; truncated<2U; truncated++ ) {
    uchar rx_buf[128], tx_buf[128], scratch[128];
    fd_h2_rbuf_t rx[1], tx[1];
    fd_h2_rbuf_init( rx, rx_buf, sizeof(rx_buf) );
    fd_h2_rbuf_init( tx, tx_buf, sizeof(tx_buf) );
    fd_h2_conn_t conn[1];
    fd_h2_conn_init_client( conn );
    conn->flags = 0U;
    conn->tx_stream_next = 3U;
    struct test_h2_header_abort_rec rec = { .tx = tx, .abort_kind = cases[i].kind,
                                          .abort_in_callback = cases[i].in_callback };
    conn->ctx = &rec;
    fd_h2_stream_open( &rec.stream, conn, 1U );
    if( cases[i].end_stream ) fd_h2_stream_close_tx( &rec.stream, conn );
    fd_h2_callbacks_t cb[1];
    fd_h2_callbacks_init( cb );
    cb->stream_query = test_h2_stream_query;
    cb->headers = test_h2_header_abort_headers;
    uchar const first[] = { 0x01, 0x03, 'a' }, last[] = { 'b', 'c' }, late[] = { 0x88, 0, 0, 0, 1 };
    fd_h2_tx( rx, first, sizeof(first), FD_H2_FRAME_TYPE_HEADERS,
              cases[i].end_stream ? FD_H2_FLAG_END_STREAM : 0U, 1U );
    fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), cb );
    FD_TEST( !conn->conn_error && rec.headers_cnt==1U && (conn->flags & FD_H2_CONN_FLAGS_CONTINUATION) );
    if( cases[i].kind && !cases[i].in_callback ) test_h2_header_abort( conn );
    FD_TEST( rec.stream.state==FD_H2_STREAM_STATE_CLOSED && !conn->stream_active_cnt[1] );
    fd_h2_tx( rx, last, truncated ? 1UL : sizeof(last), FD_H2_FRAME_TYPE_CONTINUATION, FD_H2_FLAG_END_HEADERS, 1U );
    /* Later HEADERS, WINDOW_UPDATE and RST_STREAM on the CLOSED stream are ignored */
    fd_h2_tx( rx, late,   1UL, FD_H2_FRAME_TYPE_HEADERS,       0U,                     1U );
    fd_h2_tx( rx, late,   0UL, FD_H2_FRAME_TYPE_CONTINUATION,  FD_H2_FLAG_END_HEADERS, 1U );
    fd_h2_tx( rx, late+1, 4UL, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U,                     1U );
    fd_h2_tx( rx, late+1, 4UL, FD_H2_FRAME_TYPE_RST_STREAM,    0U,                     1U );
    fd_h2_rx( conn, rx, tx, scratch, sizeof(scratch), cb );
    FD_TEST( conn->conn_error==(truncated ? FD_H2_ERR_COMPRESSION : FD_H2_SUCCESS) && ( truncated || fd_h2_rbuf_is_empty( rx ) ) );
    FD_TEST( rec.headers_cnt==(!cases[i].kind && !truncated ? 2U : 1U) );
    FD_TEST( !conn->stream_active_cnt[1] && rec.stream.state==FD_H2_STREAM_STATE_CLOSED && rec.stream.tx_wnd==65535U );
    FD_TEST( fd_h2_rbuf_used_sz(tx)==(cases[i].kind==2U && !cases[i].end_stream ? sizeof(fd_h2_rst_stream_t) : 0UL) );
  }
}

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

FD_UNIT_TEST( h2_client_handshake ) {
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
  conn->flags |= FD_H2_CONN_FLAGS_WINDOW_UPDATE; /* must not delay establishment */
  fd_h2_rbuf_push( rbuf_rx, settings_ack_expected, sizeof(settings_ack_expected) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==0 );
  FD_TEST( conn->flags == FD_H2_CONN_FLAGS_WINDOW_UPDATE );
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

FD_UNIT_TEST( h2_ping_tx ) {
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

FD_UNIT_TEST( h2_buffer_guard ) {
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
       incremental path.  Stream 1 was never opened (idle), resulting
       in PROTOCOL_ERROR without RST_STREAM (RFC 9113 Sections 5.1 and
       6.4) -- the point is that it didn't trigger the buffer guard. */
    FD_TEST( conn->conn_error==FD_H2_ERR_PROTOCOL && fd_h2_rbuf_is_empty( rbuf_tx ) );
  }

  FD_LOG_NOTICE(( "test_h2_buffer_guard: pass" ));
}

FD_UNIT_TEST( h2_invalid_max_frame_size ) {
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
