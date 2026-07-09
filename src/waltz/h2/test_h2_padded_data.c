#include "fd_h2_callback.h"
#include "fd_h2_conn.h"
#include "fd_h2_stream.h"
#include "../../util/fd_util.h"

static ulong g_fail_cnt = 0UL;

#define CHECK(cond) do {                                                                         \
    if( FD_UNLIKELY( !(cond) ) ) {                                                               \
      FD_LOG_WARNING(( "FAIL %s:%d: %s", __FILE__, __LINE__, #cond ));                          \
      g_fail_cnt++;                                                                              \
    }                                                                                            \
  } while(0)

struct padded_data_rec {
  fd_h2_stream_t stream;
  ulong          data_cnt;
  ulong          data_sz;
  ulong          data_flags;
  uchar          data[ 64 ];
};

typedef struct padded_data_rec padded_data_rec_t;

static padded_data_rec_t g_rec;

static fd_h2_stream_t *
test_stream_query( fd_h2_conn_t * conn,
                   uint           stream_id ) {
  (void)conn;
  if( g_rec.stream.stream_id == stream_id ) return &g_rec.stream;
  return NULL;
}

static void
test_data( fd_h2_conn_t *   conn,
           fd_h2_stream_t * stream,
           void const *     data,
           ulong            data_sz,
           ulong            flags ) {
  (void)conn;
  (void)stream;
  g_rec.data_cnt++;
  g_rec.data_sz    = data_sz;
  g_rec.data_flags = flags;
  ulong copy_sz = fd_ulong_min( data_sz, sizeof(g_rec.data) );
  fd_memcpy( g_rec.data, data, copy_sz );
}

static void
test_fixture_init( fd_h2_conn_t *       conn,
                   fd_h2_callbacks_t *  cb,
                   fd_h2_rbuf_t *       rbuf_rx,
                   fd_h2_rbuf_t *       rbuf_tx,
                   uchar *              rx_mem,
                   ulong                rx_mem_sz,
                   uchar *              tx_mem,
                   ulong                tx_mem_sz ) {
  fd_memset( &g_rec, 0, sizeof(g_rec) );

  fd_h2_conn_init_server( conn );
  conn->flags = 0;

  fd_h2_stream_open( fd_h2_stream_init( &g_rec.stream ), conn, 1U );

  fd_h2_callbacks_init( cb );
  cb->stream_query = test_stream_query;
  cb->data         = test_data;

  fd_h2_rbuf_init( rbuf_rx, rx_mem, rx_mem_sz );
  fd_h2_rbuf_init( rbuf_tx, tx_mem, tx_mem_sz );
}

static void
test_push_frame( fd_h2_rbuf_t * rbuf,
                 uint           frame_type,
                 uint           flags,
                 uint           stream_id,
                 void const *   payload,
                 ulong          payload_sz ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( frame_type, payload_sz ),
    .flags       = (uchar)flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( rbuf, &hdr, sizeof(hdr) );
  if( payload_sz ) fd_h2_rbuf_push( rbuf, payload, payload_sz );
}

static void
test_padded_data_excludes_padding( void ) {
  uchar rx_mem [ 128 ] = {0};
  uchar tx_mem [ 128 ] = {0};
  uchar scratch[ 128 ] = {0};

  fd_h2_conn_t conn[1];
  fd_h2_callbacks_t cb[1];
  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t rbuf_tx[1];
  test_fixture_init( conn, cb, rbuf_rx, rbuf_tx, rx_mem, sizeof(rx_mem), tx_mem, sizeof(tx_mem) );

  uchar const payload[ 16 ] = {
    10U,
    0xde, 0xad, 0xbe, 0xef, 0x05,
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'
  };
  test_push_frame( rbuf_rx, FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_PADDED, 1U, payload, sizeof(payload) );

  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

  CHECK( g_rec.data_cnt==1UL );
  CHECK( g_rec.data_sz==5UL );
  CHECK( fd_memeq( g_rec.data, payload+1, 5UL ) );
  FD_LOG_NOTICE(( "Received data frame with %lu bytes of payload and %u bytes of padding",
                g_rec.data_sz, payload[0] ));
  FD_LOG_HEXDUMP_NOTICE(( "data", g_rec.data, g_rec.data_sz ));
  CHECK( g_rec.data_flags==0UL );
  CHECK( conn->rx_pad_rem==0U );
  CHECK( fd_h2_rbuf_used_sz( rbuf_rx )==0UL );
}

static void
test_padded_data_does_not_desync_next_frame( void ) {
  uchar rx_mem [ 256 ] = {0};
  uchar tx_mem [ 256 ] = {0};
  uchar scratch[ 256 ] = {0};

  fd_h2_conn_t conn[1];
  fd_h2_callbacks_t cb[1];
  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t rbuf_tx[1];
  test_fixture_init( conn, cb, rbuf_rx, rbuf_tx, rx_mem, sizeof(rx_mem), tx_mem, sizeof(tx_mem) );

  uchar const data_payload[ 16 ] = {
    10U,
    0xde, 0xad, 0xbe, 0xef, 0x05,
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'
  };
  test_push_frame( rbuf_rx, FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_PADDED, 1U, data_payload, sizeof(data_payload) );
  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

  fd_memset( &g_rec.data, 0, sizeof(g_rec.data) );
  g_rec.data_cnt   = 0UL;
  g_rec.data_sz    = 0UL;
  g_rec.data_flags = 0UL;

  uchar const ping_payload[ 8 ] = {
    0x00U, 0xffU, 0xffU, 0xffU, 0x06U, 0x00U, 0x00U, 0x00U
  };
  test_push_frame( rbuf_rx, FD_H2_FRAME_TYPE_PING, 0U, 0U, ping_payload, sizeof(ping_payload) );
  test_push_frame( rbuf_rx, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, NULL, 0UL );

  fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), cb );

  CHECK( !( conn->flags & FD_H2_CONN_FLAGS_SEND_GOAWAY ) );
  CHECK( conn->conn_error==0U );
  CHECK( fd_h2_rbuf_used_sz( rbuf_rx )==0UL );
  CHECK( fd_h2_rbuf_used_sz( rbuf_tx )==sizeof(fd_h2_ping_t)+sizeof(fd_h2_frame_hdr_t) );

  if( FD_UNLIKELY( fd_h2_rbuf_used_sz( rbuf_tx )<sizeof(fd_h2_ping_t)+sizeof(fd_h2_frame_hdr_t) ) ) return;

  fd_h2_ping_t pong;
  fd_h2_frame_hdr_t settings_ack;
  fd_h2_rbuf_pop_copy( rbuf_tx, &pong, sizeof(pong) );
  fd_h2_rbuf_pop_copy( rbuf_tx, &settings_ack, sizeof(settings_ack) );

  CHECK( fd_h2_frame_type( pong.hdr.typlen )==FD_H2_FRAME_TYPE_PING );
  CHECK( pong.hdr.flags==FD_H2_FLAG_ACK );
  CHECK( pong.payload==FD_LOAD( ulong, ping_payload ) );

  CHECK( fd_h2_frame_type( settings_ack.typlen )==FD_H2_FRAME_TYPE_SETTINGS );
  CHECK( fd_h2_frame_length( settings_ack.typlen )==0U );
  CHECK( settings_ack.flags==FD_H2_FLAG_ACK );
  CHECK( fd_h2_frame_stream_id( settings_ack.r_stream_id )==0U );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing padded DATA handling" ));

  test_padded_data_excludes_padding();
  test_padded_data_does_not_desync_next_frame();

  if( FD_UNLIKELY( g_fail_cnt ) ) {
    FD_LOG_ERR(( "%lu padded DATA regression checks failed", g_fail_cnt ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
