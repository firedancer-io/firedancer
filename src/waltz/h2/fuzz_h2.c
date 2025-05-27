/* fuzz_h2.c covers the fd_h2 connection-level APIs.  It attempts to
   find crashes, spinloops, and other bugs.  */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_h2.h"
#include "../../util/fd_util.h"

struct fuzz_h2_ctx {
  fd_h2_rbuf_t   rbuf_tx[1];
  fd_h2_conn_t   conn[1];
  fd_h2_stream_t stream[1];
  fd_h2_tx_op_t  tx_op[1];
};

typedef struct fuzz_h2_ctx fuzz_h2_ctx_t;

static FD_TL fuzz_h2_ctx_t g_ctx;

static FD_TL fd_rng_t g_rng[1];

/* Stream leak detector (detects unbalanced callbacks) */
static FD_TL long g_stream_cnt;

/* Double callback detector */
static FD_TL long g_conn_final_cnt;

static void
test_response_continue( void ) {
  if( !g_ctx.stream->stream_id ) return;
  fd_h2_tx_op_copy( g_ctx.conn, g_ctx.stream, g_ctx.rbuf_tx, g_ctx.tx_op );
  if( g_ctx.stream->state==FD_H2_STREAM_STATE_CLOSED ) {
    g_stream_cnt--;
    memset( g_ctx.tx_op,  0, sizeof(g_ctx.tx_op ) );
    memset( g_ctx.stream, 0, sizeof(g_ctx.stream) );
  }
}

static void
test_response_init( fd_h2_conn_t *   conn,
                    fd_h2_stream_t * stream ) {
  (void)conn;
  uint stream_id = stream->stream_id;

  fd_h2_rbuf_t * rbuf_tx = g_ctx.rbuf_tx;
  uchar hpack[] = { 0x88 /* :status: 200 */ };
  fd_h2_tx( rbuf_tx, hpack, sizeof(hpack), FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );

  fd_h2_tx_op_t * tx_op = g_ctx.tx_op;
  fd_h2_tx_op_init( tx_op, "Ok", 2UL, FD_H2_FLAG_END_STREAM );
  test_response_continue();
}

static fd_h2_stream_t *
cb_stream_create( fd_h2_conn_t * conn,
                  uint           stream_id ) {
  (void)conn; (void)stream_id;
  if( g_ctx.stream->stream_id ) {
    return NULL;
  }
  fd_h2_stream_init( g_ctx.stream );
  g_stream_cnt++;
  return g_ctx.stream;
}

static fd_h2_stream_t *
cb_stream_query( fd_h2_conn_t * conn,
                 uint           stream_id ) {
  assert( conn == g_ctx.conn );
  if( g_ctx.stream->stream_id!=stream_id ) return NULL;
  return g_ctx.stream;
}

static void
cb_conn_established( fd_h2_conn_t * conn ) {
  assert( conn == g_ctx.conn );
  return;
}

static void
cb_conn_final( fd_h2_conn_t * conn,
               uint           h2_err,
               int            closed_by ) {
  assert( conn == g_ctx.conn );
  assert( closed_by==0 || closed_by==1 );
  (void)h2_err;
  g_stream_cnt = 0L;
  g_conn_final_cnt++;
  return;
}

static void
cb_headers( fd_h2_conn_t *   conn,
            fd_h2_stream_t * stream,
            void const *     data,
            ulong            data_sz,
            ulong            flags ) {
  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, data, data_sz );
  while( !fd_hpack_rd_done( hpack_rd ) )  {
    static FD_TL uchar scratch_buf[ 4096 ];
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) );
    if( FD_UNLIKELY( err ) ) {
      fd_h2_conn_error( conn, err );
      return;
    }
  }
  if( flags & FD_H2_FLAG_END_STREAM ) {
    test_response_init( conn, stream );
  }
  return;
}

static void
cb_data( fd_h2_conn_t *   conn,
         fd_h2_stream_t * stream,
         void const *     data,
         ulong            data_sz,
         ulong            flags ) {
  assert( conn == g_ctx.conn );
  (void)stream; (void)data; (void)data_sz; (void)flags;
  if( flags & FD_H2_FLAG_END_STREAM ) {
    test_response_init( conn, stream );
  }
  return;
}

static void
cb_rst_stream( fd_h2_conn_t *   conn,
               fd_h2_stream_t * stream,
               uint             error_code,
               int              closed_by ) {
  (void)stream; (void)error_code;
  assert( conn == g_ctx.conn );
  assert( closed_by==0 || closed_by==1 );
  memset( &g_ctx.stream, 0, sizeof(fd_h2_stream_t) );
  g_stream_cnt--;
  return;
}

static void
cb_window_update( fd_h2_conn_t * conn,
                  uint           increment ) {
  (void)conn; (void)increment;
  return;
}

static void
cb_stream_window_update( fd_h2_conn_t *   conn,
                         fd_h2_stream_t * stream,
                         uint             increment ) {
  (void)conn; (void)stream; (void)increment;
  return;
}

static fd_h2_callbacks_t fuzz_h2_cb = {
  .stream_create        = cb_stream_create,
  .stream_query         = cb_stream_query,
  .conn_established     = cb_conn_established,
  .conn_final           = cb_conn_final,
  .headers              = cb_headers,
  .data                 = cb_data,
  .rst_stream           = cb_rst_stream,
  .window_update        = cb_window_update,
  .stream_window_update = cb_stream_window_update
};

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  memset( &g_ctx, 0, sizeof(fuzz_h2_ctx_t) );

  if( size<4 ) return -1;
  uint seed = FD_LOAD( uint, data );
  data += 4; size -= 4;

  fd_rng_t * rng = fd_rng_join( fd_rng_new( g_rng, seed, 0UL ) );

  uchar buf_rx [ 256 ];
  uchar buf_tx [ 256 ];
  uchar scratch[ 256 ];
  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t * rbuf_tx = g_ctx.rbuf_tx;
  fd_h2_rbuf_init( rbuf_rx, buf_rx, sizeof(buf_rx) );
  fd_h2_rbuf_init( rbuf_tx, buf_tx, sizeof(buf_tx) );

  if( seed&1 ) {
    fd_h2_conn_init_client( g_ctx.conn );
  } else {
    fd_h2_conn_init_server( g_ctx.conn );
  }
  g_ctx.conn->self_settings.max_frame_size = 256;

  g_stream_cnt     = 0L;
  g_conn_final_cnt = 0L;

  while( size ) {
    fd_h2_tx_control( g_ctx.conn, rbuf_tx, &fuzz_h2_cb );
    rbuf_tx->lo_off = rbuf_tx->hi_off;
    rbuf_tx->lo     = rbuf_tx->hi;

    if( FD_UNLIKELY( g_ctx.conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) {
      assert( g_conn_final_cnt==1 );
      assert( g_stream_cnt==0     );
      break;
    }

    ulong chunk = fd_ulong_min( size, (fd_rng_uint( rng )&15)+1 );
    if( fd_h2_rbuf_used_sz( rbuf_rx )+chunk > rbuf_rx->bufsz ) break;
    fd_h2_rbuf_push( rbuf_rx, data, chunk );
    data += chunk; size -= chunk;

    fd_h2_rx( g_ctx.conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), &fuzz_h2_cb );
  }
  fd_h2_tx_control( g_ctx.conn, rbuf_tx, &fuzz_h2_cb );

  assert( g_stream_cnt>=0 );
  assert( g_conn_final_cnt==0 || g_conn_final_cnt==1 );
  if( g_stream_cnt==1 ) {
    assert( g_ctx.stream->state==FD_H2_STREAM_STATE_OPEN ||
            g_ctx.stream->state==FD_H2_STREAM_STATE_CLOSING_RX ||
            g_ctx.stream->state==FD_H2_STREAM_STATE_CLOSING_TX );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
