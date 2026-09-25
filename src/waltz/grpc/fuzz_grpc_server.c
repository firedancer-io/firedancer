/* fuzz_grpc_server.c drives fd_grpc_server with arbitrary HTTP/2 frame
   streams from a client: request field blocks, gRPC message framing,
   flow control, and the zstd coded request path.  It looks for crashes,
   spin loops, leaked stream slots, and unbalanced callbacks. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_grpc_server_private.h"
#include "../../util/fd_util.h"

#define FUZZ_ROUTE_UNARY  "/fuzz.Svc/Unary"
#define FUZZ_ROUTE_STREAM "/fuzz.Svc/Stream"

static FD_TL fd_rng_t g_rng[1];

/* Stream accounting: every stream the app accepted must be closed
   exactly once */
static FD_TL long g_stream_cnt;
static FD_TL long g_conn_cnt;

/* The compression context that zstd sizes for level 1 dominates. */
static uchar g_server_mem[ 8UL<<20 ] __attribute__((aligned(FD_GRPC_SERVER_ALIGN)));
static fd_grpc_server_t * g_server;

static int
cb_conn_open( void *                  ctx,
              fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  g_conn_cnt++;
  return 0;
}

static void
cb_conn_close( void *                  ctx,
               fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  g_conn_cnt--;
  assert( g_conn_cnt>=0L );
}

static void
cb_stream_hdr( void *                    ctx,
               fd_grpc_server_stream_t * stream,
               char const *              name,
               ulong                     name_len,
               char const *              value,
               ulong                     value_len ) {
  (void)ctx; (void)stream;
  assert( name_len );
  /* Touch the bytes so that a use-after-free or bad length shows up */
  ulong sum = 0UL;
  for( ulong i=0UL; i<name_len;  i++ ) sum += (ulong)(uchar)name [i];
  for( ulong i=0UL; i<value_len; i++ ) sum += (ulong)(uchar)value[i];
  FD_COMPILER_UNPREDICTABLE( sum );
}

static int
cb_stream_open( void *                    ctx,
                fd_grpc_server_stream_t * stream,
                char const *              path,
                ulong                     path_len ) {
  (void)ctx; (void)stream;
  if( path_len==sizeof(FUZZ_ROUTE_UNARY)-1UL && fd_memeq( path, FUZZ_ROUTE_UNARY, path_len ) ) {
    g_stream_cnt++;
    return FD_GRPC_SERVER_ACCEPT_UNARY;
  }
  if( path_len==sizeof(FUZZ_ROUTE_STREAM)-1UL && fd_memeq( path, FUZZ_ROUTE_STREAM, path_len ) ) {
    g_stream_cnt++;
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }
  return FD_GRPC_SERVER_REJECT;
}

static void
cb_stream_msg( void *                    ctx,
               fd_grpc_server_stream_t * stream,
               uchar const *             msg,
               ulong                     msg_sz ) {
  (void)ctx;
  static uchar big[ 1500 ];
  for( ulong i=0UL; i<sizeof(big); i++ ) big[i] = (uchar)( i&0x07 );

  if( msg_sz && msg[0]=='L' ) {
    /* A message no send queue can hold, which goes out through a
       large send slot */
    static uchar huge[ 9000 ];
    for( ulong i=0UL; i<sizeof(huge); i++ ) huge[i] = (uchar)( i*3UL );
    ulong sz  = 4097UL + ( (ulong)msg[ msg_sz>1UL ] * 17UL ) % ( sizeof(huge)-4097UL );
    int   err = fd_grpc_server_send( stream, huge, sz, 0U );
    assert( err==FD_GRPC_SERVER_SUCCESS || err==FD_GRPC_SERVER_ERR_AGAIN ||
            err==FD_GRPC_SERVER_ERR_TOOBIG );
    return;
  }

  if( msg_sz && msg[0]=='B' ) {
    /* Large, compressible response: exercises the compressor */
    int err = fd_grpc_server_send( stream, big, sizeof(big), 0U );
    assert( err==FD_GRPC_SERVER_SUCCESS || err==FD_GRPC_SERVER_ERR_AGAIN ||
            err==FD_GRPC_SERVER_ERR_TOOBIG );
    return;
  }
  int err = fd_grpc_server_send( stream, msg, msg_sz, 0U );
  assert( err==FD_GRPC_SERVER_SUCCESS || err==FD_GRPC_SERVER_ERR_AGAIN ||
          err==FD_GRPC_SERVER_ERR_TOOBIG );
  if( msg_sz && msg[0]=='F' ) fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, "done", 4UL );
}

static void
cb_stream_half_close( void *                    ctx,
                      fd_grpc_server_stream_t * stream ) {
  (void)ctx;
  fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
}

static void
cb_stream_writable( void *                    ctx,
                    fd_grpc_server_stream_t * stream ) {
  (void)ctx; (void)stream;
}

static void
cb_stream_close( void *                    ctx,
                 fd_grpc_server_stream_t * stream,
                 int                       reason ) {
  (void)ctx; (void)stream;
  assert( reason>=FD_GRPC_SERVER_CLOSE_FINISHED && reason<=FD_GRPC_SERVER_CLOSE_ABORTED );
  g_stream_cnt--;
  assert( g_stream_cnt>=0L );
}

static fd_grpc_server_callbacks_t const fuzz_callbacks = {
  .conn_open         = cb_conn_open,
  .conn_close        = cb_conn_close,
  .stream_hdr        = cb_stream_hdr,
  .stream_open       = cb_stream_open,
  .stream_msg        = cb_stream_msg,
  .stream_half_close = cb_stream_half_close,
  .stream_writable   = cb_stream_writable,
  .stream_close      = cb_stream_close
};

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */

  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = 1UL;
  params->max_stream_cnt     = 3UL;
  params->max_request_msg_sz = 2048UL;
  params->stream_tx_queue_sz = 4096UL;
  /* Room for one message of eight queues, so the large send path is
     reachable and its slot accounting is exercised */
  params->max_msg_sz              = 32768UL;
  params->large_msg_slot_cnt      = 1UL;
  params->stream_tx_queue_msg_max = 8UL;
  params->conn_rx_buf_sz     = 20480UL;
  params->conn_tx_buf_sz     = 20480UL;
  params->max_frame_sz       = 16384UL;
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 1UL<<18;
  params->compression        = FD_GRPC_SERVER_COMPRESSION_ZSTD;
  params->compression_min_sz = 128UL;
  params->compression_level  = 1;
  params->seed               = 1UL;

  assert( fd_grpc_server_footprint( params )<=sizeof(g_server_mem) );
  g_server = fd_grpc_server_join( fd_grpc_server_new( g_server_mem, params, &fuzz_callbacks, NULL ) );
  assert( g_server );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<4UL ) return -1;
  uint seed = FD_LOAD( uint, data );
  data += 4UL; size -= 4UL;

  fd_rng_t * rng = fd_rng_join( fd_rng_new( g_rng, seed, 0UL ) );
  long now = 1000L*1000L*1000L;

  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_open_direct( g_server, now );
  assert( conn );
  assert( g_conn_cnt==1L );

  /* The connection preface and a client SETTINGS frame, so that the
     fuzzer spends its bytes on requests instead of rediscovering the
     handshake */
  static uchar const hello[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"  /* SETTINGS */
    "\x00\x00\x00\x04\x01\x00\x00\x00\x00"; /* SETTINGS ACK */
  assert( fd_grpc_server_conn_push_rx( conn, hello, sizeof(hello)-1UL, now )==sizeof(hello)-1UL );

  if( seed&1u ) {
    /* Open a unary call that declares zstd request messages, so the
       remaining input reaches the decompressor as DATA frames.  The
       field block spells out every header as an HPACK literal without
       indexing. */
    static uchar const request[] =
      "\x00\x00\x8e\x01\x04\x00\x00\x00\x01"       /* HEADERS, END_HEADERS, stream 1 */
      "\x00\x07" ":method" "\x04" "POST"
      "\x00\x07" ":scheme" "\x04" "http"
      "\x00\x05" ":path"   "\x0f" FUZZ_ROUTE_UNARY
      "\x00\x0c" "content-type" "\x10" "application/grpc"
      "\x00\x02" "te" "\x08" "trailers"
      "\x00\x0d" "grpc-encoding" "\x04" "zstd"
      "\x00\x14" "grpc-accept-encoding" "\x04" "zstd";
    assert( sizeof(request)-1UL==0x8eUL+9UL );
    assert( fd_grpc_server_conn_push_rx( conn, request, sizeof(request)-1UL, now )==sizeof(request)-1UL );
  }

  static uchar drain[ 4096 ];
  while( size && fd_grpc_server_conn_is_open( conn ) ) {
    ulong chunk = fd_ulong_min( size, ( (ulong)fd_rng_uint( rng ) & 255UL )+1UL );
    ulong n     = fd_grpc_server_conn_push_rx( conn, data, chunk, now );
    data += n; size -= n;

    while( fd_grpc_server_conn_pop_tx( conn, drain, sizeof(drain) ) ) {}

    now += (long)( fd_rng_uint( rng ) & 0xffffff );
    fd_grpc_server_service( g_server, now );
    while( fd_grpc_server_conn_pop_tx( conn, drain, sizeof(drain) ) ) {}

    if( !n ) break; /* no progress */
  }

  if( fd_grpc_server_conn_is_open( conn ) ) fd_grpc_server_conn_close( conn );
  assert( g_conn_cnt    ==0L );
  assert( g_stream_cnt  ==0L );
  assert( fd_grpc_server_is_idle( g_server ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
