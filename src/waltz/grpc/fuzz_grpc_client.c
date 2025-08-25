#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif


#include "fd_grpc_client.h"
#include "fd_grpc_client_private.h"
#include "../../util/fd_util.h"

uchar client_mem[2 << 17] __attribute__((aligned(128)));
ulong const buf_max = 4096UL;

static void
cb_rx_start( void *app_ctx,
             ulong request_ctx ) {
  (void) app_ctx;
  (void) request_ctx;
}

static void
cb_rx_end( void *app_ctx,
           ulong request_ctx,
           fd_grpc_resp_hdrs_t *resp_hdrs ) {
  (void) app_ctx;
  (void) request_ctx;
  (void) resp_hdrs;
}

static void
cb_rx_timeout( void *app_ctx,
               ulong request_ctx,
               int deadline_kind ) {
  (void) app_ctx;
  (void) request_ctx;
  (void) deadline_kind;
}

fd_grpc_client_callbacks_t callbacks = {
    .rx_start   = cb_rx_start,
    .rx_end     = cb_rx_end,
    .rx_timeout = cb_rx_timeout,
};

static void
test_grpc_client_mock_conn( fd_grpc_client_t *client ) {
  client->ssl_hs_done = 1;
  client->h2_hs_done  = 1;
  client->conn->flags = 0;
}

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 3 ); /* crash on warning log */

  FD_TEST( fd_grpc_client_footprint( buf_max )<=sizeof(client_mem));
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
#define PARAMS_SIZE (3)
  if( FD_UNLIKELY( size < PARAMS_SIZE )) {
    return -1;
  }
  fd_grpc_client_metrics_t metrics = {0};
  void *app_ctx = (void *) (0x1234UL);
  ulong rng_seed = 1UL;
  fd_grpc_client_t *client = fd_grpc_client_new( client_mem, &callbacks, &metrics, app_ctx, buf_max, rng_seed );
  FD_TEST( client );

  fd_grpc_client_reset( client );
  test_grpc_client_mock_conn( client );

  fd_grpc_h2_stream_t *stream = fd_grpc_client_stream_acquire( client, 0UL );
  FD_TEST( stream );
  FD_TEST( !stream->hdrs_received );

  /* Inject a few bits of state so that the code paths inside the
     callback can be exercised. */
  stream->hdrs.is_grpc_proto = data[ 0 ] & 1u;
  stream->hdrs.h2_status = data[ 1 ];
  ulong flags = data[ 2 ];

  uchar const *payload = data+PARAMS_SIZE;
  ulong payload_sz = size>PARAMS_SIZE ? size-PARAMS_SIZE : 0UL;

  fd_grpc_h2_cb_headers( client->conn, &stream->s, payload, payload_sz, flags );

  /* stream may have been released by the callback, so we ask the
     client whether it is still around before touching it again. */
  if( fd_grpc_client_stream_acquire_is_safe( client )) {
    /* The stream is still alive.  Basic invariants: hdrs_received
       is a boolean and msg_buf_used never exceeds its capacity. */
    FD_TEST( stream->hdrs_received<=1 );
    FD_TEST( stream->msg_buf_used<=stream->msg_buf_max );
  }

  fd_grpc_client_delete( client );
#undef PARAMS_SIZE
  return 0;
}
