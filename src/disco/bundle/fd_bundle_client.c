#include "fd_bundle_client_private.h"
#include "../../waltz/h2/fd_h2_rbuf_ossl.h"
#include "../../waltz/grpc/fd_grpc.h"
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Forward declarations */

static fd_h2_callbacks_t const fd_bundle_h2_callbacks;

ulong
fd_bundle_client_align( void ) {
  return alignof(fd_bundle_client_t);
}

ulong
fd_bundle_client_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_bundle_client_t), sizeof(fd_bundle_client_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_bundle_client_bufs_t), sizeof(fd_bundle_client_bufs_t) );
  l = FD_LAYOUT_APPEND( l, fd_bundle_h2_stream_pool_align(), fd_bundle_h2_stream_pool_footprint( FD_BUNDLE_CLIENT_MAX_STREAMS ) );
  return FD_LAYOUT_FINI( l, fd_bundle_client_align() );
}

fd_bundle_client_t *
fd_bundle_client_new( void *                       mem,
                      SSL *                        ssl,
                      fd_bundle_client_metrics_t * metrics ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * client_mem      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_bundle_client_t), sizeof(fd_bundle_client_t) );
  void * bufs_mem        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_bundle_client_bufs_t), sizeof(fd_bundle_client_bufs_t) );
  void * stream_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bundle_h2_stream_pool_align(), fd_bundle_h2_stream_pool_footprint( FD_BUNDLE_CLIENT_MAX_STREAMS ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_bundle_client_align() );

  fd_bundle_client_t *      client = client_mem;
  fd_bundle_client_bufs_t * bufs   = bufs_mem;

  fd_bundle_h2_stream_t * stream_pool =
    fd_bundle_h2_stream_pool_join( fd_bundle_h2_stream_pool_new( stream_pool_mem, FD_BUNDLE_CLIENT_MAX_STREAMS ) );
  if( FD_UNLIKELY( !stream_pool ) ) FD_LOG_CRIT(( "Failed to create stream pool" )); /* unreachable */

  *client = (fd_bundle_client_t){
    .ssl           = ssl,
    .stream_pool   = stream_pool,
    .nanopb_rx     = bufs->nanopb_rx,
    .nanopb_tx     = bufs->nanopb_tx,
    .frame_scratch = bufs->frame_scratch,
    .metrics       = metrics
  };
  fd_h2_rbuf_init( client->frame_rx, bufs->frame_rx_buf, sizeof(bufs->frame_rx_buf) );
  fd_h2_rbuf_init( client->frame_tx, bufs->frame_tx_buf, sizeof(bufs->frame_tx_buf) );

  fd_h2_conn_init_client( client->conn );
  client->conn->ctx = client;

  /* Don't memset bufs for better performance */

  return client;
}

void *
fd_bundle_client_delete( fd_bundle_client_t * client ) {
  return client;
}

static int
fd_ossl_log_error( char const * str,
                   ulong        len,
                   void *       ctx ) {
  (void)ctx;
  FD_LOG_WARNING(( "%.*s", (int)len, str ));
  return 0;
}

void
fd_bundle_client_rxtx( fd_bundle_client_t * client ) {
  SSL * ssl = client->ssl;
  if( FD_UNLIKELY( !client->ssl_hs_done ) ) {
    int res = SSL_do_handshake( ssl );
    if( res<=0 ) {
      int error = SSL_get_error( ssl, res );
      if( FD_LIKELY( error==SSL_ERROR_WANT_READ || error==SSL_ERROR_WANT_WRITE ) ) return;
      ERR_print_errors_cb( fd_ossl_log_error, NULL );
      client->failed = 1;
      return;
    } else {
      client->ssl_hs_done = 1;
    }
  }

  fd_h2_conn_t * conn = client->conn;
  fd_h2_rbuf_ssl_read( client->frame_rx, ssl );
  if( FD_UNLIKELY( conn->flags ) ) fd_h2_tx_control( conn, client->frame_tx );
  fd_h2_rx( conn, client->frame_rx, client->frame_tx, client->frame_scratch, FD_BUNDLE_CLIENT_BUFSZ, &fd_bundle_h2_callbacks );
  fd_h2_rbuf_ssl_write( client->frame_tx, ssl );
}

/* fd_bundle_client_request continue attempts to write a request data
   frame. */

static int
fd_bundle_client_request_continue1( fd_bundle_client_t * client ) {
  fd_h2_stream_t * stream = client->request_stream;
  fd_h2_tx_op_copy( client->conn, stream, client->frame_tx, client->request_tx_op );
  if( FD_UNLIKELY( client->request_tx_op->chunk_sz ) ) return 0;
  if( FD_UNLIKELY( stream->state != FD_H2_STREAM_STATE_CLOSING_TX ) ) return 0;
  /* Request finished */
  client->request_stream = NULL;
  return 1;
}

static int
fd_bundle_client_request_continue( fd_bundle_client_t * client ) {
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) return 0;
  if( FD_UNLIKELY( !client->request_stream ) ) return 0;
  if( FD_UNLIKELY( !client->request_tx_op->chunk_sz ) ) return 0;
  return fd_bundle_client_request_continue1( client );
}

/* fd_bundle_client_stream_acquire grabs a new stream ID and a stream
   object. */

static inline int
fd_bundle_client_stream_acquire_is_safe( fd_bundle_client_t * client ) {
  /* Sufficient quota to start a stream? */
  if( FD_UNLIKELY( client->conn->stream_active_cnt[1]+1 <= client->conn->peer_settings.max_concurrent_streams ) ) return 0;

  /* Free stream object available? */
  if( FD_UNLIKELY( !fd_bundle_h2_stream_pool_free( client->stream_pool ) ) ) return 0;
  if( FD_UNLIKELY( client->stream_cnt >= FD_BUNDLE_CLIENT_MAX_STREAMS ) ) return 0;

  return 1;
}

static fd_h2_stream_t *
fd_bundle_client_stream_acquire( fd_bundle_client_t * client ) {
  if( FD_UNLIKELY( client->stream_cnt >= FD_BUNDLE_CLIENT_MAX_STREAMS ) ) {
    FD_LOG_CRIT(( "stream pool exhausted" ));
  }

  fd_h2_conn_t * conn = client->conn;
  uint const stream_id = client->conn->rx_stream_next;
  conn->rx_stream_next += 2U;

  fd_bundle_h2_stream_t * stream_node = fd_bundle_h2_stream_pool_ele_acquire( client->stream_pool );

  fd_h2_stream_t * stream = fd_h2_stream_open( fd_h2_stream_init( &stream_node->s ), conn, stream_id );
  client->request_stream = stream;
  client->stream_ids[ stream_id ] = stream_id;
  client->stream_cnt++;
  return stream;
}

static void
fd_bundle_client_stream_release( fd_bundle_client_t * client,
                                 fd_h2_stream_t *     stream ) {
  if( FD_UNLIKELY( !client->stream_cnt ) ) FD_LOG_CRIT(( "stream map corrupt" )); /* unreachable */

  /* Deallocate tx_op */
  if( FD_UNLIKELY( stream == client->request_stream ) ) {
    client->request_stream = NULL;
    *client->request_tx_op = (fd_h2_tx_op_t){0};
  }

  /* Remove stream from map */
  int map_idx = -1;
  for( int i=0UL; i<FD_BUNDLE_CLIENT_MAX_STREAMS; i++ ) {
    if( client->stream_ids[ i ] == stream->stream_id ) {
      map_idx = i;
    }
  }
  if( FD_UNLIKELY( map_idx<0 ) ) FD_LOG_CRIT(( "stream map corrupt" )); /* unreachable */
  if( (ulong)map_idx+1 < client->stream_cnt ) {
    client->stream_ids[ map_idx ] = client->stream_ids[ client->stream_cnt-1 ];
    client->streams   [ map_idx ] = client->streams   [ client->stream_cnt-1 ];
    client->stream_cnt--;
  }

  fd_bundle_h2_stream_t * stream_node = (void *)( (ulong)stream - offsetof(fd_bundle_h2_stream_t, s) );
  fd_bundle_h2_stream_pool_ele_release( client->stream_pool, stream_node );
}

int
fd_bundle_client_request_start(
    fd_bundle_client_t * client,
    char const *         path,
    ulong                path_len,
    pb_msgdesc_t const * fields,
    void const *         message,
    char const *         auth_token,
    ulong                auth_token_sz
) {
  /* Sanity check conn */
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) return 0;
  if( FD_UNLIKELY( !fd_h2_rbuf_is_empty( client->frame_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_bundle_client_stream_acquire_is_safe( client ) ) ) return 0;

  /* Encode message */
  FD_STATIC_ASSERT( sizeof((fd_bundle_client_bufs_t *)0)->nanopb_rx == sizeof(fd_grpc_hdr_t)+FD_BUNDLE_CLIENT_MSG_SZ_MAX, sz );
  uchar * proto_buf = client->nanopb_rx + sizeof(fd_grpc_hdr_t);
  pb_ostream_t ostream = pb_ostream_from_buffer( proto_buf, FD_BUNDLE_CLIENT_MSG_SZ_MAX );
  if( FD_UNLIKELY( !pb_encode( &ostream, fields, message ) ) ) {
    FD_LOG_WARNING(( "Failed to encode Protobuf message (%.*s). This is a bug (insufficient buffer space?)", (int)path_len, path ));
    return 0;
  }
  ulong const serialized_sz = ostream.bytes_written;

  /* Create gRPC length prefix */
  fd_grpc_hdr_t hdr = { .compressed=0, .msg_sz=(uint)serialized_sz };
  memcpy( client->nanopb_rx, &hdr, sizeof(fd_grpc_hdr_t) );
  ulong const payload_sz = serialized_sz + sizeof(fd_grpc_hdr_t);

  /* Allocate stream descriptor */
  fd_h2_stream_t * stream    = fd_bundle_client_stream_acquire( client );
  uint const       stream_id = stream->stream_id;

  /* Write HTTP/2 request headers */
  fd_h2_tx_prepare( client->conn, client->frame_tx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );
  fd_grpc_req_hdrs_t req_meta = {
    .path     = path,
    .path_len = path_len,
    .https    = 1, /* bundle_client assumes TLS encryption for now */

    .bearer_auth     = auth_token,
    .bearer_auth_len = auth_token_sz
  };
  if( FD_UNLIKELY( !fd_grpc_h2_gen_request_hdrs( &req_meta, client->frame_tx ) ) ) {
    FD_LOG_WARNING(( "Failed to generate gRPC request headers (%.*s). This is a bug", (int)path_len, path ));
    return 0;
  }
  fd_h2_tx_commit( client->conn, client->frame_tx );

  /* Queue request payload for send
     (Protobuf message might have to be fragmented into multiple HTTP/2
     DATA frames if the client gets blocked) */
  fd_h2_tx_op_init( client->request_tx_op, client->nanopb_rx, payload_sz, FD_H2_FLAG_END_STREAM );
  fd_bundle_client_request_continue1( client );
  client->metrics->requests_sent++;

  FD_LOG_DEBUG(( "gRPC request path=%.*s sz=%lu", (int)path_len, path, serialized_sz ));

  return 1;
}

/* A HTTP/2 flow control change might unblock a queued request send op */

void
fd_bundle_h2_window_update( fd_h2_conn_t * conn,
                            uint           increment ) {
  (void)increment;
  fd_bundle_client_request_continue( conn->ctx );
}

void
fd_bundle_h2_stream_window_update( fd_h2_conn_t *   conn,
                                   fd_h2_stream_t * stream,
                                   uint             increment ) {
  (void)stream; (void)increment;
  fd_bundle_client_request_continue( conn->ctx );
}

/* fd_bundle_h2_callbacks specifies h2->bundle_client callbacks.
   Stored in .rodata for security.  Must be kept in sync with fd_h2 to
   avoid NULL pointers. */

static fd_h2_callbacks_t const fd_bundle_h2_callbacks = {
  .stream_create        = fd_h2_noop_stream_create,
  .stream_query         = fd_bundle_h2_stream_query,
  .conn_established     = fd_h2_noop_conn_established,
  .conn_final           = fd_h2_noop_conn_final,
  .headers              = fd_bundle_h2_cb_headers,
  .data                 = fd_bundle_h2_cb_data,
  .rst_stream           = fd_bundle_h2_rst_stream,
  .window_update        = fd_bundle_h2_window_update,
  .stream_window_update = fd_bundle_h2_stream_window_update,
};
