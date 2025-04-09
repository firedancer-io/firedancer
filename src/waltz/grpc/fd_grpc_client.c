#include "fd_grpc_client.h"
#include "fd_grpc_client_private.h"
#include "../h2/fd_h2_rbuf_ossl.h"
#include "../../flamenco/nanopb/pb_encode.h" /* pb_msgdesc_t */
#include <sys/socket.h>
#if FD_HAS_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* Forward declarations */

static fd_h2_callbacks_t const fd_grpc_client_h2_callbacks;

ulong
fd_grpc_client_align( void ) {
  return alignof(fd_grpc_client_t);
}

ulong
fd_grpc_client_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_client_t), sizeof(fd_grpc_client_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_client_bufs_t), sizeof(fd_grpc_client_bufs_t) );
  l = FD_LAYOUT_APPEND( l, fd_grpc_h2_stream_pool_align(), fd_grpc_h2_stream_pool_footprint( FD_GRPC_CLIENT_MAX_STREAMS ) );
  return FD_LAYOUT_FINI( l, fd_grpc_client_align() );
}

fd_grpc_client_t *
fd_grpc_client_new( void *                             mem,
                    fd_grpc_client_callbacks_t const * callbacks,
                    fd_grpc_client_metrics_t *         metrics,
                    void *                             app_ctx ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * client_mem      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_client_t), sizeof(fd_grpc_client_t) );
  void * bufs_mem        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_client_bufs_t), sizeof(fd_grpc_client_bufs_t) );
  void * stream_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_h2_stream_pool_align(), fd_grpc_h2_stream_pool_footprint( FD_GRPC_CLIENT_MAX_STREAMS ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_grpc_client_align() );

  fd_grpc_client_t *      client = client_mem;
  fd_grpc_client_bufs_t * bufs   = bufs_mem;

  fd_grpc_h2_stream_t * stream_pool =
    fd_grpc_h2_stream_pool_join( fd_grpc_h2_stream_pool_new( stream_pool_mem, FD_GRPC_CLIENT_MAX_STREAMS ) );
  if( FD_UNLIKELY( !stream_pool ) ) FD_LOG_CRIT(( "Failed to create stream pool" )); /* unreachable */

  *client = (fd_grpc_client_t){
    .callbacks     = callbacks,
    .ctx           = app_ctx,
    .stream_pool   = stream_pool,
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
fd_grpc_client_delete( fd_grpc_client_t * client ) {
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

#if FD_HAS_OPENSSL

int
fd_grpc_client_rxtx_ossl( fd_grpc_client_t * client,
                          SSL *              ssl ) {
  if( FD_UNLIKELY( !client->ssl_hs_done ) ) {
    int res = SSL_do_handshake( ssl );
    if( res<=0 ) {
      int error = SSL_get_error( ssl, res );
      if( FD_LIKELY( error==SSL_ERROR_WANT_READ || error==SSL_ERROR_WANT_WRITE ) ) return 1;
      ERR_print_errors_cb( fd_ossl_log_error, NULL );
      client->failed = 1;
      return 0;
    } else {
      client->ssl_hs_done = 1;
    }
  }

  fd_h2_conn_t * conn = client->conn;
  fd_h2_rbuf_ssl_read( client->frame_rx, ssl );
  if( FD_UNLIKELY( conn->flags ) ) fd_h2_tx_control( conn, client->frame_tx, &fd_grpc_client_h2_callbacks );
  fd_h2_rx( conn, client->frame_rx, client->frame_tx, client->frame_scratch, FD_GRPC_CLIENT_BUFSZ, &fd_grpc_client_h2_callbacks );
  fd_h2_rbuf_ssl_write( client->frame_tx, ssl );

  return 1;
}

#endif /* FD_HAS_OPENSSL */

/* fd_grpc_client_request continue attempts to write a request data
   frame. */

static int
fd_grpc_client_request_continue1( fd_grpc_client_t * client ) {
  fd_grpc_h2_stream_t * stream    = client->request_stream;
  fd_h2_stream_t *      h2_stream = &stream->s;
  fd_h2_tx_op_copy( client->conn, h2_stream, client->frame_tx, client->request_tx_op );
  if( FD_UNLIKELY( client->request_tx_op->chunk_sz ) ) return 0;
  if( FD_UNLIKELY( h2_stream->state != FD_H2_STREAM_STATE_CLOSING_TX ) ) return 0;
  client->metrics->stream_chunks_tx_cnt++;
  /* Request finished */
  client->request_stream = NULL;
  return 1;
}

static int
fd_grpc_client_request_continue( fd_grpc_client_t * client ) {
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) return 0;
  if( FD_UNLIKELY( !client->request_stream ) ) return 0;
  if( FD_UNLIKELY( !client->request_tx_op->chunk_sz ) ) return 0;
  return fd_grpc_client_request_continue1( client );
}

/* fd_grpc_client_stream_acquire grabs a new stream ID and a stream
   object. */

static inline int
fd_grpc_client_stream_acquire_is_safe( fd_grpc_client_t * client ) {
  /* Sufficient quota to start a stream? */
  if( FD_UNLIKELY( client->conn->stream_active_cnt[1]+1 <= client->conn->peer_settings.max_concurrent_streams ) ) return 0;

  /* Free stream object available? */
  if( FD_UNLIKELY( !fd_grpc_h2_stream_pool_free( client->stream_pool ) ) ) return 0;
  if( FD_UNLIKELY( client->stream_cnt >= FD_GRPC_CLIENT_MAX_STREAMS ) ) return 0;

  return 1;
}

static fd_grpc_h2_stream_t *
fd_grpc_client_stream_acquire( fd_grpc_client_t * client,
                               ulong              request_ctx ) {
  if( FD_UNLIKELY( client->stream_cnt >= FD_GRPC_CLIENT_MAX_STREAMS ) ) {
    FD_LOG_CRIT(( "stream pool exhausted" ));
  }

  fd_h2_conn_t * conn = client->conn;
  uint const stream_id = client->conn->rx_stream_next;
  conn->rx_stream_next += 2U;

  fd_grpc_h2_stream_t * stream_node = fd_grpc_h2_stream_pool_ele_acquire( client->stream_pool );
  stream_node->request_ctx = request_ctx;

  fd_h2_stream_open( fd_h2_stream_init( &stream_node->s ), conn, stream_id );
  client->request_stream = stream_node;
  client->stream_ids[ stream_id ] = stream_id;
  client->stream_cnt++;

  return stream_node;
}

static void
fd_grpc_client_stream_release( fd_grpc_client_t *    client,
                               fd_grpc_h2_stream_t * stream ) {
  if( FD_UNLIKELY( !client->stream_cnt ) ) FD_LOG_CRIT(( "stream map corrupt" )); /* unreachable */

  /* Deallocate tx_op */
  if( FD_UNLIKELY( stream == client->request_stream ) ) {
    client->request_stream = NULL;
    *client->request_tx_op = (fd_h2_tx_op_t){0};
  }

  /* Remove stream from map */
  int map_idx = -1;
  for( int i=0UL; i<FD_GRPC_CLIENT_MAX_STREAMS; i++ ) {
    if( client->stream_ids[ i ] == stream->s.stream_id ) {
      map_idx = i;
    }
  }
  if( FD_UNLIKELY( map_idx<0 ) ) FD_LOG_CRIT(( "stream map corrupt" )); /* unreachable */
  if( (ulong)map_idx+1 < client->stream_cnt ) {
    client->stream_ids[ map_idx ] = client->stream_ids[ client->stream_cnt-1 ];
    client->streams   [ map_idx ] = client->streams   [ client->stream_cnt-1 ];
    client->stream_cnt--;
  }

  fd_grpc_h2_stream_pool_ele_release( client->stream_pool, stream );
}

int
fd_grpc_client_request_is_blocked( fd_grpc_client_t * client ) {
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD      ) ) return 1;
  if( FD_UNLIKELY( !fd_h2_rbuf_is_empty( client->frame_tx )         ) ) return 1;
  if( FD_UNLIKELY( !fd_grpc_client_stream_acquire_is_safe( client ) ) ) return 1;
  return 0;
}

int
fd_grpc_client_request_start(
    fd_grpc_client_t *   client,
    char const *         path,
    ulong                path_len,
    ulong                request_ctx,
    pb_msgdesc_t const * fields,
    void const *         message,
    char const *         auth_token,
    ulong                auth_token_sz
) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return 0;

  /* Encode message */
  FD_STATIC_ASSERT( sizeof(((fd_grpc_client_bufs_t *)0)->nanopb_tx) >= FD_GRPC_CLIENT_MSG_SZ_MAX, sz );
  uchar * proto_buf = client->nanopb_tx + sizeof(fd_grpc_hdr_t);
  pb_ostream_t ostream = pb_ostream_from_buffer( proto_buf, FD_GRPC_CLIENT_MSG_SZ_MAX );
  if( FD_UNLIKELY( !pb_encode( &ostream, fields, message ) ) ) {
    FD_LOG_WARNING(( "Failed to encode Protobuf message (%.*s). This is a bug (insufficient buffer space?)", (int)path_len, path ));
    return 0;
  }
  ulong const serialized_sz = ostream.bytes_written;

  /* Create gRPC length prefix */
  fd_grpc_hdr_t hdr = { .compressed=0, .msg_sz=(uint)serialized_sz };
  memcpy( client->nanopb_tx, &hdr, sizeof(fd_grpc_hdr_t) );
  ulong const payload_sz = serialized_sz + sizeof(fd_grpc_hdr_t);

  /* Allocate stream descriptor */
  fd_grpc_h2_stream_t * stream    = fd_grpc_client_stream_acquire( client, request_ctx );
  uint const            stream_id = stream->s.stream_id;

  /* Write HTTP/2 request headers */
  fd_h2_tx_prepare( client->conn, client->frame_tx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );
  fd_grpc_req_hdrs_t req_meta = {
    .path     = path,
    .path_len = path_len,
    .https    = 1, /* grpc_client assumes TLS encryption for now */

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
  fd_h2_tx_op_init( client->request_tx_op, client->nanopb_tx, payload_sz, FD_H2_FLAG_END_STREAM );
  fd_grpc_client_request_continue1( client );
  client->metrics->requests_sent++;
  client->metrics->streams_active++;

  FD_LOG_DEBUG(( "gRPC request path=%.*s sz=%lu", (int)path_len, path, serialized_sz ));

  return 1;
}

/* Lookup stream by ID */

static fd_h2_stream_t *
fd_grpc_h2_stream_query( fd_h2_conn_t * conn,
                           uint           stream_id ) {
  fd_grpc_client_t * client = conn->ctx;
  fd_h2_stream_t * stream = NULL;
  for( ulong i=0UL; i<FD_GRPC_CLIENT_MAX_STREAMS; i++ ) {
    if( client->stream_ids[ i ] == stream_id ) {
      stream = &client->streams[ i ]->s;
    }
  }
  return stream;
}

/* React to response data */

static void
fd_grpc_h2_cb_headers(
    fd_h2_conn_t *   conn,
    fd_h2_stream_t * h2_stream,
    void const *     data,
    ulong            data_sz,
    ulong            flags
) {
  (void)flags;

  fd_grpc_h2_stream_t * stream = fd_grpc_h2_stream_upcast( h2_stream );
  fd_grpc_client_t * client = conn->ctx;
  int h2_status = fd_grpc_h2_read_response_hdrs( &stream->hdrs, client->matcher, data, data_sz );
  if( FD_UNLIKELY( h2_status!=FD_H2_SUCCESS ) ) {
    /* Failed to parse HTTP/2 headers */
    fd_h2_stream_error( h2_stream, client->frame_tx, FD_H2_ERR_PROTOCOL );
    fd_grpc_client_stream_release( client, stream );
  }

  /* FIXME react to HTTP/2 headers */
}

static void
fd_grpc_h2_cb_data(
    fd_h2_conn_t *   conn,
    fd_h2_stream_t * h2_stream,
    void const *     data,
    ulong            data_sz,
    ulong            flags
) {
  fd_grpc_client_t *    client = conn->ctx;
  fd_grpc_h2_stream_t * stream = fd_grpc_h2_stream_upcast( h2_stream );

  do {

    /* Read header bytes */
    if( stream->msg_buf_used < sizeof(fd_grpc_hdr_t) ) {
      ulong hdr_frag_sz = fd_ulong_min( sizeof(fd_grpc_hdr_t) - stream->msg_buf_used, data_sz );
      fd_memcpy( stream->msg_buf + stream->msg_buf_used, data, hdr_frag_sz );
      stream->msg_buf_used += hdr_frag_sz;
      data     = (void const *)( (ulong)data + (ulong)hdr_frag_sz );
      data_sz -= hdr_frag_sz;
      if( FD_UNLIKELY( stream->msg_buf_used < sizeof(fd_grpc_hdr_t) ) ) return;

      stream->msg_sz = fd_uint_bswap( FD_LOAD( uint, (void *)( (ulong)data+1 ) ) );
      if( FD_UNLIKELY( stream->msg_sz > FD_GRPC_CLIENT_MSG_SZ_MAX ) ) {
        /* Header complete */
        FD_LOG_WARNING(( "Received oversized gRPC message (%lu bytes), killing request", stream->msg_sz ));
        fd_h2_stream_error( h2_stream, client->frame_tx, FD_H2_ERR_INTERNAL );
        fd_grpc_client_stream_release( client, stream );
        return;
      }
    }

    /* Read payload bytes */
    ulong wmark    = sizeof(fd_grpc_hdr_t) + stream->msg_sz;
    ulong chunk_sz = fd_ulong_min( stream->msg_buf_used+data_sz, wmark ) - stream->msg_buf_used;
    if( FD_UNLIKELY( chunk_sz>data_sz ) ) FD_LOG_CRIT(( "integer underflow" )); /* unreachable */
    fd_memcpy( stream->msg_buf + stream->msg_buf_used, data, chunk_sz );
    stream->msg_buf_used += chunk_sz;
    data     = (void const *)( (ulong)data + (ulong)chunk_sz );
    data_sz -= chunk_sz;

    if( stream->msg_buf_used >= wmark ) {
      /* Data complete */
      /* FIXME call back with message */
      stream->msg_buf_used = 0UL;
      stream->msg_sz       = 0UL;
    }

  } while( data_sz );

  if( flags & FD_H2_FLAG_END_STREAM ) {
    /* FIXME incomplete gRPC message */
    if( stream->msg_buf_used ) {
    }
  }
}

/* Server might kill our request */

static void
fd_grpc_h2_rst_stream( fd_h2_conn_t *   conn,
                       fd_h2_stream_t * stream,
                       uint             error_code,
                       int              closed_by ) {
  if( closed_by==1 ) {
    FD_LOG_WARNING(( "Server terminated request stream_id=%u (%u-%s)",
                     stream->stream_id, error_code, fd_h2_strerror( error_code ) ));
  } else {
    FD_LOG_WARNING(( "Stream failed stream_id=%u (%u-%s)",
                     stream->stream_id, error_code, fd_h2_strerror( error_code ) ));
  }
  fd_grpc_client_t * client = conn->ctx;
  fd_grpc_client_stream_release( client, fd_grpc_h2_stream_upcast( stream ) );
}

/* A HTTP/2 flow control change might unblock a queued request send op */

void
fd_grpc_h2_window_update( fd_h2_conn_t * conn,
                            uint           increment ) {
  (void)increment;
  fd_grpc_client_request_continue( conn->ctx );
}

void
fd_grpc_h2_stream_window_update( fd_h2_conn_t *   conn,
                                 fd_h2_stream_t * stream,
                                 uint             increment ) {
  (void)stream; (void)increment;
  fd_grpc_client_request_continue( conn->ctx );
}

/* fd_grpc_client_h2_callbacks specifies h2->grpc_client callbacks.
   Stored in .rodata for security.  Must be kept in sync with fd_h2 to
   avoid NULL pointers. */

static fd_h2_callbacks_t const fd_grpc_client_h2_callbacks = {
  .stream_create        = fd_h2_noop_stream_create,
  .stream_query         = fd_grpc_h2_stream_query,
  .conn_established     = fd_h2_noop_conn_established,
  .conn_final           = fd_h2_noop_conn_final,
  .headers              = fd_grpc_h2_cb_headers,
  .data                 = fd_grpc_h2_cb_data,
  .rst_stream           = fd_grpc_h2_rst_stream,
  .window_update        = fd_grpc_h2_window_update,
  .stream_window_update = fd_grpc_h2_stream_window_update,
};
