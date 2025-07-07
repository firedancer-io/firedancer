#include "fd_grpc_client.h"
#include "fd_grpc_client_private.h"
#include "../../ballet/nanopb/pb_encode.h" /* pb_msgdesc_t */
#include <sys/socket.h>
#include "../h2/fd_h2_rbuf_sock.h"
#include "fd_grpc_codec.h"
#if FD_HAS_OPENSSL
#include "../openssl/fd_openssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../h2/fd_h2_rbuf_ossl.h"
#endif

ulong
fd_grpc_client_align( void ) {
  return fd_ulong_max( alignof(fd_grpc_client_t), fd_grpc_h2_stream_pool_align() );
}

ulong
fd_grpc_client_footprint( ulong buf_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_client_t), sizeof(fd_grpc_client_t) );
  l = FD_LAYOUT_APPEND( l, 1UL, buf_max ); /* nanopb_tx */
  l = FD_LAYOUT_APPEND( l, 1UL, buf_max ); /* frame_scratch */
  l = FD_LAYOUT_APPEND( l, 1UL, buf_max ); /* frame_rx_buf */
  l = FD_LAYOUT_APPEND( l, 1UL, buf_max ); /* frame_tx_buf */
  l = FD_LAYOUT_APPEND( l, fd_grpc_h2_stream_pool_align(), fd_grpc_h2_stream_pool_footprint( FD_GRPC_CLIENT_MAX_STREAMS ) );
  l = FD_LAYOUT_APPEND( l, 1UL, buf_max*FD_GRPC_CLIENT_MAX_STREAMS );
  return FD_LAYOUT_FINI( l, fd_grpc_client_align() );
}

static void
fd_grpc_h2_stream_reset( fd_grpc_h2_stream_t * stream ) {
  memset( &stream->s, 0, sizeof(fd_h2_stream_t) );
  stream->request_ctx = 0UL;
  memset( &stream->hdrs, 0, sizeof(fd_grpc_resp_hdrs_t) );
  stream->hdrs.grpc_status    = FD_GRPC_STATUS_UNKNOWN;
  stream->hdrs_received       = 0;
  stream->msg_buf_used        = 0UL;
  stream->msg_sz              = 0UL;
  stream->has_header_deadline = 0;
  stream->has_rx_end_deadline = 0;
}

fd_grpc_client_t *
fd_grpc_client_new( void *                             mem,
                    fd_grpc_client_callbacks_t const * callbacks,
                    fd_grpc_client_metrics_t *         metrics,
                    void *                             app_ctx,
                    ulong                              buf_max,
                    ulong                              rng_seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( buf_max<4096UL ) ) {
    FD_LOG_WARNING(( "undersz buf_max" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_grpc_client_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * client_mem      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_client_t), sizeof(fd_grpc_client_t) );
  void * nanopb_tx       = FD_SCRATCH_ALLOC_APPEND( l, 1UL, buf_max ); /* nanopb_tx */
  void * frame_scratch   = FD_SCRATCH_ALLOC_APPEND( l, 1UL, buf_max ); /* frame_scratch */
  void * frame_rx_buf    = FD_SCRATCH_ALLOC_APPEND( l, 1UL, buf_max ); /* frame_rx_buf */
  void * frame_tx_buf    = FD_SCRATCH_ALLOC_APPEND( l, 1UL, buf_max ); /* frame_tx_buf */
  void * stream_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_h2_stream_pool_align(), fd_grpc_h2_stream_pool_footprint( FD_GRPC_CLIENT_MAX_STREAMS ) );
  void * stream_buf_mem  = FD_SCRATCH_ALLOC_APPEND( l, 1UL, buf_max*FD_GRPC_CLIENT_MAX_STREAMS );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, fd_grpc_client_align() );
  FD_TEST( end-(ulong)mem == fd_grpc_client_footprint( buf_max ) );

  fd_grpc_client_t * client = client_mem;

  fd_grpc_h2_stream_t * stream_pool =
    fd_grpc_h2_stream_pool_join( fd_grpc_h2_stream_pool_new( stream_pool_mem, FD_GRPC_CLIENT_MAX_STREAMS ) );
  if( FD_UNLIKELY( !stream_pool ) ) FD_LOG_CRIT(( "Failed to create stream pool" )); /* unreachable */

  *client = (fd_grpc_client_t){
    .callbacks         = callbacks,
    .ctx               = app_ctx,
    .stream_pool       = stream_pool,
    .stream_bufs       = stream_buf_mem,
    .nanopb_tx         = nanopb_tx,
    .nanopb_tx_max     = buf_max,
    .frame_scratch     = frame_scratch,
    .frame_scratch_max = buf_max,
    .frame_rx_buf      = frame_rx_buf,
    .frame_rx_buf_max  = buf_max,
    .frame_tx_buf      = frame_tx_buf,
    .frame_tx_buf_max  = buf_max,
    .metrics           = metrics
  };

  /* FIXME for performance, cache this? */
  fd_h2_hdr_matcher_init( client->matcher, rng_seed );
  fd_h2_hdr_matcher_insert_literal( client->matcher, FD_GRPC_HDR_STATUS,  "grpc-status"  );
  fd_h2_hdr_matcher_insert_literal( client->matcher, FD_GRPC_HDR_MESSAGE, "grpc-message" );

  client->version_len = 5;
  memcpy( client->version, "0.0.0", 5 );

  for( ulong i=0UL; i<FD_GRPC_CLIENT_MAX_STREAMS; i++ ) {
    fd_grpc_h2_stream_t * stream = &client->stream_pool[ i ];
    stream->msg_buf     = (uchar *)stream_buf_mem + (i*buf_max);
    stream->msg_buf_max = buf_max;
    FD_TEST( (ulong)( stream->msg_buf + stream->msg_buf_max )<=end );
  }
  fd_grpc_client_reset( client );

  return client;
}

void *
fd_grpc_client_delete( fd_grpc_client_t * client ) {
  return client;
}

void
fd_grpc_client_set_version( fd_grpc_client_t * client,
                            char const *       version,
                            ulong              version_len ) {
  if( FD_UNLIKELY( version_len > FD_GRPC_CLIENT_VERSION_LEN_MAX ) ) {
    FD_LOG_WARNING(( "Version string too long (%lu chars), ignoring", version_len ));
    return;
  }
  client->version_len = (uchar)version_len;
  memcpy( client->version, version, version_len );
}

void
fd_grpc_client_set_authority( fd_grpc_client_t * client,
                              char const *       host,
                              ulong              host_len,
                              ushort             port ) {
  host_len = fd_ulong_min( host_len, sizeof(client->host)-1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( client->host ), host, host_len ) );
  client->host_len = (uchar)host_len;
  client->port     = (ushort)port;
}

int
fd_grpc_client_stream_acquire_is_safe( fd_grpc_client_t * client ) {
  /* Sufficient quota to start a stream? */
  if( FD_UNLIKELY( client->conn->stream_active_cnt[1]+1 > client->conn->peer_settings.max_concurrent_streams ) ) {
    return 0;
  }

  /* Free stream object available? */
  if( FD_UNLIKELY( !fd_grpc_h2_stream_pool_free( client->stream_pool ) ) ) {
    return 0;
  }
  if( FD_UNLIKELY( client->stream_cnt >= FD_GRPC_CLIENT_MAX_STREAMS ) ) {
    return 0;
  }

  return 1;
}

fd_grpc_h2_stream_t *
fd_grpc_client_stream_acquire( fd_grpc_client_t * client,
                               ulong              request_ctx ) {
  if( FD_UNLIKELY( client->stream_cnt >= FD_GRPC_CLIENT_MAX_STREAMS ) ) {
    FD_LOG_CRIT(( "stream pool exhausted" ));
  }

  fd_h2_conn_t * conn = client->conn;
  uint const stream_id = client->conn->tx_stream_next;
  conn->tx_stream_next += 2U;

  fd_grpc_h2_stream_t * stream = fd_grpc_h2_stream_pool_ele_acquire( client->stream_pool );
  fd_grpc_h2_stream_reset( stream );
  stream->request_ctx = request_ctx;

  fd_h2_stream_open( fd_h2_stream_init( &stream->s ), conn, stream_id );
  client->request_stream = stream;
  client->stream_ids[ client->stream_cnt ] = stream_id;
  client->streams   [ client->stream_cnt ] = stream;
  client->stream_cnt++;

  return stream;
}

void
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
  for( uint i=0UL; i<(client->stream_cnt); i++ ) {
    if( client->stream_ids[ i ] == stream->s.stream_id ) {
      map_idx = (int)i;
    }
  }
  if( FD_UNLIKELY( map_idx<0 ) ) FD_LOG_CRIT(( "stream map corrupt" )); /* unreachable */
  if( (ulong)map_idx+1 < client->stream_cnt ) {
    client->stream_ids[ map_idx ] = client->stream_ids[ client->stream_cnt-1 ];
    client->streams   [ map_idx ] = client->streams   [ client->stream_cnt-1 ];
  }
  client->stream_cnt--;

  fd_grpc_h2_stream_pool_ele_release( client->stream_pool, stream );
}

void
fd_grpc_client_reset( fd_grpc_client_t * client ) {
  fd_h2_rbuf_init( client->frame_rx, client->frame_rx_buf, client->frame_rx_buf_max );
  fd_h2_rbuf_init( client->frame_tx, client->frame_tx_buf, client->frame_tx_buf_max );
  fd_h2_conn_init_client( client->conn );
  client->conn->ctx      = client;
  client->h2_hs_done     = 0;
  client->ssl_hs_done    = 0;
  client->request_stream = NULL;
  *client->request_tx_op = (fd_h2_tx_op_t){0};

  /* Disable RX flow control */
  client->conn->self_settings.initial_window_size = (1U<<31)-1U;
  client->conn->rx_wnd_max   = (1U<<31)-1U;
  client->conn->rx_wnd_wmark = client->conn->rx_wnd_max - (1U<<20);

  /* Free all stream objects */
  while( client->stream_cnt ) {
    fd_grpc_h2_stream_t * stream = client->streams[ client->stream_cnt-1 ];
    fd_grpc_client_stream_release( client, stream );
  }
}

/* fd_grpc_client_send_stream_quota writes a WINDOW_UPDATE frame, which
   eventually allows the peer to send more data bytes. */

static void
fd_grpc_client_send_stream_quota( fd_h2_rbuf_t *        rbuf_tx,
                                  fd_grpc_h2_stream_t * stream,
                                  uint                  bump ) {
  fd_h2_window_update_t window_update = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_WINDOW_UPDATE, 4UL ),
      .r_stream_id = fd_uint_bswap( stream->s.stream_id )
    },
    .increment = fd_uint_bswap( bump )
  };
  fd_h2_rbuf_push( rbuf_tx, &window_update, sizeof(fd_h2_window_update_t) );
  stream->s.rx_wnd += bump;
}

/* fd_grpc_client_send_timeout is called when a stream timeout triggers.
   Calls back to the user, writes a RST_STREAM frame, and frees the
   stream object. */

static void
fd_grpc_client_send_timeout( fd_h2_rbuf_t *        rbuf_tx,
                             fd_grpc_client_t *    client,
                             fd_grpc_h2_stream_t * stream,
                             int                   deadline_kind ) {
  client->callbacks->rx_timeout( client->ctx, stream->request_ctx, deadline_kind );
  fd_h2_tx_rst_stream( rbuf_tx, stream->s.stream_id, FD_H2_ERR_CANCEL );
  fd_grpc_client_stream_release( client, stream );
}

void
fd_grpc_client_service_streams( fd_grpc_client_t * client,
                                long               ts_nanos ) {
  ulong const meta_frame_max =
    fd_ulong_max( sizeof(fd_h2_window_update_t), sizeof(fd_h2_rst_stream_t) );
  fd_h2_conn_t * conn    = client->conn;
  fd_h2_rbuf_t * rbuf_tx = client->frame_tx;
  if( FD_UNLIKELY( conn->flags ) ) return;
  uint  const wnd_max    = conn->self_settings.initial_window_size;
  uint  const wnd_thres  = wnd_max / 2;
  for( ulong i=0UL; i<(client->stream_cnt); i++ ) {
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<meta_frame_max ) ) break;
    fd_grpc_h2_stream_t * stream = client->streams[ i ];

    if( FD_UNLIKELY( ( stream->has_header_deadline ) &
                     ( stream->header_deadline_nanos - ts_nanos <= 0L ) ) ) {
      fd_grpc_client_send_timeout( rbuf_tx, client, stream, FD_GRPC_DEADLINE_HEADER );
      i--; /* stream removed */
      continue;
    }

    if( FD_UNLIKELY( ( stream->has_rx_end_deadline ) &
                     ( stream->rx_end_deadline_nanos - ts_nanos <= 0L ) ) ) {
      fd_grpc_client_send_timeout( rbuf_tx, client, stream, FD_GRPC_DEADLINE_RX_END );
      i--; /* stream removed */
      continue;
    }

    if( FD_UNLIKELY( stream->s.rx_wnd < wnd_thres ) ) {
      uint const bump = wnd_max - stream->s.rx_wnd;
      fd_grpc_client_send_stream_quota( rbuf_tx, stream, bump );
    }
  }
}

#if FD_HAS_OPENSSL

static int
fd_ossl_log_error( char const * str,
                   ulong        len,
                   void *       ctx ) {
  (void)ctx;
  if( len>0 && str[ len-1 ]=='\n' ) len--;
  FD_LOG_INFO(( "%.*s", (int)len, str ));
  return 0;
}

int
fd_grpc_client_rxtx_ossl( fd_grpc_client_t * client,
                          SSL *              ssl,
                          int *              charge_busy ) {
  if( FD_UNLIKELY( !client->ssl_hs_done ) ) {
    int res = SSL_do_handshake( ssl );
    if( res<=0 ) {
      int error = SSL_get_error( ssl, res );
      if( FD_LIKELY( error==SSL_ERROR_WANT_READ || error==SSL_ERROR_WANT_WRITE ) ) return 1;
      FD_LOG_INFO(( "SSL_do_handshake failed (%i-%s)", error, fd_openssl_ssl_strerror( error ) ));
      long verify_result = SSL_get_verify_result( ssl );
      if( error == SSL_ERROR_SSL && verify_result != X509_V_OK ) {
        FD_LOG_WARNING(( "Certificate verification failed: %s", X509_verify_cert_error_string( verify_result ) ));
      }
      ERR_print_errors_cb( fd_ossl_log_error, NULL );
      return 0;
    } else {
      client->ssl_hs_done = 1;
    }
  }

  fd_h2_conn_t * conn = client->conn;
  int ssl_err = 0;
  ulong read_sz = fd_h2_rbuf_ssl_read( client->frame_rx, ssl, &ssl_err );
  if( FD_UNLIKELY( ssl_err && ssl_err!=SSL_ERROR_WANT_READ ) ) {
    if( ssl_err==SSL_ERROR_ZERO_RETURN ) {
      FD_LOG_WARNING(( "gRPC server closed connection" ));
      return 0;
    }
    FD_LOG_WARNING(( "SSL_read_ex failed (%i-%s)", ssl_err, fd_openssl_ssl_strerror( ssl_err ) ));
    ERR_print_errors_cb( fd_ossl_log_error, NULL );
    return 0;
  }
  if( FD_UNLIKELY( conn->flags ) ) fd_h2_tx_control( conn, client->frame_tx, &fd_grpc_client_h2_callbacks );
  fd_h2_rx( conn, client->frame_rx, client->frame_tx, client->frame_scratch, client->frame_scratch_max, &fd_grpc_client_h2_callbacks );
  fd_grpc_client_service_streams( client, fd_log_wallclock() );
  ulong write_sz = fd_h2_rbuf_ssl_write( client->frame_tx, ssl );

  if( read_sz!=0 || write_sz!=0 ) *charge_busy = 1;
  return 1;
}

#endif /* FD_HAS_OPENSSL */

#if FD_H2_HAS_SOCKETS

int
fd_grpc_client_rxtx_socket( fd_grpc_client_t * client,
                            int                sock_fd,
                            int *              charge_busy ) {
  fd_h2_conn_t * conn = client->conn;
  ulong const frame_rx_lo_0 = client->frame_rx->lo_off;
  ulong const frame_rx_hi_0 = client->frame_rx->hi_off;
  ulong const frame_tx_lo_1 = client->frame_tx->lo_off;
  ulong const frame_tx_hi_1 = client->frame_tx->hi_off;

  int rx_err = fd_h2_rbuf_recvmsg( client->frame_rx, sock_fd, MSG_NOSIGNAL|MSG_DONTWAIT );
  if( FD_UNLIKELY( rx_err ) ) {
    FD_LOG_INFO(( "Disconnected: recvmsg error (%i-%s)", rx_err, fd_io_strerror( rx_err ) ));
    return 0;
  }

  if( FD_UNLIKELY( conn->flags ) ) fd_h2_tx_control( conn, client->frame_tx, &fd_grpc_client_h2_callbacks );
  fd_h2_rx( conn, client->frame_rx, client->frame_tx, client->frame_scratch, client->frame_scratch_max, &fd_grpc_client_h2_callbacks );
  fd_grpc_client_service_streams( client, fd_log_wallclock() );

  int tx_err = fd_h2_rbuf_sendmsg( client->frame_tx, sock_fd, MSG_NOSIGNAL|MSG_DONTWAIT );
  if( FD_UNLIKELY( tx_err ) ) {
    FD_LOG_WARNING(( "fd_h2_rbuf_sendmsg failed (%i-%s)", tx_err, fd_io_strerror( tx_err ) ));
    return 0;
  }

  ulong const frame_rx_lo_1 = client->frame_rx->lo_off;
  ulong const frame_rx_hi_1 = client->frame_rx->hi_off;
  ulong const frame_tx_lo_0 = client->frame_tx->lo_off;
  ulong const frame_tx_hi_0 = client->frame_tx->hi_off;

  if( frame_rx_lo_0!=frame_rx_lo_1 || frame_rx_hi_0!=frame_rx_hi_1 ||
      frame_tx_lo_0!=frame_tx_lo_1 || frame_tx_hi_0!=frame_tx_hi_1 ) {
    *charge_busy = 1;
  }

  return 1;
}

#endif /* FD_H2_HAS_SOCKETS */

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
  client->callbacks->tx_complete( client->ctx, stream->request_ctx );
  return 1;
}

static int
fd_grpc_client_request_continue( fd_grpc_client_t * client ) {
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) return 0;
  if( FD_UNLIKELY( !client->request_stream ) ) return 0;
  if( FD_UNLIKELY( !client->request_tx_op->chunk_sz ) ) return 0;
  return fd_grpc_client_request_continue1( client );
}

int
fd_grpc_client_is_connected( fd_grpc_client_t * client ) {
  if( FD_UNLIKELY( !client                                          ) ) return 0;
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD      ) ) return 0;
  if( FD_UNLIKELY( !client->h2_hs_done                              ) ) return 0;
  return 1;
}

int
fd_grpc_client_request_is_blocked( fd_grpc_client_t * client ) {
  if( FD_UNLIKELY( !client                                          ) ) return 1;
  if( FD_UNLIKELY( client->conn->flags & FD_H2_CONN_FLAGS_DEAD      ) ) return 1;
  if( FD_UNLIKELY( !client->h2_hs_done                              ) ) return 1;
  if( FD_UNLIKELY( !fd_h2_rbuf_is_empty( client->frame_tx )         ) ) return 1;
  if( FD_UNLIKELY( !fd_grpc_client_stream_acquire_is_safe( client ) ) ) return 1;
  return 0;
}

fd_grpc_h2_stream_t *
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
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return NULL;

  /* Encode message */
  FD_TEST( client->nanopb_tx_max > sizeof(fd_grpc_hdr_t) );
  uchar * proto_buf = client->nanopb_tx + sizeof(fd_grpc_hdr_t);
  pb_ostream_t ostream = pb_ostream_from_buffer( proto_buf, client->nanopb_tx_max - sizeof(fd_grpc_hdr_t) );
  if( FD_UNLIKELY( !pb_encode( &ostream, fields, message ) ) ) {
    FD_LOG_WARNING(( "Failed to encode Protobuf message (%.*s). This is a bug (insufficient buffer space?)", (int)path_len, path ));
    return NULL;
  }
  ulong const serialized_sz = ostream.bytes_written;

  /* Create gRPC length prefix */
  fd_grpc_hdr_t hdr = {
    .compressed=0,
    .msg_sz=fd_uint_bswap( (uint)serialized_sz )
  };
  memcpy( client->nanopb_tx, &hdr, sizeof(fd_grpc_hdr_t) );
  ulong const payload_sz = serialized_sz + sizeof(fd_grpc_hdr_t);

  /* Allocate stream descriptor */
  fd_grpc_h2_stream_t * stream    = fd_grpc_client_stream_acquire( client, request_ctx );
  uint const            stream_id = stream->s.stream_id;

  /* Write HTTP/2 request headers */
  fd_h2_tx_prepare( client->conn, client->frame_tx, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );
  fd_grpc_req_hdrs_t req_meta = {
    .host     = client->host,
    .host_len = client->host_len,
    .port     = client->port,
    .path     = path,
    .path_len = path_len,
    .https    = 1, /* grpc_client assumes TLS encryption for now */

    .bearer_auth     = auth_token,
    .bearer_auth_len = auth_token_sz
  };
  if( FD_UNLIKELY( !fd_grpc_h2_gen_request_hdrs(
      &req_meta,
      client->frame_tx,
      client->version,
      client->version_len
  ) ) ) {
    FD_LOG_WARNING(( "Failed to generate gRPC request headers (%.*s). This is a bug", (int)path_len, path ));
    return NULL;
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

  return stream;
}

void
fd_grpc_client_deadline_set( fd_grpc_h2_stream_t * stream,
                             int                   deadline_kind,
                             long                  ts_nanos ) {
  switch( deadline_kind ) {
  case FD_GRPC_DEADLINE_HEADER:
    stream->header_deadline_nanos = ts_nanos;
    stream->has_header_deadline   = 1;
    break;
  case FD_GRPC_DEADLINE_RX_END:
    stream->rx_end_deadline_nanos = ts_nanos;
    stream->has_rx_end_deadline   = 1;
    break;
  }
}

/* Lookup stream by ID */

static fd_h2_stream_t *
fd_grpc_h2_stream_query( fd_h2_conn_t * conn,
                         uint           stream_id ) {
  fd_grpc_client_t * client = conn->ctx;
  for( ulong i=0UL; i<client->stream_cnt; i++ ) {
    if( client->stream_ids[ i ] == stream_id ) {
      return &client->streams[ i ]->s;
    }
  }
  return NULL;
}

static void
fd_grpc_h2_conn_established( fd_h2_conn_t * conn ) {
  fd_grpc_client_t * client = conn->ctx;
  client->h2_hs_done = 1;
  client->callbacks->conn_established( client->ctx );
}

static void
fd_grpc_h2_conn_final( fd_h2_conn_t * conn,
                       uint           h2_err,
                       int            closed_by ) {
  fd_grpc_client_t * client = conn->ctx;
  client->callbacks->conn_dead( client->ctx, h2_err, closed_by );
}

/* React to response data */

void
fd_grpc_h2_cb_headers(
    fd_h2_conn_t *   conn,
    fd_h2_stream_t * h2_stream,
    void const *     data,
    ulong            data_sz,
    ulong            flags
) {
  fd_grpc_h2_stream_t * stream = fd_grpc_h2_stream_upcast( h2_stream );
  fd_grpc_client_t * client = conn->ctx;

  int h2_status = fd_grpc_h2_read_response_hdrs( &stream->hdrs, client->matcher, data, data_sz );
  if( FD_UNLIKELY( h2_status!=FD_H2_SUCCESS ) ) {
    /* Failed to parse HTTP/2 headers */
    fd_h2_stream_error( h2_stream, client->frame_tx, FD_H2_ERR_PROTOCOL );
    client->callbacks->rx_end( client->ctx, stream->request_ctx, &stream->hdrs ); /* invalidates stream->hdrs */
    fd_grpc_client_stream_release( client, stream );
    return;
  }

  if( !stream->hdrs_received && !!( flags & FD_H2_FLAG_END_HEADERS) ) {
    /* Got initial response header */
    stream->hdrs_received = 1;
    stream->has_header_deadline = 0;
    if( FD_LIKELY( ( stream->hdrs.h2_status==200  ) &
                   ( !!stream->hdrs.is_grpc_proto ) ) ) {
      client->callbacks->rx_start( client->ctx, stream->request_ctx );
    }
  }

  if( ( flags & (FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM) )
              ==(FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM)   ) {
    client->callbacks->rx_end( client->ctx, stream->request_ctx, &stream->hdrs );
    fd_grpc_client_stream_release( client, stream );
    return;
  }
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
  if( FD_UNLIKELY( ( stream->hdrs.h2_status!=200 ) |
                   ( !stream->hdrs.is_grpc_proto ) ) ) {
    return;
  }

  do {

    /* Read header bytes */
    if( stream->msg_buf_used < sizeof(fd_grpc_hdr_t) ) {
      ulong hdr_frag_sz = fd_ulong_min( sizeof(fd_grpc_hdr_t) - stream->msg_buf_used, data_sz );
      fd_memcpy( stream->msg_buf + stream->msg_buf_used, data, hdr_frag_sz );
      stream->msg_buf_used += hdr_frag_sz;
      data     = (void const *)( (ulong)data + (ulong)hdr_frag_sz );
      data_sz -= hdr_frag_sz;
      if( FD_UNLIKELY( stream->msg_buf_used < sizeof(fd_grpc_hdr_t) ) ) return;

      /* Header complete */
      stream->msg_sz = fd_uint_bswap( FD_LOAD( uint, (void *)( (ulong)stream->msg_buf+1 ) ) );
      if( FD_UNLIKELY( sizeof(fd_grpc_hdr_t)  + stream->msg_sz > stream->msg_buf_max ) ) {
        FD_LOG_WARNING(( "Received oversized gRPC message (%lu bytes), killing request", stream->msg_sz ));
        client->callbacks->rx_end( client->ctx, stream->request_ctx, &stream->hdrs );
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

    client->metrics->stream_chunks_rx_cnt++;
    client->metrics->stream_chunks_rx_bytes += chunk_sz;

    if( stream->msg_buf_used >= wmark ) {
      /* Data complete */
      void const * msg_ptr = stream->msg_buf + sizeof(fd_grpc_hdr_t);
      client->callbacks->rx_msg( client->ctx, msg_ptr, stream->msg_sz, stream->request_ctx );
      stream->msg_buf_used = 0UL;
      stream->msg_sz       = 0UL;
    }

  } while( data_sz );

  if( flags & FD_H2_FLAG_END_STREAM ) {
    /* FIXME incomplete gRPC message */
    if( FD_UNLIKELY( !stream->msg_buf_used ) ) {
      FD_LOG_WARNING(( "Received incomplete gRPC message" ));
    }
    client->callbacks->rx_end( client->ctx, stream->request_ctx, &stream->hdrs );
  }
}

/* Server might kill our request */

static void
fd_grpc_h2_rst_stream( fd_h2_conn_t *   conn,
                       fd_h2_stream_t * h2_stream,
                       uint             error_code,
                       int              closed_by ) {
  if( closed_by==1 ) {
    FD_LOG_WARNING(( "Server terminated request stream_id=%u (%u-%s)",
                     h2_stream->stream_id, error_code, fd_h2_strerror( error_code ) ));
  } else {
    FD_LOG_WARNING(( "Stream failed stream_id=%u (%u-%s)",
                     h2_stream->stream_id, error_code, fd_h2_strerror( error_code ) ));
  }
  fd_grpc_client_t *    client = conn->ctx;
  fd_grpc_h2_stream_t * stream = fd_grpc_h2_stream_upcast( h2_stream );
  client->callbacks->rx_end( client->ctx, stream->request_ctx, &stream->hdrs ); /* invalidates stream->hdrs */
  fd_grpc_client_stream_release( client, stream );
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

void
fd_grpc_h2_ping_ack( fd_h2_conn_t * conn ) {
  fd_grpc_client_t * client = conn->ctx;
  client->callbacks->ping_ack( client->ctx );
}

fd_h2_rbuf_t *
fd_grpc_client_rbuf_tx( fd_grpc_client_t * client ) {
  return client->frame_tx;
}

fd_h2_rbuf_t *
fd_grpc_client_rbuf_rx( fd_grpc_client_t * client ) {
  return client->frame_rx;
}

fd_h2_conn_t *
fd_grpc_client_h2_conn( fd_grpc_client_t * client ) {
  return client->conn;
}

/* fd_grpc_client_h2_callbacks specifies h2->grpc_client callbacks.
   Stored in .rodata for security.  Must be kept in sync with fd_h2 to
   avoid NULL pointers. */

fd_h2_callbacks_t const fd_grpc_client_h2_callbacks = {
  .stream_create        = fd_h2_noop_stream_create,
  .stream_query         = fd_grpc_h2_stream_query,
  .conn_established     = fd_grpc_h2_conn_established,
  .conn_final           = fd_grpc_h2_conn_final,
  .headers              = fd_grpc_h2_cb_headers,
  .data                 = fd_grpc_h2_cb_data,
  .rst_stream           = fd_grpc_h2_rst_stream,
  .window_update        = fd_grpc_h2_window_update,
  .stream_window_update = fd_grpc_h2_stream_window_update,
  .ping_ack             = fd_grpc_h2_ping_ack,
};
