/* fd_grpc_web.c implements gRPC-Web for browser support.

   It serves HTTP/1.1 on a gRPC server port, so that browsers can request:
   "GET /" for the index page, and POST for a binary gRPC-Web call. */

#include "fd_grpc_server_private.h"
#include "../../third_party/picohttpparser/picohttpparser.h"

#include <strings.h>

/* FD_GRPC_WEB_HDR_MAX bounds the header lines of a request */

#define FD_GRPC_WEB_HDR_MAX (64UL)

/* fd_grpc_web_reply answers the request with one response and marks the
   connection to close once it drains. */

static void
fd_grpc_web_reply( fd_grpc_server_conn_t * conn,
                   char const *            status,
                   char const *            ctype,
                   char const *            body,
                   ulong                   body_sz ) {
  fd_grpc_server_t * server = conn->server;
  char  head[ FD_GRPC_WEB_HEAD_MAX ];
  ulong head_len;
  FD_TEST( fd_cstr_printf_check( head, sizeof(head), &head_len,
                                 "HTTP/1.1 %s\r\n"
                                 "content-type: %s\r\n"
                                 "content-length: %lu\r\n"
                                 "cache-control: no-store\r\n"
                                 "connection: close\r\n"
                                 "\r\n",
                                 status, ctype, body_sz ) );

  conn->flags |= FD_GRPC_SERVER_CONN_FLAG_HTTP1;
  if( FD_UNLIKELY( head_len+body_sz > fd_h2_rbuf_free_sz( conn->rbuf_tx ) ) ) {
    server->metrics.request_error_cnt++;
  } else {
    fd_h2_rbuf_push( conn->rbuf_tx, head, head_len );
    if( body_sz ) fd_h2_rbuf_push( conn->rbuf_tx, body, body_sz );
  }
  fd_grpc_server_conn_closing( conn );
}

#define FD_GRPC_WEB_REPLY(conn,status) fd_grpc_web_reply( (conn), (status), "text/plain", "", 0UL )

/* fd_grpc_web_content_len parses a content-length value.  Returns
   ULONG_MAX if it is not a plain decimal number. */

static ulong
fd_grpc_web_content_len( char const * value,
                         ulong        value_len ) {
  if( FD_UNLIKELY( !value_len || value_len>12UL ) ) return ULONG_MAX;
  ulong len = 0UL;
  for( ulong i=0UL; i<value_len; i++ ) {
    if( FD_UNLIKELY( value[ i ]<'0' || value[ i ]>'9' ) ) return ULONG_MAX;
    len = len*10UL + (ulong)( value[ i ]-'0' );
  }
  return len;
}

void
fd_grpc_web_conn_rx( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_t * server = conn->server;

  /* The request is read whole into the frame scratch, which bounds it */
  char * req   = (char *)server->frame_scratch;
  ulong  cap   = server->params.max_frame_sz;
  ulong  avail = fd_ulong_min( fd_h2_rbuf_used_sz( conn->rbuf_rx ), cap );
  ulong  chunk0, chunk1;
  uchar const * p = fd_h2_rbuf_peek_used( conn->rbuf_rx, &chunk0, &chunk1 );
  ulong n0 = fd_ulong_min( avail, chunk0 );
  fd_memcpy( req, p, n0 );
  if( n0<avail ) fd_memcpy( req+n0, conn->rbuf_rx->buf0, avail-n0 );

  char const *      method;
  ulong             method_len;
  char const *      path;
  ulong             path_len;
  int               minor_version;
  struct phr_header hdrs[ FD_GRPC_WEB_HDR_MAX ];
  ulong             hdr_cnt = FD_GRPC_WEB_HDR_MAX;
  int head_sz = phr_parse_request( req, avail, &method, &method_len, &path, &path_len,
                                   &minor_version, hdrs, &hdr_cnt, 0UL );
  if( head_sz==-2 ) {
    if( avail<cap ) return;
    FD_GRPC_WEB_REPLY( conn, "431 Request Header Fields Too Large" );
    return;
  }
  if( FD_UNLIKELY( head_sz<0 ) ) {
    FD_GRPC_WEB_REPLY( conn, "400 Bad Request" );
    return;
  }

  if( method_len==3UL && fd_memeq( method, "GET", 3UL ) ) {
    if( path_len==1UL && path[ 0 ]=='/' && server->params.web_index ) {
      fd_grpc_web_reply( conn, "200 OK", "text/html; charset=utf-8",
                         server->params.web_index, server->params.web_index_sz );
    } else {
      fd_grpc_web_reply( conn, "404 Not Found", "text/plain", "not found\n", 10UL );
    }
    return;
  }
  if( FD_UNLIKELY( method_len!=4UL || !fd_memeq( method, "POST", 4UL ) ) ) {
    FD_GRPC_WEB_REPLY( conn, "405 Method Not Allowed" );
    return;
  }

  ulong content_len = ULONG_MAX;
  int   grpc_web    = 0;
  for( ulong i=0UL; i<hdr_cnt; i++ ) {
    struct phr_header const * h = hdrs+i;
    if( h->name_len==14UL && !strncasecmp( h->name, "content-length", 14UL ) ) {
      content_len = fd_grpc_web_content_len( h->value, h->value_len );
    } else if( h->name_len==12UL && !strncasecmp( h->name, "content-type", 12UL ) ) {
      grpc_web = ( h->value_len==20UL && fd_memeq( h->value, "application/grpc-web",       20UL ) ) ||
                 ( h->value_len==26UL && fd_memeq( h->value, "application/grpc-web+proto", 26UL ) );
    }
  }
  if( FD_UNLIKELY( !grpc_web                      ) ) { FD_GRPC_WEB_REPLY( conn, "415 Unsupported Media Type" ); return; }
  if( FD_UNLIKELY( content_len==ULONG_MAX         ) ) { FD_GRPC_WEB_REPLY( conn, "411 Length Required"        ); return; }
  if( FD_UNLIKELY( content_len>cap-(ulong)head_sz ) ) { FD_GRPC_WEB_REPLY( conn, "413 Content Too Large"      ); return; }
  if( (ulong)head_sz+content_len>avail ) return;

  fd_h2_rbuf_skip( conn->rbuf_rx, (ulong)head_sz+content_len );
  conn->flags |= FD_GRPC_SERVER_CONN_FLAG_HTTP1;

  fd_grpc_server_stream_t * stream = fd_grpc_server_stream_acquire( conn ); /* the conn's first stream */
  /* A path longer than any route is left empty, which matches none */
  if( FD_LIKELY( path_len<=FD_GRPC_SERVER_PATH_MAX ) ) {
    stream->path_len = (ushort)path_len;
    fd_memcpy( stream->path, path, path_len );
  }
  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_HDRS_DONE;

  /* The other headers reach the app as HTTP/2 would carry them, with
     lowercase names */
  for( ulong i=0UL; i<hdr_cnt; i++ ) {
    struct phr_header const * h = hdrs+i;
    char name[ 64 ];
    if( !h->name || h->name_len>sizeof(name) ) continue;
    for( ulong j=0UL; j<h->name_len; j++ ) {
      char c = h->name[ j ];
      name[ j ] = ( c>='A' && c<='Z' ) ? (char)( c+32 ) : c;
    }
    if( ( h->name_len==14UL && fd_memeq( name, "content-length", 14UL ) ) ||
        ( h->name_len==12UL && fd_memeq( name, "content-type",   12UL ) ) ||
        !fd_grpc_server_hdr_name_valid ( name,     h->name_len  ) ||
        !fd_grpc_server_hdr_value_valid( h->value, h->value_len ) ) continue;
    if( fd_grpc_server_transport_hdr( stream, name, h->name_len, h->value, h->value_len ) ) continue;
    server->callbacks->stream_hdr( server->app_ctx, stream, name, h->name_len, h->value, h->value_len );
    if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ) ) return;
  }

  fd_grpc_server_stream_start( stream );
  if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ) ) return;
  fd_grpc_server_rx_data( stream, (uchar const *)req+head_sz, content_len );
  fd_grpc_server_rx_fin( stream );
}

static void
fd_grpc_web_stream_flush( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_conn_t * conn    = stream->conn;
  fd_grpc_server_t *      server  = conn->server;
  fd_h2_rbuf_t *          rbuf_tx = conn->rbuf_tx;

  /* The client sees the response cut short */
  if( FD_UNLIKELY( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_TRUNC ) ) {
    fd_grpc_server_stream_end( stream, ( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW )
                                       ? FD_GRPC_SERVER_CLOSE_TOO_SLOW : FD_GRPC_SERVER_CLOSE_ABORTED );
    fd_grpc_server_conn_closing( conn );
    return;
  }

  if( !( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS ) ) {
    if( !stream->ref_cnt && stream->state!=FD_GRPC_SERVER_STREAM_FINISH ) return;
    char  head[ 256 ];
    ulong head_len = 0UL;
    FD_TEST( fd_cstr_printf_check( head, sizeof(head), &head_len,
                                   "HTTP/1.1 200 OK\r\n"
                                   "content-type: application/grpc-web+proto\r\n"
                                   "%s"
                                   "grpc-accept-encoding: %s\r\n"
                                   "cache-control: no-store\r\n"
                                   "connection: close\r\n"
                                   "\r\n",
                                   ( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD ) ? "grpc-encoding: zstd\r\n" : "",
                                   server->dctx ? "zstd" : "identity" ) );
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<head_len ) ) return;
    fd_h2_rbuf_push( rbuf_tx, head, head_len );
    stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS;
  }

  while( stream->ref_cnt ) {
    fd_grpc_server_tx_ref_t const * ref = stream->refs + stream->ref_idx;
    uchar const * chunk = server->tx_ring + ( ( ref->off + stream->ref_written ) % server->tx_ring_sz );
    ulong sz = fd_ulong_min( ref->len - stream->ref_written, fd_h2_rbuf_free_sz( rbuf_tx ) );
    if( !sz ) return;
    fd_h2_rbuf_push( rbuf_tx, chunk, sz );
    fd_grpc_server_ref_advance( stream, sz );
  }

  if( stream->state!=FD_GRPC_SERVER_STREAM_FINISH ) return;

  uchar trailer[ 64UL + 3UL*FD_GRPC_SERVER_MSG_MAX ];
  ulong sz = 5UL;
  fd_memcpy( trailer+sz, "grpc-status:", 12UL ); sz += 12UL;
  sz += fd_grpc_server_wr_uint( (char *)trailer+sz, stream->fin_status );
  trailer[ sz++ ] = '\r'; trailer[ sz++ ] = '\n';
  if( stream->fin_msg_len ) {
    fd_memcpy( trailer+sz, "grpc-message:", 13UL ); sz += 13UL;
    sz += fd_grpc_server_pct_encode( (char *)trailer+sz, 3UL*FD_GRPC_SERVER_MSG_MAX, stream->fin_msg, stream->fin_msg_len );
    trailer[ sz++ ] = '\r'; trailer[ sz++ ] = '\n';
  }
  trailer[ 0 ] = 0x80;
  FD_STORE( uint, trailer+1, fd_uint_bswap( (uint)( sz-5UL ) ) );
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<sz ) ) return;
  fd_h2_rbuf_push( rbuf_tx, trailer, sz );
  fd_grpc_server_stream_end( stream,
                             ( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW )
                             ? FD_GRPC_SERVER_CLOSE_TOO_SLOW : FD_GRPC_SERVER_CLOSE_FINISHED );
  fd_grpc_server_conn_closing( conn );
}

void
fd_grpc_web_conn_flush( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_stream_t * s = conn->stream; /* the call is the conn's first stream */
  if( ( s->state==FD_GRPC_SERVER_STREAM_ACTIVE ) | ( s->state==FD_GRPC_SERVER_STREAM_FINISH ) ) {
    fd_grpc_web_stream_flush( s );
  }
}
