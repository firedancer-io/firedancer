/* test_grpc_server drives fd_grpc_server through memory buffers, with
   no sockets involved: the test writes raw HTTP/2 frames the way a gRPC
   client would and inspects the frames that come back.

   Run with --listen <port> to serve the same routes on a TCP port
   instead, for interop checks with a real client. */

#define _GNU_SOURCE

#include "fd_grpc_server_private.h"
#include "../h2/fd_hpack_wr.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

/* Routes that the test handler serves */

#define ROUTE_UNARY  "/test.Svc/Unary"   /* echoes the request message */
#define ROUTE_STREAM "/test.Svc/Stream"  /* sends N 256 byte messages */
#define ROUTE_PCT    "/test.Svc/Pct"     /* fails with a funny message */
#define ROUTE_SLOW   "/test.Svc/Slow"    /* fills the send queue */
#define ROUTE_BIG    "/test.Svc/Big"      /* sends one oversized message */

/* Test handler *******************************************************/

struct test_app_stream {
  int  writable_cnt;
  int  close_cnt;
  int  close_reason;
  int  msg_cnt;
  int  half_close_cnt;
  int  again_cnt;
  int  large_err;    /* what the oversized send returned */
  int  large_follow; /* what a send behind it returned */
  int  large_second; /* what a second oversized send returned */
  int  needs_large_big;   /* whether that message needed a slot */
  int  needs_large_small; /* whether a queue sized one would */
  ulong rx_byte_cnt;
  char  token[ 64 ];
};

typedef struct test_app_stream test_app_stream_t;

struct test_app {
  fd_grpc_server_t * server;
  test_app_stream_t  stream[ 16 ];
  ulong              stream_cnt;
  ulong              conn_open_cnt;
  ulong              conn_close_cnt;
  int                reject_all;
  ulong              large_sz;     /* bytes the Big route sends */
  int                large_finish; /* whether it ends the call right away */
  int                large_twice;  /* whether it tries a second oversized send */
};

typedef struct test_app test_app_t;

static test_app_t g_app[1];

/* The bytes the Big route sends, which a test compares against what
   the client received. */

static uchar test_big_payload[ 384UL<<10 ];

static void
test_big_payload_init( void ) {
  for( ulong i=0UL; i<sizeof(test_big_payload); i++ ) {
    test_big_payload[ i ] = (uchar)( i*7UL + i/251UL );
  }
}

static test_app_stream_t *
test_app_stream_new( fd_grpc_server_stream_t * stream ) {
  FD_TEST( g_app->stream_cnt < 16UL );
  test_app_stream_t * s = g_app->stream + g_app->stream_cnt++;
  *s = (test_app_stream_t){0};
  fd_grpc_server_stream_set_ctx( stream, s );
  return s;
}

static int
test_app_conn_open( void *                  ctx,
                    fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  g_app->conn_open_cnt++;
  return 0;
}

static void
test_app_conn_close( void *                  ctx,
                     fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  g_app->conn_close_cnt++;
}

static void
test_app_stream_hdr( void *                    ctx,
                     fd_grpc_server_stream_t * stream,
                     char const *              name,
                     ulong                     name_len,
                     char const *              value,
                     ulong                     value_len ) {
  (void)ctx;
  if( name_len==7UL && fd_memeq( name, "x-token", 7UL ) ) {
    test_app_stream_t * s = fd_grpc_server_stream_ctx( stream );
    if( !s ) s = test_app_stream_new( stream );
    ulong len = fd_ulong_min( value_len, sizeof(s->token)-1UL );
    fd_memcpy( s->token, value, len );
    s->token[ len ] = '\0';
  }
}

static int
test_app_stream_open( void *                    ctx,
                      fd_grpc_server_stream_t * stream,
                      char const *              path,
                      ulong                     path_len ) {
  (void)ctx;
  test_app_stream_t * s = fd_grpc_server_stream_ctx( stream );
  if( !s ) s = test_app_stream_new( stream );

  if( FD_UNLIKELY( g_app->reject_all ) ) {
    fd_grpc_server_finish( stream, FD_GRPC_STATUS_UNAUTHENTICATED, "No valid auth token", 19UL );
    return FD_GRPC_SERVER_REJECT;
  }
  if( path_len==sizeof(ROUTE_UNARY)-1UL && fd_memeq( path, ROUTE_UNARY, path_len ) ) {
    return FD_GRPC_SERVER_ACCEPT_UNARY;
  }
  if( path_len==sizeof(ROUTE_STREAM)-1UL && fd_memeq( path, ROUTE_STREAM, path_len ) ) {
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }
  if( path_len==sizeof(ROUTE_SLOW)-1UL && fd_memeq( path, ROUTE_SLOW, path_len ) ) {
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }
  if( path_len==sizeof(ROUTE_BIG)-1UL && fd_memeq( path, ROUTE_BIG, path_len ) ) {
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }
  if( path_len==sizeof(ROUTE_PCT)-1UL && fd_memeq( path, ROUTE_PCT, path_len ) ) {
    fd_grpc_server_finish( stream, FD_GRPC_STATUS_INTERNAL, "bad\ttoken \x80 50%", 15UL );
    /* Sends after finish are refused rather than reordered */
    FD_TEST( fd_grpc_server_send( stream, "x", 1UL, 0U )==FD_GRPC_SERVER_ERR_CLOSED );
    return FD_GRPC_SERVER_REJECT;
  }
  return FD_GRPC_SERVER_REJECT;
}

static void
test_app_stream_msg( void *                    ctx,
                     fd_grpc_server_stream_t * stream,
                     uchar const *             msg,
                     ulong                     msg_sz ) {
  (void)ctx;
  test_app_stream_t * s = fd_grpc_server_stream_ctx( stream );
  s->msg_cnt++;
  s->rx_byte_cnt += msg_sz;

  static uchar payload[ 256 ];
  for( ulong i=0UL; i<sizeof(payload); i++ ) payload[i] = (uchar)( 0x40+(i&0x1f) );

  if( msg_sz>=1UL && msg[0]=='S' ) {
    /* Server streaming: the count is the second byte */
    ulong cnt = msg_sz>=2UL ? (ulong)msg[1] : 1UL;
    for( ulong i=0UL; i<cnt; i++ ) {
      int err = fd_grpc_server_send( stream, payload, sizeof(payload), 0U );
      if( err==FD_GRPC_SERVER_ERR_AGAIN ) { s->again_cnt++; return; }
      FD_TEST( err==FD_GRPC_SERVER_SUCCESS );
    }
    fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
    return;
  }

  if( msg_sz>=1UL && msg[0]=='O' ) {
    /* One oversized message, then a run of small ones that have to
       come out behind it, in order.  The payload of the i-th small
       message is the byte i, so the wire order is checkable. */
    static uchar huge[ 200UL<<10 ];
    for( ulong i=0UL; i<sizeof(huge); i++ ) huge[i] = (uchar)( i*11UL );
    s->large_err = fd_grpc_server_send( stream, huge, sizeof(huge), 0U );
    for( ulong i=0UL; i<8UL; i++ ) {
      uchar one[ 64 ];
      fd_memset( one, (int)i, sizeof(one) );
      int err = fd_grpc_server_send( stream, one, sizeof(one), FD_GRPC_SERVER_SEND_NO_COMPRESS );
      if( err!=FD_GRPC_SERVER_SUCCESS ) { s->again_cnt++; break; }
      s->msg_cnt++;
    }
    fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
    return;
  }

  if( msg_sz>=1UL && msg[0]=='L' ) {
    /* One message larger than any send queue, which goes out through a
       large send slot */
    s->large_err = fd_grpc_server_send( stream, test_big_payload, g_app->large_sz, 0U );
    if( s->large_err==FD_GRPC_SERVER_SUCCESS ) {
      /* A message that fits the queue is taken behind it, and goes
         out behind it */
      s->large_follow = fd_grpc_server_send( stream, payload, sizeof(payload), 0U );
      /* A second oversized message has to wait, and only it does */
      if( g_app->large_twice ) {
        s->large_second = fd_grpc_server_send( stream, test_big_payload, g_app->large_sz, 0U );
        /* which of the two reasons the refusal was */
        s->needs_large_big   = fd_grpc_server_msg_needs_large( stream, g_app->large_sz );
        s->needs_large_small = fd_grpc_server_msg_needs_large( stream, 256UL );
      }
    }
    if( g_app->large_finish ) fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
    return;
  }

  if( msg_sz>=1UL && msg[0]=='T' ) {
    /* A message that can never fit the send queue is refused outright */
    static uchar huge[ 128UL<<10 ];
    FD_TEST( fd_grpc_server_send( stream, huge, sizeof(huge), 0U )==FD_GRPC_SERVER_ERR_TOOBIG );
    fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
    return;
  }

  if( msg_sz>=1UL && msg[0]=='Q' ) {
    /* Fill the send queue until it refuses, and stay open */
    for(;;) {
      int err = fd_grpc_server_send( stream, payload, sizeof(payload), 0U );
      if( err==FD_GRPC_SERVER_ERR_AGAIN ) { s->again_cnt++; return; }
      FD_TEST( err==FD_GRPC_SERVER_SUCCESS );
    }
  }

  /* Unary echo */
  int err = fd_grpc_server_send( stream, msg, msg_sz, 0U );
  FD_TEST( err==FD_GRPC_SERVER_SUCCESS );
  fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
}

static void
test_app_stream_half_close( void *                    ctx,
                            fd_grpc_server_stream_t * stream ) {
  (void)ctx;
  test_app_stream_t * s = fd_grpc_server_stream_ctx( stream );
  s->half_close_cnt++;
}

static void
test_app_stream_writable( void *                    ctx,
                          fd_grpc_server_stream_t * stream ) {
  (void)ctx;
  test_app_stream_t * s = fd_grpc_server_stream_ctx( stream );
  s->writable_cnt++;
}

static void
test_app_stream_close( void *                    ctx,
                       fd_grpc_server_stream_t * stream,
                       int                       reason ) {
  (void)ctx;
  test_app_stream_t * s = fd_grpc_server_stream_ctx( stream );
  s->close_cnt++;
  s->close_reason = reason;
}

static fd_grpc_server_callbacks_t const test_app_callbacks = {
  .conn_open         = test_app_conn_open,
  .conn_close        = test_app_conn_close,
  .stream_hdr        = test_app_stream_hdr,
  .stream_open       = test_app_stream_open,
  .stream_msg        = test_app_stream_msg,
  .stream_half_close = test_app_stream_half_close,
  .stream_writable   = test_app_stream_writable,
  .stream_close      = test_app_stream_close
};

/* Client side ********************************************************/

#define TC_STREAM_MAX 8

struct tc_stream {
  uint  id;
  int   used;
  int   hdr_block_cnt;
  int   end_stream;
  int   rst;
  uint  rst_code;
  char  status[ 16 ];
  char  content_type[ 64 ];
  char  grpc_status[ 16 ];
  char  grpc_message[ 1024 ];
  char  grpc_encoding[ 32 ];
  char  grpc_accept_encoding[ 64 ];
  ulong data_sz;
  uchar data[ 512UL<<10 ];
};

typedef struct tc_stream tc_stream_t;

struct tc {
  fd_grpc_server_t *      server;
  fd_grpc_server_conn_t * conn;
  long                    now;
  tc_stream_t             stream[ TC_STREAM_MAX ];
  int                     goaway;
  uint                    goaway_err;
  uint                    goaway_last_id;
  int                     ping_cnt;
  int                     settings_cnt;
  ulong                   conn_wnd_update;
  uchar                   res[ 1UL<<20 ];
  ulong                   res_sz;
  uchar                   req[ 1UL<<20 ];
  ulong                   req_sz;
};

typedef struct tc tc_t;

static tc_t g_tc[1];

static tc_stream_t *
tc_stream( tc_t * tc,
           uint   id ) {
  for( ulong i=0UL; i<TC_STREAM_MAX; i++ ) {
    if( tc->stream[i].used && tc->stream[i].id==id ) return tc->stream+i;
  }
  for( ulong i=0UL; i<TC_STREAM_MAX; i++ ) {
    if( !tc->stream[i].used ) {
      tc_stream_t * s = tc->stream+i;
      s->used = 1;
      s->id   = id;
      return s;
    }
  }
  FD_LOG_ERR(( "out of test stream slots" ));
}

/* Frame and HPACK writers */

static void
tc_frame( tc_t *       tc,
          uint         type,
          uint         flags,
          uint         stream_id,
          void const * payload,
          ulong        payload_sz ) {
  FD_TEST( tc->req_sz + 9UL + payload_sz <= sizeof(tc->req) );
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( type, payload_sz ),
    .flags       = (uchar)flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_memcpy( tc->req+tc->req_sz, &hdr, 9UL );
  tc->req_sz += 9UL;
  if( payload_sz ) {
    fd_memcpy( tc->req+tc->req_sz, payload, payload_sz );
    tc->req_sz += payload_sz;
  }
}

/* hdr_lit writes a literal header field without indexing, spelling out
   both the name and the value (RFC 7541 Section 6.2.2) */

static ulong
hdr_lit( uchar *      p,
         char const * name,
         ulong        name_len,
         char const * value,
         ulong        value_len ) {
  ulong o = 0UL;
  p[ o++ ] = 0x00;
  FD_TEST( name_len<127UL && value_len<127UL );
  p[ o++ ] = (uchar)name_len;
  fd_memcpy( p+o, name, name_len ); o += name_len;
  p[ o++ ] = (uchar)value_len;
  fd_memcpy( p+o, value, value_len ); o += value_len;
  return o;
}

#define HDR_LIT(p,name,value) hdr_lit( (p), (name), sizeof(name)-1UL, (value), strlen( value ) )

struct req_opt {
  char const * method;          /* NULL: POST, indexed */
  char const * scheme;          /* NULL: http, indexed */
  char const * path;
  char const * content_type;    /* NULL: application/grpc */
  char const * te;              /* NULL: trailers */
  char const * timeout;
  char const * accept_encoding;
  char const * encoding;
  char const * x_token;
  char const * bad_name;        /* a header name to send verbatim */
  int          no_content_type;
  int          no_path;
  int          dup_method;
  int          pseudo_last;     /* :authority after a regular header */
  int          status_pseudo;   /* include :status */
  int          end_stream;
};

typedef struct req_opt req_opt_t;

static void
tc_request( tc_t *            tc,
            uint              stream_id,
            req_opt_t const * opt ) {
  uchar block[ 1024 ];
  ulong o = 0UL;

  if( opt->method ) o += HDR_LIT( block+o, ":method", opt->method );
  else              block[ o++ ] = FD_HPACK_INDEXED_SHORT( 3 ); /* :method: POST */
  if( opt->dup_method ) o += HDR_LIT( block+o, ":method", "POST" );
  if( opt->scheme ) o += HDR_LIT( block+o, ":scheme", opt->scheme );
  else              block[ o++ ] = FD_HPACK_INDEXED_SHORT( 6 ); /* :scheme: http */
  if( opt->status_pseudo ) o += HDR_LIT( block+o, ":status", "200" );
  if( !opt->no_path ) o += HDR_LIT( block+o, ":path", opt->path );
  if( !opt->pseudo_last ) o += HDR_LIT( block+o, ":authority", "localhost" );

  if( !opt->no_content_type ) {
    o += hdr_lit( block+o, "content-type", 12UL,
                  opt->content_type ? opt->content_type : "application/grpc",
                  strlen( opt->content_type ? opt->content_type : "application/grpc" ) );
  }
  o += HDR_LIT( block+o, "te", opt->te ? opt->te : "trailers" );
  o += HDR_LIT( block+o, "user-agent", "test-grpc-server/1" );
  if( opt->timeout         ) o += HDR_LIT( block+o, "grpc-timeout",         opt->timeout         );
  if( opt->accept_encoding ) o += HDR_LIT( block+o, "grpc-accept-encoding", opt->accept_encoding );
  if( opt->encoding        ) o += HDR_LIT( block+o, "grpc-encoding",        opt->encoding        );
  if( opt->x_token         ) o += HDR_LIT( block+o, "x-token",              opt->x_token         );
  if( opt->bad_name        ) o += hdr_lit( block+o, opt->bad_name, strlen( opt->bad_name ), "1", 1UL );
  if( opt->pseudo_last     ) o += HDR_LIT( block+o, ":authority", "localhost" );

  uint flags = FD_H2_FLAG_END_HEADERS;
  if( opt->end_stream ) flags |= FD_H2_FLAG_END_STREAM;
  tc_frame( tc, FD_H2_FRAME_TYPE_HEADERS, flags, stream_id, block, o );
}

static void
tc_msg( tc_t *       tc,
        uint         stream_id,
        int          compressed,
        void const * msg,
        ulong        msg_sz,
        int          end_stream ) {
  static uchar buf[ 1UL<<18 ];
  FD_TEST( msg_sz+5UL<=sizeof(buf) );
  buf[0] = (uchar)compressed;
  uint be = fd_uint_bswap( (uint)msg_sz );
  fd_memcpy( buf+1, &be, 4UL );
  fd_memcpy( buf+5, msg, msg_sz );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, end_stream ? FD_H2_FLAG_END_STREAM : 0U,
            stream_id, buf, msg_sz+5UL );
}

static void
tc_window_update( tc_t * tc,
                  uint   stream_id,
                  uint   increment ) {
  uint be = fd_uint_bswap( increment );
  tc_frame( tc, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, stream_id, &be, 4UL );
}

static void
tc_settings( tc_t * tc,
             ushort id,
             uint   value ) {
  uchar payload[ 6 ];
  ushort id_be = fd_ushort_bswap( id );
  uint   va_be = fd_uint_bswap( value );
  fd_memcpy( payload,   &id_be, 2UL );
  fd_memcpy( payload+2, &va_be, 4UL );
  tc_frame( tc, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, payload, 6UL );
}

static void
tc_rst( tc_t * tc,
        uint   stream_id,
        uint   err ) {
  uint be = fd_uint_bswap( err );
  tc_frame( tc, FD_H2_FRAME_TYPE_RST_STREAM, 0U, stream_id, &be, 4UL );
}

/* Response parsing */

static void
tc_parse_hdrs( tc_t *        tc,
               tc_stream_t * s,
               uchar const * block,
               ulong         block_sz ) {
  static uchar scratch_buf[ 16384 ];
  fd_hpack_rd_t rd[1];
  FD_TEST( fd_hpack_rd_init( rd, block, block_sz ) );
  (void)tc;
  while( !fd_hpack_rd_done( rd ) ) {
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    FD_TEST( !fd_hpack_rd_next( rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) ) );
    char * dst    = NULL;
    ulong  dst_sz = 0UL;
    if     ( hdr->name_len== 7UL && fd_memeq( hdr->name, ":status",              7UL ) ) { dst = s->status;               dst_sz = sizeof(s->status              ); }
    else if( hdr->name_len==12UL && fd_memeq( hdr->name, "content-type",        12UL ) ) { dst = s->content_type;         dst_sz = sizeof(s->content_type        ); }
    else if( hdr->name_len==11UL && fd_memeq( hdr->name, "grpc-status",         11UL ) ) { dst = s->grpc_status;          dst_sz = sizeof(s->grpc_status         ); }
    else if( hdr->name_len==12UL && fd_memeq( hdr->name, "grpc-message",        12UL ) ) { dst = s->grpc_message;         dst_sz = sizeof(s->grpc_message        ); }
    else if( hdr->name_len==13UL && fd_memeq( hdr->name, "grpc-encoding",       13UL ) ) { dst = s->grpc_encoding;        dst_sz = sizeof(s->grpc_encoding       ); }
    else if( hdr->name_len==20UL && fd_memeq( hdr->name, "grpc-accept-encoding",20UL ) ) { dst = s->grpc_accept_encoding; dst_sz = sizeof(s->grpc_accept_encoding); }
    if( dst ) {
      ulong len = fd_ulong_min( hdr->value_len, dst_sz-1UL );
      fd_memcpy( dst, hdr->value, len );
      dst[ len ] = '\0';
    }
  }
  s->hdr_block_cnt++;
}

static void
tc_parse( tc_t * tc ) {
  ulong off = 0UL;
  while( tc->res_sz-off >= 9UL ) {
    fd_h2_frame_hdr_t hdr;
    fd_memcpy( &hdr, tc->res+off, 9UL );
    ulong payload_sz = fd_h2_frame_length( hdr.typlen );
    uint  type       = fd_h2_frame_type  ( hdr.typlen );
    uint  stream_id  = fd_h2_frame_stream_id( hdr.r_stream_id );
    if( tc->res_sz-off < 9UL+payload_sz ) break;
    uchar const * payload = tc->res+off+9UL;
    off += 9UL+payload_sz;

    switch( type ) {
    case FD_H2_FRAME_TYPE_SETTINGS:
      if( !( hdr.flags & FD_H2_FLAG_ACK ) ) tc->settings_cnt++;
      break;
    case FD_H2_FRAME_TYPE_PING:
      if( !( hdr.flags & FD_H2_FLAG_ACK ) ) tc->ping_cnt++;
      break;
    case FD_H2_FRAME_TYPE_GOAWAY:
      tc->goaway         = 1;
      tc->goaway_last_id = fd_uint_bswap( FD_LOAD( uint, payload   ) ) & 0x7fffffffU;
      tc->goaway_err     = fd_uint_bswap( FD_LOAD( uint, payload+4 ) );
      break;
    case FD_H2_FRAME_TYPE_WINDOW_UPDATE:
      if( !stream_id ) tc->conn_wnd_update += fd_uint_bswap( FD_LOAD( uint, payload ) );
      break;
    case FD_H2_FRAME_TYPE_HEADERS: {
      tc_stream_t * s = tc_stream( tc, stream_id );
      tc_parse_hdrs( tc, s, payload, payload_sz );
      if( hdr.flags & FD_H2_FLAG_END_STREAM ) s->end_stream = 1;
      break;
    }
    case FD_H2_FRAME_TYPE_DATA: {
      tc_stream_t * s = tc_stream( tc, stream_id );
      FD_TEST( s->data_sz+payload_sz<=sizeof(s->data) );
      fd_memcpy( s->data+s->data_sz, payload, payload_sz );
      s->data_sz += payload_sz;
      if( hdr.flags & FD_H2_FLAG_END_STREAM ) s->end_stream = 1;
      break;
    }
    case FD_H2_FRAME_TYPE_RST_STREAM: {
      tc_stream_t * s = tc_stream( tc, stream_id );
      s->rst      = 1;
      s->rst_code = fd_uint_bswap( FD_LOAD( uint, payload ) );
      break;
    }
    default:
      break;
    }
  }
  /* Keep any partial frame for the next drain */
  if( off ) {
    memmove( tc->res, tc->res+off, tc->res_sz-off );
    tc->res_sz -= off;
  }
}

/* tc_drain moves everything the server produced into the parser */

static void
tc_drain( tc_t * tc ) {
  for(;;) {
    if( FD_UNLIKELY( !fd_grpc_server_conn_is_open( tc->conn ) ) ) break;
    ulong n = fd_grpc_server_conn_pop_tx( tc->conn, tc->res+tc->res_sz, sizeof(tc->res)-tc->res_sz );
    if( !n ) break;
    tc->res_sz += n;
  }
  tc_parse( tc );
}

/* tc_flush hands the queued request bytes to the server */

static void
tc_flush( tc_t * tc ) {
  ulong off = 0UL;
  while( off<tc->req_sz ) {
    ulong n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+off, tc->req_sz-off, tc->now );
    tc_drain( tc );
    if( !n ) {
      if( FD_UNLIKELY( !fd_grpc_server_conn_is_open( tc->conn ) ) ) break;
      /* Receive ring is full: let the server consume it */
      fd_grpc_server_service( tc->server, tc->now );
      tc_drain( tc );
      n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+off, tc->req_sz-off, tc->now );
      tc_drain( tc );
      if( !n ) break;
    }
    off += n;
  }
  tc->req_sz = 0UL;
  fd_grpc_server_service( tc->server, tc->now );
  tc_drain( tc );
}

static void
tc_open( tc_t *             tc,
         fd_grpc_server_t * server ) {
  *tc = (tc_t){0};
  tc->server = server;
  tc->now    = 1000L*1000L*1000L;
  tc->conn   = fd_grpc_server_conn_open_direct( server, tc->now );
  FD_TEST( tc->conn );

  FD_TEST( sizeof(tc->req)>=24UL );
  fd_memcpy( tc->req, fd_h2_client_preface, 24UL );
  tc->req_sz = 24UL;
  tc_frame( tc, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, NULL, 0UL );
  tc_flush( tc );
  FD_TEST( tc->settings_cnt==1 );
  /* Acknowledge the server's SETTINGS to complete the handshake */
  tc_frame( tc, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
  tc_flush( tc );
}

static void
tc_close( tc_t * tc ) {
  if( fd_grpc_server_conn_is_open( tc->conn ) ) fd_grpc_server_conn_close( tc->conn );
}

/* Assertions */

static void
tc_expect_trailers( tc_t *       tc,
                    uint         stream_id,
                    char const * grpc_status,
                    char const * grpc_message ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  FD_TEST( s->end_stream );
  FD_TEST( !strcmp( s->status, "200" ) );
  FD_TEST( !strcmp( s->content_type, "application/grpc" ) );
  if( FD_UNLIKELY( strcmp( s->grpc_status, grpc_status ) || ( grpc_message && strcmp( s->grpc_message, grpc_message ) ) ) ) {
    FD_LOG_WARNING(( "stream %u: grpc-status %s grpc-message \"%s\"", stream_id, s->grpc_status, s->grpc_message ));
  }
  FD_TEST( !strcmp( s->grpc_status, grpc_status ) );
  if( grpc_message ) FD_TEST( !strcmp( s->grpc_message, grpc_message ) );
}

/* Message iteration over a stream's DATA bytes */

static ulong
tc_msg_at( tc_stream_t * s,
           ulong         off,
           uchar *       flag,
           uchar const **msg,
           ulong *       msg_sz ) {
  FD_TEST( off+5UL<=s->data_sz );
  *flag   = s->data[ off ];
  *msg_sz = fd_uint_bswap( FD_LOAD( uint, s->data+off+1UL ) );
  FD_TEST( off+5UL+*msg_sz<=s->data_sz );
  *msg = s->data+off+5UL;
  return off+5UL+*msg_sz;
}

/* Server construction ************************************************/

static uchar server_mem[ 8UL<<20 ] __attribute__((aligned(FD_GRPC_SERVER_ALIGN)));

/* The large send path and the message count bound of a send queue,
   which only the tests that exercise them set.  Zero leaves the server
   with queues alone. */

static ulong g_opt_max_msg_sz;
static ulong g_opt_large_slots;
static ulong g_opt_queue_msg_max;

static fd_grpc_server_t *
test_server_new_ex( int   compression,
                    ulong max_request_msg_sz,
                    ulong stream_tx_queue_sz,
                    long  idle_nanos ) {
  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = 2UL;
  params->max_stream_cnt     = 4UL;
  params->max_request_msg_sz = max_request_msg_sz;
  params->stream_tx_queue_sz = stream_tx_queue_sz;
  params->max_msg_sz              = g_opt_max_msg_sz ? g_opt_max_msg_sz : stream_tx_queue_sz;
  params->large_msg_slot_cnt      = g_opt_large_slots;
  params->stream_tx_queue_msg_max = g_opt_queue_msg_max;
  params->conn_rx_buf_sz     = 32768UL;
  params->conn_tx_buf_sz     = 32768UL;
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 1UL<<20;
  params->compression        = compression;
  params->compression_min_sz = 128UL;
  params->compression_level  = 1;
  params->seed               = 42UL;
  params->idle_timeout_nanos       = idle_nanos;

  ulong footprint = fd_grpc_server_footprint( params );
  FD_TEST( footprint );
  FD_TEST( footprint<=sizeof(server_mem) );
  *g_app = (test_app_t){0};
  void * shserver = fd_grpc_server_new( server_mem, params, &test_app_callbacks, g_app );
  FD_TEST( shserver );
  fd_grpc_server_t * server = fd_grpc_server_join( shserver );
  FD_TEST( server );
  g_app->server = server;
  return server;
}

static fd_grpc_server_t *
test_server_new( int   compression,
                 ulong max_request_msg_sz,
                 ulong stream_tx_queue_sz ) {
  return test_server_new_ex( compression, max_request_msg_sz, stream_tx_queue_sz,
                             300L*1000L*1000L*1000L );
}

static void
test_server_delete( fd_grpc_server_t * server ) {
  FD_TEST( fd_grpc_server_delete( fd_grpc_server_leave( server ) ) );
}

/* Tests **************************************************************/

static void
test_params( void ) {
  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  FD_TEST( fd_grpc_server_footprint( params ) );
  FD_LOG_NOTICE(( "default footprint: %lu bytes (%lu conns x %lu streams)",
                  fd_grpc_server_footprint( params ),
                  params->max_conn_cnt, params->max_stream_cnt ));
  FD_LOG_NOTICE(( "zstd arena: %lu bytes at level 1, %lu at level 3, "
                  "%lu at level %i (cctx), %lu (dctx)",
                  FD_GRPC_SERVER_ZSTD_MEM( 1 ), FD_GRPC_SERVER_ZSTD_MEM( 3 ),
                  ZSTD_estimateCCtxSize( fd_grpc_server_compression_level_max() ),
                  fd_grpc_server_compression_level_max(),
                  ZSTD_estimateDCtxSize() ));

  fd_grpc_server_params_t bad = *params;
  bad.max_conn_cnt = 0UL;
  FD_TEST( !fd_grpc_server_footprint( &bad ) );
  bad = *params; bad.max_frame_sz = 1024UL;
  FD_TEST( !fd_grpc_server_footprint( &bad ) );
  bad = *params; bad.compression_level = 0;
  FD_TEST( !fd_grpc_server_footprint( &bad ) );
  bad = *params; bad.compression_level = fd_grpc_server_compression_level_max()+1;
  FD_TEST( !fd_grpc_server_footprint( &bad ) );
  bad = *params; bad.conn_rx_buf_sz = 128UL;
  FD_TEST( !fd_grpc_server_footprint( &bad ) );
}

static void
test_unary( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  char const * body = "hello grpc";
  req_opt_t opt = { .path = ROUTE_UNARY, .x_token = "secret" };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, body, strlen( body ), 1 );
  tc_flush( tc );

  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( s->hdr_block_cnt==2 ); /* headers + trailers */
  FD_TEST( !strcmp( s->grpc_accept_encoding, "identity" ) );
  FD_TEST( !s->grpc_encoding[0] );
  tc_expect_trailers( tc, 1U, "0", NULL );

  uchar flag; uchar const * msg; ulong msg_sz;
  ulong off = tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( off==s->data_sz );
  FD_TEST( flag==0 );
  FD_TEST( msg_sz==strlen( body ) );
  FD_TEST( fd_memeq( msg, body, msg_sz ) );

  FD_TEST( g_app->stream_cnt==1UL );
  FD_TEST( !strcmp( g_app->stream[0].token, "secret" ) );
  FD_TEST( g_app->stream[0].msg_cnt==1 );
  FD_TEST( g_app->stream[0].half_close_cnt==1 );
  FD_TEST( g_app->stream[0].close_cnt==1 );
  FD_TEST( g_app->stream[0].close_reason==FD_GRPC_SERVER_CLOSE_FINISHED );

  fd_grpc_server_metrics_t const * m = fd_grpc_server_metrics( server );
  FD_TEST( m->stream_open_cnt==1UL );
  FD_TEST( m->rx_msg_cnt==1UL );
  FD_TEST( m->tx_msg_cnt==1UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_reassembly( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  uchar body[ 700 ];
  for( ulong i=0UL; i<sizeof(body); i++ ) body[i] = (uchar)i;

  req_opt_t opt = { .path = ROUTE_UNARY };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );

  /* One message split over the length prefix and three DATA frames */
  uchar prefix[ 5 ] = {0};
  uint be = fd_uint_bswap( (uint)sizeof(body) );
  fd_memcpy( prefix+1, &be, 4UL );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, 0U, 1U, prefix,   3UL );
  tc_flush( tc );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, 0U, 1U, prefix+3, 2UL );
  tc_flush( tc );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, 0U, 1U, body,     100UL );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].msg_cnt==0 );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, 0U, 1U, body+100, 500UL );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].msg_cnt==0 );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_END_STREAM, 1U, body+600, 100UL );
  tc_flush( tc );

  FD_TEST( g_app->stream[0].msg_cnt==1 );
  FD_TEST( g_app->stream[0].rx_byte_cnt==sizeof(body) );
  tc_expect_trailers( tc, 1U, "0", NULL );

  tc_stream_t * s = tc_stream( tc, 1U );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==sizeof(body) && fd_memeq( msg, body, msg_sz ) );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_oversize( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 512UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  uchar body[ 600 ] = {0};
  req_opt_t opt = { .path = ROUTE_UNARY };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, body, sizeof(body), 1 );
  tc_flush( tc );

  tc_expect_trailers( tc, 1U, "8", "grpc: received message larger than max" );
  FD_TEST( tc_stream( tc, 1U )->data_sz==0UL ); /* Trailers-Only */
  FD_TEST( g_app->stream[0].msg_cnt==0 );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_unknown_path( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  req_opt_t opt = { .path = "/nope.Svc/Nope", .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );

  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( s->hdr_block_cnt==1 ); /* Trailers-Only: one HEADERS frame */
  FD_TEST( s->data_sz==0UL );
  tc_expect_trailers( tc, 1U, "12", "unknown method" );
  FD_TEST( g_app->stream[0].close_cnt==0 ); /* rejected before accept */
  FD_TEST( fd_grpc_server_metrics( server )->stream_reject_cnt==1UL );

  /* A rejecting handler picks the status itself */
  g_app->reject_all = 1;
  req_opt_t opt2 = { .path = ROUTE_UNARY, .end_stream = 1 };
  tc_request( tc, 3U, &opt2 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "16", "No valid auth token" );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_bad_content_type( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  req_opt_t opt = { .path = ROUTE_UNARY, .content_type = "text/plain", .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( !strcmp( s->status, "415" ) );
  FD_TEST( s->end_stream );
  FD_TEST( !s->grpc_status[0] );

  req_opt_t opt2 = { .path = ROUTE_UNARY, .no_content_type = 1, .end_stream = 1 };
  tc_request( tc, 3U, &opt2 );
  tc_flush( tc );
  FD_TEST( !strcmp( tc_stream( tc, 3U )->status, "415" ) );

  /* content-type with a suffix is a gRPC request: the call reaches the
     handler, which answers with a gRPC status */
  req_opt_t opt3 = { .path = ROUTE_PCT, .content_type = "application/grpc+proto", .end_stream = 1 };
  tc_request( tc, 5U, &opt3 );
  tc_flush( tc );
  FD_TEST( !strcmp( tc_stream( tc, 5U )->status, "200" ) );
  FD_TEST( !strcmp( tc_stream( tc, 5U )->grpc_status, "13" ) );

  /* Non-POST */
  req_opt_t opt4 = { .path = ROUTE_UNARY, .method = "GET", .end_stream = 1 };
  tc_request( tc, 7U, &opt4 );
  tc_flush( tc );
  FD_TEST( !strcmp( tc_stream( tc, 7U )->status, "405" ) );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_continuation_refused( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* A field block split across CONTINUATION frames is refused, since
     the server decodes one frame at a time */
  uchar block[ 256 ];
  ulong o = 0UL;
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 3 );
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 6 );
  o += HDR_LIT( block+o, ":path",       ROUTE_STREAM       );
  o += HDR_LIT( block+o, ":authority",  "localhost"        );
  o += HDR_LIT( block+o, "content-type", "application/grpc" );
  o += HDR_LIT( block+o, "te",          "trailers"         );
  ulong split = o/2UL;
  tc_frame( tc, FD_H2_FRAME_TYPE_HEADERS, 0U, 1U, block, split );
  tc_flush( tc );
  FD_TEST( tc->goaway );
  FD_TEST( tc->goaway_err==FD_H2_ERR_COMPRESSION );
  FD_TEST( fd_grpc_server_metrics( server )->stream_open_cnt==0UL );

  test_server_delete( server );
}

/* A stream the transport resets for a protocol error did not finish,
   so the handler hears CLOSE_ABORTED rather than CLOSE_FINISHED. */

static void
test_close_aborted( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  req_opt_t opt = { .path = ROUTE_STREAM, .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].half_close_cnt==1 );

  /* DATA after the client half-closed is a stream error */
  tc_msg( tc, 1U, 0, "x", 1UL, 0 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].close_cnt==1 );
  FD_TEST( g_app->stream[0].close_reason==FD_GRPC_SERVER_CLOSE_ABORTED );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_malformed( void ) {
  struct {
    char const * name;
    req_opt_t    opt;
  } cases[] = {
    { "duplicate pseudo",   { .path = ROUTE_UNARY, .dup_method = 1        } },
    { "pseudo after field", { .path = ROUTE_UNARY, .pseudo_last = 1       } },
    { "response pseudo",    { .path = ROUTE_UNARY, .status_pseudo = 1     } },
    { "missing path",       { .path = ROUTE_UNARY, .no_path = 1           } },
    { "bad scheme",         { .path = ROUTE_UNARY, .scheme = "ftp"        } },
    { "uppercase name",     { .path = ROUTE_UNARY, .bad_name = "X-Upper"  } },
    { "connection header",  { .path = ROUTE_UNARY, .bad_name = "connection" } },
    { "keep-alive header",  { .path = ROUTE_UNARY, .bad_name = "keep-alive" } },
    { "proxy-connection",   { .path = ROUTE_UNARY, .bad_name = "proxy-connection" } },
    { "upgrade header",     { .path = ROUTE_UNARY, .bad_name = "upgrade"  } },
    { "transfer-encoding",  { .path = ROUTE_UNARY, .bad_name = "transfer-encoding" } },
    { "te not trailers",    { .path = ROUTE_UNARY, .te = "gzip"           } }
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
    tc_t * tc = g_tc;
    tc_open( tc, server );
    req_opt_t opt = cases[i].opt;
    opt.end_stream = 1;
    tc_request( tc, 1U, &opt );
    tc_flush( tc );
    tc_stream_t * s = tc_stream( tc, 1U );
    if( FD_UNLIKELY( !( s->rst && s->rst_code==FD_H2_ERR_PROTOCOL ) ) ) {
      FD_LOG_ERR(( "case '%s': expected RST_STREAM PROTOCOL_ERROR (rst=%i code=%u status=%s)",
                   cases[i].name, s->rst, s->rst_code, s->status ));
    }
    FD_TEST( !s->hdr_block_cnt );
    FD_TEST( fd_grpc_server_metrics( server )->request_error_cnt==1UL );
    tc_close( tc );
    test_server_delete( server );
  }
}

static void
test_streaming( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* Shrink the per-stream send window so flow control bites */
  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 300U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  uchar cmd[2] = { 'S', 40 }; /* 40 messages of 256 bytes */
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 1 );
  tc_flush( tc );

  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( s->hdr_block_cnt==1 );    /* response headers only so far */
  FD_TEST( s->data_sz==300UL );      /* exactly the stream window */
  FD_TEST( !s->end_stream );

  /* Refill in steps and check the server resumes each time */
  for( ulong i=0UL; i<20UL; i++ ) {
    tc_window_update( tc, 1U, 600U );
    tc_flush( tc );
  }
  FD_TEST( s->data_sz==40UL*(256UL+5UL) );
  FD_TEST( s->hdr_block_cnt==2 );
  tc_expect_trailers( tc, 1U, "0", NULL );

  /* Every message arrived intact and in order */
  ulong off = 0UL;
  for( ulong i=0UL; i<40UL; i++ ) {
    uchar flag; uchar const * msg; ulong msg_sz;
    off = tc_msg_at( s, off, &flag, &msg, &msg_sz );
    FD_TEST( flag==0 && msg_sz==256UL );
    for( ulong j=0UL; j<msg_sz; j++ ) FD_TEST( msg[j]==(uchar)( 0x40+(j&0x1f) ) );
  }
  FD_TEST( off==s->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_queue_full( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 2048UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE_SLOW };
  tc_request( tc, 1U, &opt );
  uchar cmd[1] = { 'Q' };
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 0 );
  tc_flush( tc );

  /* The send window is closed, so the queue filled up and the app was
     told rather than blocked or silently dropped */
  FD_TEST( g_app->stream[0].again_cnt==1 );
  FD_TEST( tc_stream( tc, 1U )->data_sz==0UL );
  FD_TEST( fd_grpc_server_metrics( server )->tx_queue_full_cnt==1UL );
  FD_TEST( g_app->stream[0].writable_cnt==0 );

  /* Opening the window drains the queue and wakes the app */
  tc_window_update( tc, 1U, 1UL<<20 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].writable_cnt==1 );
  FD_TEST( tc_stream( tc, 1U )->data_sz>0UL );

  /* A message larger than the queue is refused, not queued */
  req_opt_t opt2 = { .path = ROUTE_STREAM };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, "T", 1UL, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "0", NULL );
  FD_TEST( tc_stream( tc, 3U )->data_sz==0UL );

  tc_close( tc );
  test_server_delete( server );
}

/* The large send path: a message larger than any send queue goes out
   whole, one DATA frame at a time, under flow control. */

/* tc_grant opens both windows wide enough for another frame and lets
   the server run, up to cap times or until the stream ended. */

static ulong
tc_grant( tc_t * tc,
          uint   stream_id,
          uint   increment,
          ulong  cap ) {
  ulong iter = 0UL;
  while( !tc_stream( tc, stream_id )->end_stream ) {
    FD_TEST( iter<cap );
    tc_window_update( tc, stream_id, increment );
    tc_window_update( tc, 0U,        increment );
    tc_flush( tc );
    iter++;
  }
  return iter;
}

static void
test_large_message( void ) {
  g_opt_max_msg_sz  = 256UL<<10;
  g_opt_large_slots = 1UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  g_app->large_sz     = 200UL<<10;
  g_app->large_finish = 1;

  req_opt_t opt = { .path = ROUTE_BIG };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, "L", 1UL, 1 );
  tc_flush( tc );

  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( g_app->stream[0].large_err   ==FD_GRPC_SERVER_SUCCESS );
  FD_TEST( g_app->stream[0].large_follow==FD_GRPC_SERVER_SUCCESS );

  /* The initial window is 65535 bytes, so the message cannot have gone
     out whole and the trailers are still waiting behind it */
  FD_TEST( s->data_sz>0UL && s->data_sz<=65535UL );
  FD_TEST( !s->end_stream );

  ulong iter = tc_grant( tc, 1U, 32768U, 64UL );
  FD_TEST( iter>1UL ); /* more than one window was needed */

  /* The oversized message first, byte for byte, then the one that was
     queued behind it, then the trailers */
  uchar flag; uchar const * msg; ulong msg_sz;
  ulong off = tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 );
  FD_TEST( msg_sz==( 200UL<<10 ) );
  FD_TEST( fd_memeq( msg, test_big_payload, msg_sz ) );
  off = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==256UL );
  FD_TEST( off==s->data_sz );
  tc_expect_trailers( tc, 1U, "0", NULL );

  fd_grpc_server_metrics_t const * m = fd_grpc_server_metrics( server );
  FD_TEST( m->tx_large_msg_cnt ==1UL );
  FD_TEST( m->tx_large_busy_cnt==0UL );
  FD_TEST( m->tx_byte_cnt      ==( 200UL<<10 )+256UL );

  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz  = 0UL;
  g_opt_large_slots = 0UL;
}

/* A message above max_msg_sz is refused however long the client
   waits, and the large path compresses like the queue does. */

static void
test_large_bounds( void ) {
  g_opt_max_msg_sz  = 64UL<<10;
  g_opt_large_slots = 1UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* 128 KiB is above max_msg_sz */
  g_app->large_sz     = 128UL<<10;
  g_app->large_finish = 1;
  req_opt_t opt = { .path = ROUTE_BIG, .accept_encoding = "zstd" };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, "L", 1UL, 1 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].large_err==FD_GRPC_SERVER_ERR_TOOBIG );
  tc_expect_trailers( tc, 1U, "0", NULL );
  FD_TEST( tc_stream( tc, 1U )->data_sz==0UL );

  /* 64 KiB is the largest there is, and the client accepts zstd */
  g_app->large_sz = 64UL<<10;
  req_opt_t opt2 = { .path = ROUTE_BIG, .accept_encoding = "zstd" };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, "L", 1UL, 1 );
  tc_flush( tc );
  FD_TEST( g_app->stream[1].large_err==FD_GRPC_SERVER_SUCCESS );
  tc_grant( tc, 3U, 65536U, 64UL );

  tc_stream_t * s = tc_stream( tc, 3U );
  FD_TEST( !strcmp( s->grpc_encoding, "zstd" ) );
  uchar flag; uchar const * msg; ulong msg_sz;
  ulong off = tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==1 );                 /* the pattern compresses */
  FD_TEST( msg_sz<( 64UL<<10 ) );
  /* and the message queued behind it followed */
  off = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( off==s->data_sz );
  /* both of them: the large one from its slot, the small one from the
     queue */
  FD_TEST( fd_grpc_server_metrics( server )->tx_msg_compressed_cnt==2UL );

  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz  = 0UL;
  g_opt_large_slots = 0UL;
}

/* A cancelled call gives its large send slot back. */

static void
test_large_cancel( void ) {
  g_opt_max_msg_sz  = 256UL<<10;
  g_opt_large_slots = 1UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  g_app->large_sz     = 200UL<<10;
  g_app->large_finish = 0;

  req_opt_t opt = { .path = ROUTE_BIG };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, "L", 1UL, 0 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].large_err==FD_GRPC_SERVER_SUCCESS );
  ulong partial = tc_stream( tc, 1U )->data_sz;
  FD_TEST( partial>0UL && partial<( 200UL<<10 ) );

  tc_rst( tc, 1U, FD_H2_ERR_CANCEL );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].close_cnt==1 );
  FD_TEST( g_app->stream[0].close_reason==FD_GRPC_SERVER_CLOSE_CANCELLED );
  /* No more of the cancelled message went out */
  tc_window_update( tc, 0U, 1UL<<20 );
  tc_flush( tc );
  FD_TEST( tc_stream( tc, 1U )->data_sz==partial );

  /* The slot is free, so the next call gets it */
  g_app->large_finish = 1;
  req_opt_t opt2 = { .path = ROUTE_BIG };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, "L", 1UL, 1 );
  tc_flush( tc );
  FD_TEST( g_app->stream[1].large_err==FD_GRPC_SERVER_SUCCESS );
  tc_grant( tc, 3U, 65536U, 64UL );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_stream_t * s3 = tc_stream( tc, 3U );
  ulong off3 = tc_msg_at( s3, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==( 200UL<<10 ) );
  FD_TEST( fd_memeq( msg, test_big_payload, msg_sz ) );
  FD_TEST( tc_msg_at( s3, off3, &flag, &msg, &msg_sz )==s3->data_sz );

  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz  = 0UL;
  g_opt_large_slots = 0UL;
}

/* With the pool exhausted the second oversized send is told to wait,
   and is woken when a slot comes back. */

static void
test_large_busy( void ) {
  g_opt_max_msg_sz  = 256UL<<10;
  g_opt_large_slots = 1UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  g_app->large_sz     = 100UL<<10;
  g_app->large_finish = 0;

  req_opt_t opt1 = { .path = ROUTE_BIG };
  tc_request( tc, 1U, &opt1 );
  tc_msg( tc, 1U, 0, "L", 1UL, 0 );
  req_opt_t opt2 = { .path = ROUTE_BIG };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, "L", 1UL, 0 );
  tc_flush( tc );

  FD_TEST( g_app->stream[0].large_err==FD_GRPC_SERVER_SUCCESS );
  FD_TEST( g_app->stream[1].large_err==FD_GRPC_SERVER_ERR_AGAIN );
  FD_TEST( fd_grpc_server_metrics( server )->tx_large_busy_cnt==1UL );
  FD_TEST( g_app->stream[1].writable_cnt==0 );

  /* Draining the first message frees the slot and wakes the second
     call, which is what the writable callback is for */
  for( ulong i=0UL; i<32UL && !g_app->stream[1].writable_cnt; i++ ) {
    tc_window_update( tc, 1U, 65536U );
    tc_window_update( tc, 0U, 65536U );
    tc_flush( tc );
  }
  FD_TEST( g_app->stream[1].writable_cnt==1 );

  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz  = 0UL;
  g_opt_large_slots = 0UL;
}

/* A stream draining an oversized message does not starve the others:
   the flush loop emits one frame per stream per turn whichever source
   it comes from. */

static void
test_large_fair( void ) {
  g_opt_max_msg_sz  = 256UL<<10;
  g_opt_large_slots = 1UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  g_app->large_sz     = 200UL<<10;
  g_app->large_finish = 1;

  req_opt_t opt1 = { .path = ROUTE_BIG };
  tc_request( tc, 1U, &opt1 );
  tc_msg( tc, 1U, 0, "L", 1UL, 1 );
  uchar cmd[2] = { 'S', 8 };
  req_opt_t opt2 = { .path = ROUTE_STREAM };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, cmd, sizeof(cmd), 1 );
  tc_flush( tc );

  /* The small call finished while the large message was still going
     out, rather than waiting behind it */
  FD_TEST( tc_stream( tc, 3U )->end_stream );
  FD_TEST( tc_stream( tc, 3U )->data_sz==8UL*261UL );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  tc_grant( tc, 1U, 65536U, 64UL );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_stream_t * s1 = tc_stream( tc, 1U );
  ulong off1 = tc_msg_at( s1, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==( 200UL<<10 ) );
  FD_TEST( fd_memeq( msg, test_big_payload, msg_sz ) );
  FD_TEST( tc_msg_at( s1, off1, &flag, &msg, &msg_sz )==s1->data_sz );

  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz  = 0UL;
  g_opt_large_slots = 0UL;
}

/* A send queue is bounded in messages as well as in bytes. */

static void
test_queue_msg_max( void ) {
  g_opt_queue_msg_max = 3UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE_SLOW };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, "Q", 1UL, 0 );
  tc_flush( tc );

  /* The queue has room for hundreds of 256 byte messages, so the count
     is what stopped it */
  FD_TEST( g_app->stream[0].again_cnt==1 );
  FD_TEST( fd_grpc_server_metrics( server )->tx_msg_cnt==3UL );

  /* Draining retires the queued messages and wakes the app */
  tc_window_update( tc, 1U, 1UL<<20 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].writable_cnt==1 );
  FD_TEST( tc_stream( tc, 1U )->data_sz==3UL*261UL );

  tc_close( tc );
  test_server_delete( server );
  g_opt_queue_msg_max = 0UL;
}

/* The message count of a send queue bounds what the queue holds, not
   what a call may send over its life: the count has to come back down
   as the queue drains, however the bytes were split into frames. */

static void
test_queue_msg_max_cycles( void ) {
  g_opt_queue_msg_max = 3UL;
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE_SLOW };
  tc_request( tc, 1U, &opt );

  /* Eight rounds of filling the queue to its message bound and
     draining it in 64 byte grants, which splits every 261 byte
     message across several frames. */
  for( ulong round=0UL; round<8UL; round++ ) {
    tc_msg( tc, 1U, 0, "Q", 1UL, 0 );
    tc_flush( tc );
    FD_TEST( g_app->stream[0].again_cnt==(int)round+1 );
    for( ulong i=0UL; i<16UL; i++ ) {
      tc_window_update( tc, 1U, 64U );
      tc_window_update( tc, 0U, 64U );
      tc_flush( tc );
    }
    FD_TEST( tc_stream( tc, 1U )->data_sz==(round+1UL)*3UL*261UL );
  }

  tc_close( tc );
  test_server_delete( server );
  g_opt_queue_msg_max = 0UL;
}

/* Messages sent while an oversized one is draining go out behind it,
   in the order they were sent, and the queue's own bounds still
   apply. */

static void
test_large_order( void ) {
  g_opt_max_msg_sz    = 256UL<<10;
  g_opt_large_slots   = 1UL;
  g_opt_queue_msg_max = 6UL;   /* fewer than the eight the app tries */
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  req_opt_t opt = { .path = ROUTE_BIG };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, "O", 1UL, 1 );
  tc_flush( tc );

  test_app_stream_t * a = g_app->stream+0;
  FD_TEST( a->large_err==FD_GRPC_SERVER_SUCCESS );
  /* The message count bound stopped it, not the large message */
  FD_TEST( a->msg_cnt==1+6 ); /* the request, plus the six that fit */
  FD_TEST( a->again_cnt==1 );

  tc_grant( tc, 1U, 65536U, 64UL );

  /* The oversized message came first, then the six small ones in the
     order they were sent */
  tc_stream_t * s = tc_stream( tc, 1U );
  uchar flag; uchar const * msg; ulong msg_sz;
  ulong off = tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==( 200UL<<10 ) );
  FD_TEST( msg[ 0 ]==0 && msg[ 1 ]==11 );
  for( ulong i=0UL; i<6UL; i++ ) {
    off = tc_msg_at( s, off, &flag, &msg, &msg_sz );
    FD_TEST( msg_sz==64UL );
    FD_TEST( msg[ 0 ]==(uchar)i && msg[ 63 ]==(uchar)i );
  }
  FD_TEST( off==s->data_sz );
  tc_expect_trailers( tc, 1U, "0", NULL );
  FD_TEST( fd_grpc_server_metrics( server )->tx_large_msg_cnt==1UL );

  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz    = 0UL;
  g_opt_large_slots   = 0UL;
  g_opt_queue_msg_max = 0UL;
}

/* A second oversized message on a stream that already holds a slot
   waits, and only it does. */

static void
test_large_second( void ) {
  g_opt_max_msg_sz  = 256UL<<10;
  g_opt_large_slots = 4UL;   /* slots to spare: the stream is the bound */
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  g_app->large_sz     = 100UL<<10;
  g_app->large_finish = 1;
  g_app->large_twice  = 1;

  req_opt_t opt = { .path = ROUTE_BIG };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, "L", 1UL, 1 );
  tc_flush( tc );

  FD_TEST( g_app->stream[0].large_err   ==FD_GRPC_SERVER_SUCCESS   );
  FD_TEST( g_app->stream[0].large_follow==FD_GRPC_SERVER_SUCCESS   );
  FD_TEST( g_app->stream[0].large_second==FD_GRPC_SERVER_ERR_AGAIN );
  FD_TEST( fd_grpc_server_metrics( server )->tx_large_busy_cnt==1UL );
  /* the refused one needed a slot, which is how an application tells
     this apart from a full queue */
  FD_TEST(  g_app->stream[0].needs_large_big   );
  FD_TEST( !g_app->stream[0].needs_large_small );

  tc_grant( tc, 1U, 65536U, 64UL );
  tc_stream_t * s = tc_stream( tc, 1U );
  uchar flag; uchar const * msg; ulong msg_sz;
  ulong off = tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==( 100UL<<10 ) );
  off = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==256UL );
  FD_TEST( off==s->data_sz );

  g_app->large_twice = 0;
  tc_close( tc );
  test_server_delete( server );
  g_opt_max_msg_sz  = 0UL;
  g_opt_large_slots = 0UL;
}

static void
test_interleave( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 1UL<<20 );
  tc_flush( tc );

  uchar cmd[2] = { 'S', 8 };
  req_opt_t opt1 = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt1 );
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 1 );
  req_opt_t opt2 = { .path = ROUTE_STREAM };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, cmd, sizeof(cmd), 1 );
  tc_flush( tc );

  /* Both calls completed, each with its own trailers */
  tc_expect_trailers( tc, 1U, "0", NULL );
  tc_expect_trailers( tc, 3U, "0", NULL );
  FD_TEST( tc_stream( tc, 1U )->data_sz==8UL*261UL );
  FD_TEST( tc_stream( tc, 3U )->data_sz==8UL*261UL );

  tc_close( tc );
  test_server_delete( server );
}

/* test_interleave_order checks that two streams with data pending take
   turns, by walking the send ring in wire order */

static void
test_interleave_order( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* One message worth of send window per stream, so that each pass over
     the streams produces exactly one DATA frame each */
  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 261U );
  tc_flush( tc );

  uchar cmd[2] = { 'S', 8 };
  req_opt_t opt1 = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt1 );
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 1 );
  req_opt_t opt2 = { .path = ROUTE_STREAM };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, cmd, sizeof(cmd), 1 );

  ulong off = 0UL;
  while( off<tc->req_sz ) {
    ulong n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+off, tc->req_sz-off, tc->now );
    FD_TEST( n );
    off += n;
  }
  tc->req_sz = 0UL;

  static uchar wire[ 1UL<<20 ];
  ulong wire_sz = 0UL;
  for( ulong i=0UL; i<16UL; i++ ) {
    wire_sz += fd_grpc_server_conn_pop_tx( tc->conn, wire+wire_sz, sizeof(wire)-wire_sz );
    tc_window_update( tc, 1U, 261U );
    tc_window_update( tc, 3U, 261U );
    ulong o = 0UL;
    while( o<tc->req_sz ) {
      ulong n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+o, tc->req_sz-o, tc->now );
      FD_TEST( n );
      o += n;
    }
    tc->req_sz = 0UL;
  }
  wire_sz += fd_grpc_server_conn_pop_tx( tc->conn, wire+wire_sz, sizeof(wire)-wire_sz );

  ulong  data_cnt[2] = {0};
  int    prev        = -1;
  int    repeats     = 0;
  ulong  o           = 0UL;
  while( o+9UL<=wire_sz ) {
    fd_h2_frame_hdr_t hdr;
    fd_memcpy( &hdr, wire+o, 9UL );
    ulong payload_sz = fd_h2_frame_length( hdr.typlen );
    uint  type       = fd_h2_frame_type  ( hdr.typlen );
    uint  sid        = fd_h2_frame_stream_id( hdr.r_stream_id );
    if( o+9UL+payload_sz>wire_sz ) break;
    o += 9UL+payload_sz;
    if( type!=FD_H2_FRAME_TYPE_DATA ) continue;
    int which = sid==1U ? 0 : 1;
    data_cnt[ which ]++;
    if( prev==which ) repeats++;
    prev = which;
  }
  FD_TEST( data_cnt[0]>4UL );
  FD_TEST( data_cnt[1]>4UL );
  /* Round-robin: while both streams have data queued, frames alternate */
  FD_TEST( repeats<=2 );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_timeout( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* Unary route, 10 milliseconds, and no request message */
  req_opt_t opt = { .path = ROUTE_UNARY, .timeout = "10m" };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  tc->now += 5L*1000L*1000L;
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  tc->now += 10L*1000L*1000L;
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  tc_expect_trailers( tc, 1U, "4", "deadline exceeded" );
  FD_TEST( fd_grpc_server_metrics( server )->deadline_exceeded_cnt==1UL );
  FD_TEST( g_app->stream[0].close_cnt==1 );

  /* A streaming route ignores the deadline */
  req_opt_t opt2 = { .path = ROUTE_STREAM, .timeout = "10m" };
  tc_request( tc, 3U, &opt2 );
  tc_flush( tc );
  tc->now += 1000L*1000L*1000L;
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  FD_TEST( !tc_stream( tc, 3U )->end_stream );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_timeout_units( void ) {
  /* fd_grpc_server_parse_timeout is internal; exercise it through the
     deadline that a request installs */
  struct { char const * text; long nanos; } cases[] = {
    { "1n",       1L },
    { "1u",    1000L },
    { "1m", 1000000L },
    { "1S", 1000000000L },
    { "2M", 120L*1000000000L },
    { "1H", 3600L*1000000000L },
    { "bad",      0L },  /* malformed: no deadline */
    { "1x",       0L },
    { "123456789S", 0L } /* too many digits */
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
    tc_t * tc = g_tc;
    tc_open( tc, server );
    req_opt_t opt = { .path = ROUTE_UNARY, .timeout = cases[i].text };
    tc_request( tc, 1U, &opt );
    tc_flush( tc );

    /* Just short of the deadline nothing happens; just past it the call
       fails.  A malformed value means no deadline at all. */
    long base = tc->now;
    tc->now = base + cases[i].nanos - 1L;
    fd_grpc_server_service( server, tc->now );
    tc_drain( tc );
    FD_TEST( !tc_stream( tc, 1U )->end_stream );
    tc->now = base + cases[i].nanos + 1L;
    fd_grpc_server_service( server, tc->now );
    tc_drain( tc );
    if( cases[i].nanos ) {
      tc_expect_trailers( tc, 1U, "4", "deadline exceeded" );
    } else {
      FD_TEST( !tc_stream( tc, 1U )->end_stream );
    }
    tc_close( tc );
    test_server_delete( server );
  }
}

static void
test_cancel( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 100U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  uchar cmd[2] = { 'S', 40 };
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 0 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].close_cnt==0 );

  tc_rst( tc, 1U, FD_H2_ERR_CANCEL );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].close_cnt==1 );
  FD_TEST( g_app->stream[0].close_reason==FD_GRPC_SERVER_CLOSE_CANCELLED );

  /* The slot is reusable right away */
  req_opt_t opt2 = { .path = ROUTE_UNARY };
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, 0, "x", 1UL, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "0", NULL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_conn_lost( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 100U );
  tc_flush( tc );
  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  uchar cmd[2] = { 'S', 40 };
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 0 );
  tc_flush( tc );

  fd_grpc_server_conn_close( tc->conn );
  FD_TEST( g_app->stream[0].close_cnt==1 );
  FD_TEST( g_app->stream[0].close_reason==FD_GRPC_SERVER_CLOSE_CONN_LOST );
  FD_TEST( g_app->conn_close_cnt==1UL );
  FD_TEST( fd_grpc_server_is_idle( server ) );

  test_server_delete( server );
}

static void
test_shutdown( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 1UL<<20 );
  tc_flush( tc );
  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].close_cnt==0 );

  fd_grpc_server_shutdown( server );
  tc_drain( tc );

  FD_TEST( tc->goaway );
  FD_TEST( tc->goaway_err==FD_H2_SUCCESS );
  FD_TEST( tc->goaway_last_id==1U );
  tc_expect_trailers( tc, 1U, "14", "server is shutting down" );
  FD_TEST( g_app->stream[0].close_cnt==1 );

  /* A new stream on the drained connection is refused */
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  FD_TEST( fd_grpc_server_is_idle( server ) );
  FD_TEST( g_app->conn_close_cnt==1UL );

  test_server_delete( server );
}

static void
test_goaway_refuses_streams( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* Occupy the connection with a stream that stays open, then shut the
     server down and try to open another stream */
  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );

  fd_grpc_server_shutdown( server );
  tc_drain( tc );
  FD_TEST( tc->goaway );

  req_opt_t opt2 = { .path = ROUTE_UNARY, .end_stream = 1 };
  tc_request( tc, 3U, &opt2 );
  ulong off = 0UL;
  while( off<tc->req_sz && fd_grpc_server_conn_is_open( tc->conn ) ) {
    ulong n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+off, tc->req_sz-off, tc->now );
    tc_drain( tc );
    if( !n ) break;
    off += n;
  }
  tc->req_sz = 0UL;
  tc_stream_t * s = tc_stream( tc, 3U );
  /* Either the connection is already gone or the stream was refused */
  FD_TEST( !fd_grpc_server_conn_is_open( tc->conn ) ||
           ( s->rst && s->rst_code==FD_H2_ERR_REFUSED_STREAM ) );

  test_server_delete( server );
}

static void
test_pct_encode( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  req_opt_t opt = { .path = ROUTE_PCT, .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  /* "bad\ttoken \x80 50%" */
  tc_expect_trailers( tc, 1U, "13", "bad%09token %80 50%25" );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_idle( void ) {
  /* An idle connection is closed with a GOAWAY */
  fd_grpc_server_t * server = test_server_new_ex( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL,
                                                  300L*1000L*1000L*1000L );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  tc->now += 301L*1000L*1000L*1000L;
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  FD_TEST( tc->goaway );
  /* The connection slot is returned once the GOAWAY has left the ring */
  fd_grpc_server_service( server, tc->now );
  FD_TEST( !fd_grpc_server_conn_is_open( tc->conn ) );
  FD_TEST( fd_grpc_server_metrics( server )->idle_timeout_cnt==1UL );
  test_server_delete( server );
}

static void
test_conn_window( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  /* The server raises the connection receive window above the 65535
     bytes that RFC 9113 fixes as the initial value */
  FD_TEST( tc->conn_wnd_update==(1UL<<20)-65535UL );
  tc_close( tc );
  test_server_delete( server );
}

static void
test_preface( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_open_direct( server, 1L );
  FD_TEST( conn );
  char const * junk = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  fd_grpc_server_conn_push_rx( conn, junk, strlen( junk ), 1L );
  FD_TEST( !fd_grpc_server_conn_is_open( conn ) );

  /* A preface that arrives in dribbles is accepted */
  conn = fd_grpc_server_conn_open_direct( server, 1L );
  FD_TEST( conn );
  for( ulong i=0UL; i<24UL; i++ ) {
    FD_TEST( fd_grpc_server_conn_push_rx( conn, fd_h2_client_preface+i, 1UL, 1L )==1UL );
    FD_TEST( fd_grpc_server_conn_is_open( conn ) );
  }
  test_server_delete( server );
}

/* Compression ********************************************************/

/* Workspace for the test's own zstd contexts, which are independent of
   the server's so that the wire bytes are checked against a second
   implementation of the same settings. */

static uchar test_zarena[ 8UL<<20 ] __attribute__((aligned(8)));

/* test_zstd_encode produces a zstd frame the way the server does: one
   shot, so the frame header declares the content size. */

static ulong
test_zstd_encode( uchar *      out,
                  ulong        out_max,
                  void const * in,
                  ulong        in_sz ) {
  FD_TEST( ZSTD_estimateCCtxSize( 1 )<=sizeof(test_zarena) );
  ZSTD_CCtx * cctx = ZSTD_initStaticCCtx( test_zarena, sizeof(test_zarena) );
  FD_TEST( cctx );
  ulong sz = ZSTD_compressCCtx( cctx, out, out_max, in, in_sz, 1 );
  FD_TEST( !ZSTD_isError( sz ) );
  return sz;
}

/* test_zstd_encode_stream produces a zstd frame the way a streaming
   encoder does, without declaring the content size in the frame
   header.  This is what tonic's client sends. */

static ulong
test_zstd_encode_stream( uchar *      out,
                         ulong        out_max,
                         void const * in,
                         ulong        in_sz ) {
  FD_TEST( ZSTD_estimateCStreamSize( 1 )<=sizeof(test_zarena) );
  ZSTD_CStream * zcs = ZSTD_initStaticCStream( test_zarena, sizeof(test_zarena) );
  FD_TEST( zcs );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( zcs, ZSTD_c_compressionLevel, 1 ) ) );
  ZSTD_inBuffer  src = { in,  in_sz,   0UL };
  ZSTD_outBuffer dst = { out, out_max, 0UL };
  ulong rem;
  do {
    rem = ZSTD_compressStream2( zcs, &dst, &src, ZSTD_e_end );
    FD_TEST( !ZSTD_isError( rem ) );
  } while( rem );
  FD_TEST( ZSTD_getFrameContentSize( out, dst.pos )==ZSTD_CONTENTSIZE_UNKNOWN );
  return dst.pos;
}

/* test_zstd_decode expands a frame the server produced. */

static ulong
test_zstd_decode( uchar *       out,
                  ulong         out_max,
                  uchar const * in,
                  ulong         in_sz ) {
  FD_TEST( ZSTD_estimateDCtxSize()<=sizeof(test_zarena) );
  ZSTD_DCtx * dctx = ZSTD_initStaticDCtx( test_zarena, sizeof(test_zarena) );
  FD_TEST( dctx );
  ulong sz = ZSTD_decompressDCtx( dctx, out, out_max, in, in_sz );
  FD_TEST( !ZSTD_isError( sz ) );
  return sz;
}

static void
test_zstd( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* A client that does not advertise zstd gets identity */
  uchar body[ 1024 ];
  for( ulong i=0UL; i<sizeof(body); i++ ) body[i] = (uchar)( i&0x0f );
  req_opt_t plain = { .path = ROUTE_UNARY };
  tc_request( tc, 1U, &plain );
  tc_msg( tc, 1U, 0, body, sizeof(body), 1 );
  tc_flush( tc );
  tc_stream_t * s1 = tc_stream( tc, 1U );
  FD_TEST( !s1->grpc_encoding[0] );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_msg_at( s1, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 && msg_sz==sizeof(body) );

  /* A client that advertises zstd gets a compressed message */
  req_opt_t gz = { .path = ROUTE_UNARY, .accept_encoding = "identity, zstd" };
  tc_request( tc, 3U, &gz );
  tc_msg( tc, 3U, 0, body, sizeof(body), 1 );
  tc_flush( tc );
  tc_stream_t * s3 = tc_stream( tc, 3U );
  FD_TEST( !strcmp( s3->grpc_encoding, "zstd" ) );
  /* With compression enabled the server also accepts zstd requests */
  FD_TEST( !strcmp( s3->grpc_accept_encoding, "zstd" ) );
  tc_msg_at( s3, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==1 );
  FD_TEST( msg_sz<sizeof(body) );

  /* The bytes are a zstd frame of exactly this payload: the same
     settings reproduce them, the frame header declares the plaintext
     size, and an independent decoder recovers the message */
  static uchar expect[ 1UL<<16 ];
  ulong expect_sz = test_zstd_encode( expect, sizeof(expect), body, sizeof(body) );
  FD_TEST( expect_sz==msg_sz );
  FD_TEST( fd_memeq( msg, expect, msg_sz ) );

  FD_TEST( FD_LOAD( uint, msg )==ZSTD_MAGICNUMBER );
  FD_TEST( ZSTD_getFrameContentSize( msg, msg_sz )==(unsigned long long)sizeof(body) );
  static uchar back[ 1UL<<16 ];
  FD_TEST( test_zstd_decode( back, sizeof(back), msg, msg_sz )==sizeof(body) );
  FD_TEST( fd_memeq( back, body, sizeof(body) ) );

  /* Messages below compression_min_sz stay uncompressed */
  uchar small[ 64 ] = {0};
  req_opt_t gz2 = { .path = ROUTE_UNARY, .accept_encoding = "zstd" };
  tc_request( tc, 5U, &gz2 );
  tc_msg( tc, 5U, 0, small, sizeof(small), 1 );
  tc_flush( tc );
  tc_stream_t * s5 = tc_stream( tc, 5U );
  FD_TEST( !strcmp( s5->grpc_encoding, "zstd" ) );
  tc_msg_at( s5, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 && msg_sz==sizeof(small) );

  fd_grpc_server_metrics_t const * m = fd_grpc_server_metrics( server );
  FD_TEST( m->tx_msg_compressed_cnt==1UL );
  FD_TEST( m->tx_byte_cnt_wire < m->tx_byte_cnt );

  tc_close( tc );
  test_server_delete( server );

  /* An incompressible message goes out plain, because the codec never
     makes a message larger on the wire */
  server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 1UL<<16 );
  tc_open( tc, server );
  static uchar noise[ 4096 ];
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 7U, 0UL ) );
  for( ulong i=0UL; i<sizeof(noise); i++ ) noise[i] = fd_rng_uchar( rng );
  req_opt_t gz3 = { .path = ROUTE_UNARY, .accept_encoding = "zstd" };
  tc_request( tc, 1U, &gz3 );
  tc_msg( tc, 1U, 0, noise, sizeof(noise), 1 );
  tc_flush( tc );
  tc_msg_at( tc_stream( tc, 1U ), 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 && msg_sz==sizeof(noise) );
  FD_TEST( fd_grpc_server_metrics( server )->tx_msg_compressed_cnt==0UL );
  fd_rng_delete( fd_rng_leave( rng ) );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_zstd_disabled( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  uchar body[ 1024 ] = {0};
  req_opt_t gz = { .path = ROUTE_UNARY, .accept_encoding = "zstd" };
  tc_request( tc, 1U, &gz );
  tc_msg( tc, 1U, 0, body, sizeof(body), 1 );
  tc_flush( tc );
  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( !s->grpc_encoding[0] );
  FD_TEST( !strcmp( s->grpc_accept_encoding, "identity" ) );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 && msg_sz==sizeof(body) );
  tc_close( tc );
  test_server_delete( server );
}

/* A client that advertises only gzip, which the server does not offer,
   gets identity coded responses. */

static void
test_zstd_other_codec( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  uchar body[ 1024 ] = {0};
  req_opt_t gz = { .path = ROUTE_UNARY, .accept_encoding = "gzip, deflate" };
  tc_request( tc, 1U, &gz );
  tc_msg( tc, 1U, 0, body, sizeof(body), 1 );
  tc_flush( tc );
  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( !s->grpc_encoding[0] );
  FD_TEST( !strcmp( s->grpc_accept_encoding, "zstd" ) );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_msg_at( s, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 && msg_sz==sizeof(body) );
  tc_close( tc );
  test_server_delete( server );
}

static void
test_compressed_request( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 1UL<<16 );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  char const * plain = "a compressed request message, repeated: "
                       "a compressed request message, repeated.";
  static uchar gz[ 4096 ];
  ulong gz_sz = test_zstd_encode( gz, sizeof(gz), plain, strlen( plain ) );
  FD_TEST( gz_sz>4UL && gz_sz<strlen( plain ) );

  /* A zstd coded request message round-trips: the handler echoes the
     plaintext, and the response is identity coded because this client
     does not advertise zstd */
  req_opt_t opt = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 1, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "0", NULL );
  tc_stream_t * s1 = tc_stream( tc, 1U );
  uchar flag; uchar const * msg; ulong msg_sz;
  tc_msg_at( s1, 0UL, &flag, &msg, &msg_sz );
  FD_TEST( flag==0 );
  FD_TEST( msg_sz==strlen( plain ) );
  FD_TEST( fd_memeq( msg, plain, msg_sz ) );
  FD_TEST( g_app->stream[0].msg_cnt==1 );
  FD_TEST( g_app->stream[0].rx_byte_cnt==strlen( plain ) );

  /* A frame that does not declare its content size, which is what a
     streaming encoder such as tonic's produces, decodes too */
  static uchar st[ 4096 ];
  ulong st_sz = test_zstd_encode_stream( st, sizeof(st), plain, strlen( plain ) );
  req_opt_t opt_st = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 3U, &opt_st );
  tc_msg( tc, 3U, 1, st, st_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "0", NULL );
  tc_msg_at( tc_stream( tc, 3U ), 0UL, &flag, &msg, &msg_sz );
  FD_TEST( msg_sz==strlen( plain ) && fd_memeq( msg, plain, msg_sz ) );

  /* Flag 1 without a grpc-encoding header names no codec */
  req_opt_t opt2 = { .path = ROUTE_UNARY };
  tc_request( tc, 5U, &opt2 );
  tc_msg( tc, 5U, 1, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 5U, "12", "grpc: unsupported message encoding" );

  /* An encoding the server does not have is refused the same way */
  req_opt_t opt2b = { .path = ROUTE_UNARY, .encoding = "gzip" };
  tc_request( tc, 7U, &opt2b );
  tc_msg( tc, 7U, 1, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 7U, "12", "grpc: unsupported message encoding" );

  tc_close( tc );
  test_server_delete( server );

  /* Bytes that are not a zstd frame at all */
  server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 1UL<<16 );
  tc_open( tc, server );
  static uchar bad[ 4096 ];
  fd_memcpy( bad, gz, gz_sz );
  bad[ 0 ] = (uchar)( bad[ 0 ] ^ 0xffU ); /* break the frame magic */
  req_opt_t opt3 = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 1U, &opt3 );
  tc_msg( tc, 1U, 1, bad, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "13", "grpc: failed to decompress message" );

  /* Truncated frame */
  req_opt_t opt4 = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 3U, &opt4 );
  tc_msg( tc, 3U, 1, gz, gz_sz-5UL, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "13", "grpc: failed to decompress message" );

  /* An empty body cannot be a frame */
  req_opt_t opt4b = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 5U, &opt4b );
  tc_msg( tc, 5U, 1, NULL, 0UL, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 5U, "13", "grpc: failed to decompress message" );

  tc_close( tc );
  test_server_delete( server );

  /* Trailing bytes after the frame */
  server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 4096UL, 1UL<<16 );
  tc_open( tc, server );
  fd_memcpy( bad, gz, gz_sz );
  bad[ gz_sz ] = 0x00;
  req_opt_t opt5 = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 1U, &opt5 );
  tc_msg( tc, 1U, 1, bad, gz_sz+1UL, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "13", "grpc: failed to decompress message" );

  /* One message carries one frame, so a second frame behind the first
     is a framing error rather than more plaintext */
  fd_memcpy( bad,       gz, gz_sz );
  fd_memcpy( bad+gz_sz, gz, gz_sz );
  req_opt_t opt5b = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 3U, &opt5b );
  tc_msg( tc, 3U, 1, bad, 2UL*gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "13", "grpc: failed to decompress message" );

  /* A reserved flag value is a protocol violation */
  req_opt_t opt6 = { .path = ROUTE_UNARY };
  tc_request( tc, 5U, &opt6 );
  tc_msg( tc, 5U, 7, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 5U, "13", "invalid compressed flag" );

  /* Identity messages on a zstd stream are fine */
  req_opt_t opt7 = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 7U, &opt7 );
  tc_msg( tc, 7U, 0, "abc", 3UL, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 7U, "0", NULL );

  tc_close( tc );
  test_server_delete( server );

  /* A plaintext larger than max_request_msg_sz is refused even though
     its coded form fits.  The frame header declares the size, so the
     refusal comes before any bytes are expanded. */
  server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 512UL, 1UL<<16 );
  tc_open( tc, server );
  static uchar big[ 4096 ];
  for( ulong i=0UL; i<sizeof(big); i++ ) big[i] = 'A';
  gz_sz = test_zstd_encode( gz, sizeof(gz), big, sizeof(big) );
  FD_TEST( gz_sz<512UL );
  req_opt_t opt8 = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 1U, &opt8 );
  tc_msg( tc, 1U, 1, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "8", "grpc: received message larger than max" );
  FD_TEST( g_app->stream[0].msg_cnt==0 );

  /* The same plaintext in a frame that declares no content size is
     refused by the output bound instead */
  gz_sz = test_zstd_encode_stream( gz, sizeof(gz), big, sizeof(big) );
  FD_TEST( gz_sz<512UL );
  req_opt_t opt8b = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 3U, &opt8b );
  tc_msg( tc, 3U, 1, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "8", "grpc: received message larger than max" );
  FD_TEST( g_app->stream[1].msg_cnt==0 );
  tc_close( tc );
  test_server_delete( server );

  /* With compression disabled there is no decompressor at all */
  server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 1UL<<16 );
  tc_open( tc, server );
  req_opt_t opt9 = { .path = ROUTE_UNARY, .encoding = "zstd" };
  tc_request( tc, 1U, &opt9 );
  tc_msg( tc, 1U, 1, gz, gz_sz, 1 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "12", "grpc: compressed requests are not supported" );
  FD_TEST( !strcmp( tc_stream( tc, 1U )->grpc_accept_encoding, "identity" ) );
  tc_close( tc );
  test_server_delete( server );
}
static void
test_incomplete_message( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  req_opt_t opt = { .path = ROUTE_UNARY };
  tc_request( tc, 1U, &opt );
  uchar prefix[5] = { 0, 0, 0, 0, 8 };
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, FD_H2_FLAG_END_STREAM, 1U, prefix, 5UL );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "13", "incomplete message" );
  tc_close( tc );
  test_server_delete( server );
}

static void
test_empty_message( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, 0, NULL, 0UL, 1 );
  tc_flush( tc );
  FD_TEST( g_app->stream[0].msg_cnt==1 );
  FD_TEST( g_app->stream[0].rx_byte_cnt==0UL );
  tc_close( tc );
  test_server_delete( server );
}

/* Socket mode ********************************************************/

#if FD_HAS_HOSTED

static void
test_listen( ushort port ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_ZSTD, 64UL<<10, 256UL<<10 );
  uint addr = 0U;
  FD_TEST( fd_cstr_to_ip4_addr( "127.0.0.1", &addr ) );
  int listen_fd = fd_grpc_server_listen( server, addr, port );
  if( FD_UNLIKELY( listen_fd<0 ) ) FD_LOG_ERR(( "fd_grpc_server_listen failed" ));
  FD_LOG_NOTICE(( "listening on 127.0.0.1:%hu (routes: %s %s)", port, ROUTE_UNARY, ROUTE_STREAM ));
  for(;;) {
    fd_grpc_server_poll( server, 1000 );
    FD_LOG_DEBUG(( "fds=%lu conns=%lu", fd_grpc_server_fd_cnt( server ),
                   (ulong)fd_grpc_server_metrics( server )->conn_open_cnt ));
  }
}

#endif

/* A refused stream's field block still advances the connection's HPACK
   table, so a later block may reference what it inserted. */

static void
test_refused_dtable( void ) {
  fd_grpc_server_t * server = test_server_new( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL );
  tc_t * tc = g_tc;
  tc_open( tc, server );

  /* Fill every stream slot; no END_STREAM so they stay held. */
  req_opt_t opt = { .path = ROUTE_UNARY };
  for( uint i=0U; i<4U; i++ ) tc_request( tc, 1U+2U*i, &opt );
  tc_flush( tc );

  /* Stream 9 is refused.  Its block inserts x-a: b at dynamic index 62
     via a literal with incremental indexing. */
  uchar block[ 512 ]; ulong o = 0UL;
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 3 );
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 6 );
  o += HDR_LIT( block+o, ":path", ROUTE_UNARY );
  o += hdr_lit( block+o, "content-type", 12UL, "application/grpc", 16UL );
  o += HDR_LIT( block+o, "te", "trailers" );
  block[ o++ ] = 0x40; /* literal, new name, incremental indexing */
  block[ o++ ] = 3; block[ o++ ]='x'; block[ o++ ]='-'; block[ o++ ]='a';
  block[ o++ ] = 1; block[ o++ ]='b';
  tc_frame( tc, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 9U, block, o );
  tc_flush( tc );
  FD_TEST( tc_stream( tc, 9U )->rst );

  /* Stream 1 sends trailers that reference index 62. */
  uchar tr[ 1 ] = { 0xBE };
  tc_frame( tc, FD_H2_FRAME_TYPE_HEADERS,
            FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM, 1U, tr, 1UL );
  tc_flush( tc );

  FD_TEST( !tc->goaway );
  FD_TEST( fd_grpc_server_conn_is_open( tc->conn ) );

  tc_close( tc );
  fd_grpc_server_delete( fd_grpc_server_leave( server ) );
}

static void
test_flowctl_stall( void ) {
  /* A peer that never opens its flow-control window leaves the response
     in the stream queue, where the idle timeout still reaches it. */
  fd_grpc_server_t * server = test_server_new_ex( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL,
                                                  300L*1000L*1000L*1000L );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE_SLOW };
  tc_request( tc, 1U, &opt );
  uchar cmd[1] = { 'Q' };
  tc_msg( tc, 1U, 0, cmd, sizeof(cmd), 0 );
  tc_flush( tc );

  /* The send ring is empty and the stream is active, so neither the
     stalled output nor the receive idle branch sees the connection. */
  uchar scratch[ 64 ];
  FD_TEST( fd_grpc_server_conn_pop_tx( tc->conn, scratch, sizeof(scratch) )==0UL );
  FD_TEST( fd_grpc_server_metrics( server )->tx_queue_full_cnt==1UL );

  tc->now += 301L*1000L*1000L*1000L;
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  FD_TEST( tc->goaway );
  fd_grpc_server_service( server, tc->now );
  FD_TEST( !fd_grpc_server_conn_is_open( tc->conn ) );
  FD_TEST( fd_grpc_server_metrics( server )->idle_timeout_cnt==1UL );
  test_server_delete( server );
}

static void
test_quiet_subscriber( void ) {
  /* A subscriber with an open window and nothing queued stays open. */
  fd_grpc_server_t * server = test_server_new_ex( FD_GRPC_SERVER_COMPRESSION_NONE, 4096UL, 8192UL,
                                                  300L*1000L*1000L*1000L );
  tc_t * tc = g_tc;
  tc_open( tc, server );
  req_opt_t opt = { .path = ROUTE_STREAM };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  tc_window_update( tc, 1U, 1UL<<20 );
  tc_flush( tc );

  tc->now += 301L*1000L*1000L*1000L;
  fd_grpc_server_service( server, tc->now );
  tc_drain( tc );
  FD_TEST( !tc->goaway );
  FD_TEST( fd_grpc_server_conn_is_open( tc->conn ) );
  FD_TEST( fd_grpc_server_metrics( server )->idle_timeout_cnt==0UL );

  tc_close( tc );
  test_server_delete( server );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ushort listen_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--listen", NULL, 0 );
# if FD_HAS_HOSTED
  if( listen_port ) {
    test_listen( listen_port );
    return 0;
  }
# else
  (void)listen_port;
# endif

  test_big_payload_init();

# define RUN(t) do { FD_LOG_NOTICE(( "%-28s ...", #t )); t(); test_cnt++; } while(0)
  ulong test_cnt = 0UL;
  RUN( test_params               );
  RUN( test_preface              );
  RUN( test_conn_window          );
  RUN( test_unary                );
  RUN( test_reassembly           );
  RUN( test_empty_message        );
  RUN( test_incomplete_message   );
  RUN( test_oversize             );
  RUN( test_unknown_path         );
  RUN( test_bad_content_type     );
  RUN( test_continuation_refused           );
  RUN( test_close_aborted                  );
  RUN( test_malformed            );
  RUN( test_streaming            );
  RUN( test_queue_full           );
  RUN( test_queue_msg_max        );
  RUN( test_queue_msg_max_cycles );
  RUN( test_large_message        );
  RUN( test_large_bounds         );
  RUN( test_large_cancel         );
  RUN( test_large_busy           );
  RUN( test_large_fair           );
  RUN( test_large_order          );
  RUN( test_large_second         );
  RUN( test_interleave           );
  RUN( test_interleave_order     );
  RUN( test_timeout              );
  RUN( test_timeout_units        );
  RUN( test_cancel               );
  RUN( test_conn_lost            );
  RUN( test_shutdown             );
  RUN( test_goaway_refuses_streams );
  RUN( test_pct_encode           );
  RUN( test_idle                 );
  RUN( test_zstd                 );
  RUN( test_zstd_disabled        );
  RUN( test_zstd_other_codec     );
  RUN( test_compressed_request   );
  RUN( test_refused_dtable       );
  RUN( test_flowctl_stall        );
  RUN( test_quiet_subscriber     );
# undef RUN

  FD_LOG_NOTICE(( "pass (%lu tests)", test_cnt ));
  fd_halt();
  return 0;
}
