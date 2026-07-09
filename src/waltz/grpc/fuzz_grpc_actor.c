#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "../../util/sanitize/fd_fuzz.h"
#include "fd_grpc_client.h"
#include "fd_grpc_client_private.h"
#include "../h2/fd_h2.h"
#include "../../util/fd_util.h"

#include <stdlib.h>

#define FUZZ_MAX_OPS           (128UL)
#define FUZZ_GRPC_BUF_MAX      (4096UL)
#define FUZZ_CLIENT_MEM_SZ     (131072UL)
#define FUZZ_SERVER_BUFSZ      (4096UL)
#define FUZZ_SERVER_SCRATCH_SZ (4096UL)

#define FUZZ_ACTOR_CLIENT ((uchar)0u)
#define FUZZ_ACTOR_SERVER ((uchar)1u)

typedef struct {
  uchar const * data;
  ulong         data_sz;
  ulong         data_off;
} fuzz_cursor_t;

typedef enum {
  FUZZ_OP_SERVICE = 0,
  FUZZ_OP_START_REQUEST,
  FUZZ_OP_SERVER_HEADERS,
  FUZZ_OP_SERVER_DATA,
  FUZZ_OP_SERVER_RST,
  FUZZ_OP_WRAP_CLIENT_RX,
  FUZZ_OP_SET_DEADLINE,
  FUZZ_OP_VALIDATE,
  FUZZ_OP_KIND_CNT
} fuzz_op_kind_t;

typedef struct {
  fuzz_op_kind_t kind;
  uchar          actor;
  uchar          arg0;
  uchar          arg1;
  uint           raw;
} fuzz_op_t;

typedef struct {
  fuzz_op_t ops[ FUZZ_MAX_OPS ];
  ulong     op_cnt;
} fuzz_program_t;

typedef struct {
  fd_h2_conn_t      conn[1];
  fd_h2_callbacks_t cb[1];
  fd_h2_rbuf_t      rbuf_rx[1];
  fd_h2_rbuf_t      rbuf_tx[1];
  fd_h2_stream_t    streams[ FD_GRPC_CLIENT_MAX_STREAMS ];
  uint              stream_ids[ FD_GRPC_CLIENT_MAX_STREAMS ];
  ulong             stream_cnt;
  uint              last_remote_stream_id;
  ulong             headers_cnt;
  ulong             data_cnt;
  ulong             rst_cnt;
  uchar             rx_buf[ FUZZ_SERVER_BUFSZ ];
  uchar             tx_buf[ FUZZ_SERVER_BUFSZ ];
  uchar             scratch[ FUZZ_SERVER_SCRATCH_SZ ];
} fuzz_server_t;

typedef struct {
  ulong conn_established_cnt;
  ulong conn_dead_cnt;
  ulong tx_complete_cnt;
  ulong rx_start_cnt;
  ulong rx_msg_cnt;
  ulong rx_end_cnt;
  ulong rx_timeout_cnt;
  ulong ping_ack_cnt;
} fuzz_app_t;

static uchar g_client_mem[ FUZZ_CLIENT_MEM_SZ ] __attribute__((aligned(128)));
static FD_TL fd_grpc_client_t *       g_client;
static FD_TL fd_grpc_client_metrics_t g_metrics[1];
static FD_TL fuzz_server_t            g_server[1];
static FD_TL fuzz_app_t               g_app[1];
static FD_TL int                      g_replay_trace;
static FD_TL int                      g_replay_state;
static FD_TL ulong                    g_replay_step;

static inline char const *
fuzz_actor_name( uchar actor ) {
  return actor==FUZZ_ACTOR_SERVER ? "server" : "client";
}

static inline char const *
fuzz_op_kind_name( fuzz_op_kind_t kind ) {
  switch( kind ) {
    case FUZZ_OP_SERVICE:        return "service";
    case FUZZ_OP_START_REQUEST:  return "start_request";
    case FUZZ_OP_SERVER_HEADERS: return "server_headers";
    case FUZZ_OP_SERVER_DATA:    return "server_data";
    case FUZZ_OP_SERVER_RST:     return "server_rst";
    case FUZZ_OP_WRAP_CLIENT_RX: return "wrap_client_rx";
    case FUZZ_OP_SET_DEADLINE:   return "set_deadline";
    case FUZZ_OP_VALIDATE:       return "validate";
    default:                     return "unknown";
  }
}

static inline uchar
fuzz_fallback_u8( fuzz_cursor_t const * cur ) {
  ulong h = fd_ulong_hash( cur->data_off ^ (cur->data_sz<<1) ^ 0x517cc1b727220a95UL );
  return (uchar)h;
}

static inline uchar
fuzz_u8( fuzz_cursor_t * cur ) {
  if( FD_LIKELY( cur->data_off < cur->data_sz ) ) {
    return cur->data[ cur->data_off++ ];
  }
  cur->data_off++;
  return fuzz_fallback_u8( cur );
}

static inline uint
fuzz_u32( fuzz_cursor_t * cur ) {
  uint v = (uint)fuzz_u8( cur );
  v |= (uint)( (uint)fuzz_u8( cur ) << 8u  );
  v |= (uint)( (uint)fuzz_u8( cur ) << 16u );
  v |= (uint)( (uint)fuzz_u8( cur ) << 24u );
  return v;
}

static inline ulong
fuzz_limit( uchar x ) {
  return x ? (ulong)x : ULONG_MAX;
}

static fd_h2_stream_t *
fuzz_server_stream_query( uint stream_id ) {
  for( ulong i=0UL; i<g_server->stream_cnt; i++ ) {
    if( g_server->stream_ids[ i ]==stream_id ) return &g_server->streams[ i ];
  }
  return NULL;
}

static fd_h2_stream_t *
fuzz_server_stream_alloc( uint stream_id ) {
  fd_h2_stream_t * stream = fuzz_server_stream_query( stream_id );
  if( FD_UNLIKELY( stream ) ) return stream;
  if( FD_UNLIKELY( g_server->stream_cnt>=FD_GRPC_CLIENT_MAX_STREAMS ) ) return NULL;

  ulong slot = g_server->stream_cnt++;
  g_server->stream_ids[ slot ] = stream_id;
  return fd_h2_stream_init( &g_server->streams[ slot ] );
}

static void
fuzz_server_stream_remove( uint stream_id ) {
  for( ulong i=0UL; i<g_server->stream_cnt; i++ ) {
    if( g_server->stream_ids[ i ]!=stream_id ) continue;
    ulong tail = g_server->stream_cnt - 1UL;
    if( i!=tail ) {
      g_server->streams   [ i ] = g_server->streams   [ tail ];
      g_server->stream_ids[ i ] = g_server->stream_ids[ tail ];
    }
    g_server->stream_cnt--;
    if( g_server->last_remote_stream_id==stream_id ) g_server->last_remote_stream_id = 0U;
    return;
  }
}

static fd_h2_stream_t *
server_cb_stream_create( fd_h2_conn_t * conn,
                         uint           stream_id ) {
  (void)conn;
  fd_h2_stream_t * stream = fuzz_server_stream_alloc( stream_id );
  if( FD_LIKELY( stream ) ) g_server->last_remote_stream_id = stream_id;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] server cb stream_create stream=%u created=%d",
                    g_replay_step, stream_id, !!stream ));
  }
  return stream;
}

static fd_h2_stream_t *
server_cb_stream_query( fd_h2_conn_t * conn,
                        uint           stream_id ) {
  (void)conn;
  return fuzz_server_stream_query( stream_id );
}

static void
server_cb_conn_established( fd_h2_conn_t * conn ) {
  (void)conn;
}

static void
server_cb_conn_final( fd_h2_conn_t * conn,
                      uint           h2_err,
                      int            closed_by ) {
  (void)conn; (void)h2_err;
  FD_TEST( closed_by==0 || closed_by==1 );
}

static void
server_cb_headers( fd_h2_conn_t *   conn,
                   fd_h2_stream_t * stream,
                   void const *     data,
                   ulong            data_sz,
                   ulong            flags ) {
  (void)conn; (void)data; (void)data_sz;
  g_server->headers_cnt++;
  g_server->last_remote_stream_id = stream->stream_id;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] server cb headers stream=%u data_sz=%lu flags=0x%lx",
                    g_replay_step, stream->stream_id, data_sz, flags ));
  }
}

static void
server_cb_data( fd_h2_conn_t *   conn,
                fd_h2_stream_t * stream,
                void const *     data,
                ulong            data_sz,
                ulong            flags ) {
  (void)conn; (void)data;
  g_server->data_cnt++;
  g_server->last_remote_stream_id = stream->stream_id;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] server cb data stream=%u data_sz=%lu flags=0x%lx",
                    g_replay_step, stream->stream_id, data_sz, flags ));
  }
}

static void
server_cb_rst_stream( fd_h2_conn_t *   conn,
                      fd_h2_stream_t * stream,
                      uint             error_code,
                      int              closed_by ) {
  (void)conn; (void)error_code;
  FD_TEST( closed_by==0 || closed_by==1 );
  g_server->rst_cnt++;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] server cb rst_stream stream=%u err=%u closed_by=%d",
                    g_replay_step, stream->stream_id, error_code, closed_by ));
  }
  fuzz_server_stream_remove( stream->stream_id );
}

static void
server_cb_window_update( fd_h2_conn_t * conn,
                         uint           increment ) {
  (void)conn; (void)increment;
}

static void
server_cb_stream_window_update( fd_h2_conn_t *   conn,
                                fd_h2_stream_t * stream,
                                uint             increment ) {
  (void)conn; (void)stream; (void)increment;
}

static void
client_cb_conn_established( void * app_ctx ) {
  (void)app_ctx;
  g_app->conn_established_cnt++;
}

static void
client_cb_conn_dead( void * app_ctx,
                     uint   h2_err,
                     int    closed_by ) {
  (void)app_ctx; (void)h2_err;
  FD_TEST( closed_by==0 || closed_by==1 );
  g_app->conn_dead_cnt++;
}

static void
client_cb_tx_complete( void * app_ctx,
                       ulong  request_ctx ) {
  (void)app_ctx; (void)request_ctx;
  g_app->tx_complete_cnt++;
}

static void
client_cb_rx_start( void * app_ctx,
                    ulong  request_ctx ) {
  (void)app_ctx; (void)request_ctx;
  g_app->rx_start_cnt++;
}

static void
client_cb_rx_msg( void *       app_ctx,
                  void const * protobuf,
                  ulong        protobuf_sz,
                  ulong        request_ctx ) {
  (void)app_ctx; (void)protobuf; (void)protobuf_sz; (void)request_ctx;
  g_app->rx_msg_cnt++;
}

static void
client_cb_rx_end( void *                app_ctx,
                  ulong                 request_ctx,
                  fd_grpc_resp_hdrs_t * resp ) {
  (void)app_ctx; (void)request_ctx; (void)resp;
  g_app->rx_end_cnt++;
}

static void
client_cb_rx_timeout( void * app_ctx,
                      ulong  request_ctx,
                      int    deadline_kind ) {
  (void)app_ctx; (void)request_ctx; (void)deadline_kind;
  g_app->rx_timeout_cnt++;
}

static void
client_cb_ping_ack( void * app_ctx ) {
  (void)app_ctx;
  g_app->ping_ack_cnt++;
}

static fd_grpc_client_callbacks_t const g_client_callbacks = {
  .conn_established = client_cb_conn_established,
  .conn_dead        = client_cb_conn_dead,
  .tx_complete      = client_cb_tx_complete,
  .rx_start         = client_cb_rx_start,
  .rx_msg           = client_cb_rx_msg,
  .rx_end           = client_cb_rx_end,
  .rx_timeout       = client_cb_rx_timeout,
  .ping_ack         = client_cb_ping_ack,
};

static void
fuzz_server_reset( void ) {
  fd_memset( g_server, 0, sizeof(fuzz_server_t) );

  fd_h2_callbacks_init( g_server->cb );
  g_server->cb->stream_create        = server_cb_stream_create;
  g_server->cb->stream_query         = server_cb_stream_query;
  g_server->cb->conn_established     = server_cb_conn_established;
  g_server->cb->conn_final           = server_cb_conn_final;
  g_server->cb->headers              = server_cb_headers;
  g_server->cb->data                 = server_cb_data;
  g_server->cb->rst_stream           = server_cb_rst_stream;
  g_server->cb->window_update        = server_cb_window_update;
  g_server->cb->stream_window_update = server_cb_stream_window_update;

  fd_h2_rbuf_init( g_server->rbuf_rx, g_server->rx_buf, sizeof(g_server->rx_buf) );
  fd_h2_rbuf_init( g_server->rbuf_tx, g_server->tx_buf, sizeof(g_server->tx_buf) );
  fd_h2_conn_init_server( g_server->conn );

  /* The socket/TLS layer would have consumed the client preface.  Start
     from a live HTTP/2 frame stream, but otherwise use the normal h2
     state machines and callbacks. */
  g_server->conn->flags = 0U;
  g_server->conn->self_settings.max_concurrent_streams = FD_GRPC_CLIENT_MAX_STREAMS;
  g_server->conn->peer_settings.max_concurrent_streams = FD_GRPC_CLIENT_MAX_STREAMS;
  g_server->conn->self_settings.max_frame_size         = FUZZ_SERVER_SCRATCH_SZ;
  g_server->conn->peer_settings.max_frame_size         = FUZZ_GRPC_BUF_MAX;
  g_server->conn->ctx = g_server;
}

static void
fuzz_client_reset( ulong seed ) {
  fd_memset( g_metrics, 0, sizeof(fd_grpc_client_metrics_t) );
  fd_memset( g_app,     0, sizeof(fuzz_app_t) );
  fd_memset( g_client_mem, 0, sizeof(g_client_mem) );

  g_client = fd_grpc_client_new( g_client_mem,
                                 &g_client_callbacks,
                                 g_metrics,
                                 g_app,
                                 FUZZ_GRPC_BUF_MAX,
                                 seed );
  FD_TEST( g_client );
  fd_grpc_client_set_authority( g_client, "localhost", 9UL, 443U );
  fd_grpc_client_set_version( g_client, "fuzz", 4UL );

  g_client->ssl_hs_done = 1;
  g_client->h2_hs_done  = 1;
  g_client->conn->flags = 0U;
  g_client->conn->self_settings.max_concurrent_streams = FD_GRPC_CLIENT_MAX_STREAMS;
  g_client->conn->peer_settings.max_concurrent_streams = FD_GRPC_CLIENT_MAX_STREAMS;
  g_client->conn->self_settings.max_frame_size         = FUZZ_GRPC_BUF_MAX;
  g_client->conn->peer_settings.max_frame_size         = FUZZ_SERVER_SCRATCH_SZ;
}

static void
fuzz_decode_program( fuzz_cursor_t *  cur,
                     fuzz_program_t * prog ) {
  prog->op_cnt = 0UL;
  while( cur->data_off < cur->data_sz && prog->op_cnt < FUZZ_MAX_OPS ) {
    fuzz_op_t * op = &prog->ops[ prog->op_cnt++ ];
    *op = (fuzz_op_t) {
      .kind  = (fuzz_op_kind_t)( fuzz_u8( cur ) % FUZZ_OP_KIND_CNT ),
      .actor = (uchar)( fuzz_u8( cur ) & 1u ),
      .arg0  = fuzz_u8( cur ),
      .arg1  = fuzz_u8( cur ),
      .raw   = fuzz_u32( cur ),
    };
  }

  if( prog->op_cnt < FUZZ_MAX_OPS ) {
    prog->ops[ prog->op_cnt++ ] = (fuzz_op_t){ .kind = FUZZ_OP_VALIDATE };
  }
}

static ulong
fuzz_transfer_one_way( fd_h2_rbuf_t * src_tx,
                       fd_h2_rbuf_t * dst_rx,
                       ulong          limit ) {
  ulong moved = 0UL;
  while( moved < limit ) {
    ulong used = fd_h2_rbuf_used_sz( src_tx );
    ulong free = fd_h2_rbuf_free_sz( dst_rx );
    if( FD_UNLIKELY( !used || !free ) ) break;

    ulong sz0, sz1;
    uchar * data = fd_h2_rbuf_peek_used( src_tx, &sz0, &sz1 );
    (void)sz1;
    ulong chunk = fd_ulong_min( sz0, free );
    chunk = fd_ulong_min( chunk, limit-moved );
    if( FD_UNLIKELY( !chunk ) ) break;

    fd_h2_rbuf_push( dst_rx, data, chunk );
    fd_h2_rbuf_skip( src_tx, chunk );
    moved += chunk;
  }
  return moved;
}

static void
fuzz_service_pair( ulong rounds,
                   ulong c2s_limit,
                   ulong s2c_limit,
                   long  ts_nanos ) {
  for( ulong j=0UL; j<rounds; j++ ) {
    fd_h2_tx_control( g_client->conn, g_client->frame_tx, &fd_grpc_client_h2_callbacks );
    fd_h2_tx_control( g_server->conn, g_server->rbuf_tx, g_server->cb );
    fd_grpc_client_service_streams( g_client, ts_nanos );

    ulong c2s_moved = fuzz_transfer_one_way( g_client->frame_tx, g_server->rbuf_rx, c2s_limit );
    ulong s2c_moved = fuzz_transfer_one_way( g_server->rbuf_tx, g_client->frame_rx, s2c_limit );

    if( FD_UNLIKELY( g_replay_trace ) ) {
      FD_LOG_NOTICE(( "[%03lu] service round=%lu moved c2s=%lu s2c=%lu",
                      g_replay_step, j, c2s_moved, s2c_moved ));
    }

    fd_h2_rx( g_server->conn, g_server->rbuf_rx, g_server->rbuf_tx,
              g_server->scratch, sizeof(g_server->scratch), g_server->cb );
    fd_h2_rx( g_client->conn, g_client->frame_rx, g_client->frame_tx,
              g_client->frame_scratch, g_client->frame_scratch_max, &fd_grpc_client_h2_callbacks );
  }
}

static fd_h2_stream_t *
fuzz_pick_server_stream( uchar selector ) {
  if( FD_UNLIKELY( !g_server->stream_cnt ) ) return NULL;

  if( selector==0u && g_server->last_remote_stream_id ) {
    fd_h2_stream_t * stream = fuzz_server_stream_query( g_server->last_remote_stream_id );
    if( FD_LIKELY( stream ) ) return stream;
  }

  ulong idx = (ulong)selector % g_server->stream_cnt;
  return &g_server->streams[ idx ];
}

static void
fuzz_start_request( uchar arg0,
                    uchar arg1,
                    uint  raw ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( g_client ) ) ) return;

  static char const * const paths[] = {
    "/fuzz.Fuzz/Unary",
    "/fuzz.Fuzz/ServerStream",
    "/fuzz.Fuzz/ClientStream",
    "/fuzz.Fuzz/Bidi"
  };

  uchar payload[ 32 ];
  ulong payload_sz = (ulong)( raw & 31U );
  for( ulong i=0UL; i<payload_sz; i++ ) {
    payload[ i ] = (uchar)( raw + (uint)i*17U + (uint)arg1 );
  }

  char const * path = paths[ arg0 & 3u ];
  int streaming = !!( arg1 & 1u );
  fd_grpc_h2_stream_t * stream =
    fd_grpc_client_request_start1( g_client,
                                   path,
                                   strlen( path ),
                                   (ulong)raw,
                                   payload,
                                   payload_sz,
                                   NULL,
                                   0UL,
                                   streaming );
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] client start_request path=%s payload_sz=%lu streaming=%d stream=%u ok=%d",
                    g_replay_step, path, payload_sz, streaming,
                    stream ? stream->s.stream_id : 0U, !!stream ));
  }
}

static ulong
fuzz_hpack_literal( uchar *      out,
                    char const * name,
                    ulong        name_len,
                    char const * val,
                    ulong        val_len ) {
  uchar * p = out;
  *p++ = 0x00; /* literal without indexing, new name */
  FD_TEST( name_len<127UL );
  *p++ = (uchar)name_len;
  fd_memcpy( p, name, name_len );
  p += name_len;
  FD_TEST( val_len<127UL );
  *p++ = (uchar)val_len;
  fd_memcpy( p, val, val_len );
  p += val_len;
  return (ulong)( p-out );
}

static ulong
fuzz_build_resp_headers( uchar * out,
                         uchar   mode ) {
  ulong off = 0UL;

  if( FD_LIKELY( (mode&3u)!=3u ) ) {
    out[ off++ ] = 0x88; /* :status: 200 */
  } else {
    off += fuzz_hpack_literal( out+off, ":status", 7UL, "500", 3UL );
  }

  if( FD_LIKELY( !(mode&1u) ) ) {
    off += fuzz_hpack_literal( out+off, "content-type", 12UL, "application/grpc+proto", 22UL );
  }

  if( mode&4u ) {
    off += fuzz_hpack_literal( out+off, "grpc-status", 11UL, "0", 1UL );
  }

  return off;
}

static void
fuzz_server_headers( uchar arg0,
                     uchar arg1 ) {
  fd_h2_stream_t * stream = fuzz_pick_server_stream( arg1 );
  if( FD_UNLIKELY( !stream ) ) return;

  uchar hpack[ 128 ];
  ulong hpack_sz;
  if( FD_UNLIKELY( arg0==0xffu ) ) {
    hpack[0] = 0xffu;
    hpack_sz = 1UL;
  } else {
    hpack_sz = fuzz_build_resp_headers( hpack, arg0 );
  }

  uint flags = FD_H2_FLAG_END_HEADERS;
  if( arg1 & 0x80u ) flags |= FD_H2_FLAG_END_STREAM;

  ulong req_sz = sizeof(fd_h2_frame_hdr_t) + hpack_sz;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( g_server->rbuf_tx ) < req_sz ) ) return;
  fd_h2_tx( g_server->rbuf_tx, hpack, hpack_sz, FD_H2_FRAME_TYPE_HEADERS, flags, stream->stream_id );

  if( flags & FD_H2_FLAG_END_STREAM ) {
    if( stream->state==FD_H2_STREAM_STATE_OPEN || stream->state==FD_H2_STREAM_STATE_CLOSING_RX ) {
      fd_h2_stream_close_tx( stream, g_server->conn );
    }
  }

  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] server headers stream=%u hpack_sz=%lu flags=0x%x",
                    g_replay_step, stream->stream_id, hpack_sz, flags ));
  }
}

static ulong
fuzz_build_grpc_data( uchar * payload,
                      uchar   mode,
                      uchar   arg1,
                      uint    raw,
                      uint *  flags ) {
  *flags = !!( arg1&1u ) ? FD_H2_FLAG_END_STREAM : 0U;

  switch( mode & 3u ) {
    case 0u: {
      FD_FUZZ_MUST_BE_COVERED;
      uint msg_sz = (uint)( FUZZ_GRPC_BUF_MAX + 1UL + (ulong)( raw & 255U ) );
      payload[0] = 0U;
      FD_STORE( uint, payload+1, fd_uint_bswap( msg_sz ) );
      for( ulong i=5UL; i<10UL; i++ ) payload[i] = (uchar)( raw + (uint)i );
      *flags = FD_H2_FLAG_END_STREAM;
      return 10UL;
    }
    case 1u: {
      uint msg_sz = (uint)( raw & 15U );
      payload[0] = 0U;
      FD_STORE( uint, payload+1, fd_uint_bswap( msg_sz ) );
      for( ulong i=0UL; i<(ulong)msg_sz; i++ ) payload[5UL+i] = (uchar)( raw + (uint)i );
      return 5UL + (ulong)msg_sz;
    }
    case 2u: {
      ulong payload_sz = 1UL + (ulong)( raw & 31U );
      for( ulong i=0UL; i<payload_sz; i++ ) payload[i] = (uchar)( raw>>( (i&3UL)*8UL ) );
      return payload_sz;
    }
    case 3u:
    default: {
      ulong payload_sz = (ulong)( arg1 & 7u );
      for( ulong i=0UL; i<payload_sz; i++ ) payload[i] = (uchar)( 0xa0u + (uchar)i + (uchar)raw );
      return payload_sz;
    }
  }
}

static void
fuzz_server_data( uchar arg0,
                  uchar arg1,
                  uint  raw ) {
  fd_h2_stream_t * stream = fuzz_pick_server_stream( arg1 );
  if( FD_UNLIKELY( !stream ) ) return;

  uchar payload[ 64 ];
  uint flags;
  ulong payload_sz = fuzz_build_grpc_data( payload, arg0, arg1, raw, &flags );

  ulong req_sz = sizeof(fd_h2_frame_hdr_t) + payload_sz;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( g_server->rbuf_tx ) < req_sz ) ) return;
  fd_h2_tx( g_server->rbuf_tx, payload, payload_sz, FD_H2_FRAME_TYPE_DATA, flags, stream->stream_id );

  if( flags & FD_H2_FLAG_END_STREAM ) {
    if( stream->state==FD_H2_STREAM_STATE_OPEN || stream->state==FD_H2_STREAM_STATE_CLOSING_RX ) {
      fd_h2_stream_close_tx( stream, g_server->conn );
    }
  }

  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] server data stream=%u payload_sz=%lu flags=0x%x mode=%u",
                    g_replay_step, stream->stream_id, payload_sz, flags, (uint)(arg0&3u) ));
  }
}

static void
fuzz_server_rst( uchar arg0,
                 uchar arg1,
                 uint  raw ) {
  fd_h2_stream_t * stream = fuzz_pick_server_stream( arg1 );
  if( FD_UNLIKELY( !stream ) ) return;

  static uint const errs[] = {
    FD_H2_ERR_CANCEL,
    FD_H2_ERR_PROTOCOL,
    FD_H2_ERR_INTERNAL,
    FD_H2_ERR_FLOW_CONTROL
  };
  uint payload = fd_uint_bswap( errs[ arg0 & 3u ] ^ (raw & 1U) );
  ulong req_sz = sizeof(fd_h2_frame_hdr_t) + 4UL;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( g_server->rbuf_tx ) < req_sz ) ) return;
  fd_h2_tx( g_server->rbuf_tx, (uchar const *)&payload, 4UL, FD_H2_FRAME_TYPE_RST_STREAM, 0U, stream->stream_id );
}

static void
fuzz_wrap_client_rx( uchar arg0 ) {
  fd_h2_rbuf_t * rbuf = g_client->frame_rx;
  if( FD_UNLIKELY( !fd_h2_rbuf_is_empty( rbuf ) ) ) return;

  ulong first_payload_chunk = 5UL + (ulong)( arg0 & 15u );
  if( FD_UNLIKELY( first_payload_chunk + sizeof(fd_h2_frame_hdr_t) >= rbuf->bufsz ) ) return;

  ulong target  = rbuf->bufsz - sizeof(fd_h2_frame_hdr_t) - first_payload_chunk;
  ulong cur     = (ulong)( rbuf->hi - rbuf->buf0 );
  ulong advance = ( target + rbuf->bufsz - cur ) % rbuf->bufsz;
  uchar junk[ 64 ];
  for( ulong i=0UL; i<sizeof(junk); i++ ) junk[i] = (uchar)( 0x80u + (uchar)i );

  while( advance ) {
    ulong chunk = fd_ulong_min( advance, sizeof(junk) );
    fd_h2_rbuf_push( rbuf, junk, chunk );
    fd_h2_rbuf_skip( rbuf, chunk );
    advance -= chunk;
  }

  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] client rx wrapped lo_off=%lu hi_off=%lu first_payload_chunk=%lu",
                    g_replay_step, rbuf->lo_off, rbuf->hi_off, first_payload_chunk ));
  }
}

static void
fuzz_set_deadline( uchar arg0,
                   uchar arg1,
                   uint  raw ) {
  if( FD_UNLIKELY( !g_client->stream_cnt ) ) return;
  ulong idx = (ulong)arg1 % g_client->stream_cnt;
  fd_grpc_h2_stream_t * stream = g_client->streams[ idx ];
  int kind = (arg0&1u) ? FD_GRPC_DEADLINE_RX_END : FD_GRPC_DEADLINE_HEADER;
  long deadline = (long)(int)raw;
  fd_grpc_client_deadline_set( stream, kind, deadline );
}

static void
fuzz_validate_all( void ) {
  fd_h2_rbuf_validate_private( g_client->frame_rx );
  fd_h2_rbuf_validate_private( g_client->frame_tx );
  fd_h2_rbuf_validate_private( g_server->rbuf_rx );
  fd_h2_rbuf_validate_private( g_server->rbuf_tx );

  FD_TEST( !g_client->conn->tx_frame_p );
  FD_TEST( !g_server->conn->tx_frame_p );
  FD_TEST( g_client->stream_cnt<=FD_GRPC_CLIENT_MAX_STREAMS );
  FD_TEST( g_server->stream_cnt<=FD_GRPC_CLIENT_MAX_STREAMS );

  for( ulong i=0UL; i<g_client->stream_cnt; i++ ) {
    fd_grpc_h2_stream_t * stream = g_client->streams[ i ];
    FD_TEST( fd_grpc_h2_stream_pool_ele_test( g_client->stream_pool, stream ) );
    FD_TEST( g_client->stream_ids[ i ]==stream->s.stream_id );
    for( ulong j=i+1UL; j<g_client->stream_cnt; j++ ) {
      FD_TEST( g_client->stream_ids[ i ]!=g_client->stream_ids[ j ] );
    }
  }

  if( g_client->request_stream ) {
    int found = 0;
    for( ulong i=0UL; i<g_client->stream_cnt; i++ ) {
      found |= g_client->streams[ i ]==g_client->request_stream;
    }
    FD_TEST( found );
  }

  for( ulong i=0UL; i<g_server->stream_cnt; i++ ) {
    FD_TEST( g_server->stream_ids[ i ]==g_server->streams[ i ].stream_id );
    for( ulong j=i+1UL; j<g_server->stream_cnt; j++ ) {
      FD_TEST( g_server->stream_ids[ i ]!=g_server->stream_ids[ j ] );
    }
  }
}

static void
fuzz_trace_op( ulong             step,
               fuzz_op_t const * op ) {
  if( FD_LIKELY( !g_replay_trace ) ) return;

  FD_LOG_NOTICE(( "[%03lu] %s op=%s arg0=%u arg1=%u raw=0x%08x",
                  step, fuzz_actor_name( op->actor ), fuzz_op_kind_name( op->kind ),
                  (uint)op->arg0, (uint)op->arg1, op->raw ));
}

static void
fuzz_trace_summary( void ) {
  if( FD_LIKELY( !g_replay_state ) ) return;
  FD_LOG_NOTICE(( "[%03lu] summary client streams=%lu rx_used=%lu tx_used=%lu h2_flags=0x%x app rx_start=%lu rx_msg=%lu rx_end=%lu timeout=%lu",
                  g_replay_step,
                  g_client->stream_cnt,
                  fd_h2_rbuf_used_sz( g_client->frame_rx ),
                  fd_h2_rbuf_used_sz( g_client->frame_tx ),
                  (uint)g_client->conn->flags,
                  g_app->rx_start_cnt,
                  g_app->rx_msg_cnt,
                  g_app->rx_end_cnt,
                  g_app->rx_timeout_cnt ));
  FD_LOG_NOTICE(( "[%03lu] summary server streams=%lu rx_used=%lu tx_used=%lu last_remote=%u headers=%lu data=%lu rst=%lu h2_flags=0x%x",
                  g_replay_step,
                  g_server->stream_cnt,
                  fd_h2_rbuf_used_sz( g_server->rbuf_rx ),
                  fd_h2_rbuf_used_sz( g_server->rbuf_tx ),
                  g_server->last_remote_stream_id,
                  g_server->headers_cnt,
                  g_server->data_cnt,
                  g_server->rst_cnt,
                  (uint)g_server->conn->flags ));
}

static void
fuzz_execute_op( ulong             step,
                 fuzz_op_t const * op ) {
  g_replay_step = step;
  fuzz_trace_op( step, op );

  switch( op->kind ) {
    case FUZZ_OP_SERVICE:
      fuzz_service_pair( 1UL + ((ulong)op->arg0 & 3UL),
                         fuzz_limit( op->arg1 ),
                         fuzz_limit( (uchar)op->raw ),
                         (long)(int)( op->raw>>8 ) );
      break;
    case FUZZ_OP_START_REQUEST:
      fuzz_start_request( op->arg0, op->arg1, op->raw );
      break;
    case FUZZ_OP_SERVER_HEADERS:
      fuzz_server_headers( op->arg0, op->arg1 );
      break;
    case FUZZ_OP_SERVER_DATA:
      fuzz_server_data( op->arg0, op->arg1, op->raw );
      break;
    case FUZZ_OP_SERVER_RST:
      fuzz_server_rst( op->arg0, op->arg1, op->raw );
      break;
    case FUZZ_OP_WRAP_CLIENT_RX:
      fuzz_wrap_client_rx( op->arg0 );
      break;
    case FUZZ_OP_SET_DEADLINE:
      fuzz_set_deadline( op->arg0, op->arg1, op->raw );
      break;
    case FUZZ_OP_VALIDATE:
      fuzz_validate_all();
      break;
    default:
      __builtin_unreachable();
  }

  fuzz_trace_summary();
}

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
  fd_log_level_core_set( 4 );
  fd_log_level_stderr_set( 4 );
  FD_TEST( fd_grpc_client_footprint( FUZZ_GRPC_BUF_MAX )<=sizeof(g_client_mem) );

  char const * replay_env = getenv( "FD_GRPC_ACTOR_FUZZ_REPLAY" );
  g_replay_trace = replay_env && replay_env[0] && replay_env[0]!='0';
  char const * replay_state_env = getenv( "FD_GRPC_ACTOR_FUZZ_REPLAY_STATE" );
  g_replay_state = replay_state_env && replay_state_env[0] && replay_state_env[0]!='0';
  if( g_replay_state ) g_replay_trace = 1;
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fuzz_cursor_t cur = {
    .data     = data,
    .data_sz  = size,
    .data_off = 0UL,
  };
  fuzz_program_t prog[1];

  fuzz_client_reset( fd_ulong_hash( size ) );
  fuzz_server_reset();
  fuzz_decode_program( &cur, prog );

  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "replay input_sz=%lu op_cnt=%lu", size, prog->op_cnt ));
  }

  for( ulong i=0UL; i<prog->op_cnt; i++ ) {
    fuzz_execute_op( i, &prog->ops[ i ] );
  }

  fuzz_validate_all();
  return 0;
}
