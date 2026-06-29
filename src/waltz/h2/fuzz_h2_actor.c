#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "../../util/sanitize/fd_fuzz.h"
#include "fd_h2.h"
#include "../../util/fd_util.h"

#include <assert.h>
#include <stdlib.h>

#define FUZZ_MAX_OPS      (128UL)
#define FUZZ_MAX_STREAMS  (8UL)
#define FUZZ_RX_BUFSZ     (64UL)
#define FUZZ_TX_BUFSZ     (64UL)
#define FUZZ_SCRATCH_SZ   (128UL)

#define FUZZ_ACTOR_CLIENT ((uchar)0u)
#define FUZZ_ACTOR_SERVER ((uchar)1u)

typedef struct {
  uchar const * data;
  ulong         data_sz;
  ulong         data_off;
} fuzz_cursor_t;

typedef enum {
  FUZZ_OP_SERVICE = 0,
  FUZZ_OP_OPEN_LOCAL,
  FUZZ_OP_SEND_WINDOW_UPDATE,
  FUZZ_OP_SET_STREAM_TX_WND,
  FUZZ_OP_JAM_TX,
  FUZZ_OP_VALIDATE,
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
  fd_h2_conn_t      conn_mem[1];
  fd_h2_callbacks_t cb[1];
  fd_h2_rbuf_t      rbuf_rx[1];
  fd_h2_rbuf_t      rbuf_tx[1];
  fd_h2_stream_t    streams[ FUZZ_MAX_STREAMS ];
  uint              stream_ids[ FUZZ_MAX_STREAMS ];
  ulong             stream_cnt;
  uint              last_local_stream_id;
  uint              last_remote_stream_id;
  ulong             headers_cnt;
  ulong             data_cnt;
  ulong             rst_cnt;
  ulong             conn_final_cnt;
  uchar             rx_buf[ FUZZ_RX_BUFSZ ];
  uchar             tx_buf[ FUZZ_TX_BUFSZ ];
  uchar             scratch[ FUZZ_SCRATCH_SZ ];
} fuzz_endpoint_t;

static FD_TL fuzz_endpoint_t g_client[1];
static FD_TL fuzz_endpoint_t g_server[1];
static FD_TL int             g_replay_trace;
static FD_TL int             g_replay_state;
static FD_TL ulong           g_replay_step;

static inline char const *
fuzz_actor_name( uchar actor ) {
  return actor==FUZZ_ACTOR_SERVER ? "server" : "client";
}

static inline char const *
fuzz_endpoint_name( fuzz_endpoint_t const * ep ) {
  return ep==g_server ? "server" : "client";
}

static inline char const *
fuzz_op_kind_name( fuzz_op_kind_t kind ) {
  switch( kind ) {
    case FUZZ_OP_SERVICE:            return "service";
    case FUZZ_OP_OPEN_LOCAL:         return "open_local";
    case FUZZ_OP_SEND_WINDOW_UPDATE: return "send_window_update";
    case FUZZ_OP_SET_STREAM_TX_WND:  return "set_stream_tx_wnd";
    case FUZZ_OP_JAM_TX:             return "jam_tx";
    case FUZZ_OP_VALIDATE:           return "validate";
    default:                         return "unknown";
  }
}

static inline uchar
fuzz_fallback_u8( fuzz_cursor_t const * cur ) {
  ulong h = fd_ulong_hash( cur->data_off ^ (cur->data_sz<<1) ^ 0x9e3779b97f4a7c15UL );
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

static inline fuzz_endpoint_t *
fuzz_ep_from_actor( uchar actor ) {
  return actor==FUZZ_ACTOR_SERVER ? g_server : g_client;
}

static inline fuzz_endpoint_t *
fuzz_ep_peer( fuzz_endpoint_t * ep ) {
  return ep==g_client ? g_server : g_client;
}

static fd_h2_stream_t *
fuzz_stream_query( fuzz_endpoint_t * ep,
                   uint              stream_id ) {
  for( ulong i=0UL; i<ep->stream_cnt; i++ ) {
    if( ep->stream_ids[ i ]==stream_id ) return &ep->streams[ i ];
  }
  return NULL;
}

static void
fuzz_refresh_last_ids( fuzz_endpoint_t * ep ) {
  ep->last_local_stream_id  = 0U;
  ep->last_remote_stream_id = 0U;
  for( ulong i=0UL; i<ep->stream_cnt; i++ ) {
    fd_h2_stream_t * stream = &ep->streams[ i ];
    if( !stream->stream_id ) continue;
    if( fd_h2_stream_is_tx( stream, ep->conn_mem ) ) {
      ep->last_local_stream_id = stream->stream_id;
    } else {
      ep->last_remote_stream_id = stream->stream_id;
    }
  }
}

static void
fuzz_stream_remove( fuzz_endpoint_t * ep,
                    uint              stream_id ) {
  for( ulong i=0UL; i<ep->stream_cnt; i++ ) {
    if( ep->stream_ids[ i ]!=stream_id ) continue;
    ulong tail = ep->stream_cnt - 1UL;
    if( i!=tail ) {
      ep->streams   [ i ] = ep->streams   [ tail ];
      ep->stream_ids[ i ] = ep->stream_ids[ tail ];
    }
    ep->stream_cnt--;
    fuzz_refresh_last_ids( ep );
    return;
  }
}

static fd_h2_stream_t *
fuzz_stream_alloc( fuzz_endpoint_t * ep,
                   uint              stream_id ) {
  fd_h2_stream_t * stream = fuzz_stream_query( ep, stream_id );
  if( FD_UNLIKELY( stream ) ) return stream;
  if( FD_UNLIKELY( ep->stream_cnt >= FUZZ_MAX_STREAMS ) ) return NULL;

  ulong slot = ep->stream_cnt++;
  ep->stream_ids[ slot ] = stream_id;
  stream = fd_h2_stream_init( &ep->streams[ slot ] );
  return stream;
}

static fd_h2_stream_t *
cb_stream_create( fd_h2_conn_t * conn,
                  uint           stream_id ) {
  fuzz_endpoint_t * ep = conn->ctx;
  fd_h2_stream_t * stream = fuzz_stream_alloc( ep, stream_id );
  if( FD_LIKELY( stream ) ) ep->last_remote_stream_id = stream_id;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] %s cb stream_create stream=%u created=%d",
                    g_replay_step, fuzz_endpoint_name( ep ), stream_id, !!stream ));
  }
  return stream;
}

static fd_h2_stream_t *
cb_stream_query( fd_h2_conn_t * conn,
                 uint           stream_id ) {
  fuzz_endpoint_t * ep = conn->ctx;
  return fuzz_stream_query( ep, stream_id );
}

static void
cb_conn_established( fd_h2_conn_t * conn ) {
  if( FD_UNLIKELY( g_replay_trace ) ) {
    fuzz_endpoint_t * ep = conn->ctx;
    FD_LOG_NOTICE(( "[%03lu] %s cb conn_established",
                    g_replay_step, fuzz_endpoint_name( ep ) ));
  }
}

static void
cb_conn_final( fd_h2_conn_t * conn,
               uint           h2_err,
               int            closed_by ) {
  fuzz_endpoint_t * ep = conn->ctx;
  FD_TEST( closed_by==0 || closed_by==1 );
  ep->conn_final_cnt++;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] %s cb conn_final err=%u closed_by=%d",
                    g_replay_step, fuzz_endpoint_name( ep ), h2_err, closed_by ));
  }
}

static void
cb_headers( fd_h2_conn_t *   conn,
            fd_h2_stream_t * stream,
            void const *     data,
            ulong            data_sz,
            ulong            flags ) {
  (void)conn;
  (void)stream;
  (void)data;
  fuzz_endpoint_t * ep = conn->ctx;
  ep->headers_cnt++;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] %s cb headers stream=%u data_sz=%lu flags=0x%lx",
                    g_replay_step, fuzz_endpoint_name( ep ), stream->stream_id, data_sz, flags ));
  }
}

static void
cb_data( fd_h2_conn_t *   conn,
         fd_h2_stream_t * stream,
         void const *     data,
         ulong            data_sz,
         ulong            flags ) {
  (void)stream;
  (void)data;
  fuzz_endpoint_t * ep = conn->ctx;
  ep->data_cnt++;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] %s cb data stream=%u data_sz=%lu flags=0x%lx",
                    g_replay_step, fuzz_endpoint_name( ep ), stream->stream_id, data_sz, flags ));
  }
}

static void
cb_rst_stream( fd_h2_conn_t *   conn,
               fd_h2_stream_t * stream,
               uint             error_code,
               int              closed_by ) {
  (void)error_code;
  fuzz_endpoint_t * ep = conn->ctx;
  FD_TEST( closed_by==0 || closed_by==1 );
  ep->rst_cnt++;
  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "[%03lu] %s cb rst_stream stream=%u err=%u closed_by=%d",
                    g_replay_step, fuzz_endpoint_name( ep ), stream->stream_id, error_code, closed_by ));
  }
  fuzz_stream_remove( ep, stream->stream_id );
}

static void
cb_window_update( fd_h2_conn_t * conn,
                  uint           increment ) {
  if( FD_UNLIKELY( g_replay_trace ) ) {
    fuzz_endpoint_t * ep = conn->ctx;
    FD_LOG_NOTICE(( "[%03lu] %s cb window_update increment=%u",
                    g_replay_step, fuzz_endpoint_name( ep ), increment ));
  }
}

static void
cb_stream_window_update( fd_h2_conn_t *   conn,
                         fd_h2_stream_t * stream,
                         uint             increment ) {
  if( FD_UNLIKELY( g_replay_trace ) ) {
    fuzz_endpoint_t * ep = conn->ctx;
    FD_LOG_NOTICE(( "[%03lu] %s cb stream_window_update stream=%u increment=%u",
                    g_replay_step, fuzz_endpoint_name( ep ), stream->stream_id, increment ));
  }
}

static void
fuzz_endpoint_reset( fuzz_endpoint_t * ep,
                     int               is_client ) {
  fd_memset( ep, 0, sizeof(*ep) );

  fd_h2_callbacks_init( ep->cb );
  ep->cb->stream_create        = cb_stream_create;
  ep->cb->stream_query         = cb_stream_query;
  ep->cb->conn_established     = cb_conn_established;
  ep->cb->conn_final           = cb_conn_final;
  ep->cb->headers              = cb_headers;
  ep->cb->data                 = cb_data;
  ep->cb->rst_stream           = cb_rst_stream;
  ep->cb->window_update        = cb_window_update;
  ep->cb->stream_window_update = cb_stream_window_update;

  fd_h2_rbuf_init( ep->rbuf_rx, ep->rx_buf, sizeof(ep->rx_buf) );
  fd_h2_rbuf_init( ep->rbuf_tx, ep->tx_buf, sizeof(ep->tx_buf) );

  if( is_client ) {
    fd_h2_conn_init_client( ep->conn_mem );
  } else {
    fd_h2_conn_init_server( ep->conn_mem );
  }

  ep->conn_mem->flags = 0U; /* Skip the preface handshake and fuzz framing-state directly. */
  ep->conn_mem->self_settings.max_concurrent_streams = (uint)FUZZ_MAX_STREAMS;
  ep->conn_mem->peer_settings.max_concurrent_streams = (uint)FUZZ_MAX_STREAMS;
  ep->conn_mem->self_settings.max_frame_size         = (uint)(FUZZ_RX_BUFSZ - sizeof(fd_h2_frame_hdr_t));
  ep->conn_mem->peer_settings.max_frame_size         = (uint)(FUZZ_TX_BUFSZ - sizeof(fd_h2_frame_hdr_t));
  ep->conn_mem->ctx = ep;
}

static void
fuzz_decode_program( fuzz_cursor_t *  cur,
                     fuzz_program_t * prog ) {
  prog->op_cnt = 0UL;

  while( cur->data_off < cur->data_sz && prog->op_cnt < FUZZ_MAX_OPS ) {
    fuzz_op_t * op = &prog->ops[ prog->op_cnt++ ];
    *op = (fuzz_op_t) {
      .kind  = (fuzz_op_kind_t)( fuzz_u8( cur ) % 6u ),
      .actor = (uchar)( fuzz_u8( cur ) & 1u ),
      .arg0  = fuzz_u8( cur ),
      .arg1  = fuzz_u8( cur ),
      .raw   = fuzz_u32( cur ),
    };
  }

  if( prog->op_cnt < FUZZ_MAX_OPS ) {
    prog->ops[ prog->op_cnt++ ] = (fuzz_op_t){
      .kind = FUZZ_OP_VALIDATE
    };
  }
}

static void
fuzz_validate_endpoint( fuzz_endpoint_t * ep ) {
  fd_h2_rbuf_validate_private( ep->rbuf_rx );
  fd_h2_rbuf_validate_private( ep->rbuf_tx );

  FD_TEST( !ep->conn_mem->tx_frame_p );
  FD_TEST( ep->conn_final_cnt <= 1UL );
  if( ep->conn_mem->flags & FD_H2_CONN_FLAGS_DEAD ) {
    FD_TEST( ep->conn_final_cnt == 1UL );
  }

  ulong active[ 2 ] = {0UL,0UL};
  for( ulong i=0UL; i<ep->stream_cnt; i++ ) {
    fd_h2_stream_t * stream = &ep->streams[ i ];
    FD_TEST( stream->stream_id == ep->stream_ids[ i ] );
    // FD_TEST( stream->state != FD_H2_STREAM_STATE_ILLEGAL );

    if( stream->state==FD_H2_STREAM_STATE_OPEN ||
        stream->state==FD_H2_STREAM_STATE_CLOSING_RX ||
        stream->state==FD_H2_STREAM_STATE_CLOSING_TX ) {
      active[ fd_h2_stream_is_tx( stream, ep->conn_mem ) ]++;
    }
  }

  // FD_TEST( active[0] == ep->conn_mem->stream_active_cnt[0] );
  // FD_TEST( active[1] == ep->conn_mem->stream_active_cnt[1] );
}

static void
fuzz_validate_all( void ) {
  fuzz_validate_endpoint( g_client );
  fuzz_validate_endpoint( g_server );
}

static void
fuzz_trace_endpoint_summary( fuzz_endpoint_t const * ep ) {
  if( FD_LIKELY( !g_replay_state ) ) return;

  FD_LOG_NOTICE(( "[%03lu] %s summary rx_used=%lu tx_used=%lu streams=%lu last_local=%u last_remote=%u finals=%lu headers=%lu data=%lu rst=%lu dead=%d",
                  g_replay_step,
                  fuzz_endpoint_name( ep ),
                  fd_h2_rbuf_used_sz( ep->rbuf_rx ),
                  fd_h2_rbuf_used_sz( ep->rbuf_tx ),
                  ep->stream_cnt,
                  ep->last_local_stream_id,
                  ep->last_remote_stream_id,
                  ep->conn_final_cnt,
                  ep->headers_cnt,
                  ep->data_cnt,
                  ep->rst_cnt,
                  !!( ep->conn_mem->flags & FD_H2_CONN_FLAGS_DEAD ) ));
}

static void
fuzz_trace_all_summaries( void ) {
  if( FD_LIKELY( !g_replay_state ) ) return;
  fuzz_trace_endpoint_summary( g_client );
  fuzz_trace_endpoint_summary( g_server );
}

static ulong
fuzz_transfer_one_way( fuzz_endpoint_t * src,
                       fuzz_endpoint_t * dst,
                       ulong             limit ) {
  ulong moved = 0UL;

  while( moved < limit ) {
    ulong used = fd_h2_rbuf_used_sz( src->rbuf_tx );
    ulong free = fd_h2_rbuf_free_sz( dst->rbuf_rx );
    if( FD_UNLIKELY( !used || !free ) ) break;

    ulong sz0, sz1;
    uchar * data = fd_h2_rbuf_peek_used( src->rbuf_tx, &sz0, &sz1 );
    (void)sz1;
    ulong chunk = fd_ulong_min( sz0, free );
    chunk = fd_ulong_min( chunk, limit - moved );
    if( FD_UNLIKELY( !chunk ) ) break;

    fd_h2_rbuf_push( dst->rbuf_rx, data, chunk );
    fd_h2_rbuf_skip( src->rbuf_tx, chunk );
    moved += chunk;
  }

  return moved;
}

static void
fuzz_service_pair( ulong rounds,
                   ulong c2s_limit,
                   ulong s2c_limit ) {
  c2s_limit = c2s_limit ? c2s_limit : ULONG_MAX;
  s2c_limit = s2c_limit ? s2c_limit : ULONG_MAX;

  for( ulong j=0UL; j<rounds; j++ ) {
    fd_h2_tx_control( g_client->conn_mem, g_client->rbuf_tx, g_client->cb );
    fd_h2_tx_control( g_server->conn_mem, g_server->rbuf_tx, g_server->cb );

    ulong c2s_moved = fuzz_transfer_one_way( g_client, g_server, c2s_limit );
    ulong s2c_moved = fuzz_transfer_one_way( g_server, g_client, s2c_limit );

    if( FD_UNLIKELY( g_replay_trace ) ) {
      FD_LOG_NOTICE(( "[%03lu] service round=%lu moved c2s=%lu s2c=%lu",
                      g_replay_step, j, c2s_moved, s2c_moved ));
    }

    fd_h2_rx( g_server->conn_mem, g_server->rbuf_rx, g_server->rbuf_tx,
              g_server->scratch, sizeof(g_server->scratch), g_server->cb );
    fd_h2_rx( g_client->conn_mem, g_client->rbuf_rx, g_client->rbuf_tx,
              g_client->scratch, sizeof(g_client->scratch), g_client->cb );
  }
}

static fd_h2_stream_t *
fuzz_pick_stream( fuzz_endpoint_t * ep,
                  uchar             selector ) {
  if( !ep->stream_cnt ) return NULL;

  if( selector==0u ) return fuzz_stream_query( ep, ep->last_local_stream_id );
  if( selector==1u ) return fuzz_stream_query( ep, ep->last_remote_stream_id );

  for( ulong i=0UL; i<ep->stream_cnt; i++ ) {
    if( selector==2u ) return &ep->streams[ i ];
    if( selector==3u && fd_h2_stream_is_tx( &ep->streams[i], ep->conn_mem ) ) return &ep->streams[i];
    if( selector==4u && !fd_h2_stream_is_tx( &ep->streams[i], ep->conn_mem ) ) return &ep->streams[i];
  }

  return &ep->streams[ 0 ];
}

static void
fuzz_open_local_stream( fuzz_endpoint_t * ep,
                        int               queue_headers,
                        int               end_stream ) {
  uint stream_id = ep->conn_mem->tx_stream_next;
  fd_h2_stream_t * stream = fuzz_stream_alloc( ep, stream_id );
  if( FD_UNLIKELY( !stream ) ) return;

  fd_h2_stream_open( fd_h2_stream_init( stream ), ep->conn_mem, stream_id );
  ep->conn_mem->tx_stream_next = stream_id + 2U;
  ep->last_local_stream_id = stream_id;

  if( !queue_headers ) return;

  uchar payload[ 1 ] = { 0x82 };
  ulong req_sz = sizeof(fd_h2_frame_hdr_t) + sizeof(payload);
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( ep->rbuf_tx ) < req_sz ) ) return;

  uint flags = FD_H2_FLAG_END_HEADERS;
  if( end_stream ) flags |= FD_H2_FLAG_END_STREAM;
  fd_h2_tx( ep->rbuf_tx, payload, sizeof(payload), FD_H2_FRAME_TYPE_HEADERS, flags, stream_id );

  if( end_stream ) {
    fd_h2_stream_close_tx( stream, ep->conn_mem );
  }
}

static uint
fuzz_window_update_increment( uchar mode,
                              uint  raw ) {
  switch( mode % 5u ) {
    case 0u:  return 0U;
    case 1u:  return 1U + ( raw & 0x0000ffffU );
    case 2u:  return 0x7fffffffU;
    case 3u:  return 0x7fffff00U | ( raw & 0x000000ffU );
    case 4u:
    default:  return ( raw & 0x7fffffffU ) | 1U;
  }
}

static uint
fuzz_stream_tx_wnd_value( uchar mode,
                          uint  raw ) {
  switch( mode % 4u ) {
    case 0u:  return raw;
    case 1u:  return 0xfffffff0U | ( raw & 0x0000000fU );
    case 2u:  return 0x7fffff00U | ( raw & 0x000000ffU );
    case 3u:
    default:  return 1U + ( raw & 0x0000ffffU );
  }
}

static uint
fuzz_resolve_window_update_stream_id( fuzz_endpoint_t * sender,
                                      uchar             stream_mode ) {
  fuzz_endpoint_t * receiver = fuzz_ep_peer( sender );

  if( ( stream_mode % 5u )==0u ) return 0U;

  fd_h2_stream_t * stream = fuzz_pick_stream( receiver, (uchar)( ( stream_mode - 1u ) % 5u ) );
  return stream ? stream->stream_id : 0U;
}

static void
fuzz_send_window_update( fuzz_endpoint_t * sender,
                         uchar             stream_mode,
                         uchar             increment_mode,
                         uint              raw ) {
  uint stream_id = fuzz_resolve_window_update_stream_id( sender, stream_mode );
  uint increment = fuzz_window_update_increment( increment_mode, raw );

  ulong req_sz = sizeof(fd_h2_frame_hdr_t) + 4UL;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( sender->rbuf_tx ) < req_sz ) ) return;

  uint payload = fd_uint_bswap( increment );
  fd_h2_tx( sender->rbuf_tx, (uchar const *)&payload, 4UL, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, stream_id );
}

static void
fuzz_set_stream_tx_wnd( fuzz_endpoint_t * ep,
                        uchar             selector,
                        uchar             mode,
                        uint              raw ) {
  fd_h2_stream_t * stream = fuzz_pick_stream( ep, selector % 5u );
  if( FD_UNLIKELY( !stream ) ) return;
  stream->tx_wnd = fuzz_stream_tx_wnd_value( mode, raw );
}

static void
fuzz_jam_tx( fuzz_endpoint_t * ep,
             uchar             fill_byte,
             uchar             skip_byte,
             uint              raw ) {
  ulong used = fd_h2_rbuf_used_sz( ep->rbuf_tx );
  ulong skip = fd_ulong_min( used, (ulong)skip_byte );
  if( skip ) fd_h2_rbuf_skip( ep->rbuf_tx, skip );

  ulong free = fd_h2_rbuf_free_sz( ep->rbuf_tx );
  ulong fill = fd_ulong_min( free, (ulong)fill_byte );
  if( FD_UNLIKELY( !fill ) ) return;

  uchar buf[ FUZZ_TX_BUFSZ ];
  uchar pattern = (uchar)( raw ^ ((uint)fill_byte<<8) ^ ((uint)skip_byte<<16) );
  for( ulong i=0UL; i<fill; i++ ) buf[i] = (uchar)( pattern + (uchar)i );
  fd_h2_rbuf_push( ep->rbuf_tx, buf, fill );
}

static void
fuzz_trace_op( ulong             step,
               fuzz_op_t const * op ) {
  if( FD_LIKELY( !g_replay_trace ) ) return;

  switch( op->kind ) {
    case FUZZ_OP_SERVICE: {
      ulong rounds    = 1UL + ((ulong)op->arg0 & 3UL);
      ulong c2s_limit = 1UL + ((ulong)(  op->raw        & 0x3fU ));
      ulong s2c_limit = 1UL + ((ulong)( (op->raw >> 8 ) & 0x3fU ));
      FD_LOG_NOTICE(( "[%03lu] op=%s rounds=%lu c2s_limit=%lu s2c_limit=%lu",
                      step, fuzz_op_kind_name( op->kind ), rounds, c2s_limit, s2c_limit ));
      break;
    }

    case FUZZ_OP_OPEN_LOCAL: {
      fuzz_endpoint_t * ep = fuzz_ep_from_actor( op->actor );
      int queue_headers = !!( op->arg0 & 1u );
      int end_stream    = !!( op->arg0 & 2u );
      ulong cnt = 1UL + ((ulong)op->arg1 & 1UL);
      FD_LOG_NOTICE(( "[%03lu] %s op=%s next_stream=%u queue_headers=%d end_stream=%d count=%lu",
                      step, fuzz_actor_name( op->actor ), fuzz_op_kind_name( op->kind ),
                      ep->conn_mem->tx_stream_next, queue_headers, end_stream, cnt ));
      break;
    }

    case FUZZ_OP_SEND_WINDOW_UPDATE: {
      fuzz_endpoint_t * sender = fuzz_ep_from_actor( op->actor );
      uint stream_id  = fuzz_resolve_window_update_stream_id( sender, op->arg0 );
      uint increment  = fuzz_window_update_increment( op->arg1, op->raw );
      FD_LOG_NOTICE(( "[%03lu] %s op=%s stream_mode=%u stream_id=%u increment_mode=%u increment=%u",
                      step, fuzz_actor_name( op->actor ), fuzz_op_kind_name( op->kind ),
                      (uint)( op->arg0 % 5u ), stream_id, (uint)( op->arg1 % 5u ), increment ));
      break;
    }

    case FUZZ_OP_SET_STREAM_TX_WND: {
      fuzz_endpoint_t * ep = fuzz_ep_from_actor( op->actor );
      fd_h2_stream_t * stream = fuzz_pick_stream( ep, (uchar)( op->arg0 % 5u ) );
      uint new_wnd = fuzz_stream_tx_wnd_value( op->arg1, op->raw );
      FD_LOG_NOTICE(( "[%03lu] %s op=%s selector=%u stream_id=%u old_tx_wnd=%u new_tx_wnd=%u",
                      step, fuzz_actor_name( op->actor ), fuzz_op_kind_name( op->kind ),
                      (uint)( op->arg0 % 5u ),
                      stream ? stream->stream_id : 0U,
                      stream ? stream->tx_wnd    : 0U,
                      new_wnd ));
      break;
    }

    case FUZZ_OP_JAM_TX: {
      fuzz_endpoint_t * ep = fuzz_ep_from_actor( op->actor );
      ulong used = fd_h2_rbuf_used_sz( ep->rbuf_tx );
      ulong skip = fd_ulong_min( used, (ulong)op->arg1 );
      ulong free = fd_h2_rbuf_free_sz( ep->rbuf_tx ) + skip;
      ulong fill = fd_ulong_min( free, (ulong)op->arg0 );
      FD_LOG_NOTICE(( "[%03lu] %s op=%s skip=%lu fill=%lu raw=0x%08x tx_used_before=%lu",
                      step, fuzz_actor_name( op->actor ), fuzz_op_kind_name( op->kind ),
                      skip, fill, op->raw, used ));
      break;
    }

    case FUZZ_OP_VALIDATE:
      FD_LOG_NOTICE(( "[%03lu] op=%s", step, fuzz_op_kind_name( op->kind ) ));
      break;

    default:
      FD_LOG_NOTICE(( "[%03lu] op=%s raw_kind=%u", step, fuzz_op_kind_name( op->kind ), (uint)op->kind ));
      break;
  }
}

static void
fuzz_execute_op( ulong             step,
                 fuzz_op_t const * op ) {
  fuzz_endpoint_t * ep = fuzz_ep_from_actor( op->actor );
  g_replay_step = step;
  fuzz_trace_op( step, op );

  switch( op->kind ) {
    case FUZZ_OP_SERVICE: {
      ulong rounds    = 1UL + ((ulong)op->arg0 & 3UL);
      ulong c2s_limit = 1UL + ((ulong)(  op->raw        & 0x3fU ));
      ulong s2c_limit = 1UL + ((ulong)( (op->raw >> 8 ) & 0x3fU ));
      fuzz_service_pair( rounds, c2s_limit, s2c_limit );
      break;
    }

    case FUZZ_OP_OPEN_LOCAL: {
      int queue_headers = !!( op->arg0 & 1u );
      int end_stream    = !!( op->arg0 & 2u );
      ulong cnt = 1UL + ((ulong)op->arg1 & 1UL);
      for( ulong j=0UL; j<cnt; j++ ) {
        fuzz_open_local_stream( ep, queue_headers, end_stream );
      }
      break;
    }

    case FUZZ_OP_SEND_WINDOW_UPDATE:
      fuzz_send_window_update( ep, op->arg0, op->arg1, op->raw );
      break;

    case FUZZ_OP_SET_STREAM_TX_WND:
      fuzz_set_stream_tx_wnd( ep, op->arg0, op->arg1, op->raw );
      break;

    case FUZZ_OP_JAM_TX:
      fuzz_jam_tx( ep, op->arg0, op->arg1, op->raw );
      break;

    case FUZZ_OP_VALIDATE:
      fuzz_validate_all();
      break;

    default:
      __builtin_unreachable();
      break;
  }

  fuzz_trace_all_summaries();
}

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 ); /* crash on warning log */
  char const * replay_env = getenv( "FD_H2_FUZZ_REPLAY" );
  g_replay_trace = replay_env && replay_env[0] && replay_env[0]!='0';
  char const * replay_state_env = getenv( "FD_H2_FUZZ_REPLAY_STATE" );
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

  fuzz_endpoint_reset( g_client, 1 );
  fuzz_endpoint_reset( g_server, 0 );

  fuzz_decode_program( &cur, prog );

  if( FD_UNLIKELY( g_replay_trace ) ) {
    FD_LOG_NOTICE(( "replay input_sz=%lu op_cnt=%lu",
                    size, prog->op_cnt ));
  }

  for( ulong i=0UL; i<prog->op_cnt; i++ ) {
    fuzz_execute_op( i, &prog->ops[ i ] );
  }

  fuzz_validate_all();
  if( FD_UNLIKELY( g_replay_state ) ) {
    if( FD_UNLIKELY( !prog->op_cnt || prog->ops[ prog->op_cnt - 1UL ].kind != FUZZ_OP_VALIDATE ) ) {
      fuzz_trace_all_summaries();
    }
  }
  return 0;
}
