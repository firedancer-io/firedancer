#include "fd_h2_conn.h"
#include "fd_h2_callback.h"
#include "fd_h2_proto.h"
#include "fd_h2_rbuf.h"
#include "fd_h2_stream.h"
#include <float.h>

#if FD_USING_GCC && __GNUC__ >= 15
#pragma GCC diagnostic ignored "-Wunterminated-string-initialization"
#endif

char const fd_h2_client_preface[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static fd_h2_settings_t const fd_h2_settings_initial = {
  .max_concurrent_streams = UINT_MAX,
  .initial_window_size    = 65535U,
  .max_frame_size         = 16384U,
  .max_header_list_size   = UINT_MAX
};

static void
fd_h2_conn_init_window( fd_h2_conn_t * conn ) {
  conn->rx_wnd_max   = 65535U;
  conn->rx_wnd       = conn->rx_wnd_max;
  conn->rx_wnd_wmark = (uint)( 0.7f * (float)conn->rx_wnd_max );
  conn->tx_wnd       = 65535U;
}

fd_h2_conn_t *
fd_h2_conn_init_client( fd_h2_conn_t * conn ) {
  *conn = (fd_h2_conn_t) {
    .self_settings  = fd_h2_settings_initial,
    .peer_settings  = fd_h2_settings_initial,
    .flags          = FD_H2_CONN_FLAGS_CLIENT_INITIAL,
    .tx_stream_next = 1U,
    .rx_stream_next = 2U
  };
  fd_h2_conn_init_window( conn );
  return conn;
}

fd_h2_conn_t *
fd_h2_conn_init_server( fd_h2_conn_t * conn ) {
  *conn = (fd_h2_conn_t) {
    .self_settings  = fd_h2_settings_initial,
    .peer_settings  = fd_h2_settings_initial,
    .flags          = FD_H2_CONN_FLAGS_SERVER_INITIAL,
    .tx_stream_next = 2U,
    .rx_stream_next = 1U
  };
  fd_h2_conn_init_window( conn );
  return conn;
}

static void
fd_h2_setting_encode( uchar * buf,
                      ushort  setting_id,
                      uint    setting_value ) {
  FD_STORE( ushort, buf,   fd_ushort_bswap( setting_id    ) );
  FD_STORE( uint,   buf+2, fd_uint_bswap  ( setting_value ) );
}

#define FD_H2_OUR_SETTINGS_ENCODED_SZ 45

static void
fd_h2_gen_settings( fd_h2_settings_t const * settings,
                    uchar                    buf[ FD_H2_OUR_SETTINGS_ENCODED_SZ ] ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 36UL ),
  };
  fd_memcpy( buf, &hdr, 9UL );

  fd_h2_setting_encode( buf+9,  FD_H2_SETTINGS_HEADER_TABLE_SIZE,      0U                               );
  fd_h2_setting_encode( buf+15, FD_H2_SETTINGS_ENABLE_PUSH,            0U                               );
  fd_h2_setting_encode( buf+21, FD_H2_SETTINGS_MAX_CONCURRENT_STREAMS, settings->max_concurrent_streams );
  fd_h2_setting_encode( buf+27, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE,    settings->initial_window_size    );
  fd_h2_setting_encode( buf+33, FD_H2_SETTINGS_MAX_FRAME_SIZE,         settings->max_frame_size         );
  fd_h2_setting_encode( buf+39, FD_H2_SETTINGS_MAX_HEADER_LIST_SIZE,   settings->max_header_list_size   );
}

/* fd_h2_rx_data handles a partial DATA frame. */

static void
fd_h2_rx_data( fd_h2_conn_t *            conn,
               fd_h2_rbuf_t *            rbuf_rx,
               fd_h2_rbuf_t *            rbuf_tx,
               fd_h2_callbacks_t const * cb ) {
  /* A receive might generate two WINDOW_UPDATE frames */
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < 2*sizeof(fd_h2_window_update_t) ) ) return;

  ulong frame_rem  = conn->rx_frame_rem;
  ulong rbuf_avail = fd_h2_rbuf_used_sz( rbuf_rx );
  uint  stream_id  = conn->rx_stream_id;
  uint  chunk_sz   = (uint)fd_ulong_min( frame_rem, rbuf_avail );
  uint  fin_flag   = conn->rx_frame_flags & FD_H2_FLAG_END_STREAM;
  if( rbuf_avail<frame_rem ) fin_flag = 0;

  fd_h2_stream_t * stream = cb->stream_query( conn, stream_id );
  if( FD_UNLIKELY( !stream ||
                   ( stream->state!=FD_H2_STREAM_STATE_OPEN        &&
                     stream->state!=FD_H2_STREAM_STATE_CLOSING_TX ) ) ) {
    fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_STREAM_CLOSED );
    goto skip_frame;
  }

  if( FD_UNLIKELY( chunk_sz > conn->rx_wnd ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
    return;
  }
  conn->rx_wnd -= chunk_sz;

  if( FD_UNLIKELY( chunk_sz > stream->rx_wnd ) ) {
    fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_FLOW_CONTROL );
    goto skip_frame;
  }
  stream->rx_wnd -= chunk_sz;

  fd_h2_stream_rx_data( stream, conn, fin_flag ? FD_H2_FLAG_END_STREAM : 0U );
  if( FD_UNLIKELY( stream->state==FD_H2_STREAM_STATE_ILLEGAL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return;
  }

  ulong sz0, sz1;
  uchar const * peek = fd_h2_rbuf_peek_used( rbuf_rx, &sz0, &sz1 );
  if( sz0>=chunk_sz ) {
    sz0 = chunk_sz;
    sz1 = 0;
  } else if( sz0+sz1>chunk_sz ) {
    sz1 = chunk_sz-sz0;
  }
  if( FD_LIKELY( !sz1 ) ) {
    cb->data( conn, stream, peek, sz0, fin_flag );
  } else {
    cb->data( conn, stream, peek,          sz0, 0        );
    cb->data( conn, stream, rbuf_rx->buf0, sz1, fin_flag );
  }

skip_frame:
  conn->rx_frame_rem -= chunk_sz;
  fd_h2_rbuf_skip( rbuf_rx, chunk_sz );
  if( FD_UNLIKELY( conn->rx_wnd < conn->rx_wnd_wmark ) ) {
    conn->flags |= FD_H2_CONN_FLAGS_WINDOW_UPDATE;
  }
}

static int
fd_h2_rx_headers( fd_h2_conn_t *            conn,
                  fd_h2_rbuf_t *            rbuf_tx,
                  uchar *                   payload,
                  ulong                     payload_sz,
                  fd_h2_callbacks_t const * cb,
                  uint                      frame_flags,
                  uint                      stream_id ) {

  if( FD_UNLIKELY( !stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }

  fd_h2_stream_t * stream = cb->stream_query( conn, stream_id );
  if( !stream ) {
    if( FD_UNLIKELY( (  stream_id    <   conn->rx_stream_next    ) |
                     ( (stream_id&1) != (conn->rx_stream_next&1) ) ) ) {
      /* FIXME should send RST_STREAM instead if the user deallocated
         stream state but we receive a HEADERS frame for a stream that
         we started ourselves. */
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return 0;
    }
    if( FD_UNLIKELY( conn->stream_active_cnt[0] >= conn->self_settings.max_concurrent_streams ) ) {
      fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_REFUSED_STREAM );
      return 1;
    }
    stream = cb->stream_create( conn, stream_id );
    if( FD_UNLIKELY( !stream ) ) {
      fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_REFUSED_STREAM );
      return 1;
    }
    fd_h2_stream_open( stream, conn, stream_id );
    stream->tx_wnd = conn->peer_settings.initial_window_size;
    conn->rx_stream_next = stream_id+2;
  }

  conn->rx_stream_id = stream_id;

  if( FD_UNLIKELY( frame_flags & FD_H2_FLAG_PRIORITY ) ) {
    if( FD_UNLIKELY( payload_sz<5UL ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
      return 0;
    }
    payload    += 5UL;
    payload_sz -= 5UL;
  }

  if( FD_UNLIKELY( !( frame_flags & FD_H2_FLAG_END_HEADERS ) ) ) {
    conn->flags |= FD_H2_CONN_FLAGS_CONTINUATION;
  }

  fd_h2_stream_rx_headers( stream, conn, frame_flags );
  if( FD_UNLIKELY( stream->state==FD_H2_STREAM_STATE_ILLEGAL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }

  cb->headers( conn, stream, payload, payload_sz, frame_flags );

  return 1;
}

static int
fd_h2_rx_priority( fd_h2_conn_t * conn,
                   ulong          payload_sz,
                   uint           stream_id ) {
  if( FD_UNLIKELY( payload_sz!=5UL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }
  if( FD_UNLIKELY( !stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }
  return 1;
}

static int
fd_h2_rx_continuation( fd_h2_conn_t *            conn,
                       fd_h2_rbuf_t *            rbuf_tx,
                       uchar *                   payload,
                       ulong                     payload_sz,
                       fd_h2_callbacks_t const * cb,
                       uint                      frame_flags,
                       uint                      stream_id ) {

  if( FD_UNLIKELY( ( conn->rx_stream_id!=stream_id                    ) |
                   ( !( conn->flags & FD_H2_CONN_FLAGS_CONTINUATION ) ) |
                   ( !stream_id                                       ) ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }

  if( FD_UNLIKELY( frame_flags & FD_H2_FLAG_END_HEADERS ) ) {
    conn->flags &= (uchar)~FD_H2_CONN_FLAGS_CONTINUATION;
  }

  fd_h2_stream_t * stream = cb->stream_query( conn, stream_id );
  if( FD_UNLIKELY( !stream ) ) {
    fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_INTERNAL );
    return 1;
  }

  fd_h2_stream_rx_headers( stream, conn, frame_flags );
  if( FD_UNLIKELY( stream->state==FD_H2_STREAM_STATE_ILLEGAL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }

  cb->headers( conn, stream, payload, payload_sz, frame_flags );

  return 1;
}

static int
fd_h2_rx_rst_stream( fd_h2_conn_t *            conn,
                     uchar const *             payload,
                     ulong                     payload_sz,
                     fd_h2_callbacks_t const * cb,
                     uint                      stream_id ) {
  if( FD_UNLIKELY( payload_sz!=4UL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }
  if( FD_UNLIKELY( !stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }
  if( FD_UNLIKELY( stream_id >= fd_ulong_max( conn->rx_stream_next, conn->tx_stream_next ) ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }
  fd_h2_stream_t * stream = cb->stream_query( conn, stream_id );
  if( FD_LIKELY( stream ) ) {
    uint error_code = fd_uint_bswap( FD_LOAD( uint, payload ) );
    fd_h2_stream_reset( stream, conn );
    cb->rst_stream( conn, stream, error_code, 1 );
    /* stream points to freed memory at this point */
  }
  return 1;
}

static int
fd_h2_rx_settings( fd_h2_conn_t *            conn,
                   fd_h2_rbuf_t *            rbuf_tx,
                   uchar const *             payload,
                   ulong                     payload_sz,
                   fd_h2_callbacks_t const * cb,
                   uint                      frame_flags,
                   uint                      stream_id ) {

  if( FD_UNLIKELY( stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }

  if( FD_UNLIKELY( conn->flags & FD_H2_CONN_FLAGS_SERVER_INITIAL ) ) {
    /* As a server, the first frame we should send is SETTINGS, not
       SETTINGS ACK as generated here */
    return 0;
  }

  if( frame_flags & FD_H2_FLAG_ACK ) {
    if( FD_UNLIKELY( payload_sz ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
      return 0;
    }
    if( FD_UNLIKELY( !conn->setting_tx ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return 0;
    }
    if( conn->flags & FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0 ) {
      conn->flags &= (uchar)~FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0;
      if( !( conn->flags & FD_H2_CONN_FLAGS_HANDSHAKING ) ) {
        cb->conn_established( conn );
      }
    }
    conn->setting_tx--;
    return 1;
  }

  if( FD_UNLIKELY( payload_sz % 6 ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }

  for( ulong off=0UL; off<payload_sz; off+=sizeof(fd_h2_setting_t) ) {
    fd_h2_setting_t setting = FD_LOAD( fd_h2_setting_t, payload+off );
    ushort id    = fd_ushort_bswap( setting.id );
    uint   value = fd_uint_bswap( setting.value );

    switch( id ) {
    case FD_H2_SETTINGS_ENABLE_PUSH:
      if( FD_UNLIKELY( value>1 ) ) {
        fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
        return 0;
      }
      break;
    case FD_H2_SETTINGS_INITIAL_WINDOW_SIZE:
      if( FD_UNLIKELY( value>0x7fffffff ) ) {
        fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
        return 0;
      }
      conn->peer_settings.initial_window_size = value;
      /* FIXME update window accordingly */
      break;
    case FD_H2_SETTINGS_MAX_FRAME_SIZE:
      if( FD_UNLIKELY( value<0x4000 || value>0xffffff ) ) {
        fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
        return 0;
      }
      conn->peer_settings.max_frame_size = value;
      /* FIXME validate min */
      break;
    case FD_H2_SETTINGS_MAX_HEADER_LIST_SIZE:
      conn->peer_settings.max_header_list_size = value;
      break;
    case FD_H2_SETTINGS_MAX_CONCURRENT_STREAMS:
      conn->peer_settings.max_concurrent_streams = value;
      break;
    }
  }

  fd_h2_frame_hdr_t hdr = {
    .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 0UL ),
    .flags  = FD_H2_FLAG_ACK
  };
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<sizeof(fd_h2_frame_hdr_t) ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_INTERNAL );
    return 0;
  }
  fd_h2_rbuf_push( rbuf_tx, &hdr, sizeof(fd_h2_frame_hdr_t) );

  if( conn->flags & FD_H2_CONN_FLAGS_WAIT_SETTINGS_0 ) {
    conn->flags &= (uchar)~FD_H2_CONN_FLAGS_WAIT_SETTINGS_0;
    if( !( conn->flags & FD_H2_CONN_FLAGS_HANDSHAKING ) ) {
      cb->conn_established( conn );
    }
  }

  return 1;
}

static int
fd_h2_rx_push_promise( fd_h2_conn_t * conn ) {
  fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
  return 0;
}

static int
fd_h2_rx_ping( fd_h2_conn_t *            conn,
               fd_h2_rbuf_t *            rbuf_tx,
               uchar const *             payload,
               ulong                     payload_sz,
               fd_h2_callbacks_t const * cb,
               uint                      frame_flags,
               uint                      stream_id ) {
  if( FD_UNLIKELY( payload_sz!=8UL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }
  if( FD_UNLIKELY( stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }

  if( FD_UNLIKELY( frame_flags & FD_H2_FLAG_ACK ) ) {

    /* Received an acknowledgement for a PING frame. */
    if( FD_UNLIKELY( conn->ping_tx==0 ) ) {
      /* Unsolicited PING ACK ... Blindly ignore, since RFC 9113
         technically doesn't forbid those. */
      return 1;
    }
    cb->ping_ack( conn );
    conn->ping_tx = (uchar)( conn->ping_tx-1 );

  } else {

    /* Received a new PING frame.  Generate a PONG. */
    /* FIMXE rate limit */
    fd_h2_ping_t pong = {
      .hdr = {
        .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
        .flags  = FD_H2_FLAG_ACK,
      },
      .payload = FD_LOAD( ulong, payload )
    };
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<sizeof(fd_h2_ping_t) ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_INTERNAL );
      return 0;
    }
    fd_h2_rbuf_push( rbuf_tx, &pong, sizeof(fd_h2_ping_t) );

  }

  return 1;
}

int
fd_h2_tx_ping( fd_h2_conn_t * conn,
               fd_h2_rbuf_t * rbuf_tx ) {
  ulong ping_tx = conn->ping_tx;
  if( FD_UNLIKELY( ( fd_h2_rbuf_free_sz( rbuf_tx )<sizeof(fd_h2_ping_t) ) |
                   ( ping_tx>=UCHAR_MAX ) ) ) {
    return 0; /* blocked */
  }

  fd_h2_ping_t ping = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
      .flags       = 0U,
      .r_stream_id = 0UL
    },
    .payload = 0UL
  };
  fd_h2_rbuf_push( rbuf_tx, &ping, sizeof(fd_h2_ping_t) );
  conn->ping_tx = (uchar)( ping_tx+1 );
  return 1;
}

static int
fd_h2_rx_goaway( fd_h2_conn_t *            conn,
                 fd_h2_callbacks_t const * cb,
                 uchar const *             payload,
                 ulong                     payload_sz,
                 uint                      stream_id ) {

  if( FD_UNLIKELY( stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
  }
  if( FD_UNLIKELY( payload_sz<8UL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }

  uint error_code = fd_uint_bswap( FD_LOAD( uint, payload+4UL ) );
  conn->flags = FD_H2_CONN_FLAGS_DEAD;
  cb->conn_final( conn, error_code, 1 /* peer */ );

  return 1;
}

static int
fd_h2_rx_window_update( fd_h2_conn_t *            conn,
                        fd_h2_rbuf_t *            rbuf_tx,
                        fd_h2_callbacks_t const * cb,
                        uchar const *             payload,
                        ulong                     payload_sz,
                        uint                      stream_id ) {
  if( FD_UNLIKELY( payload_sz!=4UL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }
  uint increment = fd_uint_bswap( FD_LOAD( uint, payload ) ) & 0x7fffffff;

  if( !stream_id ) {

    /* Connection-level window update */
    uint tx_wnd = conn->tx_wnd;
    if( FD_UNLIKELY( !increment ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return 0;
    }
    uint tx_wnd_new;
    if( FD_UNLIKELY( __builtin_uadd_overflow( tx_wnd, increment, &tx_wnd_new ) ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
      return 0;
    }
    conn->tx_wnd = tx_wnd_new;
    cb->window_update( conn, (uint)increment );

  } else {

    if( FD_UNLIKELY( stream_id >= fd_ulong_max( conn->rx_stream_next, conn->tx_stream_next ) ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return 0;
    }

    if( FD_UNLIKELY( !increment ) ) {
      fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_PROTOCOL );
      return 1;
    }

    fd_h2_stream_t * stream = cb->stream_query( conn, stream_id );
    if( FD_UNLIKELY( !stream ) ) {
      fd_h2_tx_rst_stream( rbuf_tx, stream_id, FD_H2_ERR_STREAM_CLOSED );
      return 1;
    }

    /* Stream-level window update */
    uint tx_wnd_new;
    if( FD_UNLIKELY( __builtin_uadd_overflow( stream->tx_wnd, increment, &tx_wnd_new ) ) ) {
      fd_h2_stream_error( stream, rbuf_tx, FD_H2_ERR_FLOW_CONTROL );
      cb->rst_stream( conn, stream, FD_H2_ERR_FLOW_CONTROL, 0 );
      /* stream points to freed memory at this point */
      return 1;
    }
    stream->tx_wnd = tx_wnd_new;
    cb->stream_window_update( conn, stream, (uint)increment );

  }

  return 1;
}

/* fd_h2_rx_frame handles a complete frame.  Returns 1 on success, and
   0 on connection error. */

static int
fd_h2_rx_frame( fd_h2_conn_t *            conn,
                fd_h2_rbuf_t *            rbuf_tx,
                uchar *                   payload,
                ulong                     payload_sz,
                fd_h2_callbacks_t const * cb,
                uint                      frame_type,
                uint                      frame_flags,
                uint                      stream_id ) {
  switch( frame_type ) {
  case FD_H2_FRAME_TYPE_HEADERS:
    return fd_h2_rx_headers( conn, rbuf_tx, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_PRIORITY:
    return fd_h2_rx_priority( conn, payload_sz, stream_id );
  case FD_H2_FRAME_TYPE_RST_STREAM:
    return fd_h2_rx_rst_stream( conn, payload, payload_sz, cb, stream_id );
  case FD_H2_FRAME_TYPE_SETTINGS:
    return fd_h2_rx_settings( conn, rbuf_tx, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_PUSH_PROMISE:
    return fd_h2_rx_push_promise( conn );
  case FD_H2_FRAME_TYPE_CONTINUATION:
    return fd_h2_rx_continuation( conn, rbuf_tx, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_PING:
    return fd_h2_rx_ping( conn, rbuf_tx, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_GOAWAY:
    return fd_h2_rx_goaway( conn, cb, payload, payload_sz, stream_id );
  case FD_H2_FRAME_TYPE_WINDOW_UPDATE:
    return fd_h2_rx_window_update( conn, rbuf_tx, cb, payload, payload_sz, stream_id );
  default:
    return 1;
  }
}

/* fd_h2_rx1 handles one frame. */

static void
fd_h2_rx1( fd_h2_conn_t *            conn,
           fd_h2_rbuf_t *            rbuf_rx,
           fd_h2_rbuf_t *            rbuf_tx,
           uchar *                   scratch,
           ulong                     scratch_sz,
           fd_h2_callbacks_t const * cb ) {
  /* All frames except DATA are fully buffered, thus assume that current
     frame is a DATA frame if rx_frame_rem != 0. */
  if( conn->rx_frame_rem ) {
    fd_h2_rx_data( conn, rbuf_rx, rbuf_tx, cb );
    return;
  }
  if( FD_UNLIKELY( conn->rx_pad_rem ) ) {
    ulong pad_rem    = conn->rx_pad_rem;
    ulong rbuf_avail = fd_h2_rbuf_used_sz( rbuf_rx );
    uint  chunk_sz   = (uint)fd_ulong_min( pad_rem, rbuf_avail );
    fd_h2_rbuf_skip( rbuf_rx, chunk_sz );
    conn->rx_pad_rem = (uchar)( conn->rx_pad_rem - chunk_sz );
    return;
  }

  /* A new frame starts.  Peek the header. */
  if( FD_UNLIKELY( fd_h2_rbuf_used_sz( rbuf_rx )<sizeof(fd_h2_frame_hdr_t) ) ) {
    conn->rx_suppress = rbuf_rx->lo_off + sizeof(fd_h2_frame_hdr_t);
    return;
  }
  fd_h2_rbuf_t rx_peek = *rbuf_rx;
  fd_h2_frame_hdr_t hdr;
  fd_h2_rbuf_pop_copy( &rx_peek, &hdr, sizeof(fd_h2_frame_hdr_t) );
  uint const frame_type = fd_h2_frame_type  ( hdr.typlen );
  uint const frame_sz   = fd_h2_frame_length( hdr.typlen );

  if( FD_UNLIKELY( frame_sz > conn->self_settings.max_frame_size ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return;
  }
  if( FD_UNLIKELY( (!!( conn->flags & FD_H2_CONN_FLAGS_CONTINUATION ) ) &
                   (    frame_type!=FD_H2_FRAME_TYPE_CONTINUATION     ) ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return;
  }

  /* Peek padding */
  uint pad_sz = 0U;
  uint rem_sz = frame_sz;
  if( ( frame_type==FD_H2_FRAME_TYPE_DATA    ||
        frame_type==FD_H2_FRAME_TYPE_HEADERS ||
        frame_type==FD_H2_FRAME_TYPE_PUSH_PROMISE ) &&
      !!( hdr.flags & FD_H2_FLAG_PADDED ) ) {
    if( FD_UNLIKELY( fd_h2_rbuf_used_sz( &rx_peek )<1UL ) ) return;
    pad_sz = rx_peek.lo[0];
    rem_sz--;
    if( FD_UNLIKELY( pad_sz>=rem_sz ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return;
    }
    fd_h2_rbuf_skip( &rx_peek, 1UL );
  }

  /* Special case: Process data incrementally */
  if( frame_type==FD_H2_FRAME_TYPE_DATA ) {
    conn->rx_frame_rem   = rem_sz;
    conn->rx_frame_flags = hdr.flags;
    conn->rx_stream_id   = fd_h2_frame_stream_id( hdr.r_stream_id );
    conn->rx_pad_rem     = (uchar)pad_sz;
    *rbuf_rx = rx_peek;
    if( FD_UNLIKELY( !conn->rx_stream_id ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return;
    }
    fd_h2_rx_data( conn, rbuf_rx, rbuf_tx, cb );
    return;
  }

  /* Consume all or nothing */
  ulong const tot_sz = sizeof(fd_h2_frame_hdr_t) + frame_sz;
  if( FD_UNLIKELY( tot_sz>fd_h2_rbuf_used_sz( rbuf_rx ) ) ) {
    conn->rx_suppress = rbuf_rx->lo_off + tot_sz;
    return;
  }

  uint payload_sz = rem_sz-pad_sz;
  if( FD_UNLIKELY( scratch_sz < payload_sz ) ) {
    if( FD_UNLIKELY( scratch_sz < conn->self_settings.max_frame_size ) ) {
      FD_LOG_WARNING(( "scratch buffer too small: scratch_sz=%lu max_frame_size=%u)",
                       scratch_sz, conn->self_settings.max_frame_size ));
      fd_h2_conn_error( conn, FD_H2_ERR_INTERNAL );
      return;
    }
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return;
  }

  *rbuf_rx = rx_peek;
  uchar * frame = fd_h2_rbuf_pop( rbuf_rx, scratch, payload_sz );
  int ok =
    fd_h2_rx_frame( conn, rbuf_tx, frame, payload_sz, cb,
                    frame_type,
                    hdr.flags,
                    fd_h2_frame_stream_id( hdr.r_stream_id ) );
  (void)ok; /* FIXME */
  fd_h2_rbuf_skip( rbuf_rx, pad_sz );
}

void
fd_h2_rx( fd_h2_conn_t *            conn,
          fd_h2_rbuf_t *            rbuf_rx,
          fd_h2_rbuf_t *            rbuf_tx,
          uchar *                   scratch,
          ulong                     scratch_sz,
          fd_h2_callbacks_t const * cb ) {
  /* Pre-receive TX work */

  /* Stop handling frames on conn error. */
  if( FD_UNLIKELY( conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) return;

  /* All other logic below can only proceed if new data arrived. */
  if( FD_UNLIKELY( !fd_h2_rbuf_used_sz( rbuf_rx ) ) ) return;

  /* Slowloris defense: Guess how much bytes are required to progress
     ahead of time based on the frame's type and size. */
  if( FD_UNLIKELY( rbuf_rx->hi_off < conn->rx_suppress ) ) return;

  /* Handle frames */
  for(;;) {
    ulong lo0 = rbuf_rx->lo_off;
    fd_h2_rx1( conn, rbuf_rx, rbuf_tx, scratch, scratch_sz, cb );
    ulong lo1 = rbuf_rx->lo_off;

    /* Terminate when no more bytes are available to read */
    if( !fd_h2_rbuf_used_sz( rbuf_rx ) ) break;

    /* Terminate when the frame handler didn't make progress (e.g. due
       to rbuf_tx full, or due to incomplete read from rbuf_tx)*/
    if( FD_UNLIKELY( lo0==lo1 ) ) break;

    /* Terminate if the conn died */
    if( FD_UNLIKELY( conn->flags & (FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_DEAD) ) ) break;
  }
}

void
fd_h2_tx_control( fd_h2_conn_t *            conn,
                  fd_h2_rbuf_t *            rbuf_tx,
                  fd_h2_callbacks_t const * cb ) {

  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<128 ) ) return;

  switch( fd_uint_find_lsb( (uint)conn->flags | 0x10000u ) ) {

  case FD_H2_CONN_FLAGS_LG_CLIENT_INITIAL:
    fd_h2_rbuf_push( rbuf_tx, fd_h2_client_preface, sizeof(fd_h2_client_preface) );
    __attribute__((fallthrough));

  case FD_H2_CONN_FLAGS_LG_SERVER_INITIAL: {
    uchar buf[ FD_H2_OUR_SETTINGS_ENCODED_SZ ];
    fd_h2_gen_settings( &conn->self_settings, buf );
    fd_h2_rbuf_push( rbuf_tx, buf, sizeof(buf) );
    conn->setting_tx++;
    conn->flags = FD_H2_CONN_FLAGS_WAIT_SETTINGS_0 | FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0;
    break;
  }

goaway:
  case FD_H2_CONN_FLAGS_LG_SEND_GOAWAY: {
    fd_h2_goaway_t goaway = {
      .hdr = {
        .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 8UL )
      },
      .last_stream_id = 0, /* FIXME */
      .error_code     = fd_uint_bswap( (uint)conn->conn_error )
    };
    conn->flags = FD_H2_CONN_FLAGS_DEAD;
    fd_h2_rbuf_push( rbuf_tx, &goaway, sizeof(fd_h2_goaway_t) );
    cb->conn_final( conn, conn->conn_error, 0 /* local */ );
    break;
  }

  case FD_H2_CONN_FLAGS_LG_WINDOW_UPDATE: {
    uint increment = conn->rx_wnd_max - conn->rx_wnd;
    if( FD_UNLIKELY( increment>0x7fffffff ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_INTERNAL );
      goto goaway;
    }
    if( FD_UNLIKELY( increment==0 ) ) break;
    fd_h2_window_update_t window_update = {
      .hdr = {
        .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_WINDOW_UPDATE, 4UL )
      },
      .increment = fd_uint_bswap( increment )
    };
    fd_h2_rbuf_push( rbuf_tx, &window_update, sizeof(fd_h2_window_update_t) );
    conn->rx_wnd = conn->rx_wnd_max;
    conn->flags = (ushort)( (conn->flags) & (~FD_H2_CONN_FLAGS_WINDOW_UPDATE) );
    break;
  }

  default:
    break;

  }

}
