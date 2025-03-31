#include "fd_h2_conn.h"
#include "fd_h2_base.h"
#include "fd_h2_callback.h"
#include "fd_h2_proto.h"
#include "../../util/log/fd_log.h"
#include "fd_h2_rbuf.h"
#include <float.h>

char const fd_h2_client_preface[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static fd_h2_settings_t const fd_h2_settings_initial = {
  .max_concurrent_streams = UINT_MAX,
  .initial_window_size    = 65535U,
  .max_frame_size         = 16384U,
  .max_header_list_size   = UINT_MAX
};

fd_h2_conn_t *
fd_h2_conn_init_client( fd_h2_conn_t * conn ) {
  *conn = (fd_h2_conn_t) {
    .self_settings = fd_h2_settings_initial,
    .peer_settings = fd_h2_settings_initial,
    .flags         = FD_H2_CONN_FLAGS_CLIENT_INITIAL
  };
  return conn;
}

fd_h2_conn_t *
fd_h2_conn_init_server( fd_h2_conn_t * conn ) {
  *conn = (fd_h2_conn_t) {
    .self_settings = fd_h2_settings_initial,
    .peer_settings = fd_h2_settings_initial,
    .flags         = FD_H2_CONN_FLAGS_SERVER_INITIAL
  };
  return conn;
}

static inline void
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
    .typlen    = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 36UL ),
    .flags     = 0,
    .stream_id = 0
  };
  fd_memcpy( buf, &hdr, 9UL );

  fd_h2_setting_encode( buf+9,  FD_H2_SETTINGS_HEADER_TABLE_SIZE,      0U                               );
  fd_h2_setting_encode( buf+15, FD_H2_SETTINGS_ENABLE_PUSH,            0U                               );
  fd_h2_setting_encode( buf+21, FD_H2_SETTINGS_MAX_CONCURRENT_STREAMS, settings->max_concurrent_streams );
  fd_h2_setting_encode( buf+27, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE,    settings->initial_window_size    );
  fd_h2_setting_encode( buf+33, FD_H2_SETTINGS_MAX_FRAME_SIZE,         settings->max_frame_size         );
  fd_h2_setting_encode( buf+39, FD_H2_SETTINGS_MAX_HEADER_LIST_SIZE,   settings->max_header_list_size   );
}

/* fd_h2_rx1 handles one frame. */

static void
fd_h2_rx_data( fd_h2_conn_t *            conn,
               fd_h2_rbuf_t *            rbuf_rx,
               fd_h2_callbacks_t const * cb ) {
  ulong frame_rem  = conn->rx_frame_rem;
  ulong rbuf_avail = fd_h2_rbuf_used_sz( rbuf_rx );
  uint  stream_id  = conn->rx_stream_id;
  uint  chunk_sz   = (uint)fd_ulong_min( frame_rem, rbuf_avail );
  uint  fin_flag   = conn->rx_frame_flags & FD_H2_FLAG_END_STREAM;
  if( rbuf_avail<frame_rem ) fin_flag = 0;

  ulong sz0, sz1;
  uchar const * peek = fd_h2_rbuf_peek_frag( rbuf_rx, &sz0, &sz1 );
  if( FD_LIKELY( !sz1 ) ) {
    cb->data( conn, stream_id, peek, sz0, fin_flag );
  } else {
    cb->data( conn, stream_id, peek,          sz0, 0        );
    cb->data( conn, stream_id, rbuf_rx->buf0, sz1, fin_flag );
  }

  conn->rx_frame_rem -= chunk_sz;
}

static int
fd_h2_rx_headers( fd_h2_conn_t *            conn,
                  uchar *                   payload,
                  ulong                     payload_sz,
                  fd_h2_callbacks_t const * cb,
                  uint                      frame_flags,
                  uint                      stream_id ) {

  if( FD_UNLIKELY( !stream_id ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;
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

  cb->headers( conn, stream_id, payload, payload_sz, frame_flags );

  return 1;
}

static int
fd_h2_rx_continuation( fd_h2_conn_t *            conn,
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

  cb->headers( conn, stream_id, payload, payload_sz, frame_flags );

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
  uint error_code = fd_uint_bswap( FD_LOAD( uint, payload ) );
  cb->rst_stream( conn, stream_id, error_code );
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
    uint value = fd_uint_bswap( setting.value );

    switch( fd_ushort_bswap( setting.id ) ) {
    case FD_H2_SETTINGS_INITIAL_WINDOW_SIZE:
      conn->peer_settings.initial_window_size = value;
      /* FIXME update window accordingly */
      break;
    case FD_H2_SETTINGS_MAX_FRAME_SIZE:
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
fd_h2_rx_ping( fd_h2_conn_t * conn,
               fd_h2_rbuf_t * rbuf_tx,
               uchar const *  payload,
               ulong          payload_sz,
               uint           frame_flags,
               uint           stream_id ) {
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
    /* fd_h2 is unable to generate PING frames, so this is always a
       protocol error. */
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return 0;

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
  cb->conn_final( conn, error_code );

  return 1;
}

static int
fd_h2_rx_window_update( fd_h2_conn_t *            conn,
                        fd_h2_callbacks_t const * cb,
                        uchar const *             payload,
                        ulong                     payload_sz,
                        uint                      stream_id ) {
  if( FD_UNLIKELY( payload_sz!=4UL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FRAME_SIZE );
    return 0;
  }
  int increment = FD_LOAD( int, payload ) & 0x7fffffff;

  if( !stream_id ) {

    /* Connection-level window update */
    int tx_wnd = conn->tx_wnd;
    if( FD_UNLIKELY( !increment ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return 0;
    }
    int tx_wnd_new;
    if( FD_UNLIKELY( __builtin_sadd_overflow( tx_wnd, increment, &tx_wnd_new ) ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
      return 0;
    }
    cb->window_update( conn, (uint)increment );
    conn->tx_wnd = tx_wnd_new;

  } else {

    /* Stream-level window update */
    cb->stream_window_update( conn, stream_id, (uint)increment );

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
    return fd_h2_rx_headers( conn, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_CONTINUATION:
    return fd_h2_rx_continuation( conn, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_RST_STREAM:
    return fd_h2_rx_rst_stream( conn, payload, payload_sz, cb, stream_id );
  case FD_H2_FRAME_TYPE_SETTINGS:
    return fd_h2_rx_settings( conn, rbuf_tx, payload, payload_sz, cb, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_PING:
    return fd_h2_rx_ping( conn, rbuf_tx, payload, payload_sz, frame_flags, stream_id );
  case FD_H2_FRAME_TYPE_GOAWAY:
    return fd_h2_rx_goaway( conn, cb, payload, payload_sz, stream_id );
  case FD_H2_FRAME_TYPE_WINDOW_UPDATE:
    return fd_h2_rx_window_update( conn, cb, payload, payload_sz, stream_id );
  default:
    return 1;
  }
}

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
    fd_h2_rx_data( conn, rbuf_rx, cb );
    return;
  }
  if( FD_UNLIKELY( conn->rx_pad_rem ) ) {
    ulong pad_rem    = conn->rx_pad_rem;
    ulong rbuf_avail = fd_h2_rbuf_used_sz( rbuf_rx );
    uint  chunk_sz   = (uint)fd_ulong_min( pad_rem, rbuf_avail );
    fd_h2_rbuf_skip( rbuf_rx, chunk_sz );
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

  /* Peek padding */
  uint pad_sz = 0U;
  uint rem_sz = frame_sz;
  if( ( frame_type==FD_H2_FRAME_TYPE_DATA    ||
        frame_type==FD_H2_FRAME_TYPE_HEADERS ||
        frame_type==FD_H2_FRAME_TYPE_PUSH_PROMISE ) &&
      !!( hdr.flags & FD_H2_FLAG_PADDED ) ) {
    if( FD_UNLIKELY( fd_h2_rbuf_used_sz( &rx_peek )<1UL ) ) return;
    pad_sz = rx_peek.lo[0];
    if( FD_UNLIKELY( pad_sz>=frame_sz ) ) {
      fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
      return;
    }
    rem_sz--;
  }

  /* Special case: Process data incrementally */
  if( frame_type==FD_H2_FRAME_TYPE_DATA ) {
    conn->rx_frame_rem   = rem_sz;
    conn->rx_frame_flags = hdr.flags;
    conn->rx_stream_id   = fd_uint_bswap( hdr.stream_id );
    conn->rx_pad_rem     = (uchar)pad_sz;
    *rbuf_rx = rx_peek;
    fd_h2_rx_data( conn, rbuf_rx, cb );
    return;
  }

  /* Consume all or nothing */
  ulong const tot_sz = sizeof(fd_h2_frame_hdr_t) + frame_sz;
  if( FD_UNLIKELY( tot_sz>fd_h2_rbuf_used_sz( rbuf_rx ) ) ) {
    conn->rx_suppress = rbuf_rx->lo_off + tot_sz;
    return;
  }

  /* FIXME generate conn errors instead */
  uint payload_sz = rem_sz-pad_sz;
  FD_TEST( payload_sz <= scratch_sz );
  FD_TEST( payload_sz <= conn->self_settings.max_frame_size );

  *rbuf_rx = rx_peek;
  uchar * frame = fd_h2_rbuf_pop( rbuf_rx, scratch, payload_sz );
  int ok =
    fd_h2_rx_frame( conn, rbuf_tx, frame, payload_sz, cb,
                    frame_type,
                    hdr.flags,
                    fd_uint_bswap( hdr.stream_id ) );
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
  }
}

void
fd_h2_tx_control( fd_h2_conn_t * conn,
                  fd_h2_rbuf_t * rbuf_tx ) {

  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<96 ) ) return;

  switch( fd_uint_find_lsb( conn->flags | 0x100 ) ) {

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

  case FD_H2_CONN_FLAGS_LG_SEND_GOAWAY: {
    fd_h2_goaway_t goaway = {
      .hdr = {
        .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 24UL )
      },
      .last_stream_id = 0, /* FIXME */
      .error_code     = fd_uint_bswap( (uint)conn->conn_error )
    };
    conn->flags = FD_H2_CONN_FLAGS_DEAD;
    fd_h2_rbuf_push( rbuf_tx, &goaway, sizeof(fd_h2_goaway_t) );
    break;
  }

  default:
    break;

  }

}
