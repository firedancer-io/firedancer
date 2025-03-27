#include "fd_h2.h"
#include "fd_h2_base.h"
#include "fd_h2_proto.h"
#include "../../tango/tempo/fd_tempo.h"
#include "../../util/log/fd_log.h"
#include <float.h>

static char const fd_h2_client_preface[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static fd_h2_settings_t const fd_h2_settings_initial = {
  .max_concurrent_streams = UINT_MAX,
  .initial_window_size    = 65535U,
  .max_frame_size         = 16384U,
  .max_header_list_size   = UINT_MAX
};

int
fd_h2_config_validate( fd_h2_config_t const * config ) {
  if( config->ns_per_tick<=FLT_EPSILON || config->ns_per_tick>=FLT_MAX ) {
    FD_LOG_WARNING(( "invalid config: invalid ns_per_tick" ));
    return FD_H2_ERR_INTERNAL;
  }
  if( config->ack_backoff<=0 ) {
    FD_LOG_WARNING(( "invalid config: missing ack_backoff" ));
    return FD_H2_ERR_INTERNAL;
  }
  if( config->settings_timeout<=0 ) {
    FD_LOG_WARNING(( "invalid config: missing settings_timeout" ));
    return FD_H2_ERR_INTERNAL;
  }
  return FD_H2_SUCCESS;
}

#if FD_HAS_DOUBLE

fd_h2_config_t *
fd_h2_config_defaults( fd_h2_config_t * config ) {
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;
  *config = (fd_h2_config_t) {
    .ns_per_tick      = (float)ns_per_tick,
    .ack_backoff      = (long)( 50e6*tick_per_ns ),
    .settings_timeout = (long)(  3e9*tick_per_ns )
  };
  return config;
}

#endif /* FD_HAS_DOUBLE */

fd_h2_conn_t *
fd_h2_conn_init_client( fd_h2_conn_t *         conn,
                        fd_h2_config_t const * config ) {
  *conn = (fd_h2_conn_t) {
    .self_settings     = fd_h2_settings_initial,
    .peer_settings     = fd_h2_settings_initial,
    .settings_timeout  = config->settings_timeout,
    .settings_deadline = LONG_MAX,
    .ack_backoff       = config->ack_backoff,
    .state             = FD_H2_CONN_STATE_CLIENT_INITIAL
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

static void
fd_h2_gen_settings( fd_h2_settings_t const * settings,
                    uchar                    buf[ FD_H2_OUR_SETTINGS_ENCODED_SZ ] ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen    = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 24UL ),
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

static void
fd_h2_gen_goaway( uchar buf[ sizeof(fd_h2_goaway_t) ],
                  uint  err,
                  uint  last_stream_id ) {
  fd_h2_goaway_t goaway = {
    .hdr = {
      .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 24UL )
    },
    .last_stream_id = last_stream_id,
    .error_code     = fd_uint_bswap( err )
  };
  fd_memcpy( buf, &goaway, sizeof(fd_h2_goaway_t) );
}

static void
fd_h2_gen_settings_ack( uchar buf[ sizeof(fd_h2_frame_hdr_t) ] ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 0UL ),
    .flags  = FD_H2_FLAG_ACK
  };
  fd_memcpy( buf, &hdr, 9UL );
}

static void
fd_h2_gen_ping_ack( uchar buf[ sizeof(fd_h2_ping_t) ],
                    ulong ping_token ) {
  fd_h2_ping_t ping = {
    .hdr = {
      .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
      .flags  = FD_H2_FLAG_ACK,
    },
    .payload = ping_token
  };
  fd_memcpy( buf, &ping, sizeof(fd_h2_ping_t) );
}

static int
fd_h2_conn_rx_header( fd_h2_conn_t * conn,
                      fd_h2_rbuf_t * rbuf ) {
  if( fd_h2_rbuf_used_sz( rbuf ) < sizeof(fd_h2_frame_hdr_t) ) return 0;

  fd_h2_frame_hdr_t hdr;
  memcpy( &hdr, fd_h2_rbuf_pop( rbuf, sizeof(fd_h2_frame_hdr_t) ), sizeof(fd_h2_frame_hdr_t) );
  conn->stream_id   = fd_uint_bswap( hdr.stream_id );
  conn->frame_type  = fd_h2_frame_type( hdr.typlen );
  conn->frame_flags = hdr.flags;
  conn->frame_rem   = fd_h2_frame_length( hdr.typlen );

  switch( conn->frame_type ) {
  case FD_H2_FRAME_TYPE_SETTINGS:
    if( conn->frame_flags & FD_H2_FLAG_ACK ) {
      if( FD_UNLIKELY( conn->frame_rem ) ) {
        conn->state = FD_H2_CONN_STATE_UPSET | FD_H2_ERR_FRAME_SIZE;
        return 0;
      }
      if( FD_UNLIKELY( !conn->setting_tx ) ) {
        conn->state = FD_H2_CONN_STATE_UPSET | FD_H2_ERR_PROTOCOL;
        return 0;
      }
      conn->setting_tx--;
    } else {
      if( FD_UNLIKELY( conn->frame_rem % 6 ) ) {
        conn->state = FD_H2_CONN_STATE_UPSET | FD_H2_ERR_FRAME_SIZE;
        return 0;
      }
      conn->setting_rx++;
    }
    break;

  case FD_H2_FRAME_TYPE_PING:
    if( FD_UNLIKELY( conn->frame_rem != 8 ) ) {
      conn->state = FD_H2_CONN_STATE_UPSET | FD_H2_ERR_FRAME_SIZE;
      return 0;
    }
    if( FD_UNLIKELY( conn->stream_id ) ) {
      /* FIXME ignore reserved bit */
      conn->state = FD_H2_CONN_STATE_UPSET | FD_H2_ERR_PROTOCOL;
      return 0;
    }
    if( FD_UNLIKELY( conn->action & FD_H2_CONN_ACTION_PING_ACK ) ) {
      /* Already handling a PING, block */
      return 2;
    }
    conn->action |= FD_H2_CONN_ACTION_PING_ACK | FD_H2_CONN_ACTION_RX_STUFFED;
    conn->ping_token = FD_LOAD( ulong, fd_h2_rbuf_pop( rbuf, 8 ) );
    break;

  case FD_H2_FRAME_TYPE_WINDOW_UPDATE:
    if( FD_UNLIKELY( conn->frame_rem != 4 ) ) {
      conn->state = FD_H2_CONN_STATE_UPSET | FD_H2_ERR_FRAME_SIZE;
      return 0;
    }
    break;

  default:
    break;
  }

  return 1;
}

static int
fd_h2_conn_rx_body( fd_h2_conn_t * conn,
                    fd_h2_rbuf_t * rbuf ) {
  switch( conn->frame_type ) {
  case FD_H2_FRAME_TYPE_WINDOW_UPDATE:
    if( FD_UNLIKELY( fd_h2_rbuf_used_sz( rbuf ) < 4 ) ) return 0;
    uint increment  = FD_LOAD( uint, fd_h2_rbuf_pop( rbuf, 4 ) );
    conn->frame_rem = 0UL;
    conn->tx_wnd    = fd_int_if( !!conn->stream_id, 0, conn->tx_wnd + (int)increment );
    return 1;
  default:
    return 0;
  }
}

static int
fd_h2_conn_rx_next1( fd_h2_conn_t * conn,
                     fd_h2_rbuf_t * rbuf ) {
  int rx_ok = fd_h2_conn_rx_body( conn, rbuf );
  if( !rx_ok ) return 0;
  return fd_h2_conn_rx_header( conn, rbuf );
}

int
fd_h2_conn_rx_next( fd_h2_conn_t * conn,
                    fd_h2_rbuf_t * rbuf ) {
  int rx_ok = fd_h2_conn_rx_next1( conn, rbuf );
  if( FD_UNLIKELY( rx_ok==2 ) ) return 0;
  conn->peek_off = fd_ulong_if( rx_ok, rbuf->lo_off, rbuf->hi_off );
  return rx_ok;
}

ulong
fd_h2_conn_respond( fd_h2_conn_t * conn,
                    uchar          buf[ FD_H2_CONN_RESPOND_BUFSZ ],
                    long           cur_time ) {

  if( FD_LIKELY( (!conn->action) & (conn->state==FD_H2_CONN_STATE_ESTABLISHED) ) ) {
    return 0UL;
  }

  /* FIXME Optimize by combining STATE and ACTION and switching by LSB set. */

  if( conn->state == FD_H2_CONN_STATE_CLIENT_INITIAL ) {
    memcpy( buf, fd_h2_client_preface, sizeof(fd_h2_client_preface) );
    conn->state   = FD_H2_CONN_STATE_WAIT_SETTINGS;
    conn->action &= (uchar)~(FD_H2_CONN_ACTION_SETTINGS );
    conn->settings_deadline = cur_time + conn->settings_timeout;
    fd_h2_gen_settings( &conn->self_settings, buf+sizeof(fd_h2_client_preface) );
    return sizeof(fd_h2_client_preface) + FD_H2_OUR_SETTINGS_ENCODED_SZ;
  }

  if( FD_UNLIKELY( conn->action & FD_H2_CONN_ACTION_SETTINGS ) ) {
    fd_h2_gen_settings( &conn->self_settings, buf );
    conn->setting_tx++;
    conn->action &= (uchar)~FD_H2_CONN_ACTION_SETTINGS;
    if( FD_UNLIKELY( conn->setting_tx > FD_H2_MAX_PENDING_SETTINGS ) ) {
      fd_h2_gen_goaway( buf, FD_H2_ERR_ENHANCE_YOUR_CALM, 0 );
      conn->state = FD_H2_CONN_STATE_DEAD;
      return sizeof(fd_h2_goaway_t);
    }
    return FD_H2_OUR_SETTINGS_ENCODED_SZ;
  }

  if( FD_UNLIKELY( !!( conn->action & FD_H2_CONN_ACTION_SETTINGS_ACK ) &&
                   cur_time >= conn->ack_next ) ) {
    fd_h2_gen_settings_ack( buf );
    conn->setting_rx--;
    conn->action &= (uchar)~fd_uchar_if( conn->setting_rx, 0, FD_H2_CONN_ACTION_SETTINGS_ACK );
    conn->ack_next = cur_time + conn->ack_backoff;
    return sizeof(fd_h2_frame_hdr_t);
  }

  if( FD_UNLIKELY( !!( conn->action & FD_H2_CONN_ACTION_PING_ACK ) &&
                   cur_time >= conn->ack_next ) ) {
    fd_h2_gen_ping_ack( buf, conn->ping_token );
    conn->action &= (uchar)~FD_H2_CONN_ACTION_PING_ACK;
    conn->ack_next = cur_time + conn->ack_backoff;
    return sizeof(fd_h2_ping_t);
  }

  if( FD_UNLIKELY( conn->state == FD_H2_CONN_STATE_WAIT_SETTINGS ) ) {
    if( cur_time > conn->settings_deadline ) {
      fd_h2_gen_goaway( buf, FD_H2_ERR_SETTINGS_TIMEOUT, 0 );
      conn->state = FD_H2_CONN_STATE_DEAD;
      return sizeof(fd_h2_goaway_t);
    }
  }

  if( conn->state & FD_H2_CONN_STATE_UPSET ) {
    fd_h2_gen_goaway( buf, conn->state & 0x0f, 0 );
    conn->state = FD_H2_CONN_STATE_DEAD;
    return sizeof(fd_h2_goaway_t);
  }

  return 0UL;
}

fd_h2_conn_t *
fd_h2_conn_init_server( fd_h2_conn_t * conn ) {
  *conn = (fd_h2_conn_t) {
    .self_settings = fd_h2_settings_initial,
    .peer_settings = fd_h2_settings_initial,
    .state         = FD_H2_CONN_STATE_SERVER_INITIAL,
    .action        = 0,
    .frame_rem     = 0
  };
  return conn;
}

FD_FN_CONST char const *
fd_h2_frame_name( uint frame_id ) {
  switch( frame_id ) {
  case FD_H2_FRAME_TYPE_DATA:          return "DATA";
  case FD_H2_FRAME_TYPE_HEADERS:       return "HEADERS";
  case FD_H2_FRAME_TYPE_PRIORITY:      return "PRIORITY";
  case FD_H2_FRAME_TYPE_RST_STREAM:    return "RST_STREAM";
  case FD_H2_FRAME_TYPE_SETTINGS:      return "SETTINGS";
  case FD_H2_FRAME_TYPE_PUSH_PROMISE:  return "PUSH_PROMISE";
  case FD_H2_FRAME_TYPE_PING:          return "PING";
  case FD_H2_FRAME_TYPE_GOAWAY:        return "GOAWAY";
  case FD_H2_FRAME_TYPE_WINDOW_UPDATE: return "WINDOW_UPDATE";
  case FD_H2_FRAME_TYPE_CONTINUATION:  return "CONTINUATION";
  case FD_H2_FRAME_TYPE_ALTSVC:        return "ALTSVC";
  default:
    return "unknown";
  }
}

FD_FN_CONST char const *
fd_h2_setting_name( uint setting_id ) {
  switch( setting_id ) {
  case FD_H2_SETTINGS_HEADER_TABLE_SIZE:      return "HEADER_TABLE_SIZE";
  case FD_H2_SETTINGS_ENABLE_PUSH:            return "ENABLE_PUSH";
  case FD_H2_SETTINGS_MAX_CONCURRENT_STREAMS: return "MAX_CONCURRENT_STREAMS";
  case FD_H2_SETTINGS_INITIAL_WINDOW_SIZE:    return "INITIAL_WINDOW_SIZE";
  case FD_H2_SETTINGS_MAX_FRAME_SIZE:         return "MAX_FRAME_SIZE";
  case FD_H2_SETTINGS_MAX_HEADER_LIST_SIZE:   return "MAX_HEADER_LIST_SIZE";
  default:                                    return "unknown";
  }
}

FD_FN_CONST char const *
fd_h2_strerror( uint err ) {
  switch( err ) {
  case FD_H2_SUCCESS:                   return "success";
  case FD_H2_ERR_PROTOCOL:              return "protocol error";
  case FD_H2_ERR_INTERNAL:              return "internal error";
  case FD_H2_ERR_FLOW_CONTROL:          return "flow control error";
  case FD_H2_ERR_SETTINGS_TIMEOUT:      return "timed out waiting for settings";
  case FD_H2_ERR_STREAM_CLOSED:         return "stream closed";
  case FD_H2_ERR_FRAME_SIZE:            return "invalid frame size";
  case FD_H2_ERR_REFUSED_STREAM:        return "stream refused";
  case FD_H2_ERR_CANCEL:                return "stream cancelled";
  case FD_H2_ERR_COMPRESSION:           return "compression error";
  case FD_H2_ERR_CONNECT:               return "error while connecting";
  case FD_H2_ERR_ENHANCE_YOUR_CALM:     return "enhance your calm";
  case FD_H2_ERR_INADEQUATE_SECURITY:   return "inadequate security";
  case FD_H2_ERR_HTTP_1_1_REQUIRED:     return "HTTP/1.1 required";
  default:                              return "unknown";
  }
}
