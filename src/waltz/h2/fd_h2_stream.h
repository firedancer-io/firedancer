#ifndef HEADER_fd_src_waltz_h2_fd_h2_stream_h
#define HEADER_fd_src_waltz_h2_fd_h2_stream_h

/* fd_h2_stream.h provides the HTTP/2 stream state machine. */

#include "fd_h2_proto.h"
#include "fd_h2_conn.h"

struct fd_h2_stream {
  uint  stream_id;
  uchar state;
  uchar hdrs_seq;

  uint tx_wnd; /* transmit quota available */
};

#define FD_H2_STREAM_STATE_IDLE       0
#define FD_H2_STREAM_STATE_OPEN       1
#define FD_H2_STREAM_STATE_CLOSING_TX 2 /* half-closed (local) */
#define FD_H2_STREAM_STATE_CLOSING_RX 3 /* half-closed (remote) */
#define FD_H2_STREAM_STATE_CLOSED     4
#define FD_H2_STREAM_STATE_ILLEGAL    5

FD_PROTOTYPES_BEGIN

static inline fd_h2_stream_t *
fd_h2_stream_init( fd_h2_stream_t * stream,
                   uint             stream_id ) {
  *stream = (fd_h2_stream_t) { .stream_id = stream_id };
  return stream;
}

static inline void
fd_h2_stream_private_deactivate( fd_h2_stream_t * stream,
                                 fd_h2_conn_t *   conn ) {
  conn->stream_active_cnt[ (stream->stream_id&1) ^ (conn->rx_stream_id&1) ]--;
}

static inline void
fd_h2_stream_close_rx( fd_h2_stream_t * stream,
                       fd_h2_conn_t *   conn ) {
  switch( stream->state ) {
  case FD_H2_STREAM_STATE_OPEN:
    stream->state = FD_H2_STREAM_STATE_CLOSING_RX;
    break;
  case FD_H2_STREAM_STATE_CLOSING_TX:
    stream->state = FD_H2_STREAM_STATE_CLOSED;
    fd_h2_stream_private_deactivate( stream, conn );
    break;
  default:
    stream->state = FD_H2_STREAM_STATE_ILLEGAL;
    break;
  }
}

static inline void
fd_h2_stream_close_tx( fd_h2_stream_t * stream,
                       fd_h2_conn_t *   conn ) {
  switch( stream->state ) {
  case FD_H2_STREAM_STATE_OPEN:
    stream->state = FD_H2_STREAM_STATE_CLOSING_TX;
    break;
  case FD_H2_STREAM_STATE_CLOSING_RX:
    stream->state = FD_H2_STREAM_STATE_CLOSED;
    fd_h2_stream_private_deactivate( stream, conn );
    break;
  default:
    stream->state = FD_H2_STREAM_STATE_ILLEGAL;
    break;
  }
}

static inline void
fd_h2_stream_reset( fd_h2_stream_t * stream,
                    fd_h2_conn_t *   conn ) {
  switch( stream->state ) {
  case FD_H2_STREAM_STATE_OPEN:
  case FD_H2_STREAM_STATE_CLOSING_TX:
  case FD_H2_STREAM_STATE_CLOSING_RX:
    stream->state = FD_H2_STREAM_STATE_CLOSED;
    fd_h2_stream_private_deactivate( stream, conn );
    break;
  default:
    stream->state = FD_H2_STREAM_STATE_ILLEGAL;
    break;
  }
}

static inline void
fd_h2_stream_rx_headers( fd_h2_stream_t * stream,
                         fd_h2_conn_t *   conn,
                         ulong            flags ) {
  if( stream->state == FD_H2_STREAM_STATE_IDLE ) {
    stream->state = FD_H2_STREAM_STATE_OPEN;
  }
  if( flags & FD_H2_FLAG_END_STREAM ) {
    fd_h2_stream_close_rx( stream, conn );
  }
  if( flags & FD_H2_FLAG_END_HEADERS ) {
    stream->hdrs_seq = (uchar)( stream->hdrs_seq + 1 );
  }
}

static inline void
fd_h2_stream_rx_data( fd_h2_stream_t * stream,
                      fd_h2_conn_t *   conn,
                      ulong            flags ) {
  if( flags & FD_H2_FLAG_END_STREAM ) {
    fd_h2_stream_close_rx( stream, conn );
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_stream_h */
