#ifndef HEADER_fd_src_waltz_h2_fd_h2_stream_h
#define HEADER_fd_src_waltz_h2_fd_h2_stream_h

/* fd_h2_stream.h provides the HTTP/2 stream state machine. */

#include "fd_h2_base.h"
#include "fd_h2_proto.h"
#include "fd_h2_conn.h"

/* The fd_h2_stream_t object holds the stream state machine.  */

struct fd_h2_stream {
  uint stream_id;
  uint tx_wnd; /* transmit quota available */
  uint rx_wnd; /* receive window bytes remaining */

  uchar state;
  uchar hdrs_seq;
};

#define FD_H2_STREAM_STATE_IDLE       0
#define FD_H2_STREAM_STATE_OPEN       1
#define FD_H2_STREAM_STATE_CLOSING_TX 2 /* half-closed (local) */
#define FD_H2_STREAM_STATE_CLOSING_RX 3 /* half-closed (remote) */
#define FD_H2_STREAM_STATE_CLOSED     4
#define FD_H2_STREAM_STATE_ILLEGAL    5

FD_PROTOTYPES_BEGIN

/* fd_h2_stream_init initializes a stream object.  On return, the stream
   is in 'IDLE' state and does not have an assigned stream ID. */

static inline fd_h2_stream_t *
fd_h2_stream_init( fd_h2_stream_t * stream ) {
  *stream = (fd_h2_stream_t){0};
  return stream;
}

/* fd_h2_stream_open transitions a stream from 'IDLE' to 'OPEN'.
   In fd_h2, this happens when the local or peer side sends a HEADERS
   frame.  The TX side of the stream assumes the peer's default send
   window. */

static inline fd_h2_stream_t *
fd_h2_stream_open( fd_h2_stream_t *     stream,
                   fd_h2_conn_t const * conn,
                   uint                 stream_id ) {
  *stream = (fd_h2_stream_t) {
    .stream_id = stream_id,
    .state     = FD_H2_STREAM_STATE_OPEN,
    .tx_wnd    = conn->peer_settings.initial_window_size,
    .rx_wnd    = conn->self_settings.initial_window_size,
    .hdrs_seq  = 0U
  };
  return stream;
}

static inline void
fd_h2_stream_error( fd_h2_stream_t * stream,
                    fd_h2_rbuf_t *   rbuf_tx,
                    uint             h2_err ) {
  fd_h2_tx_rst_stream( rbuf_tx, stream->stream_id, h2_err );
  stream->state = FD_H2_STREAM_STATE_CLOSED;
}

/* fd_h2_rst_stream generates a RST_STREAM frame on the given stream.
   On return, the stream is in CLOSED state, and the underlying stream
   object and map entry can be discarded.  conn->active_stream_cnt is
   decremented accordingly. */

void
fd_h2_rst_stream( fd_h2_conn_t *   conn,
                  fd_h2_rbuf_t *   rbuf_tx,
                  fd_h2_stream_t * stream );

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
    /* FIXME This is probably redundant */
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
