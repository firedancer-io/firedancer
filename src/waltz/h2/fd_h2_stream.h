#ifndef HEADER_fd_src_waltz_h2_fd_h2_stream_h
#define HEADER_fd_src_waltz_h2_fd_h2_stream_h

/* fd_h2_stream.h provides the HTTP/2 stream state machine. */

#include "fd_h2_proto.h"
#include "fd_h2_conn.h"

struct fd_h2_stream {
  uint  stream_id;
  uchar state;
  uchar hdrs_seq;
};

typedef struct fd_h2_stream fd_h2_stream_t;

#define FD_H2_STREAM_STATE_IDLE       0
#define FD_H2_STREAM_STATE_OPEN       1
#define FD_H2_STREAM_STATE_CLOSING_TX 2
#define FD_H2_STREAM_STATE_CLOSING_RX 3
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
fd_h2_stream_close( fd_h2_stream_t * stream,
                    fd_h2_conn_t *   conn ) {
  if( FD_UNLIKELY( stream->state==FD_H2_STREAM_STATE_CLOSED ) ) return;
  if( ( (stream->stream_id&1) == (conn->rx_stream_id&1) ) &
      ( stream->state != FD_H2_STREAM_STATE_CLOSED      ) ) {
    conn->rx_active--;
  }
  stream->state = FD_H2_STREAM_STATE_CLOSED;
}

static inline void
fd_h2_stream_rx_end( fd_h2_stream_t * stream ) {
  if( stream->state == FD_H2_STREAM_STATE_OPEN ) {
    stream->state = FD_H2_STREAM_STATE_CLOSING_RX;
  } else if( stream->state == FD_H2_STREAM_STATE_CLOSING_TX ) {
    stream->state = FD_H2_STREAM_STATE_CLOSED;
  } else {
    stream->state = FD_H2_STREAM_STATE_ILLEGAL;
    return;
  }
}

static inline void
fd_h2_stream_rx_headers( fd_h2_stream_t * stream,
                         ulong            flags ) {

  if( stream->state == FD_H2_STREAM_STATE_IDLE ) {
    stream->state = FD_H2_STREAM_STATE_OPEN;
  }

  if( flags & FD_H2_FLAG_END_STREAM ) {
    fd_h2_stream_rx_end( stream );
  }

  if( flags & FD_H2_FLAG_END_HEADERS ) {
    stream->hdrs_seq = (uchar)( stream->hdrs_seq + 1 );
  }

}

static inline void
fd_h2_stream_rx_data( fd_h2_stream_t * stream,
                      ulong            flags ) {

  if( FD_UNLIKELY( stream->state == FD_H2_STREAM_STATE_IDLE ) ) {
    stream->state = FD_H2_STREAM_STATE_ILLEGAL;
    return;
  }

  if( flags & FD_H2_FLAG_END_STREAM ) {
    fd_h2_stream_rx_end( stream );
  }

}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_stream_h */
