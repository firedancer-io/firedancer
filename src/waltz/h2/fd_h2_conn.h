#ifndef HEADER_fd_src_waltz_h2_fd_h2_conn_h
#define HEADER_fd_src_waltz_h2_fd_h2_conn_h

/* fd_h2_conn.h provides the HTTP/2 connection state machine and utils
   for multiplexing frames. */

#include "fd_h2_callback.h"
#include "fd_h2_rbuf.h"
#include "fd_h2_proto.h"

/* fd_h2_settings_t contains HTTP/2 settings that fd_h2 understands. */

struct fd_h2_settings {
  uint initial_window_size;
  uint max_frame_size;
  uint max_header_list_size;
  uint max_concurrent_streams;
};

typedef struct fd_h2_settings fd_h2_settings_t;

/* fd_h2_config_t contains fd_h2-specific settings that are invisible to
   the peer. */

struct fd_h2_config {
  float ns_per_tick;
  long  settings_timeout;
};

typedef struct fd_h2_config fd_h2_config_t;

/* FD_H2_MAX_PENDING_SETTINGS limits the number of SETTINGS frames that
   fd_h2 can burst without an acknowledgement.  Aborts the conn with a
   TCP RST if fd_h2 or the peer pile on too many unacknowledged SETTINGS
   frames. */

#define FD_H2_MAX_PENDING_SETTINGS 64

/* fd_h2_conn is a framing-layer HTTP/2 connection handle.
   It implements RFC 9113 mandatory behavior, such as negotiating conn
   settings with a peer. */

struct fd_h2_conn {
  fd_h2_callbacks_t const * cb;

  union { /* arbitrary value for use by caller */
    void * ctx;
    ulong  memo;
  };

  fd_h2_settings_t self_settings;
  fd_h2_settings_t peer_settings;

  long settings_timeout;
  long settings_deadline;

  uchar * tx_frame_p;     /* points to first byte of frame header */
  ulong   tx_payload_off;
  ulong   rx_suppress;    /* skip frame handlers until this RX offset */

  uint  rx_frame_rem;    /* current RX frame: payload bytes remaining */
  uint  rx_stream_id;    /* current RX frame: stream ID */

  uint  rx_wnd_wmark;    /* receive window refill threshold */
  uint  rx_wnd_max;      /* receive window max size */
  uint  rx_wnd;          /* receive window bytes remaining */
  int   tx_wnd;          /* transmit quota available */
  uint  rx_active;       /* currently active receive streams */
  uint  tx_active;       /* currently active transmit streams */

  uchar state;           /* one of FD_H2_CONN_STATE_* */
  uchar action;          /* bit set of FD_H2_CONN_ACTION_* */
  uchar setting_tx;      /* no of sent SETTINGS frames pending their ACK */
  uchar rx_frame_flags;  /* current RX frame: flags */
  uchar rx_pad_rem;      /* current RX frame: pad bytes remaining */
};

typedef struct fd_h2_conn fd_h2_conn_t;

/* FD_H2_CONN_STATE_* give states in the connection lifecycle */

#define FD_H2_CONN_STATE_DEAD           ((uchar)0x00)
#define FD_H2_CONN_STATE_CLIENT_INITIAL ((uchar)0x01) /* send preface+settings */
#define FD_H2_CONN_STATE_SERVER_INITIAL ((uchar)0x02) /* send settings */
#define FD_H2_CONN_STATE_WAIT_SETTINGS  ((uchar)0x03) /* wait for initial settings */
#define FD_H2_CONN_STATE_ESTABLISHED    ((uchar)0x04) /* wait for frames */
#define FD_H2_CONN_STATE_UPSET          ((uchar)0x80) /* forcibly closing with error */

#define FD_H2_CONN_ACTION_SETTINGS     ((uchar)0x02) /* need to send a SETTINGS frame */
#define FD_H2_CONN_ACTION_RX_STUFFED   ((uchar)0x10) /* need to generate frames to unblock RX */

FD_PROTOTYPES_BEGIN

/* fd_h2_config_validate returns FD_H2_SUCCESS if a config object is
   valid and FD_H2_ERR_INTERNAL otherwise.  Logs reason for validate
   failure. */

int
fd_h2_config_validate( fd_h2_config_t const * config );

#if FD_HAS_DOUBLE

/* fd_h2_config_defaults derives sensible defaults for an h2_config.
   WARNING: Creates the assumption that fd_tickcount() is used for
   timestamps.  Take appropriate precautions (thread pinning, etc.).
   WARNING: Calls fd_tempo_tick_per_ns() which may block the caller for
   a couple 100 milliseconds to train the clock. */

fd_h2_config_t *
fd_h2_config_defaults( fd_h2_config_t * config );

#endif /* FD_HAS_DOUBLE */

/* fd_h2_conn_init_client bootstraps a conn object for use as a client
   side HTTP/2 connection.  config is copied into the conn object.
   Returns conn on success, or NULL on failure (logs warning).  This
   call is currently infallible so there are no failure conditions.  The
   client should check for failure regardless (future proofing). */

fd_h2_conn_t *
fd_h2_conn_init_client( fd_h2_conn_t *         conn,
                        fd_h2_config_t const * config );

/* FIXME implement fd_h2_conn_init_server */

/* fd_h2_conn_fini destroys a h2_conn object.  Since h2_conn has no
   references or ownership over external objects, this is a no-op. */

void *
fd_h2_conn_fini( fd_h2_conn_t * conn );

/* fd_h2_rx consumes as much incoming bytes from rbuf_rx as possible.
   May write control messages to rbuf_out.  Stops when no more data in
   rbuf_tx is full, rbuf_rx is available, or a connection error
   occurred.  scratch points to a scratch buffer used for reassembly.
   Assumes scratch_sz >= conn.self_settings.max_frame_size. */

void
fd_h2_rx( fd_h2_conn_t *      conn,
          fd_h2_rbuf_t *      rbuf_rx,
          fd_h2_rbuf_t *      rbuf_tx,
          uchar *             scratch,
          ulong               scratch_sz,
          fd_h2_callbacks_t * cb );

/* fd_h2_tx_control writes out control messages to rbuf_out.  Should be
   called immediately when creating a conn or whenever a timer
   expires. */

void
fd_h2_tx_control( fd_h2_conn_t * conn,
                  fd_h2_rbuf_t * rbuf_tx,
                  long           cur_time );

/* fd_h2_tx_check_sz checks whether rbuf_tx has enough space to buffer
   a frame for sending.  frame_max is the max frame size to check for.
   Returns 1 if the send buffer has enough space to hold a frame, 0
   otherwise.

   Note that the caller should separately do the following checks:
   - TCP send window space (optional, if fast delivery is desired)
   - HTTP/2 connection send window space
   - HTTP/2 stream limit check
   - HTTP/2 stream send window space */

static inline int
fd_h2_tx_check_sz( fd_h2_rbuf_t const * rbuf_tx,
                   ulong                frame_max ) {
  /* Calculate the wire size of a frame */
  ulong tot_sz = 9UL + frame_max;
  /* Leave some room in rbuf_tx for control frames */
  ulong req_sz = tot_sz + 64UL;
  return fd_h2_rbuf_free_sz( rbuf_tx ) >= req_sz;
}

/* fd_h2_tx_prepare appends a partial frame header to rbuf_tx.  Assumes
   that rbuf_tx has enough space to write a frame header.  On return,
   the caller can start appending the actual payload to rbuf_tx. */

static inline void
fd_h2_tx_prepare( fd_h2_conn_t * conn,
                  fd_h2_rbuf_t * rbuf_tx,
                  uint           frame_type,
                  uint           flags,
                  uint           stream_id ) {
  conn->tx_frame_p     = rbuf_tx->hi;
  conn->tx_payload_off = rbuf_tx->hi_off + 9;

  fd_h2_frame_hdr_t hdr = {
    .typlen    = fd_h2_frame_typlen( frame_type, 0 ),
    .flags     = (uchar)flags,
    .stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( rbuf_tx, &hdr, sizeof(fd_h2_frame_hdr_t) );
}

/* fd_h2_tx_commit finishes up a HTTP/2 frame. */

static inline void
fd_h2_tx_commit( fd_h2_conn_t const * conn,
                 fd_h2_rbuf_t const * rbuf_tx ) {
  ulong   off0  = conn->tx_payload_off;
  ulong   off1  = rbuf_tx->hi_off;
  uchar * buf0  = rbuf_tx->buf0;
  uchar * buf1  = rbuf_tx->buf1;
  ulong   bufsz = rbuf_tx->bufsz;
  uchar * frame = conn->tx_frame_p;
  uchar * sz0   = frame+1;
  uchar * sz1   = frame+2;
  uchar * sz2   = frame+2;
  sz0 = sz0>=buf1 ? sz0-bufsz : sz0;
  sz1 = sz1>=buf1 ? sz1-bufsz : sz1;
  sz2 = sz2>=buf1 ? sz2-bufsz : sz2;

  if( FD_UNLIKELY( frame<buf0 || frame>=buf1 ) ) {
    FD_LOG_CRIT(( "Can't finish frame: rbuf_tx doesn't match" ));
  }

  ulong write_sz = (ulong)( off1-off0 );
  /* FIXME check write_sz? */
  *sz0 = (uchar)( write_sz>>16 );
  *sz1 = (uchar)( write_sz>> 8 );
  *sz2 = (uchar)( write_sz     );
}

/* fd_h2_tx is a slow streamlined variant of fd_h2_tx_{prepare,commit}.
   This variant assumes that the frame paylaod is already available in
   a separate buffer. */

static inline void
fd_h2_tx( fd_h2_rbuf_t * rbuf_tx,
          uchar const *  payload,
          ulong          payload_sz,
          uint           frame_type,
          uint           flags,
          uint           stream_id ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen    = fd_h2_frame_typlen( frame_type, payload_sz ),
    .flags     = (uchar)flags,
    .stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( rbuf_tx, &hdr, sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_push( rbuf_tx, payload, payload_sz );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_conn_h */
