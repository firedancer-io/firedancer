#ifndef HEADER_fd_src_waltz_h2_fd_h2_conn_h
#define HEADER_fd_src_waltz_h2_fd_h2_conn_h

/* fd_h2_conn.h provides the HTTP/2 connection state machine and utils
   for multiplexing frames. */

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

/* FD_H2_MAX_PENDING_SETTINGS limits the number of SETTINGS frames that
   fd_h2 can burst without an acknowledgement.  Aborts the conn with a
   TCP RST if fd_h2 or the peer pile on too many unacknowledged SETTINGS
   frames. */

#define FD_H2_MAX_PENDING_SETTINGS 64

/* fd_h2_conn is a framing-layer HTTP/2 connection handle.
   It implements RFC 9113 mandatory behavior, such as negotiating conn
   settings with a peer. */

struct fd_h2_conn {
  union { /* arbitrary value for use by caller */
    void * ctx;
    ulong  memo;
  };

  fd_h2_settings_t self_settings;
  fd_h2_settings_t peer_settings;

  uchar * tx_frame_p;     /* in-progress frame: first byte in rbuf */
  ulong   tx_payload_off; /* in-progress frame: cum sent byte cnt before payload */
  ulong   rx_suppress;    /* skip frame handlers until this RX offset */

  uint  rx_frame_rem;    /* current RX frame: payload bytes remaining */
  uint  rx_stream_id;    /* current RX frame: stream ID */
  uint  rx_stream_next;  /* next unused RX stream ID */

  uint  rx_wnd_wmark;    /* receive window refill threshold */
  uint  rx_wnd_max;      /* receive window max size */
  uint  rx_wnd;          /* receive window bytes remaining */

  uint  tx_stream_next;  /* next unused TX stream ID */
  uint  tx_wnd;          /* transmit quota available */

  uint  stream_active_cnt[2]; /* currently active {rx,tx} streams  */

  ushort flags;           /* bit set of FD_H2_CONN_FLAGS_* */
  uchar  conn_error;
  uchar  setting_tx;      /* no of sent SETTINGS frames pending their ACK */
  uchar  rx_frame_flags;  /* current RX frame: flags */
  uchar  rx_pad_rem;      /* current RX frame: pad bytes remaining */
  uchar  ping_tx;         /* no of sent PING frames pending their ACK */
};

/* FD_H2_CONN_FLAGS_* give flags related to conn lifecycle */

#define FD_H2_CONN_FLAGS_LG_DEAD                (0) /* conn has passed */
#define FD_H2_CONN_FLAGS_LG_SEND_GOAWAY         (1) /* send GOAWAY */
#define FD_H2_CONN_FLAGS_LG_CONTINUATION        (2) /* next frame must be CONTINUATION */
#define FD_H2_CONN_FLAGS_LG_CLIENT_INITIAL      (3) /* send preface, SETTINGS */
#define FD_H2_CONN_FLAGS_LG_WAIT_SETTINGS_ACK_0 (4) /* wait for initial ACK of initial SETTINGS */
#define FD_H2_CONN_FLAGS_LG_WAIT_SETTINGS_0     (5) /* wait for peer's initial SETTINGS */
#define FD_H2_CONN_FLAGS_LG_SERVER_INITIAL      (6) /* wait for client preface, then send settings */
#define FD_H2_CONN_FLAGS_LG_WINDOW_UPDATE       (7) /* send WINDOW_UPDATE */

#define FD_H2_CONN_FLAGS_DEAD                ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_DEAD                ))
#define FD_H2_CONN_FLAGS_SEND_GOAWAY         ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_SEND_GOAWAY         ))
#define FD_H2_CONN_FLAGS_CONTINUATION        ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_CONTINUATION        ))
#define FD_H2_CONN_FLAGS_CLIENT_INITIAL      ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_CLIENT_INITIAL      ))
#define FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0 ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_WAIT_SETTINGS_ACK_0 ))
#define FD_H2_CONN_FLAGS_WAIT_SETTINGS_0     ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_WAIT_SETTINGS_0     ))
#define FD_H2_CONN_FLAGS_SERVER_INITIAL      ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_SERVER_INITIAL      ))
#define FD_H2_CONN_FLAGS_WINDOW_UPDATE       ((uchar)( 1U<<FD_H2_CONN_FLAGS_LG_WINDOW_UPDATE       ))

/* A connection is established when no more handshake-related flags are
   sent.  Specifically: The connection preface was sent, the peer's
   preface was received, a SETTINGS frame was sent, a SETTINGS frame was
   received, a SETTINGS ACK was sent, and a SETTINGS ACK was received. */

#define FD_H2_CONN_FLAGS_HANDSHAKING (0xf0)

FD_PROTOTYPES_BEGIN

/* fd_h2_conn_init_{client,server} bootstraps a conn object for use as a
   {client,server}-side HTTP/2 connection.  Returns conn on success, or
   NULL on failure (logs warning).  This call is currently infallible so
   there are no failure conditions.  The caller should check for failure
   regardless (future proofing).

   fd_h2_conn_init_server assumes that the client preface was already
   received from the incoming stream.  The preface is the 24 byte
   constant string fd_h2_client_preface. */

fd_h2_conn_t *
fd_h2_conn_init_client( fd_h2_conn_t * conn );

fd_h2_conn_t *
fd_h2_conn_init_server( fd_h2_conn_t * conn );

extern char const fd_h2_client_preface[24];

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
fd_h2_rx( fd_h2_conn_t *            conn,
          fd_h2_rbuf_t *            rbuf_rx,
          fd_h2_rbuf_t *            rbuf_tx,
          uchar *                   scratch,
          ulong                     scratch_sz,
          fd_h2_callbacks_t const * cb );

/* fd_h2_tx_control writes out control messages to rbuf_out.  Should be
   called immediately when creating a conn or whenever a timer
   expires. */

void
fd_h2_tx_control( fd_h2_conn_t *            conn,
                  fd_h2_rbuf_t *            rbuf_tx,
                  fd_h2_callbacks_t const * cb );

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
  if( FD_UNLIKELY( conn->tx_frame_p ) ) {
    FD_LOG_CRIT(( "Mismatched fd_h2_tx_prepare" ));
  }

  conn->tx_frame_p     = rbuf_tx->hi;
  conn->tx_payload_off = rbuf_tx->hi_off + 9;

  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( frame_type, 0 ),
    .flags       = (uchar)flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( rbuf_tx, &hdr, sizeof(fd_h2_frame_hdr_t) );
}

/* fd_h2_tx_commit finishes up a HTTP/2 frame. */

static inline void
fd_h2_tx_commit( fd_h2_conn_t *       conn,
                 fd_h2_rbuf_t const * rbuf_tx ) {
  ulong   off0  = conn->tx_payload_off;
  ulong   off1  = rbuf_tx->hi_off;
  uchar * buf0  = rbuf_tx->buf0;
  uchar * buf1  = rbuf_tx->buf1;
  ulong   bufsz = rbuf_tx->bufsz;
  uchar * frame = conn->tx_frame_p;
  uchar * sz0   = frame;
  uchar * sz1   = frame+1;
  uchar * sz2   = frame+2;
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

  conn->tx_frame_p     = NULL;
  conn->tx_payload_off = 0UL;
}

/* fd_h2_tx is a slow streamlined variant of fd_h2_tx_{prepare,commit}.
   This variant assumes that the frame payload is already available in
   a separate buffer. */

static inline void
fd_h2_tx( fd_h2_rbuf_t * rbuf_tx,
          uchar const *  payload,
          ulong          payload_sz,
          uint           frame_type,
          uint           flags,
          uint           stream_id ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( frame_type, payload_sz ),
    .flags       = (uchar)flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( rbuf_tx, &hdr, sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_push( rbuf_tx, payload, payload_sz );
}

/* fd_h2_tx_ping attempts to enqueue a PING frame for sending
   (in fd_h2_tx_control). */

int
fd_h2_tx_ping( fd_h2_conn_t * conn,
               fd_h2_rbuf_t * rbuf_tx );

/* fd_h2_conn_error enqueues a GOAWAY frame for sending
   (in fd_h2_tx_control). */

static inline void
fd_h2_conn_error( fd_h2_conn_t * conn,
                  uint           err_code ) {
  /* Clear all other flags */
  conn->flags = FD_H2_CONN_FLAGS_SEND_GOAWAY;
  conn->conn_error = (uchar)err_code;
}

/* fd_h2_tx_rst_stream writes a RST_STREAM frame for sending.  rbuf_tx
   must have at least sizeof(fd_h2_rst_stream_t) free space.  (This is
   a low-level API) */

static inline void
fd_h2_tx_rst_stream( fd_h2_rbuf_t * rbuf_tx,
                     uint           stream_id,
                     uint           h2_err ) {
  fd_h2_rst_stream_t rst_stream = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ),
      .flags       = 0U,
      .r_stream_id = fd_uint_bswap( stream_id )
    },
    .error_code = fd_uint_bswap( h2_err )
  };
  fd_h2_rbuf_push( rbuf_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_conn_h */
