#ifndef HEADER_fd_src_waltz_h2_fd_h2_h
#define HEADER_fd_src_waltz_h2_fd_h2_h

/* fd_h2 implements the HTTP/2 framing layer.

   ### Features

   This library is mostly optimized for simplicity.  No particular
   effort was made to achieve low latency (no support for header
   streaming), nor high throughput (no fancy algorithms or SIMD).

   Fully supports use as a HTTP/2 client.  Is not fully spec-compliant
   when used as a HTTP/2 server due to lack of support for the HPACK
   dynamic table/dictionary.  (Although the endpoint can force the peer
   to refrain from using the HPACK dynamic table via HTTP/2 SETTINGS,
   the client can sneak in a request that obeys protocol default
   settings, which permit HPACK dynamic compression, in the first leg of
   the connection.)

   This library is deterministic/pure.  The same sequence of identical
   API calls will result in the same behavior.  Timing data (timestamps,
   timeouts, rate limits, etc.) are externally provided, too.  fd_h2 is
   somewhat tolerant to clock stutter and rewind.

   ### HTTP/2 DoS pitfalls

   When getting multiple HTTP/2 SETTINGS frames in short succession,
   fd_h2 waits a while before responding to each.  This defends against
   a SETTINGS flood attack. */

#include "fd_h2_rbuf.h"

/* Connection API */

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
  long  ack_backoff;
  long  settings_timeout;
};

typedef struct fd_h2_config fd_h2_config_t;

/* FD_H2_OUR_SETTINGS_ENCODED_SZ is the total size of a SETTINGS frame
   containing all values in fd_h2_settings_t. */

#define FD_H2_OUR_SETTINGS_ENCODED_SZ 45

/* FD_H2_MAX_PENDING_SETTINGS limits the number of SETTINGS frames that
   fd_h2 or the peer can burst without an acknowledgement.  Aborts the
   conn with a TCP RST if fd_h2 or the peer pile on too many
   unacknowledged SETTINGS frames. */

#define FD_H2_MAX_PENDING_SETTINGS 64

/* fd_h2_conn is a framing-layer HTTP/2 connection handle.
   It implements RFC 9113 mandatory behavior, such as negotiating conn
   settings with a peer. */

struct fd_h2_conn {
  fd_h2_settings_t self_settings;
  fd_h2_settings_t peer_settings;

  ulong memo; /* arbitrary value for use by caller */

  long  settings_timeout;
  long  settings_deadline;

  /* Rate limiter for ACKs for PING and SETTINGS frames */
  long  ack_next;
  long  ack_backoff;

  ulong peek_off;     /* number of bytes seen by rx_next */
  uint  rx_wnd_wmark; /* threshold for receive window refill */
  uint  rx_wnd_max;   /* max receive window */
  uint  rx_wnd;       /* last receive window */
  int   tx_wnd;       /* last transmit quota */
  uint  rx_active;    /* currently active receive streams */
  uint  tx_active;    /* currently active transmit streams */

  ulong ping_token;

  uint  frame_rem;    /* number of bytes until next frame header */
  uint  stream_id;    /* stream ID of last frame */

  uchar frame_type;   /* frame type of last frame */
  uchar frame_flags;  /* flags of last frame */
  uchar state;        /* one of FD_H2_CONN_STATE_* */
  uchar action;       /* bit set of FD_H2_CONN_ACTION_* */
  uchar setting_rx;   /* no of received SETTINGS frames pending our ACK */
  uchar setting_tx;   /* no of sent SETTINGS frames pending their ACK */
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
#define FD_H2_CONN_ACTION_SETTINGS_ACK ((uchar)0x04) /* need to ACK a SETTINGS frame */
#define FD_H2_CONN_ACTION_PING_ACK     ((uchar)0x08) /* need to ACK a PING frame */
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

/* fd_h2_conn_rx_done returns 1 if fd_h2_conn_rx_next needs more data
   to make progress.  Otherwise, returns 0. */

static inline int
fd_h2_conn_rx_done( fd_h2_conn_t const * conn,
                    fd_h2_rbuf_t const * rbuf ) {
  return ( rbuf->hi_off <= conn->peek_off ) | ( conn->action & FD_H2_CONN_ACTION_RX_STUFFED );
}

/* fd_h2_conn_rx_next seeks to the payload of the next frame.  Returns
   1 if a new frame header was fully read, 0 otherwise.  The caller may
   pop bytes off rbuf for HEADERS and DATA frames, but not any other
   frame types. */

int
fd_h2_conn_rx_next( fd_h2_conn_t * conn,
                    fd_h2_rbuf_t * rbuf );

/* fd_h2_conn_respond generates control data bytes to send over the
   underlying stream (e.g. TCP or TLS).  If there is data to write,
   returns the number of bytes to write (in [1,96)).

   If there is nothing to do (conn->action==0), or the response is
   suppressed by a rate limit, returns 0.  In this case the caller
   should start polling the socket for new data to avoid excessive
   elays. */

#define FD_H2_CONN_RESPOND_BUFSZ 96

ulong
fd_h2_conn_respond( fd_h2_conn_t * conn,
                    uchar          buf[ FD_H2_CONN_RESPOND_BUFSZ ],
                    long           cur_time );

/* fd_h2_conn_sync_settings notifies h2_conn that self_settings was
   changed.  Causes the client to write a SETTINGS farme in the next
   fd_h2_conn_respond call. */

static inline void
fd_h2_conn_sync_settings( fd_h2_conn_t * conn ) {
  conn->action |= FD_H2_CONN_ACTION_SETTINGS;
}

FD_PROTOTYPES_END

/* Util API */

FD_PROTOTYPES_BEGIN

/* fd_h2_frame_name returns a static-lifetime uppercase cstr with the
   name of a HTTP/2 frame. */

FD_FN_CONST char const *
fd_h2_frame_name( uint frame_id );

/* fd_h2_setting_name returns a static-lifetime uppercase cstr with the
   name of a HTTP/2 setting. */

FD_FN_CONST char const *
fd_h2_setting_name( uint setting_id );

/* fd_h2_strerror returns a static-lifetime cstr briefly describing the
   given FD_H2_ERR_* code. */

FD_FN_CONST char const *
fd_h2_strerror( uint err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_h */
