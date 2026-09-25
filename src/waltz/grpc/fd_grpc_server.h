#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_server_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_server_h

/* fd_grpc_server.h provides a gRPC server over HTTP/2 cleartext (h2c).

   The server implements the transport half of gRPC: HTTP/2 connection
   and stream management, request header validation (RFC 9113 Sections
   8.1 and 8.3), Length-Prefixed-Message framing, response headers,
   trailers, statuses, gRPC deadlines, and zstd compression
   in both directions.  It does not know about protobuf or any particular
   service: handlers receive and send opaque message bytes, and decide
   themselves which :path values they serve.

   https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md

   All memory is laid out once by fd_grpc_server_new from a
   caller-provided region.  The server never allocates at runtime.

   Event loop: the server owns a non-blocking listen socket and one
   non-blocking socket per connection.
   fd_grpc_server_service runs the timers (deadlines, idle,
   handshake) and drains the per-stream send queues; fd_grpc_server_poll
   calls it with the current wallclock.  Timers only run when
   fd_grpc_server_poll returns, so a caller that blocks in it bounds
   timeout_millis by the deadlines it cares about.

   Handlers see the following call order on a stream:

     stream_hdr    (0 or more)     request metadata
     stream_open                   request headers complete
     stream_msg    (0 or more)     one per complete request message
     stream_half_close             client sent END_STREAM
     stream_writable (0 or more)   send queue drained after ERR_AGAIN
     stream_close                  stream is gone, free handler state

   stream_close reports a stream that stream_open accepted, whatever
   the reason it ended. */

#include "fd_grpc_codec.h"

/* FD_GRPC_SERVER_ALIGN is the alignment of an fd_grpc_server_t. */

#define FD_GRPC_SERVER_ALIGN (128UL)

/* FD_GRPC_SERVER_PATH_MAX is the longest :path that the server hands to
   a handler.  Longer paths cannot match a route and are rejected with
   UNIMPLEMENTED. */

#define FD_GRPC_SERVER_PATH_MAX (192UL)

/* FD_GRPC_SERVER_MSG_MAX is the longest grpc-message string that the
   server sends.  Longer strings are truncated. */

#define FD_GRPC_SERVER_MSG_MAX (256UL)

/* Compression modes */

#define FD_GRPC_SERVER_COMPRESSION_NONE (0)
#define FD_GRPC_SERVER_COMPRESSION_ZSTD (1)

/* fd_grpc_server_send return codes */

#define FD_GRPC_SERVER_SUCCESS       ( 0)
#define FD_GRPC_SERVER_ERR_AGAIN     (-1) /* send queue full, retry after stream_writable */
#define FD_GRPC_SERVER_ERR_CLOSED    (-2) /* stream is finishing or gone */
#define FD_GRPC_SERVER_ERR_TOOBIG    (-3) /* no send path can ever take it, see fd_grpc_server_send */
#define FD_GRPC_SERVER_ERR_INTERNAL  (-4) /* e.g., compression failure */

/* fd_grpc_server_send flags */

#define FD_GRPC_SERVER_SEND_NO_COMPRESS (1U)

/* stream_open return values.  Neither accept mode limits how many
   messages flow. */

#define FD_GRPC_SERVER_ACCEPT_UNARY  ( 0) /* terminating: grpc-timeout enforced */
#define FD_GRPC_SERVER_ACCEPT_STREAM ( 1) /* open ended: grpc-timeout ignored */
#define FD_GRPC_SERVER_REJECT        (-1) /* end the call, see fd_grpc_server_finish */

/* stream_close reasons */

#define FD_GRPC_SERVER_CLOSE_FINISHED  (0) /* trailers were sent */
#define FD_GRPC_SERVER_CLOSE_CANCELLED (1) /* client sent RST_STREAM */
#define FD_GRPC_SERVER_CLOSE_CONN_LOST (2) /* connection died */
#define FD_GRPC_SERVER_CLOSE_ABORTED   (3) /* reset for a protocol or flow control error */

struct fd_grpc_server;
typedef struct fd_grpc_server fd_grpc_server_t;

struct fd_grpc_server_conn;
typedef struct fd_grpc_server_conn fd_grpc_server_conn_t;

struct fd_grpc_server_stream;
typedef struct fd_grpc_server_stream fd_grpc_server_stream_t;

/* fd_grpc_server_params_t configures an fd_grpc_server_t.  All fields
   must be set; fd_grpc_server_params_default fills in sane values. */

struct fd_grpc_server_params {

  /* protocol params sent to client */
  ulong max_stream_cnt;       /* SETTINGS_MAX_CONCURRENT_STREAMS, in [1,256] */
  ulong max_frame_sz;         /* SETTINGS_MAX_FRAME_SIZE, in [16384,2^24) */
  ulong stream_rx_wnd_sz;     /* SETTINGS_INITIAL_WINDOW_SIZE, HTTP/2 stream receive window, in [65535,2^31) */
  ulong conn_rx_wnd_sz;       /* HTTP/2 connection flow-control window, granted by WINDOW_UPDATE, >=65535 */

  /* memory sizing */
  ulong max_conn_cnt;         /* max concurrent connections, in [1,4096] */
  ulong conn_rx_buf_sz;       /* per-connection receive ring, in [max_frame_sz+9,2^30] */
  ulong conn_tx_buf_sz;       /* per-connection send ring, in [max_frame_sz+9,2^30] */
  ulong stream_tx_queue_sz;   /* per-stream send queue capacity in bytes, >=64 */
  ulong max_request_msg_sz;   /* largest request message accepted, in [1,2^31). alloc is per stream */
  ulong max_msg_sz;           /* largest response message, >=stream_tx_queue_sz, <2^31 */
  ulong large_msg_slot_cnt;   /* large send slots, in [0,256] */
  ulong seed;                 /* header matcher hash seed */

  /* timeouts */
  long  idle_timeout_nanos;   /* close connections idle for this long, 0 disables */
  long  handshake_timeout_nanos; /* close if the HTTP/2 handshake takes longer, 0 disables */
  long  large_drain_timeout_nanos; /* abort a stream whose large message stalls this long, 0 disables */
  long  response_timeout_nanos; /* end a call whose handler never responds, 0 disables */

  /* zstd compression */
  int   compression;          /* FD_GRPC_SERVER_COMPRESSION_* */
  ulong compression_min_sz;   /* messages below this size are sent uncompressed */
  int   compression_level;    /* zstd compression level */

  /* policy */

  /* Analogous to stream_tx_queue_sz, but by number of messages instead of raw bytes.
     This allows an application to react to a slow client, and configure the application
     in terms of number of messages the client is leaving in the queue, rather than raw bytes. */
  ulong stream_tx_queue_msg_max; /* per-stream send queue capacity in messages. 0=disabled */

};

typedef struct fd_grpc_server_params fd_grpc_server_params_t;

/* fd_grpc_server_callbacks_t is the handler interface.  No pointer may
   be NULL.  The server is re-entrant from these callbacks: a handler
   may call fd_grpc_server_send, fd_grpc_server_finish, and
   fd_grpc_server_conn_close. */

struct fd_grpc_server_callbacks {

  /* conn_open reports a new connection.  Returns 0 to accept it, or
     non-zero to close it immediately. */

  int
  (* conn_open)( void *                  app_ctx,
                 fd_grpc_server_conn_t * conn );

  /* conn_close reports that a connection is gone.  Every stream on it
     has already been reported to stream_close. */

  void
  (* conn_close)( void *                  app_ctx,
                  fd_grpc_server_conn_t * conn );

  /* stream_hdr reports one request metadata header (a header that is
     neither an HTTP/2 pseudo-header nor consumed by the transport).
     name and value point to decoded bytes that are only valid for the
     duration of the call.  Issued before stream_open. */

  void
  (* stream_hdr)( void *                    app_ctx,
                  fd_grpc_server_stream_t * stream,
                  char const *              name,
                  ulong                     name_len,
                  char const *              value,
                  ulong                     value_len );

  /* stream_open reports a complete, valid set of request headers.
     path points to the :path value, and is empty if it was longer than
     FD_GRPC_SERVER_PATH_MAX.  Returns FD_GRPC_SERVER_ACCEPT_UNARY or
     FD_GRPC_SERVER_ACCEPT_STREAM to accept the call, or
     FD_GRPC_SERVER_REJECT to end it.  A rejecting handler may call
     fd_grpc_server_finish first to pick the status; otherwise the
     server responds UNIMPLEMENTED.  A rejected stream is not reported
     to stream_close. */

  int
  (* stream_open)( void *                    app_ctx,
                   fd_grpc_server_stream_t * stream,
                   char const *              path,
                   ulong                     path_len );

  /* stream_msg delivers one complete request message. */

  void
  (* stream_msg)( void *                    app_ctx,
                  fd_grpc_server_stream_t * stream,
                  uchar const *             msg,
                  ulong                     msg_sz );

  /* stream_half_close reports that the client will not send more
     messages. */

  void
  (* stream_half_close)( void *                    app_ctx,
                         fd_grpc_server_stream_t * stream );

  /* stream_writable reports that a send queue which answered
     FD_GRPC_SERVER_ERR_AGAIN has room for that message again. */

  void
  (* stream_writable)( void *                    app_ctx,
                       fd_grpc_server_stream_t * stream );

  /* stream_close reports that a stream accepted by stream_open is gone.
     reason is one of FD_GRPC_SERVER_CLOSE_*.  The handler must drop all
     references to stream. */

  void
  (* stream_close)( void *                    app_ctx,
                    fd_grpc_server_stream_t * stream,
                    int                       reason );

};

typedef struct fd_grpc_server_callbacks fd_grpc_server_callbacks_t;

FD_PROTOTYPES_BEGIN

/* fd_grpc_server_compression_level_max is the highest
   compression_level the codec accepts. */

int
fd_grpc_server_compression_level_max( void );

/* fd_grpc_server_params_default fills params with defaults suitable for
   a low volume control plane. */

fd_grpc_server_params_t *
fd_grpc_server_params_default( fd_grpc_server_params_t * params );

/* fd_grpc_server_{align,footprint} describe the memory region backing a
   server.  footprint returns 0 if params are out of bounds (logs
   warning).

   The region holds, in order: the server object, the connection array,
   the stream array (max_conn_cnt*max_stream_cnt entries, each
   embedding an fd_h2_stream_t), the per-connection receive/send rings
   and field block buffers, the per-stream request reassembly buffers
   and send queues, the large send slot pool, the header name matcher,
   the HPACK and frame scratch buffers, the codec output buffers, and
   the area for zstd contexts.  Note that zstd may vary a lot, from 663KiB at
   level 1 to 705MiB at level 22. */

FD_FN_CONST ulong
fd_grpc_server_align( void );

ulong
fd_grpc_server_footprint( fd_grpc_server_params_t const * params );

/* fd_grpc_server_new formats a memory region for use as a server.
   mem must be aligned to fd_grpc_server_align and have room for
   fd_grpc_server_footprint( params ) bytes.  callbacks and app_ctx are
   retained for the lifetime of the object.
   Returns mem on success, or NULL on failure (logs warning). */

void *
fd_grpc_server_new( void *                             mem,
                    fd_grpc_server_params_t const *    params,
                    fd_grpc_server_callbacks_t const * callbacks,
                    void *                             app_ctx );

fd_grpc_server_t *
fd_grpc_server_join( void * mem );

void *
fd_grpc_server_leave( fd_grpc_server_t * server );

void *
fd_grpc_server_delete( void * mem );

/* fd_grpc_server_listen creates a non-blocking listen socket bound to
   ip4_addr (network order) and port, and takes ownership of it.
   Returns the listen socket on success, or -1 on failure (logs
   warning). */

int
fd_grpc_server_listen( fd_grpc_server_t * server,
                       uint               ip4_addr,
                       ushort             port );

/* fd_grpc_server_fd_cnt returns the number of sockets the server
   currently owns: the listen socket, if any, followed by one socket per
   connection.  fd_grpc_server_fd returns socket idx, or -1 if idx is
   out of bounds.  The set changes whenever fd_grpc_server_poll runs. */

ulong
fd_grpc_server_fd_cnt( fd_grpc_server_t const * server );

int
fd_grpc_server_fd( fd_grpc_server_t const * server,
                   ulong                    idx );

/* fd_grpc_server_poll services the sockets the server owns: it accepts
   new connections, reads and writes as much as the kernel allows
   without blocking, and runs fd_grpc_server_service.  timeout_millis is
   passed to poll(2); 0 returns immediately, which is what a stem tile
   wants in before_credit.  Returns the number of sockets that were
   ready. */

int
fd_grpc_server_poll( fd_grpc_server_t * server,
                     int                timeout_millis );

/* fd_grpc_server_service runs the server's timers against the
   wallclock now_nanos and flushes pending sends into the HTTP/2 send
   rings.  fd_grpc_server_poll calls this; a caller that drives the
   server over its own transport calls it directly. */

void
fd_grpc_server_service( fd_grpc_server_t * server,
                        long               now_nanos );

/* fd_grpc_server_tx_pending returns 1 if any connection holds bytes
   that the kernel has not accepted yet.  An event loop that waits for
   readability only (a level triggered epoll set with EPOLLIN) uses
   this to keep polling until the backlog drains. */

int
fd_grpc_server_tx_pending( fd_grpc_server_t const * server );

/* fd_grpc_server_shutdown starts a graceful shutdown: every connection
   gets a GOAWAY, in-flight streams are finished with
   UNAVAILABLE("server is shutting down"), new streams are refused, and
   connections close once their send rings drain or a close timeout
   passes, whichever is first.  The server rejects new connections from
   this point on, though the listen socket stays open until
   fd_grpc_server_delete.  fd_grpc_server_is_idle returns 1 once no
   connection remains. */

void
fd_grpc_server_shutdown( fd_grpc_server_t * server );

int
fd_grpc_server_is_idle( fd_grpc_server_t const * server );

/* fd_grpc_server_conn_close closes a connection without waiting for its
   send ring to drain.  In-flight streams are reported to stream_close
   with FD_GRPC_SERVER_CLOSE_CONN_LOST. */

void
fd_grpc_server_conn_close( fd_grpc_server_conn_t * conn );

/* fd_grpc_server_conn_fd returns the connection's socket, or -1 if the
   connection has none: a direct transport connection, or one whose
   socket is already closed (which is the case in the conn_close
   callback; the kernel drops a closed socket from every epoll set it
   was in).  A tile that keeps the server's sockets in its own epoll
   set registers them from conn_open. */

int
fd_grpc_server_conn_fd( fd_grpc_server_conn_t const * conn );

/* fd_grpc_server_conn_{ctx,set_ctx} access the handler's per-connection
   pointer. */

void *
fd_grpc_server_conn_ctx( fd_grpc_server_conn_t const * conn );

void
fd_grpc_server_conn_set_ctx( fd_grpc_server_conn_t * conn,
                             void *                  ctx );

/* fd_grpc_server_send appends one response message to the stream's send
   queue.  The message is compressed if the client accepts zstd, the
   server has compression enabled, msg_sz is at least
   compression_min_sz, and FD_GRPC_SERVER_SEND_NO_COMPRESS is not set.
   The response headers are emitted before the first message.

   The bytes are copied, so msg may be reused on return.  The queue is
   drained into the connection subject to HTTP/2 flow control.

   A message that does not fit the stream's send queue takes a large
   send slot from the shared pool and is drained from there, between
   the queue bytes that were pending when it was sent and the ones
   sent after it, so that message order on the stream is the order
   they were sent in.  A stream holds one slot at a time: a second
   oversized message waits, while messages that fit the queue keep
   being accepted behind the first one.

   Returns FD_GRPC_SERVER_SUCCESS, or one of the FD_GRPC_SERVER_ERR_*
   codes.  ERR_AGAIN means the queue is full, or the message needs a
   large send slot and none is free (fd_grpc_server_msg_needs_large
   tells the two apart): the application decides whether to wait for
   stream_writable, to drop that message, or to end the call.
   ERR_TOOBIG means msg_sz is above max_msg_sz, or the message needs a
   large send slot and large_msg_slot_cnt is zero; neither changes with
   waiting.  Nothing is ever silently dropped. */

int
fd_grpc_server_send( fd_grpc_server_stream_t * stream,
                     void const *              msg,
                     ulong                     msg_sz,
                     uint                      flags );

/* fd_grpc_server_finish ends a call with the given gRPC status.
   grpc_msg points to msg_len bytes of free-form UTF-8 text (may be
   NULL), which is percent-encoded into the grpc-message trailer and
   truncated to FD_GRPC_SERVER_MSG_MAX bytes.  Messages already queued
   are sent first; trailers follow.  If nothing was sent yet, the
   response is a Trailers-Only reply.  Further sends on the stream fail
   with FD_GRPC_SERVER_ERR_CLOSED. */

void
fd_grpc_server_finish( fd_grpc_server_stream_t * stream,
                       uint                      grpc_status,
                       char const *              grpc_msg,
                       ulong                     msg_len );

/* fd_grpc_server_stream_{ctx,set_ctx} access the handler's per-stream
   pointer. */

void *
fd_grpc_server_stream_ctx( fd_grpc_server_stream_t const * stream );

void
fd_grpc_server_stream_set_ctx( fd_grpc_server_stream_t * stream,
                               void *                    ctx );

/* fd_grpc_server_stream_id returns the HTTP/2 stream ID. */

uint
fd_grpc_server_stream_id( fd_grpc_server_stream_t const * stream );

/* fd_grpc_server_stream_conn returns the stream's connection. */

fd_grpc_server_conn_t *
fd_grpc_server_stream_conn( fd_grpc_server_stream_t const * stream );

/* fd_grpc_server_stream_tx_free_sz returns the number of message bytes
   that the stream's send queue would accept right now, ignoring
   compression and the large send path.  Zero means the next send of a
   queue sized message returns ERR_AGAIN. */

ulong
fd_grpc_server_stream_tx_free_sz( fd_grpc_server_stream_t const * stream );

/* fd_grpc_server_msg_needs_large returns 1 if a message of msg_sz
   bytes is too large for the stream's send queue and so needs a slot
   of the large send pool.  An application that got ERR_AGAIN asks this
   to tell the two reasons apart: a queue that is full drains on its
   own, a pool that is busy may not before the message is stale. */

FD_FN_PURE int
fd_grpc_server_msg_needs_large( fd_grpc_server_stream_t const * stream,
                                ulong                           msg_sz );

/* fd_grpc_server_stream_tx_queue_hi returns the most bytes the
   stream's send queue has held at once, which is how close the call
   came to being closed for falling behind. */

ulong
fd_grpc_server_stream_tx_queue_hi( fd_grpc_server_stream_t const * stream );

/* fd_grpc_server_metrics_t counts events since fd_grpc_server_new. */

struct fd_grpc_server_metrics {
  ulong conn_open_cnt;
  ulong conn_close_cnt;
  ulong stream_open_cnt;
  ulong stream_reject_cnt;
  ulong rx_msg_cnt;
  ulong rx_byte_cnt;
  ulong tx_msg_cnt;
  ulong tx_msg_compressed_cnt;
  ulong tx_byte_cnt;             /* message bytes handed to fd_grpc_server_send */
  ulong tx_byte_cnt_wire;        /* message bytes after compression */
  ulong tx_queue_full_cnt;
  ulong tx_large_msg_cnt;        /* messages sent through a large send slot */
  ulong tx_large_busy_cnt;       /* sends refused for want of a large send slot */
  ulong deadline_exceeded_cnt;
  ulong idle_timeout_cnt;
  ulong handshake_timeout_cnt;
  ulong large_drain_timeout_cnt; /* streams aborted for a stalled large message */
  ulong request_error_cnt;       /* malformed or unsupported requests */
  ulong accept_error_cnt;        /* accept4 failures */
  ulong poll_error_cnt;          /* poll failures */
  ulong reset_flood_cnt;         /* connections closed for resetting streams too fast */
};

typedef struct fd_grpc_server_metrics fd_grpc_server_metrics_t;

fd_grpc_server_metrics_t const *
fd_grpc_server_metrics( fd_grpc_server_t const * server );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_server_h */
