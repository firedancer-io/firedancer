#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_client_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_client_h

/* fd_grpc_client.h provides an API for dispatching unary and server-
   streaming gRPC requests over HTTP/2+TLS. */

#include "fd_grpc_codec.h"
#include "../../ballet/nanopb/pb_firedancer.h" /* pb_msgdesc_t */
#if FD_HAS_OPENSSL
#include <openssl/types.h> /* SSL */
#endif

struct fd_grpc_client_private;
typedef struct fd_grpc_client_private fd_grpc_client_t;

struct fd_grpc_h2_stream;
typedef struct fd_grpc_h2_stream fd_grpc_h2_stream_t;

/* FD_GRPC_CLIENT_MAX_STREAMS specifies the max number of inflight
   unary and server-streaming requests.  Note that grpc_client does
   not scale well to large numbers due to O(n) algorithms. */

#define FD_GRPC_CLIENT_MAX_STREAMS 8

/* FD_GRPC_DEADLINE_* identify different types of request deadlines. */

#define FD_GRPC_DEADLINE_HEADER 1 /* deadline by which Response-Headers are recevied */
#define FD_GRPC_DEADLINE_RX_END 2 /* deadline by which 'end of stream' must have been reached */

/* fd_grpc_client_metrics_t hold counters that are incremented by a
   grpc_client. */

struct fd_grpc_client_metrics {

  /* wakeup_cnt counts the number of times the gRPC client was polled
     for I/O. */
  ulong wakeup_cnt;

  /* stream_err_cnt counts the number of survivable stream errors.
     These include out-of-memory conditions and decode failures. */
  ulong stream_err_cnt;

  /* conn_err_cnt counts the number of connection errors that resulted
     in connection termination.  These include protocol and I/O errors. */
  ulong conn_err_cnt;

  /* stream_chunks_tx_cnt increments whenever a DATA frame containing
     request bytes is sent.  stream_chunks_tx_bytes counts the number of
     stream bytes sent. */
  ulong stream_chunks_tx_cnt;
  ulong stream_chunks_tx_bytes;

  /* stream_chunks_rx_cnt increments whenever a DATA frame containing
     response bytes is received.  stream_chunks_rx_bytes counts the
     number of stream bytes received. */
  ulong stream_chunks_rx_cnt;
  ulong stream_chunks_rx_bytes;

  /* requests_sent increments whenever a gRPC request finished sending. */
  ulong requests_sent;

  /* streams_active is the number of streams not in 'closed' state. */
  long streams_active;

  /* rx_wait_ticks_cum is the cumulative time in ticks that incoming
     gRPC messages were in a "waiting" state.  The waiting state begins
     when the first byte of a HTTP/2 frame is received, and ends when
     all gRPC message bytes are received.

     This is a rough measure of server-to-client congestion.  On a
     healthy connection, this value should be close to zero. */
  long rx_wait_ticks_cum;

  /* tx_wait_ticks_cum is the cumulative time in ticks that an outgoing
     message was in a "waiting" state.  The waiting state begins when
     a message is ready to be sent, and ends when all message bytes were
     handed to the TCP layer.

     This is a rough measure of client-to-server congestion, which can
     be caused by the TCP server receive window, TCP client congestion
     control, or HTTP/2 server flow control.  On a healthy connection,
     this value should be close to zero. */
  long tx_wait_ticks_cum;

};

typedef struct fd_grpc_client_metrics fd_grpc_client_metrics_t;

/* fd_grpc_client_callbacks_t is a virtual function table containing
   grpc_client->app callbacks. */

struct fd_grpc_client_callbacks {

  /* conn_established is called when the initial HTTP/2 SETTINGS
     exchange concludes.  Technically, requests can be sent before this
     point, though. */

  void
  (* conn_established)( void * app_ctx );

  /* conn_dead is called when the HTTP/2 connection ends.  To recover
     from this condition, call fd_grpc_client_reset(). */

  void
  (* conn_dead)( void * app_ctx,
                 uint   h2_err,
                 int    closed_by );

  /* tx_complete marks the completion of a tx operation. */

  void
  (* tx_complete)( void * app_ctx,
                   ulong  request_ctx );

  /* rx_start signals that the server sent back a response header
     indicating success.  rx_start is always called before the first
     call to rx_msg for that request_ctx. */

  void
  (* rx_start)( void * app_ctx,
                ulong  request_ctx );

  /* rx_msg delivers a gRPC message.  May be called multiple times for
     the same request (server streaming). */

  void
  (* rx_msg)( void *       app_ctx,
              void const * protobuf,
              ulong        protobuf_sz,
              ulong        request_ctx );

  /* rx_end indicates that no more rx_msg callbacks will be delivered
     for a request. */

  void
  (* rx_end)( void *                app_ctx,
              ulong                 request_ctx,
              fd_grpc_resp_hdrs_t * resp );

  /* rx_timeout indicates that a request deadline was exceeded.
     deadline_kind indicates which timer fired. */

  void
  (* rx_timeout)( void * app_ctx,
                  ulong  request_ctx,
                  int    deadline_kind );

  /* ping_ack delivers an acknowledgement of a PING that was previously
     sent by fd_h2_tx_ping. */

  void
  (* ping_ack)( void * app_ctx );

};

typedef struct fd_grpc_client_callbacks fd_grpc_client_callbacks_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

ulong
fd_grpc_client_align( void );

ulong
fd_grpc_client_footprint( ulong buf_max );

fd_grpc_client_t *
fd_grpc_client_new( void *                             mem,
                    fd_grpc_client_callbacks_t const * callbacks,
                    fd_grpc_client_metrics_t *         metrics,
                    void *                             app_ctx,
                    ulong                              buf_max,
                    ulong                              rng_seed );

void *
fd_grpc_client_delete( fd_grpc_client_t * client );

/* fd_grpc_client_reset cancels all inflight requests and abandons the
   HTTP/2 client connection.  Config params are kept intact (e.g. host,
   port, version). */

void
fd_grpc_client_reset( fd_grpc_client_t * client );

/* fd_grpc_client_set_version sets the gRPC client's version string
   (relayed via user-agent header).  No reference to the provided string
   is kept (the content is copied out to the client object).  version
   does not have to be null-terminated.  version_len must be
   FD_GRPC_CLIENT_VERSION_LEN_MAX or less, otherwise a warning is logged
   and the client's version string remains unchanged. */

#define FD_GRPC_CLIENT_VERSION_LEN_MAX (63UL)

void
fd_grpc_client_set_version( fd_grpc_client_t * client,
                            char const *       version,
                            ulong              version_len );

/* fd_grpc_client_set_authority sets the authority header to the
   specified hostname and port number.  host_len should be <= 255,
   otherwise host is truncated. */

void
fd_grpc_client_set_authority( fd_grpc_client_t * client,
                              char const *       host,
                              ulong              host_len,
                              ushort             port );

#if FD_HAS_OPENSSL

/* fd_grpc_client_rxtx_ossl drives I/O against the SSL object
   (SSL_read_ex and SSL_write_ex).

   This function currently copies back-and-forth between SSL and
   fd_h2 rbuf.  This could be improved by adding an interface to allow
   OpenSSL->h2 or h2->OpenSSL writes to directly place data into the
   target buffer.

   Returns 1 on success and 0 if there is an unrecoverable SSL error. */

int
fd_grpc_client_rxtx_ossl( fd_grpc_client_t * client,
                          SSL *              ssl,
                          int *              charge_busy );

#endif /* FD_HAS_OPENSSL */

/* fd_grpc_client_rxtx_socket drives I/O against a TCP socket.
   (recvmsg(2) and sendmsg(2)).  Uses MSG_NOSIGNAL|MSG_DONTWAIT flags.

   Returns -1 if an error was encountered, and errno will be set.
   Otherwise, returns 0. */

int
fd_grpc_client_rxtx_socket( fd_grpc_client_t * client,
                            int                sock_fd,
                            int *              charge_busy );

/* fd_grpc_client_request_start queues a gRPC request for send.  The
   request includes one Protobuf message (unary request).  The client
   can only write one request payload at a time, but can have multiple
   requests pending for responses.

   path is the HTTP request path which usually follows the pattern
   '/path.to.package/Service.Function'.  If auth_token_sz is greater
   than zero, adds a request header 'authorization: Bearer *auth_token'.

   request_ctx is an arbitrary number used to identify the request.  It
   echoes in callbacks.

   fields points to a generated nanopb descriptor.  message points to a
   generated nanopb struct that the user filled in with info.  Calls
   pb_encode() internally.

   auth_token is an optional authorization header.  The header value is
   prepended with "Bearer ".  auth_token_sz==0 omits the auth header.

   is_streaming: If 0, this is a unary request and the stream is closed
   after sending the first message (END_STREAM flag set).  If non-zero,
   this is a client streaming request and the stream remains open for
   additional messages via fd_grpc_client_stream_send_msg().  The stream
   must be explicitly closed with fd_grpc_client_stream_close().

   Conditions for starting send:
   - The connection is not dead and the HTTP/2 handshake is complete.
   - Client has quota to open a new stream (MAX_CONCURRENT_STREAMS)
   - There is no other request still sending.
   - The message serialized size does not exceed buf_max (set in
     fd_grpc_client_new())
   - rbuf_tx is empty.  (HTTP/2 frames all flushed out to sockets) */

fd_grpc_h2_stream_t *
fd_grpc_client_request_start(
    fd_grpc_client_t *   client,
    char const *         path,
    ulong                path_len, /* in [0,128) */
    ulong                request_ctx,
    pb_msgdesc_t const * fields,
    void const *         message,
    char const *         auth_token,
    ulong                auth_token_sz,
    int                  is_streaming
);

fd_grpc_h2_stream_t *
fd_grpc_client_request_start1(
    fd_grpc_client_t *   client,
    char const *         path,
    ulong                path_len, /* in [0,128) */
    ulong                request_ctx,
    uchar const *        protobuf,
    ulong                protobuf_sz,
    char const *         auth_token,
    ulong                auth_token_sz,
    int                  is_streaming );

/* fd_grpc_client_stream_send_msg sends an additional message on an
   already-open client streaming request.  This function can only be
   called after fd_grpc_client_request_start() was called with
   is_streaming=1.

   Returns 1 on success, 0 if the operation failed (connection dead,
   buffers blocked, or encoding failure).

   Conditions for sending:
   - The connection is alive
   - No other send operation is in progress
   - rbuf_tx is empty
   - The message serialized size does not exceed buf_max */

int
fd_grpc_client_stream_send_msg(
    fd_grpc_client_t *    client,
    fd_grpc_h2_stream_t * stream,
    pb_msgdesc_t const *  fields,
    void const *          message
);

int
fd_grpc_client_stream_send_msg1(
    fd_grpc_client_t *    client,
    fd_grpc_h2_stream_t * stream,
    uchar const *         protobuf,
    ulong                 protobuf_sz );

/* fd_grpc_client_stream_close explicitly closes a client streaming
   request by sending an empty DATA frame with the END_STREAM flag.
   This signals to the server that no more messages will be sent.

   This function should be called after all messages have been sent via
   fd_grpc_client_stream_send_msg() to complete the client stream.

   Returns 1 on success, 0 if the operation failed (connection dead or
   buffers blocked).

   Conditions for closing:
   - The connection is alive
   - No other send operation is in progress
   - rbuf_tx is empty */

int
fd_grpc_client_stream_close(
    fd_grpc_client_t *    client,
    fd_grpc_h2_stream_t * stream
);

/* fd_grpc_client_deadline_set sets a request deadline (used to
   configure timeouts).  deadline_kind is FD_GRPC_DEADLINE_*.  Logs
   error and aborts app if deadline_kind is unsupported.

   Behavior for different deadline kinds:
   - HEADER: Deadline by which gRPC Response-Headers must have been
             received
   - RX_END: Deadline by which the response stream must have been ended.
             For unary responses, this is the point at which the message
             has been fully received.  For server-streaming responses,
             it is the point at which the last message has been
             received, and there are no more messages remaining.  (Under
             the hood, this is indicated by the HTTP/2 END_STREAM flag.) */

void
fd_grpc_client_deadline_set( fd_grpc_h2_stream_t * stream,
                             int                   deadline_kind,
                             long                  ts_nanos );

/* fd_grpc_client_is_connected returns 1 if HTTP/2 SETTINGS were
   exchanged, the TLS handshake is complete (if applicable), and the
   conn hasn't died.  Otherwise, returns 0. */

int
fd_grpc_client_is_connected( fd_grpc_client_t * client );

/* fd_grpc_client_request_is_blocked returns 1 if a call to
   fd_grpc_client_request_start would certainly fail.  Reasons include
   SSL / HTTP/2 handshake not complete, or buffers blocked. */

int
fd_grpc_client_request_is_blocked( fd_grpc_client_t * client );

int
fd_grpc_client_request_stream_busy( fd_grpc_client_t * client );

/* Pointers to internals for testing */

fd_h2_rbuf_t *
fd_grpc_client_rbuf_tx( fd_grpc_client_t * client );

fd_h2_rbuf_t *
fd_grpc_client_rbuf_rx( fd_grpc_client_t * client );

fd_h2_conn_t *
fd_grpc_client_h2_conn( fd_grpc_client_t * client );

extern fd_h2_callbacks_t const fd_grpc_client_h2_callbacks;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_client_h */
