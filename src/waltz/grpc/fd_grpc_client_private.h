#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_client_private_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_client_private_h

#include "fd_grpc_client.h"
#include "../grpc/fd_grpc_codec.h"
#include "../h2/fd_h2.h"

/* fd_grpc_h2_stream_t holds the state of a gRPC request. */

struct fd_grpc_h2_stream {
  fd_h2_stream_t s;

  ulong request_ctx;
  uint  next;

  /* Buffer response headers */
  fd_grpc_resp_hdrs_t hdrs;

  /* Buffer an incoming gRPC message */
  uchar msg_buf[ sizeof(fd_grpc_hdr_t)+FD_GRPC_CLIENT_MSG_SZ_MAX ];
  uint  hdrs_received : 1;
  ulong msg_buf_used; /* including header */
  ulong msg_sz;       /* size of next message */
};

typedef struct fd_grpc_h2_stream fd_grpc_h2_stream_t;

/* Declare a pool of stream objects.

   While only one stream is used to write requests out to the wire at a
   time, a gRPC client might be waiting for multiple responses. */

#define POOL_NAME fd_grpc_h2_stream_pool
#define POOL_T fd_grpc_h2_stream_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

static inline fd_grpc_h2_stream_t *
fd_grpc_h2_stream_upcast( fd_h2_stream_t * stream ) {
  return (fd_grpc_h2_stream_t *)( (ulong)stream - offsetof(fd_grpc_h2_stream_t, s) );
}

/* I/O paths

   RX path
   - fd_grpc_client_rxtx
   - calls fd_h2_rbuf_ssl_read
   - calls SSL_read_ex
   - calls recv(2)

   TX path
   - fd_grpc_client_rxtx
   - calls fd_h2_rbuf_ssl_write
   - calls SSL_write_ex
   - calls send(2) */

#include "../../waltz/h2/fd_h2_rbuf_ossl.h"

/* gRPC client internal state.  Quick overview:

   - The client maintains exactly one gRPC connection.
   - This conn includes a TCP socket, SSL handle, and a fd_h2 conn
     (and accompanying buffers).
   - The client object dies when the connection dies.

   - The client manages a small pool of stream objects.
   - Each stream has one of 3 states:
     - IDLE: marked free in stream_pool
     - OPEN: sending request data. marked used in stream_pool, present
          in stream_ids/streams, referred to by request_stream, has
          associated tx_op object.
     - CLOSE_TX: request sent, waiting for response. marked used in
          stream_pool,  present in stream_ids/streams.
    - Only 1 stream can be in OPEN state.

   Regular state transitions:

   - IDLE->OPEN: Client acquires a stream object and starts a tx_op
     See fd_grpc_client_request_start
   - OPEN->CLOSE_TX: tx_op finished writing request data and is now
     waiting for the response.  tx_op object finalized.
     See fd_grpc_client_request_continue1
   - CLOSE_TX->IDLE: All response data arrived.  Stream object
     deallocated.

   Irregular state transitions:

   - CLOSE_TX->IDLE: Server aborts stream before request is fully sent.
   - OPEN->IDLE: Server aborts stream before response is received. */

struct fd_grpc_client_private {
  fd_grpc_client_callbacks_t const * callbacks;
  void *                             ctx;

  fd_h2_hdr_matcher_t matcher[1];

  /* HTTP/2 connection */
  fd_h2_conn_t conn[1];
  fd_h2_rbuf_t frame_rx[1]; /* unencrypted HTTP/2 RX frame buffer */
  fd_h2_rbuf_t frame_tx[1]; /* unencrypted HTTP/2 TX frame buffer */

  /* TLS connection */
  uint  ssl_hs_done : 1;
  uint  h2_hs_done : 1;

  /* Inflight request
     Non-NULL until a gRPC request is fully written out. */
  fd_grpc_h2_stream_t * request_stream;
  fd_h2_tx_op_t         request_tx_op[1];

  /* Stream pool */
  fd_grpc_h2_stream_t * stream_pool;

  /* Stream map */
  /* FIXME pull this into a fd_map_tiny.c? */
  uint                  stream_ids[ FD_GRPC_CLIENT_MAX_STREAMS ];
  fd_grpc_h2_stream_t * streams   [ FD_GRPC_CLIENT_MAX_STREAMS ];
  ulong                 stream_cnt;

  /* Buffers */
  uchar * nanopb_tx;
  uchar * frame_scratch;

  /* Version string */
  uchar version_len;
  char  version[ FD_GRPC_CLIENT_VERSION_LEN_MAX ];

  fd_grpc_client_metrics_t * metrics;
};

struct fd_grpc_client_bufs {
  /* Nanopb serialize buffer */
  uchar nanopb_tx[ FD_GRPC_CLIENT_MSG_SZ_MAX ];

  /* Frame buffers */
  uchar frame_rx_buf[ FD_GRPC_CLIENT_BUFSZ ];
  uchar frame_tx_buf[ FD_GRPC_CLIENT_BUFSZ ];
  uchar frame_scratch[ FD_GRPC_CLIENT_BUFSZ ];
};

typedef struct fd_grpc_client_bufs fd_grpc_client_bufs_t;

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_client_private_h */
