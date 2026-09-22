#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_server_private_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_server_private_h

/* fd_grpc_server_private.h internals of fd_grpc_server */

#include "fd_grpc_server.h"
#include "../h2/fd_h2.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <zstd_errors.h>

/* FD_GRPC_SERVER_ZSTD_MEM is the size of the arena that backs the
   server two zstd contexts. */

#define FD_GRPC_SERVER_ZSTD_MEM(level)                              \
  ( fd_ulong_align_up( ZSTD_estimateCCtxSize( (level) ), 128UL ) +  \
    fd_ulong_align_up( ZSTD_estimateDCtxSize(),          128UL ) )

/* FD_GRPC_SERVER_HDR_BUF_MAX bounds the HPACK encoding of a response
   HEADERS or trailers field block: the status, content-type, and
   encoding headers fit in under 128 bytes, and grpc-message expands to
   at most three bytes per input byte plus a name and length prefix. */

#define FD_GRPC_SERVER_HDR_BUF_MAX (128UL + 3UL*FD_GRPC_SERVER_MSG_MAX + 32UL)

/* Header IDs for the request header matcher. */

#define FD_GRPC_SERVER_HDR_TIMEOUT          (1)
#define FD_GRPC_SERVER_HDR_ENCODING         (2)
#define FD_GRPC_SERVER_HDR_ACCEPT_ENCODING  (3)
#define FD_GRPC_SERVER_HDR_TE               (4)
#define FD_GRPC_SERVER_HDR_CONNECTION       (5)
#define FD_GRPC_SERVER_HDR_KEEP_ALIVE       (6)
#define FD_GRPC_SERVER_HDR_PROXY_CONNECTION (7)
#define FD_GRPC_SERVER_HDR_UPGRADE          (8)

/* Stream states */

#define FD_GRPC_SERVER_STREAM_FREE    (0) /* slot is unused */
#define FD_GRPC_SERVER_STREAM_HEADERS (1) /* reading the request field block */
#define FD_GRPC_SERVER_STREAM_ACTIVE  (2) /* handler owns the call */
#define FD_GRPC_SERVER_STREAM_FINISH  (3) /* trailers queued */

/* Stream flags */

#define FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN    (1U<< 0) /* handler accepted the call */
#define FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS   (1U<< 1) /* response HEADERS emitted */
#define FD_GRPC_SERVER_STREAM_FLAG_UNARY       (1U<< 2) /* deadline enforced */
#define FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD     (1U<< 3) /* client accepts zstd */
#define FD_GRPC_SERVER_STREAM_FLAG_RX_ZSTD     (1U<< 4) /* request declares zstd */
#define FD_GRPC_SERVER_STREAM_FLAG_RX_FIN      (1U<< 5) /* client sent END_STREAM */
#define FD_GRPC_SERVER_STREAM_FLAG_TX_BLOCKED  (1U<< 6) /* a send returned ERR_AGAIN */
#define FD_GRPC_SERVER_STREAM_FLAG_RX_DROP     (1U<< 7) /* discard remaining request bytes */
#define FD_GRPC_SERVER_STREAM_FLAG_HDRS_DONE   (1U<< 8) /* request headers were processed */
#define FD_GRPC_SERVER_STREAM_FLAG_RX_MSG_ZSTD (1U<< 9) /* message being reassembled is zstd coded */
#define FD_GRPC_SERVER_STREAM_FLAG_TX_LARGE    (1U<<10) /* a send is waiting for a large send slot */

/* Connection flags */

#define FD_GRPC_SERVER_CONN_FLAG_GOAWAY   (1U<<0) /* GOAWAY was sent */
#define FD_GRPC_SERVER_CONN_FLAG_CLOSING  (1U<<1) /* close once the send ring drains */
#define FD_GRPC_SERVER_CONN_FLAG_WND_INIT (1U<<2) /* connection receive window was granted */

/* fd_grpc_server_large_t is one slot of the large send pool: a framed
   response message too big for a stream's send queue, drained into
   DATA frames from off onwards.  A slot belongs to at most one stream
   at a time. */

struct fd_grpc_server_large {
  uchar * buf;  /* large_slot_sz bytes */
  ulong   sz;   /* framed bytes in buf */
  ulong   off;  /* bytes already sent */
  int     busy;
};

typedef struct fd_grpc_server_large fd_grpc_server_large_t;

struct fd_grpc_server_stream {
  fd_h2_stream_t h2[1]; /* first member: see fd_grpc_server_stream_from_h2 */

  fd_grpc_server_conn_t * conn;
  void *                  ctx;

  fd_h2_rbuf_t tx_queue[1]; /* framed response messages awaiting DATA frames */
  long         large_idx;   /* large send slot the stream holds, -1 if none */
  long         large_nanos; /* last time the large message made progress */

  /* The messages the send queue holds, and the bytes of the oldest of
     them that have not gone out yet.  The next message's length prefix
     is at the front of the queue once the oldest one has drained, so
     the count needs no per-message bookkeeping of its own. */
  ulong tx_msg_pending;
  ulong tx_head_rem;
  ulong tx_queue_hi;        /* the most bytes the queue has held at once */

  /* Queue bytes that were pending when the stream claimed its large
     send slot, and so go out in front of it.  Everything queued after
     that goes out behind it, which is the order the messages were
     sent in. */
  ulong tx_pre_slot;

  uchar * msg_buf;          /* request message reassembly, max_request_msg_sz bytes */
  ulong   msg_sz;           /* request bytes in msg_buf */
  ulong   msg_rem;          /* request bytes still expected for this message */
  uchar   msg_hdr[ 5 ];
  ulong   msg_hdr_sz;

  long  deadline;           /* wallclock nanos, LONG_MAX if the client set none */
  long  resp_deadline;      /* deadline for the first response byte, LONG_MAX if none */
  long  tx_wnd_debt;        /* send window owed after a SETTINGS_INITIAL_WINDOW_SIZE shrink */
  ulong tx_blocked_sz;      /* message size that hit a full queue */

  uint  state;
  uint  flags;
  uint  fin_status;
  uint  fin_msg_len;
  char  fin_msg[ FD_GRPC_SERVER_MSG_MAX ];

  ushort path_len;
  char   path[ FD_GRPC_SERVER_PATH_MAX ];
};

struct fd_grpc_server_conn {
  fd_h2_conn_t h2[1];

  fd_grpc_server_t *        server;
  fd_grpc_server_stream_t * stream; /* max_stream_cnt entries */
  void *                    ctx;

  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t rbuf_tx[1];

  int  sock;               /* socket, or -1 for the direct transport */
  uint preface_rem;        /* client preface bytes not yet received */
  uint active;             /* 1 if the slot is in use */
  uint flags;
  uint rr_idx;             /* round-robin cursor over stream slots */

  long open_nanos;         /* time the connection was accepted */
  long rx_nanos;           /* last time bytes arrived */
  long tx_nanos;           /* last time queued bytes reached the socket */
  long reset_nanos;        /* start of the current peer reset window */
  ulong reset_cnt;         /* peer stream resets counted in that window */
  long close_nanos;        /* deadline to release a closing connection */
};

struct fd_grpc_server {
  ulong magic;

  fd_grpc_server_params_t            params;
  fd_grpc_server_callbacks_t const * callbacks;
  void *                             app_ctx;

  fd_grpc_server_conn_t * conn;   /* max_conn_cnt entries */
  fd_h2_hdr_matcher_t *   matcher;

  fd_grpc_server_large_t * large;         /* large_msg_slot_cnt entries */
  ulong                    large_slot_sz; /* max_msg_sz + sizeof(fd_grpc_hdr_t) */

  uchar * frame_scratch; /* max_frame_sz bytes */
  uchar * hpack_scratch; /* 2*max_frame_sz + 2*FD_HPACK_DTABLE_SZ_MAX bytes */
  uchar * compress_out;   /* ZSTD_compressBound(stream_tx_queue_sz) bytes */
  ulong   compress_out_sz;
  uchar * decompress_out; /* max_request_msg_sz bytes */

  void *  pollfd_mem;   /* 16*(max_conn_cnt+1) bytes of poll(2) descriptors */

  /* The two zstd contexts live in zarena, which is sized by
     FD_GRPC_SERVER_ZSTD_MEM.  Both are NULL when compression is off,
     which is also how the rest of the server asks whether it can
     compress and decompress. */
  uchar *     zarena;
  ulong       zarena_sz;
  ZSTD_CCtx * cctx;
  ZSTD_DCtx * dctx;

  int   listen_fd;
  int   shutdown;
  ulong conn_cnt;
  long  now; /* wallclock of the most recent service call */

  fd_grpc_server_metrics_t metrics;
};

#define FD_GRPC_SERVER_MAGIC (0xf17eda2547e2c000UL) /* firedancer grpc srv */

FD_PROTOTYPES_BEGIN

/* fd_grpc_server_conn_open_direct claims a connection slot that is not
   backed by a socket.  The caller feeds bytes with
   fd_grpc_server_conn_push_rx and removes them with
   fd_grpc_server_conn_pop_tx.  Returns NULL if no slot is free or the
   handler rejected the connection. */

fd_grpc_server_conn_t *
fd_grpc_server_conn_open_direct( fd_grpc_server_t * server,
                                 long               now_nanos );

/* fd_grpc_server_conn_push_rx hands sz bytes of received data to the
   connection and runs the HTTP/2 state machine.  Returns the number of
   bytes consumed, which is less than sz if the receive ring filled
   up. */

ulong
fd_grpc_server_conn_push_rx( fd_grpc_server_conn_t * conn,
                             void const *            data,
                             ulong                   sz,
                             long                    now_nanos );

/* fd_grpc_server_conn_pop_tx copies up to out_sz pending bytes out of
   the connection's send ring.  Returns the number of bytes copied. */

ulong
fd_grpc_server_conn_pop_tx( fd_grpc_server_conn_t * conn,
                            void *                  out,
                            ulong                   out_sz );

/* fd_grpc_server_conn_is_open returns 1 while the connection slot is in
   use. */

int
fd_grpc_server_conn_is_open( fd_grpc_server_conn_t const * conn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_server_private_h */
