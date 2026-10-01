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
#define FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW    (1U<< 6) /* closed for falling behind */
#define FD_GRPC_SERVER_STREAM_FLAG_RX_DROP     (1U<< 7) /* discard remaining request bytes */
#define FD_GRPC_SERVER_STREAM_FLAG_HDRS_DONE   (1U<< 8) /* request headers were processed */
#define FD_GRPC_SERVER_STREAM_FLAG_RX_MSG_ZSTD (1U<< 9) /* message being reassembled is zstd coded */
#define FD_GRPC_SERVER_STREAM_FLAG_TX_TRUNC    (1U<<10) /* a message was cut off, so trailers cannot follow */

/* Connection flags */

#define FD_GRPC_SERVER_CONN_FLAG_GOAWAY   (1U<<0) /* GOAWAY was sent */
#define FD_GRPC_SERVER_CONN_FLAG_CLOSING  (1U<<1) /* close once the send ring drains */
#define FD_GRPC_SERVER_CONN_FLAG_WND_INIT (1U<<2) /* connection receive window was granted */
#define FD_GRPC_SERVER_CONN_FLAG_HTTP1    (1U<<3) /* peer spoke HTTP/1.1: one page or one gRPC-Web call, then the connection ends */

/* fd_grpc_server_tx_ref_t is one gRPC message of a stream's pending
   output, length prefix included: len bytes at virtual offset off of
   the send ring, which never wrap around its physical end. */

struct fd_grpc_server_tx_ref {
  ulong off;
  ulong len;
};

typedef struct fd_grpc_server_tx_ref fd_grpc_server_tx_ref_t;

struct fd_grpc_server_stream {
  fd_h2_stream_t h2[1]; /* first member: see fd_grpc_server_stream_from_h2 */

  fd_grpc_server_conn_t * conn;
  void *                  ctx;

  /* Pending output, as references into the server's send ring.  refs
     is a ring of stream_tx_ref_max entries; ref_idx is the oldest one
     and ref_written how many of its bytes are already framed. */
  fd_grpc_server_tx_ref_t * refs;
  ulong ref_idx;
  ulong ref_cnt;
  ulong ref_written;
  ulong ref_hi;             /* the most references the stream has held at once */

  /* Slot in the server's treap of streams with pending output, keyed
     by the offset of the oldest reference. */
  uint treap_parent;
  uint treap_left;
  uint treap_right;
  uint treap_prio;
  uint treap_next;
  uint treap_prev;

  uchar * msg_buf;          /* request message reassembly, max_request_msg_sz bytes */
  ulong   msg_sz;           /* request bytes in msg_buf */
  ulong   msg_rem;          /* request bytes still expected for this message */
  uchar   msg_hdr[ 5 ];
  ulong   msg_hdr_sz;

  long  deadline;           /* wallclock nanos, LONG_MAX if the client set none */
  long  resp_deadline;      /* deadline for the first response byte, LONG_MAX if none */
  long  tx_wnd_debt;        /* send window owed after a SETTINGS_INITIAL_WINDOW_SIZE shrink */

  uint  state;
  uint  flags;
  uint  fin_status;
  uint  fin_msg_len;
  char  fin_msg[ FD_GRPC_SERVER_MSG_MAX ];

  ushort path_len;
  char   path[ FD_GRPC_SERVER_PATH_MAX ];
};

struct fd_grpc_server_conn {
  fd_h2_conn_t      h2[1];
  fd_hpack_dtable_t rx_dtable[1]; /* HPACK dynamic table for inbound field blocks */

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

  fd_grpc_server_conn_t *   conn;   /* max_conn_cnt entries */
  fd_grpc_server_stream_t * stream; /* max_conn_cnt*max_stream_cnt entries, the treap's pool */
  fd_h2_hdr_matcher_t *     matcher;
  void *                    stream_treap; /* streams with pending output, slowest first */

  /* The send ring.  Every response byte of every stream is staged here
     once and referenced from the streams that carry it.  stage_off is
     the virtual offset of the message being staged and only ever
     grows; a byte at virtual offset o lives at tx_ring[ o%tx_ring_sz ]. */
  uchar * tx_ring;
  ulong   tx_ring_sz;
  ulong   stage_off;
  ulong   stage_len;

  uchar * frame_scratch; /* max_frame_sz bytes */
  uchar * hpack_scratch; /* 2*max_frame_sz + 2*FD_HPACK_DTABLE_SZ_MAX bytes */
  uchar * compress_out;   /* ZSTD_compressBound(max_msg_sz) bytes */
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

/* FD_GRPC_WEB_HEAD_MAX bounds the head of an HTTP/1.1 response */

#define FD_GRPC_WEB_HEAD_MAX (256UL)

FD_PROTOTYPES_BEGIN

/* Server internals that fd_grpc_web.c drives a call with */

fd_grpc_server_stream_t * fd_grpc_server_stream_acquire( fd_grpc_server_conn_t * conn );
void fd_grpc_server_stream_start ( fd_grpc_server_stream_t * stream );
void fd_grpc_server_stream_end   ( fd_grpc_server_stream_t * stream, int reason );
void fd_grpc_server_rx_data      ( fd_grpc_server_stream_t * stream, uchar const * data, ulong data_sz );
void fd_grpc_server_rx_fin       ( fd_grpc_server_stream_t * stream );
void fd_grpc_server_ref_advance  ( fd_grpc_server_stream_t * stream, ulong sz );
void fd_grpc_server_conn_closing ( fd_grpc_server_conn_t * conn );
int  fd_grpc_server_hdr_name_valid ( char const * name,  ulong name_len  );
int  fd_grpc_server_hdr_value_valid( char const * value, ulong value_len );

/* fd_grpc_server_transport_hdr applies a grpc-timeout, grpc-encoding or
   grpc-accept-encoding header to the stream and returns 1, else 0. */

int
fd_grpc_server_transport_hdr( fd_grpc_server_stream_t * stream,
                              char const *              name,
                              ulong                     name_len,
                              char const *              value,
                              ulong                     value_len );

ulong fd_grpc_server_pct_encode( char * out, ulong out_max, char const * in, ulong in_len );
ulong fd_grpc_server_wr_uint   ( char * out, uint value );

/* fd_grpc_web_conn_rx serves a connection that opened with an HTTP/1.1
   request line instead of the HTTP/2 preface.  An incomplete request
   is left in the receive ring until more of it arrives. */

void
fd_grpc_web_conn_rx( fd_grpc_server_conn_t * conn );

/* fd_grpc_web_conn_flush moves the pending output of an HTTP/1.1
   connection's gRPC-Web call into its send ring. */

void
fd_grpc_web_conn_flush( fd_grpc_server_conn_t * conn );

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
