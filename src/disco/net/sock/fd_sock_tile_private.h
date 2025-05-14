#ifndef HEADER_fd_src_disco_net_sock_fd_sock_tile_private_h
#define HEADER_fd_src_disco_net_sock_fd_sock_tile_private_h

#if FD_HAS_HOSTED

#include "../../../util/fd_util_base.h"
#include "../../metrics/generated/fd_metrics_enums.h"
#include <poll.h>
#include <sys/socket.h>

/* FD_SOCK_TILE_MAX_SOCKETS controls the max number of UDP ports that a
   sock tile can bind to. */

#define FD_SOCK_TILE_MAX_SOCKETS (8)

/* MAX_NET_INS controls the max number of TX links that a sock tile can
   serve. */

#define MAX_NET_INS (32UL)

/* MAX_NET_OUTS controls the max number of RX links that a sock tile can
   serve. */

#define MAX_NET_OUTS (4UL)

/* Local metrics.  Periodically copied to the metric_in shm region. */

struct fd_sock_tile_metrics {
  ulong sys_recvmmsg_cnt;
  ulong sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_CNT ];
  ulong rx_pkt_cnt;
  ulong tx_pkt_cnt;
  ulong tx_drop_cnt;
  ulong rx_bytes_total;
  ulong tx_bytes_total;
};

typedef struct fd_sock_tile_metrics fd_sock_tile_metrics_t;

/* Tile private state */

struct fd_sock_link_tx {
  void * base;
  ulong  chunk0;
  ulong  wmark;
};

typedef struct fd_sock_link_tx fd_sock_link_tx_t;

struct fd_sock_link_rx {
  void * base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
};

typedef struct fd_sock_link_rx fd_sock_link_rx_t;

struct fd_sock_tile {
  /* RX SOCK_DGRAM sockets */
  struct pollfd pollfd[ FD_SOCK_TILE_MAX_SOCKETS ];
  uint          sock_cnt;
  uchar         proto_id[ FD_SOCK_TILE_MAX_SOCKETS ];

  /* TX SOCK_RAW socket */
  int  tx_sock;
  uint tx_idle_cnt;
  uint bind_address;

  /* RX/TX batches
     FIXME transpose arrays for better cache locality? */
  ulong                batch_cnt; /* <=STEM_BURST */
  struct iovec *       batch_iov;
  void *               batch_cmsg;
  struct sockaddr_in * batch_sa;
  struct mmsghdr *     batch_msg;

  /* RX links */
  ushort            rx_sock_port[ FD_SOCK_TILE_MAX_SOCKETS ];
  uchar             link_rx_map [ FD_SOCK_TILE_MAX_SOCKETS ];
  fd_sock_link_rx_t link_rx[ MAX_NET_OUTS ];

  /* TX links */
  fd_sock_link_tx_t link_tx[ MAX_NET_INS ];

  /* TX scratch memory */
  uchar * tx_scratch0;
  uchar * tx_scratch1;
  uchar * tx_ptr; /* in [tx_scratch0,tx_scratch1) */

  fd_sock_tile_metrics_t metrics;
};

typedef struct fd_sock_tile fd_sock_tile_t;

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_disco_net_sock_fd_sock_tile_private_h */
