#ifndef HEADER_fd_src_disco_net_mlx5_fd_mlx5_private_h
#define HEADER_fd_src_disco_net_mlx5_fd_mlx5_private_h

#if defined(__linux__)

#include "fd_mlx5.h"

/* fd_mlx5 sets up raw mlx5 resources through Linux uverbs.  It does not
   depend on libibverbs or libmlx5.

   fd_uverbs_init opens one uverbs context, validates the selected device
   and port, registers packet memory, and creates a shared protection domain
   and receive indirection table over caller-owned queue memory.  Each tile
   gets a UAR, RX CQ, TX CQ, receive WQ, and send-only raw-packet QP.  Linux
   creates and tracks these resources, while the packet path uses the mapped
   queues and doorbells directly.

   mlx5 queue fields are big-endian.  This implementation reserves 64
   bytes for each TX WQE and 16 bytes for each RX WQE. */

#define FD_MLX5_TX_WQE_SZ     (64UL)
#define FD_MLX5_RQ_WQE_SZ     (16UL)
#define FD_MLX5_CQE_SZ        (64UL)
#define FD_MLX5_PAGE_SZ       (4096UL)

struct __attribute__((aligned(FD_MLX5_TX_WQE_SZ))) fd_mlx5_tx_wqe {
  uchar bytes[ FD_MLX5_TX_WQE_SZ ];
};
typedef struct fd_mlx5_tx_wqe fd_mlx5_tx_wqe_t;

struct __attribute__((aligned(FD_MLX5_RQ_WQE_SZ))) fd_mlx5_rx_wqe {
  uchar bytes[ FD_MLX5_RQ_WQE_SZ ];
};
typedef struct fd_mlx5_rx_wqe fd_mlx5_rx_wqe_t;

struct __attribute__((aligned(FD_MLX5_CQE_SZ))) fd_mlx5_cqe {
  uchar bytes[ FD_MLX5_CQE_SZ ];
};
typedef struct fd_mlx5_cqe fd_mlx5_cqe_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_tx_wqe_t)==FD_MLX5_TX_WQE_SZ, mlx5_tx_wqe_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_rx_wqe_t)==FD_MLX5_RQ_WQE_SZ, mlx5_rx_wqe_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_cqe_t   )==FD_MLX5_CQE_SZ,    mlx5_cqe_sz    );

/* fd_uverbs_ctx owns a uverbs command descriptor and the async
   event descriptor returned with it. */
struct fd_uverbs_ctx {
  int  cmd_fd;
  int  async_fd;
  uint port_num;
};
typedef struct fd_uverbs_ctx fd_uverbs_ctx_t;

/* fd_mlx5_cq_control is the mlx5 CQ doorbell record.  Linux names the
   words set_ci_db and arm_db.  request_notification is unused because
   the tile polls completion queues.  Both fields are stored big-endian. */
struct __attribute__((aligned(8UL))) fd_mlx5_cq_control {
  uint consumer_idx;
  uint request_notification;
};
typedef struct fd_mlx5_cq_control fd_mlx5_cq_control_t;

/* fd_mlx5_qp_control is the mlx5 QP doorbell record in host memory,
   separate from UAR MMIO.  Linux names these words MLX5_RCV_DBR and
   MLX5_SND_DBR.  Both fields are stored big-endian. */
struct __attribute__((aligned(8UL))) fd_mlx5_qp_control {
  uint reserved;
  uint sq_prod;
};
typedef struct fd_mlx5_qp_control fd_mlx5_qp_control_t;

/* fd_mlx5_rx_wq_control is the mlx5 receive WQ doorbell record. */
struct __attribute__((aligned(8UL))) fd_mlx5_rx_wq_control {
  uint rq_prod;
  uint reserved;
};
typedef struct fd_mlx5_rx_wq_control fd_mlx5_rx_wq_control_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_cq_control_t)==8UL, mlx5_cq_control_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_qp_control_t)==8UL, mlx5_qp_control_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_rx_wq_control_t)==8UL, mlx5_rx_wq_control_sz );

struct fd_mlx5_cq {
  fd_mlx5_cqe_t *        entries;
  fd_mlx5_cq_control_t * control;
  uint                   depth;
  uint                   cons_idx;
};
typedef struct fd_mlx5_cq fd_mlx5_cq_t;

/* fd_mlx5_rx_wq owns one standalone Linux receive WQ. */
struct fd_mlx5_rx_wq {
  fd_mlx5_rx_wqe_t * rq;
  fd_mlx5_cq_t *     rx_cq;
  uint               rx_depth;
  uint               rq_prod;
  uint               rq_cons;
  uint *             rq_wqe_buf_chunk;

  fd_mlx5_rx_wq_control_t * control;
  uint                      handle;
  uint                      wqn;
};
typedef struct fd_mlx5_rx_wq fd_mlx5_rx_wq_t;

/* fd_mlx5_tx_qp owns one send-only raw-packet QP. */
struct fd_mlx5_tx_qp {
  fd_mlx5_tx_wqe_t *     sq;
  fd_mlx5_cq_t *         tx_cq;
  uint                   tx_depth;
  uint                   sq_prod;
  uint                   sq_posted;
  uint                   sq_cons;
  uint *                 sq_wqe_frame_sz;

  fd_mlx5_qp_control_t * control;
  volatile uchar *       sq_doorbell;      /* points to the SQ doorbell register in a non-cached UAR mapping. */
  ulong                  uar_mmap_offset;  /* maps this QP's non-cached mlx5 UAR page. */
  uint                   handle;           /* identifies this QP in later Linux uverbs commands. */
  uint                   qpn;              /* identifies this QP to the NIC. */
  uchar                  tx_inline_hdr_sz; /* number of Ethernet header bytes copied into each TX WQE. */

};
typedef struct fd_mlx5_tx_qp fd_mlx5_tx_qp_t;

/* fd_mlx5_rss_qp identifies the receive-only QP used as a flow target. */
struct fd_mlx5_rss_qp {
  uint handle;
};
typedef struct fd_mlx5_rss_qp fd_mlx5_rss_qp_t;

/* fd_mlx5_uverbs_tile identifies one tile's queues and packet-memory region
   during shared uverbs initialization. */
struct fd_mlx5_uverbs_tile {
  fd_mlx5_cq_t *    rx_cq;
  fd_mlx5_cq_t *    tx_cq;
  fd_mlx5_rx_wq_t * rx_wq;
  fd_mlx5_tx_qp_t * tx_qp;
  uint *            lkey;
  void *            packet_memory;
  ulong             packet_memory_sz;
  ulong             packet_iova;
};
typedef struct fd_mlx5_uverbs_tile fd_mlx5_uverbs_tile_t;

/* fd_netlink_rdma_ctx stores the state used to request one QP-bound counter
   through Linux NETLINK_RDMA. */
struct fd_netlink_rdma_ctx {
  int  fd;         /* socket used to request RDMA QP counters. */
  uint dev_idx;    /* selects the RDMA device in counter requests. */
  uint port_num;   /* selects the device port in counter requests. */
  uint counter_id; /* identifies the counter bound to this QP. */
  uint seq;        /* matches each netlink reply to its request. */
};
typedef struct fd_netlink_rdma_ctx fd_netlink_rdma_ctx_t;

FD_PROTOTYPES_BEGIN

/* fd_uverbs_init creates one shared context, PD, receive indirection table,
   and two RSS QPs, one hashing outer headers and one hashing inner tunnel
   headers.  It creates an MR, UAR, RX CQ, TX CQ, receive WQ, and send-only QP
   for each entry in tiles.  On failure, process-scoped resources can remain
   live.  Callers must exit rather than retry initialization. */
fd_mlx5_rss_qp_t *
fd_uverbs_init( fd_uverbs_ctx_t *         uverbs,
                fd_mlx5_uverbs_tile_t *   tiles,
                ulong                     tile_cnt,
                fd_mlx5_rss_qp_t *        outer_rss_qp,
                fd_mlx5_rss_qp_t *        gre_rss_qp,
                char const *              rdma_name,
                uint                      port_num );

/* fd_uverbs_map_uar maps a previously allocated non-cached mlx5 UAR. */
volatile uchar *
fd_uverbs_map_uar( fd_uverbs_ctx_t * uverbs,
                   ulong             mmap_offset );

/* fd_uverbs_create_udp_flow and fd_uverbs_create_gre_udp_flow steer matching
   IPv4 traffic to an RSS QP.  The GRE destination IP and port select the inner
   packet.  A zero destination IP matches every IPv4 address. */
int
fd_uverbs_create_udp_flow( fd_uverbs_ctx_t *        uverbs,
                           fd_mlx5_rss_qp_t const * rss_qp,
                           uint                     dst_ip,
                           ushort                   dst_port );

int
fd_uverbs_create_gre_udp_flow( fd_uverbs_ctx_t *        uverbs,
                               fd_mlx5_rss_qp_t const * rss_qp,
                               uint                     inner_dst_ip,
                               ushort                   inner_dst_port );

/* fd_mlx5_netlink_rdma_init binds a manual RDMA counter to qpn. */
fd_netlink_rdma_ctx_t *
fd_mlx5_netlink_rdma_init( fd_netlink_rdma_ctx_t * netlink_rdma,
                           char const *            rdma_name,
                           uint                    port_num,
                           uint                    qpn );

/* fd_mlx5_netlink_rdma_qp_counter_read returns the QP-specific mlx5
   out_of_buffer counter.  This counts packets dropped because the RQ had no
   WQE. */
int
fd_mlx5_netlink_rdma_qp_counter_read( fd_netlink_rdma_ctx_t * netlink_rdma,
                                      ulong *                 out_of_buffer );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_disco_net_mlx5_fd_mlx5_private_h */
