#ifndef HEADER_fd_src_disco_net_mlx5_fd_mlx5_private_h
#define HEADER_fd_src_disco_net_mlx5_fd_mlx5_private_h

#if defined(__linux__)

#include "../../../util/bits/fd_bits.h"

/* fd_mlx5 sets up raw mlx5 resources through Linux uverbs.  It does not
   depend on libibverbs or libmlx5.

   fd_uverbs_init opens one uverbs context, validates the selected device
   and port, maps a UAR, registers packet memory, and creates a protection
   domain, one raw-packet QP, and separate RX and TX CQs over caller-owned
   queue memory, leaving the QP ready to run.  The tile installs flow steering
   separately.  Linux creates and tracks these resources, while the packet
   path uses the mapped queues and doorbells directly.

   mlx5 queue fields are big-endian.  This implementation reserves 64
   bytes for each TX WQE and 16 bytes for each RX WQE. */

#define FD_MLX5_TX_WQE_SZ     (64UL)
#define FD_MLX5_RQ_WQE_SZ     (16UL)
#define FD_MLX5_CQE_SZ        (64UL)
#define FD_MLX5_PAGE_SZ       (4096UL)
#define FD_MLX5_RDMA_NAME_MAX (64UL)

/* FD_MLX5_TILE_MAX is the max number of mlx5 tiles sharing one device. */
#define FD_MLX5_TILE_MAX      (32UL)

/* FD_MLX5_RQT_LG_SZ selects the size of the receive queue indirection
   table (RSS). */
#define FD_MLX5_RQT_LG_SZ     (7)
#define FD_MLX5_RQT_SZ        (1UL<<FD_MLX5_RQT_LG_SZ)

/* FD_MLX5_RSS_KEY_SZ is the length of the Toeplitz hash key. */
#define FD_MLX5_RSS_KEY_SZ    (40UL)

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
  uint rq_prod;
  uint sq_prod;
};
typedef struct fd_mlx5_qp_control fd_mlx5_qp_control_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_cq_control_t)==8UL, mlx5_cq_control_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_qp_control_t)==8UL, mlx5_qp_control_sz );

struct fd_mlx5_cq {
  fd_mlx5_cqe_t *        entries;
  fd_mlx5_cq_control_t * control;
  uint                   depth;
  uint                   cons_idx;
};
typedef struct fd_mlx5_cq fd_mlx5_cq_t;

struct fd_mlx5_qp {
  fd_mlx5_rx_wqe_t *     rq;
  fd_mlx5_tx_wqe_t *     sq;
  fd_mlx5_cq_t *         rx_cq;
  fd_mlx5_cq_t *         tx_cq;
  uint                   rx_depth;
  uint                   tx_depth;

  uint                   sq_prod;
  uint                   sq_posted;
  uint                   sq_cons;
  uint                   rq_prod;
  uint                   rq_cons;

  uint *                 rq_wqe_buf_chunk;
  uint *                 sq_wqe_frame_sz;

  fd_mlx5_qp_control_t * control;
  volatile uchar *       sq_doorbell;      /* points to the SQ doorbell register in a non-cached UAR mapping. */
  uint                   handle;           /* identifies this QP in later Linux uverbs commands. */
  uint                   qpn;              /* identifies this QP to the NIC. */
  uint                   lkey;             /* lkey permits the NIC to DMA the registered packet memory. */
  uchar                  tx_inline_hdr_sz; /* number of Ethernet header bytes copied into each TX WQE. */

};
typedef struct fd_mlx5_qp fd_mlx5_qp_t;

/* fd_mlx5_caps_t holds the device and context limits that constrain
   queue depths and memory region sizes. */
struct fd_mlx5_caps {
  ulong max_mr_size;
  uint  max_send_wqe; /* max_send_wqebb, SQ WQE capacity */
  uint  max_recv_wr;
  uint  max_cqe;
  uchar eth_min_inline_hdr_sz;
};
typedef struct fd_mlx5_caps fd_mlx5_caps_t;

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

/* FD_MLX5_RSS_TIMEOUT_NS bounds how long one mlx5 tile waits on mlx5:0
   to do RSS setup during boot.  This is practically instant. */
#define FD_MLX5_RSS_TIMEOUT_NS (30e9) /* 30 seconds */

FD_PROTOTYPES_BEGIN

/* fd_uverbs_init creates one UAR, RX CQ, TX CQ, PD, MR, and QP over
   caller-initialized queue and packet memory.  The QP is returned in RTS
   state.  On failure, process-scoped resources can remain live.  Callers
   must exit rather than retry initialization. */
fd_mlx5_qp_t *
fd_uverbs_init( fd_uverbs_ctx_t * uverbs,
                fd_mlx5_cq_t *    rx_cq,
                fd_mlx5_cq_t *    tx_cq,
                fd_mlx5_qp_t *    qp,
                char const *      rdma_name,
                uint              port_num,
                void *            packet_memory,
                ulong             packet_memory_sz );

/* fd_uverbs_create_udp_flow and fd_uverbs_create_gre_udp_flow steer
   matching IPv4 traffic to the queue pair named by qp_handle, which is
   either a raw packet QP or an RSS QP.  The GRE destination IP and port
   select the inner packet.  A zero destination IP matches every IPv4
   address. */

int
fd_uverbs_create_udp_flow( fd_uverbs_ctx_t * uverbs,
                           uint              qp_handle,
                           uint              dst_ip,
                           ushort            dst_port );

int
fd_uverbs_create_gre_udp_flow( fd_uverbs_ctx_t * uverbs,
                               uint              qp_handle,
                               uint              inner_dst_ip,
                               ushort            inner_dst_port );

/* fd_mlx5_rdma_dev_find maps a network interface, or one of its bond
   slaves, to Linux's RDMA device name and port number.  Dies if no port
   matches or if more than one does. */

void
fd_mlx5_rdma_dev_find( char         rdma_name[ FD_MLX5_RDMA_NAME_MAX ],
                       uint *       port_num,
                       char const * if_name );

/* fd_uverbs_open_cmd_fd opens the uverbs command device belonging to
   rdma_name without creating a context on it.  Returns a file
   descriptor, or -1 on failure. */

int
fd_uverbs_open_cmd_fd( char const * rdma_name );

/* fd_uverbs_join wraps an already open command fd. */

fd_uverbs_ctx_t *
fd_uverbs_join( fd_uverbs_ctx_t * uverbs,
                int               cmd_fd,
                uint              port_num );

/* fd_uverbs_open_shared creates the uverbs context and protection
   domain that every tile on this command fd will use.  Called by mlx5:0. */

int
fd_uverbs_open_shared( fd_uverbs_ctx_t * uverbs,
                       fd_mlx5_caps_t *  caps,
                       uint *            pd_handle );

/* fd_uverbs_init_rss_tile creates one tile's queues on a shared command
   fd: a UAR, the RX and TX CQs, a memory region over the tile's own
   packet memory, a work queue over its own RQ memory, and a send-only
   raw packet QP.  The work queue is left in the ready state and its
   handle is returned in wq_handle for the indirection table. */

int
fd_uverbs_init_rss_tile( fd_uverbs_ctx_t *      uverbs,
                         fd_mlx5_caps_t const * caps,
                         uint                   pd_handle,
                         fd_mlx5_qp_t *         qp,
                         void *                 packet_memory,
                         ulong                  packet_memory_sz,
                         uint *                 wq_handle );

/* fd_uverbs_create_rqt builds the receive queue indirection table over
   wq_cnt work queues, repeating them to fill FD_MLX5_RQT_SZ entries. */

int
fd_uverbs_create_rqt( fd_uverbs_ctx_t * uverbs,
                      uint const *      wq_handle,
                      uint              wq_cnt,
                      uint *            rqt_handle );

/* fd_uverbs_create_rss_qp creates the RSS queue pair that spreads
   packets over rqt_handle using a Toeplitz hash of the IPv4 addresses
   and UDP ports.  When inner is set the hash covers the tunnelled
   headers instead of the outer ones, which callers use for GRE and may
   fail on older firmware.  Returns 0 on success, -1 on failure. */

int
fd_uverbs_create_rss_qp( fd_uverbs_ctx_t * uverbs,
                         uint              pd_handle,
                         uint              rqt_handle,
                         int               inner,
                         uint *            qp_handle,
                         uint *            qpn );

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
