#ifndef HEADER_fd_src_waltz_mlx5_fd_mlx5_h
#define HEADER_fd_src_waltz_mlx5_fd_mlx5_h

#if defined(__linux__)

#include "../../util/bits/fd_bits.h"

/* fd_mlx5 sets up raw mlx5 resources through Linux uverbs.  It does not
   depend on libibverbs or libmlx5.

   fd_mlx5_init opens one uverbs context, validates the selected device and
   port, maps a UAR, registers packet memory, and creates a protection domain,
   one raw-packet QP, and separate RX and TX CQs over caller-owned queue
   memory, leaving the QP ready to run.  The tile installs flow steering
   separately.  Linux creates and tracks these resources, while the packet
   path uses the mapped queues and doorbells directly.

   mlx5 queue fields are big-endian.  The SQ is a ring of 64-byte WQEBBs
   (work queue entry basic blocks), while each RQ WQE occupies 16 bytes. */

#define FD_MLX5_SQ_WQEBB_SZ   (64UL)
#define FD_MLX5_RQ_WQE_SZ     (16UL)
#define FD_MLX5_CQE_SZ        (64UL)
#define FD_MLX5_PAGE_SZ       (4096UL)

#define FD_MLX5_SQ_DS_SZ             (16UL)
#define FD_MLX5_SQ_WQEBB_DS          (4U)
/* One below the mlx5 16-WQEBB limit keeps the 6-bit DS count representable. */
#define FD_MLX5_SQ_MPWQE_MAX_WQEBBS (15U)

#define FD_MLX5_RDMA_NAME_MAX (64UL)

struct __attribute__((aligned(FD_MLX5_SQ_WQEBB_SZ))) fd_mlx5_sq_wqebb {
  uchar bytes[ FD_MLX5_SQ_WQEBB_SZ ];
};
typedef struct fd_mlx5_sq_wqebb fd_mlx5_sq_wqebb_t;

struct fd_mlx5_sq_wqe_info {
  uchar wqebb_cnt;
  uchar pkt_cnt;
  ushort reserved;
};
typedef struct fd_mlx5_sq_wqe_info fd_mlx5_sq_wqe_info_t;

struct __attribute__((aligned(FD_MLX5_RQ_WQE_SZ))) fd_mlx5_rx_wqe {
  uchar bytes[ FD_MLX5_RQ_WQE_SZ ];
};
typedef struct fd_mlx5_rx_wqe fd_mlx5_rx_wqe_t;

struct __attribute__((aligned(FD_MLX5_CQE_SZ))) fd_mlx5_cqe {
  uchar bytes[ FD_MLX5_CQE_SZ ];
};
typedef struct fd_mlx5_cqe fd_mlx5_cqe_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_sq_wqebb_t  )==FD_MLX5_SQ_WQEBB_SZ, mlx5_sq_wqebb_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_sq_wqe_info_t)==4UL,                  mlx5_sq_wqe_info_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_rx_wqe_t    )==FD_MLX5_RQ_WQE_SZ,   mlx5_rx_wqe_sz     );
FD_STATIC_ASSERT( sizeof(fd_mlx5_cqe_t       )==FD_MLX5_CQE_SZ,      mlx5_cqe_sz         );

/* fd_mlx5_context_t owns a uverbs command descriptor and the async
   event descriptor returned with it. */

struct fd_mlx5_context {
  int cmd_fd;
  int async_fd;
  uint port_num;
};
typedef struct fd_mlx5_context fd_mlx5_context_t;

/* A UAR is a mapped 4 KiB device page containing NIC doorbell registers.
   reg points to the SQ doorbell register at offset 0x800.  The non-cached
   mapping accepts the first 8 bytes of a WQE control segment and causes the
   NIC to fetch the complete WQE from SQ memory. */

struct fd_mlx5_uar {
  volatile uchar * reg;
};
typedef struct fd_mlx5_uar fd_mlx5_uar_t;

/* mlx5 calls this the CQ doorbell record.  Linux names the words
   set_ci_db and arm_db.  request_notification is unused because the
   tile polls completion queues.  Both fields are stored big-endian. */

struct __attribute__((aligned(8UL))) fd_mlx5_cq_control {
  uint consumer_idx;
  uint request_notification;
};
typedef struct fd_mlx5_cq_control fd_mlx5_cq_control_t;

/* mlx5 QP doorbell record in host memory, separate from UAR MMIO.
   Linux names these words MLX5_RCV_DBR and MLX5_SND_DBR.  Both fields
   are stored big-endian. */

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
  uint                    depth;
  uint                    cons_idx;
};
typedef struct fd_mlx5_cq fd_mlx5_cq_t;

struct fd_mlx5_qp {
  fd_mlx5_context_t *     ctx;
  fd_mlx5_cq_t *          rx_cq;
  fd_mlx5_cq_t *          tx_cq;
  fd_mlx5_uar_t *         uar;
  fd_mlx5_rx_wqe_t *      rq;
  fd_mlx5_sq_wqebb_t *    sq;
  uint *                  rq_chunk;
  uint *                  sq_pkt_sz;
  fd_mlx5_sq_wqe_info_t * sq_wqe_info;
  fd_mlx5_qp_control_t *  control;
  uint                    rx_depth;
  uint                    tx_depth;
  uint                    handle;
  uint                    qpn;
  uint                    lkey;
  uchar                   tx_mpwqe_pkt_cap;
  uint                    tx_prod;
  uint                    tx_posted;
  uint                    tx_cons;
  uint                    sq_prod;
  uint                    sq_posted;
  uint                    sq_cons;
  uint                    sq_last_wqe;
  uint                    sq_wqe_start;
  uchar                   sq_wqe_pkt_cnt;
  uchar                   sq_wqe_pkt_cap;
  uint                    rq_prod;
  uint                    rq_cons;
};
typedef struct fd_mlx5_qp fd_mlx5_qp_t;

struct fd_mlx5_qp_stats {
  int  fd;
  uint dev_idx;
  uint port_num;
  uint counter_id;
  uint seq;
};
typedef struct fd_mlx5_qp_stats fd_mlx5_qp_stats_t;

struct fd_mlx5 {
  fd_mlx5_context_t context;
  fd_mlx5_uar_t     uar;
  fd_mlx5_cq_t      rx_cq;
  fd_mlx5_cq_t      tx_cq;
  fd_mlx5_qp_t      qp;
  fd_mlx5_qp_stats_t qp_stats;
};
typedef struct fd_mlx5 fd_mlx5_t;

FD_PROTOTYPES_BEGIN

/* fd_mlx5_init opens an mlx5 context and creates one UAR, RX CQ, TX CQ,
   PD, MR, and QP over caller-owned queue and packet memory.  The QP is
   returned in RTS state.  queue_memory must have
   fd_mlx5_queue_footprint(rx_depth,tx_depth) bytes and be page aligned.
   On failure, process-scoped resources can remain live.  Callers must exit
   rather than retry initialization. */

fd_mlx5_t *
fd_mlx5_init( fd_mlx5_t *  mlx5,
              char const * rdma_name,
              uint         port_num,
              void *       queue_memory,
              uint         rx_depth,
              uint         tx_depth,
              void *       packet_memory,
              ulong        packet_memory_sz );

int
fd_mlx5_flow_create_udp( fd_mlx5_qp_t * qp,
                         uint           dst_ip,
                         ushort         dst_port );

/* fd_mlx5_qp_stats_read returns the QP-specific mlx5 out_of_buffer
   counter.  This counts packets dropped because the RQ had no WQE. */

int
fd_mlx5_qp_stats_read( fd_mlx5_qp_stats_t * stats,
                       ulong *              out_of_buffer );

/* fd_mlx5_queue_footprint returns the page-aligned queue-memory size
   required by fd_mlx5_init, or zero for invalid queue depths. */

ulong
fd_mlx5_queue_footprint( uint rx_depth,
                         uint tx_depth );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_mlx5_fd_mlx5_h */
