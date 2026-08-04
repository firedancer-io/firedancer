#ifndef HEADER_fd_src_waltz_mlx5_fd_mlx5_h
#define HEADER_fd_src_waltz_mlx5_fd_mlx5_h

#if defined(__linux__)

#include "../../util/bits/fd_bits.h"

/* fd_mlx5 sets up raw mlx5 resources through Linux uverbs.  It does not
   depend on libibverbs or libmlx5.

   mlx5 queue entries use big-endian fields regardless of host byte
   order.  SQ WQEs occupy one 64-byte basic block.  RQ WQEs contain a
   single data segment. */

#define FD_MLX5_WQEBB_SZ      (64UL)
#define FD_MLX5_RQ_WQE_SZ     (16UL)
#define FD_MLX5_CQE_SZ        (64UL)
#define FD_MLX5_PAGE_SZ       (4096UL)

#define FD_MLX5_RDMA_NAME_MAX (64UL)

struct __attribute__((aligned(FD_MLX5_WQEBB_SZ))) fd_mlx5_tx_wqe {
  uchar bytes[ FD_MLX5_WQEBB_SZ ];
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

FD_STATIC_ASSERT( sizeof(fd_mlx5_tx_wqe_t)==FD_MLX5_WQEBB_SZ,  mlx5_tx_wqe_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_rx_wqe_t)==FD_MLX5_RQ_WQE_SZ, mlx5_rx_wqe_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_cqe_t   )==FD_MLX5_CQE_SZ,    mlx5_cqe_sz    );

/* fd_mlx5_context_t owns a uverbs command descriptor and the async
   event descriptor returned with it. */

struct fd_mlx5_context {
  int cmd_fd;
  int async_fd;
  uint port_num;
};
typedef struct fd_mlx5_context fd_mlx5_context_t;

struct fd_mlx5_uar {
  volatile uchar * reg;
};
typedef struct fd_mlx5_uar fd_mlx5_uar_t;

struct fd_mlx5_cq {
  fd_mlx5_cqe_t * entries;
  uint *          dbrec;
  uint            depth;
  uint            cons_idx;
};
typedef struct fd_mlx5_cq fd_mlx5_cq_t;

struct fd_mlx5_qp {
  fd_mlx5_context_t * ctx;
  fd_mlx5_cq_t *      rx_cq;
  fd_mlx5_cq_t *      tx_cq;
  fd_mlx5_uar_t *     uar;
  fd_mlx5_rx_wqe_t *  rq;
  fd_mlx5_tx_wqe_t *  sq;
  ulong *             rx_user_data;
  ulong *             tx_user_data;
  uint *              dbrec;
  uint                rx_depth;
  uint                tx_depth;
  uint                handle;
  uint                qpn;
  uint                lkey;
  uint                bf_reg_size;
  uchar               tx_inline_sz;
  uint                sq_prod;
  uint                sq_cons;
  uint                rq_prod;
  uint                rq_cons;
  uint                bf_offset;
};
typedef struct fd_mlx5_qp fd_mlx5_qp_t;

struct fd_mlx5 {
  fd_mlx5_context_t context;
  fd_mlx5_uar_t     uar;
  fd_mlx5_cq_t      rx_cq;
  fd_mlx5_cq_t      tx_cq;
  fd_mlx5_qp_t      qp;
};
typedef struct fd_mlx5 fd_mlx5_t;

FD_PROTOTYPES_BEGIN

/* fd_mlx5_init opens an mlx5 context and creates one UAR, RX CQ, TX CQ,
   PD, MR, and QP over caller-owned queue and packet memory.  The QP is
   returned in RTS state.  queue_memory must have
   fd_mlx5_queue_footprint(rx_depth,tx_depth) bytes and be page aligned. */

fd_mlx5_t *
fd_mlx5_init( fd_mlx5_t *  mlx5,
              char const * rdma_name,
              uint         port_num,
              void *       queue_memory,
              uint         rx_depth,
              uint         tx_depth,
              ulong *      rx_user_data,
              ulong *      tx_user_data,
              void *       packet_memory,
              ulong        packet_memory_sz );

int
fd_mlx5_flow_create_udp( fd_mlx5_qp_t * qp,
                         uint           dst_ip,
                         ushort         dst_port );

/* fd_mlx5_queue_footprint returns the page-aligned queue-memory size
   required by fd_mlx5_init, or zero for invalid queue depths. */

ulong
fd_mlx5_queue_footprint( uint rx_depth,
                         uint tx_depth );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_mlx5_fd_mlx5_h */
