/* The mlx5 tile translates Ethernet frames between raw mlx5 packet
   queues and fd_tango traffic. */

#include "../fd_net_router.h"
#include "../fd_linux_bond.h"
#include "../fd_net_common.h"
#include "../fd_net_tile.h"
#include "../../metrics/fd_metrics.h"
#include "../../topo/fd_topo.h"
#include "../../../waltz/ip/fd_iproute.h"
#include "../../../waltz/mlx5/fd_mlx5.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"
#include "../../../util/pod/fd_pod_format.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <rdma/ib_user_verbs.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef FD_TILE_TEST
#include "generated/fd_mlx5_tile_seccomp.h"
#endif

#define FD_MLX5_FLOW_CAP (64UL)

#define FD_MLX5_OPCODE_SEND        (0x0aU)
#define FD_MLX5_WQE_CTRL_CQ_UPDATE (0x08U)

#define FD_MLX5_CQE_REQ       ( 0U)
#define FD_MLX5_CQE_RESP_SEND ( 2U)
#define FD_MLX5_CQE_REQ_ERR   (13U)
#define FD_MLX5_CQE_RESP_ERR  (14U)
#define FD_MLX5_CQE_INVALID   (15U)

/* Fatal values reported through ib_uverbs_async_event_desc.event_type. */

#define FD_MLX5_EVENT_CQ_ERR        ( 0U)
#define FD_MLX5_EVENT_QP_FATAL      ( 1U)
#define FD_MLX5_EVENT_QP_REQ_ERR    ( 2U)
#define FD_MLX5_EVENT_QP_ACCESS_ERR ( 3U)
#define FD_MLX5_EVENT_DEVICE_FATAL  ( 8U)
#define FD_MLX5_EVENT_WQ_FATAL      (19U)

#define IN_KIND_NET     (0U)
#define IN_KIND_IPROUTE (1U)

#define DEQUE_NAME tx_free
#define DEQUE_T    uint
#include "../../../util/tmpl/fd_deque_dynamic.c"

/* fd_mlx5_tile_t is private tile state */

struct fd_mlx5_tile_txq {
  void * base;
  ulong  chunk0;
  ulong  wmark;
};
typedef struct fd_mlx5_tile_txq fd_mlx5_tile_txq_t;

struct fd_mlx5_tile_recv_wr {
  uint chunk;
};
typedef struct fd_mlx5_tile_recv_wr fd_mlx5_tile_recv_wr_t;

struct fd_mlx5_tile_send_wr {
  uint chunk;
  uint sz;
};
typedef struct fd_mlx5_tile_send_wr fd_mlx5_tile_send_wr_t;

struct fd_mlx5_tile_rx_stats {
  ulong pkt_cnt;
  ulong bytes_total;
};
typedef struct fd_mlx5_tile_rx_stats fd_mlx5_tile_rx_stats_t;

struct __attribute__((packed)) fd_mlx5_tile_wqe_ctrl_wire {
  uint  opmod_idx_opcode;
  uint  qpn_ds;
  uchar signature;
  uchar reserved[2];
  uchar flags;
  uint  imm;
};
typedef struct fd_mlx5_tile_wqe_ctrl_wire fd_mlx5_tile_wqe_ctrl_wire_t;

struct __attribute__((packed)) fd_mlx5_tile_wqe_eth_wire {
  uchar  reserved[12];
  ushort inline_hdr_sz;
  uchar  inline_hdr[2];
};
typedef struct fd_mlx5_tile_wqe_eth_wire fd_mlx5_tile_wqe_eth_wire_t;

struct __attribute__((packed)) fd_mlx5_tile_wqe_data_wire {
  uint  byte_cnt;
  uint  lkey;
  ulong addr;
};
typedef struct fd_mlx5_tile_wqe_data_wire fd_mlx5_tile_wqe_data_wire_t;

struct __attribute__((packed)) fd_mlx5_tile_cqe_wire {
  uchar  reserved0[44];
  uint   byte_cnt;
  uchar  reserved1[6];
  uchar  vendor_err;
  uchar  syndrome;
  uint   sop_drop_qpn;
  ushort wqe_counter;
  uchar  signature;
  uchar  op_own;
};
typedef struct fd_mlx5_tile_cqe_wire fd_mlx5_tile_cqe_wire_t;

struct fd_mlx5_tile_rx_comp {
  ulong user_data;
  uint  byte_len;
  uint  opcode;
};
typedef struct fd_mlx5_tile_rx_comp fd_mlx5_tile_rx_comp_t;

struct fd_mlx5_tile_tx_comp {
  ulong user_data;
  uint  opcode;
};
typedef struct fd_mlx5_tile_tx_comp fd_mlx5_tile_tx_comp_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_tile_wqe_ctrl_wire_t)==16UL, mlx5_tile_wqe_ctrl_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_tile_wqe_eth_wire_t )==16UL, mlx5_tile_wqe_eth_sz  );
FD_STATIC_ASSERT( sizeof(fd_mlx5_tile_wqe_data_wire_t)==16UL, mlx5_tile_wqe_data_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_tile_cqe_wire_t     )==64UL, mlx5_tile_cqe_sz      );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_wqe_ctrl_wire_t, flags        )==11UL, mlx5_tile_wqe_ctrl_flags_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_wqe_eth_wire_t,  inline_hdr_sz)==12UL, mlx5_tile_wqe_eth_inline_off  );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_cqe_wire_t, byte_cnt    )==44UL, mlx5_tile_cqe_byte_cnt_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_cqe_wire_t, vendor_err  )==54UL, mlx5_tile_cqe_vendor_off   );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_cqe_wire_t, syndrome    )==55UL, mlx5_tile_cqe_syndrome_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_cqe_wire_t, sop_drop_qpn)==56UL, mlx5_tile_cqe_sop_off      );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_cqe_wire_t, wqe_counter )==60UL, mlx5_tile_cqe_counter_off  );
FD_STATIC_ASSERT( offsetof(fd_mlx5_tile_cqe_wire_t, op_own      )==63UL, mlx5_tile_cqe_op_own_off   );

static inline ulong
fd_mlx5_tile_tx_user_data( fd_mlx5_tile_send_wr_t meta ) {
  return ((ulong)meta.sz<<32) | (ulong)meta.chunk;
}

static inline fd_mlx5_tile_send_wr_t
fd_mlx5_tile_tx_meta( ulong user_data ) {
  return (fd_mlx5_tile_send_wr_t) { .chunk=(uint)user_data, .sz=(uint)(user_data>>32) };
}

struct fd_mlx5_tile {
  fd_mlx5_t         hw;
  uint              batch_size;
  uint              rx_pending_rem;
  uint              tx_pending_cnt;
  uint              tx_pending_idle;

  /* UMEM frame region within dcache */
  uchar * umem_base;   /* Workspace base */
  uchar * umem_frame0; /* First UMEM frame */

  /* UMEM chunk region within workspace */
  uint umem_chunk0; /* Lowest allowed chunk number */
  uint umem_wmark;  /* Highest allowed chunk number */

  /* TX */
  fd_mlx5_tile_txq_t txq[ FD_TOPO_MAX_TILE_IN_LINKS ];
  uchar              in_kind[ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_iproute_msg_t   iproute_msg;

  /* TX free ring */
  uint * tx_free;

  /* Router */
  fd_net_router_t   r;
  fd_net_tx_route_t tx_route;

  /* Port matcher */
  uint   dst_port_cnt;
  ushort dst_ports  [ FD_MLX5_FLOW_CAP ];
  uchar  dst_protos [ FD_MLX5_FLOW_CAP ];
  uchar  dst_out_idx[ FD_MLX5_FLOW_CAP ];
  uchar  repair_out_idx;

  /* Batched work requests */
  fd_mlx5_tile_recv_wr_t rx_pending[ FD_MLX5_BATCH_MAX ];
  fd_mlx5_tile_send_wr_t tx_pending[ FD_MLX5_BATCH_MAX ];

  /* Out links */
  uchar rx_out_cnt;

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong tx_pkt_cnt;
    ulong tx_bytes_total;
  } metrics;
};
typedef struct fd_mlx5_tile fd_mlx5_tile_t;

static inline void
fd_mlx5_tile_dma_to_device( void ) {
#if FD_HAS_X86
  FD_COMPILER_MFENCE();
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshst" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline void
fd_mlx5_tile_dma_from_device( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "lfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshld" ::: "memory" );
#else
  FD_HW_MFENCE();
#endif
}

static inline void
fd_mlx5_tile_mmio_wc_fence( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "sfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dsb st" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline int
fd_mlx5_tile_tx_wqe_init( fd_mlx5_tx_wqe_t * wqe,
                          uint                sq_idx,
                          uint                qpn,
                          void const *        frame,
                          ulong               frame_sz,
                          uint                lkey,
                          ulong               tx_inline_sz,
                          int                 request_cqe ) {
  if( FD_UNLIKELY( !frame_sz || frame_sz>UINT_MAX || qpn>0xffffffU || tx_inline_sz>frame_sz ) ) return 0;
  fd_memset( wqe, 0, sizeof(*wqe) );

  uint const ds = tx_inline_sz ? 4U : 3U;
  fd_mlx5_tile_wqe_ctrl_wire_t * ctrl = (fd_mlx5_tile_wqe_ctrl_wire_t *)wqe;
  fd_mlx5_tile_wqe_eth_wire_t *  eth  = (fd_mlx5_tile_wqe_eth_wire_t *)(wqe->bytes+sizeof(*ctrl));
  ctrl->opmod_idx_opcode = fd_uint_bswap( ((sq_idx & 0xffffU)<<8) | FD_MLX5_OPCODE_SEND );
  ctrl->qpn_ds           = fd_uint_bswap( (qpn<<8) | ds );
  ctrl->flags            = request_cqe ? FD_MLX5_WQE_CTRL_CQ_UPDATE : 0U;

  eth->inline_hdr_sz = fd_ushort_bswap( (ushort)tx_inline_sz );
  if( tx_inline_sz ) fd_memcpy( eth->inline_hdr, frame, tx_inline_sz );

  ulong const data_off = tx_inline_sz ? 48UL : 32UL;
  fd_mlx5_tile_wqe_data_wire_t * data = (fd_mlx5_tile_wqe_data_wire_t *)(wqe->bytes+data_off);
  data->byte_cnt = fd_uint_bswap( (uint)(frame_sz-tx_inline_sz) );
  data->lkey     = fd_uint_bswap( lkey );
  data->addr     = fd_ulong_bswap( (ulong)frame+tx_inline_sz );
  return 1;
}

static inline void
fd_mlx5_tile_rx_wqe_init( fd_mlx5_rx_wqe_t * wqe,
                          void *              frame,
                          ulong               frame_sz,
                          uint                lkey ) {
  fd_mlx5_tile_wqe_data_wire_t * data = (fd_mlx5_tile_wqe_data_wire_t *)wqe;
  data->byte_cnt = fd_uint_bswap( (uint)frame_sz );
  data->lkey     = fd_uint_bswap( lkey );
  data->addr     = fd_ulong_bswap( (ulong)frame );
}

static inline void
fd_mlx5_tile_ring_sq( fd_mlx5_qp_t *     qp,
                      fd_mlx5_tx_wqe_t * wqe,
                      uint                wqe_cnt ) {
  qp->sq_prod += wqe_cnt;
  fd_mlx5_tile_dma_to_device();
  FD_VOLATILE( qp->dbrec[1] ) = fd_uint_bswap( qp->sq_prod & 0xffffU );

  fd_mlx5_tile_mmio_wc_fence();
  volatile ulong * bf = (volatile ulong *)(qp->uar->reg + qp->bf_offset);
  if( wqe_cnt==1U ) {
    bf[0] = FD_LOAD( ulong, wqe->bytes    );
    bf[1] = FD_LOAD( ulong, wqe->bytes+ 8 );
    bf[2] = FD_LOAD( ulong, wqe->bytes+16 );
    bf[3] = FD_LOAD( ulong, wqe->bytes+24 );
    bf[4] = FD_LOAD( ulong, wqe->bytes+32 );
    bf[5] = FD_LOAD( ulong, wqe->bytes+40 );
    bf[6] = FD_LOAD( ulong, wqe->bytes+48 );
    bf[7] = FD_LOAD( ulong, wqe->bytes+56 );
  } else {
    bf[0] = FD_LOAD( ulong, wqe->bytes );
  }
  fd_mlx5_tile_mmio_wc_fence();
  qp->bf_offset ^= qp->bf_reg_size/2U;
}

static inline int
fd_mlx5_tile_post_send( fd_mlx5_tile_t * ctx,
                        uint             send_cnt ) {
  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  uint const outstanding = qp->sq_prod-qp->sq_cons;
  if( FD_UNLIKELY( outstanding>qp->tx_depth || send_cnt>qp->tx_depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }

  uint const sq_prod = qp->sq_prod;
  for( uint i=0U; i<send_cnt; i++ ) {
    uint const sq_idx = sq_prod+i;
    fd_mlx5_tile_send_wr_t meta = ctx->tx_pending[ i ];
    fd_mlx5_tx_wqe_t * wqe = qp->sq+(sq_idx & (qp->tx_depth-1U));
    if( FD_UNLIKELY( !fd_mlx5_tile_tx_wqe_init( wqe, sq_idx, qp->qpn,
                                                fd_chunk_to_laddr( ctx->umem_base, meta.chunk ), meta.sz,
                                                qp->lkey, qp->tx_inline_sz, i+1U==send_cnt ) ) ) {
      errno = EINVAL;
      return -1;
    }
    qp->tx_user_data[ sq_idx & (qp->tx_depth-1U) ] = fd_mlx5_tile_tx_user_data( meta );
  }

  fd_mlx5_tx_wqe_t * last = qp->sq+((sq_prod+send_cnt-1U) & (qp->tx_depth-1U));
  fd_mlx5_tile_ring_sq( qp, last, send_cnt );
  return 0;
}

static inline int
fd_mlx5_tile_post_recv( fd_mlx5_tile_t * ctx,
                        uint             recv_cnt ) {
  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  uint const outstanding = qp->rq_prod-qp->rq_cons;
  if( FD_UNLIKELY( outstanding>qp->rx_depth || recv_cnt>qp->rx_depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }

  uint const rq_prod = qp->rq_prod;
  for( uint i=0U; i<recv_cnt; i++ ) {
    uint const chunk = ctx->rx_pending[ ctx->rx_pending_rem+i ].chunk;
    uint const rq_idx = rq_prod+i;
    fd_mlx5_tile_rx_wqe_init( qp->rq+(rq_idx & (qp->rx_depth-1U)),
                              fd_chunk_to_laddr( ctx->umem_base, chunk ), FD_NET_MTU, qp->lkey );
    qp->rx_user_data[ rq_idx & (qp->rx_depth-1U) ] = chunk;
  }
  qp->rq_prod += recv_cnt;
  fd_mlx5_tile_dma_to_device();
  FD_VOLATILE( qp->dbrec[0] ) = fd_uint_bswap( qp->rq_prod & 0xffffU );
  return 0;
}

static inline int
fd_mlx5_tile_poll_rx_cq( fd_mlx5_qp_t *          qp,
                         fd_mlx5_tile_rx_comp_t * comp,
                         uint                     comp_max ) {
  fd_mlx5_cq_t * cq = qp->rx_cq;
  uint comp_cnt = 0U;
  uint const max = fd_uint_min( comp_max, cq->depth );
  uint cq_cons = cq->cons_idx;
  uint rq_cons = qp->rq_cons;
  uint const rq_prod = qp->rq_prod;
  if( FD_UNLIKELY( rq_prod-rq_cons>qp->rx_depth ) ) { errno = EPROTO; return -1; }

  for( ; comp_cnt<max; comp_cnt++ ) {
    fd_mlx5_tile_cqe_wire_t const * cqe = (fd_mlx5_tile_cqe_wire_t const *)(cq->entries+(cq_cons & (cq->depth-1U)));
    uchar const op_own = FD_VOLATILE_CONST( cqe->op_own );
    uint const opcode = (uint)(op_own>>4);
    if( FD_LIKELY( opcode==FD_MLX5_CQE_INVALID ||
                   (op_own & 1U)!=!!(cq_cons & cq->depth) ) ) break;
    fd_mlx5_tile_dma_from_device();

    if( FD_UNLIKELY( opcode!=FD_MLX5_CQE_RESP_SEND && opcode!=FD_MLX5_CQE_RESP_ERR ) ) {
      errno = EINVAL;
      goto fail;
    }
    uint const wqe_counter = (uint)fd_ushort_bswap( cqe->wqe_counter );
    uint const distance = (uint)(ushort)(wqe_counter-(ushort)rq_cons);
    if( FD_UNLIKELY( distance>=rq_prod-rq_cons ) ) { errno = EPROTO; goto fail; }
    rq_cons += distance+1U;
    comp[ comp_cnt ] = (fd_mlx5_tile_rx_comp_t) {
      .user_data = qp->rx_user_data[ wqe_counter & (qp->rx_depth-1U) ],
      .byte_len  = fd_uint_bswap( cqe->byte_cnt ),
      .opcode    = opcode
    };
    cq_cons++;
  }
  if( FD_UNLIKELY( !comp_cnt ) ) return 0;
  qp->rq_cons = rq_cons;
  cq->cons_idx = cq_cons;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cq->dbrec[0] ) = fd_uint_bswap( cq_cons & 0xffffffU );
  return (int)comp_cnt;

fail:
  if( comp_cnt ) {
    qp->rq_cons = rq_cons;
    cq->cons_idx = cq_cons;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( cq->dbrec[0] ) = fd_uint_bswap( cq_cons & 0xffffffU );
  }
  return -1;
}

static inline int
fd_mlx5_tile_poll_tx_cq( fd_mlx5_qp_t *          qp,
                         fd_mlx5_tile_tx_comp_t * comp,
                         uint                     comp_max ) {
  fd_mlx5_cq_t * cq = qp->tx_cq;
  uint const cq_cons = cq->cons_idx;
  fd_mlx5_tile_cqe_wire_t const * cqe = (fd_mlx5_tile_cqe_wire_t const *)(cq->entries+(cq_cons & (cq->depth-1U)));
  uchar const op_own = FD_VOLATILE_CONST( cqe->op_own );
  uint const opcode = (uint)(op_own>>4);
  if( FD_LIKELY( opcode==FD_MLX5_CQE_INVALID ||
                 (op_own & 1U)!=!!(cq_cons & cq->depth) ) ) return 0;
  fd_mlx5_tile_dma_from_device();
  if( FD_UNLIKELY( opcode!=FD_MLX5_CQE_REQ && opcode!=FD_MLX5_CQE_REQ_ERR ) ) {
    errno = EINVAL;
    return -1;
  }

  uint const sq_cons = qp->sq_cons;
  uint const wqe_counter = (uint)fd_ushort_bswap( cqe->wqe_counter );
  uint const distance = (uint)(ushort)(wqe_counter-(ushort)sq_cons);
  uint const outstanding = qp->sq_prod-sq_cons;
  if( FD_UNLIKELY( outstanding>qp->tx_depth || distance>=outstanding ) ) {
    errno = EPROTO;
    return -1;
  }
  uint const comp_cnt = distance+1U;
  if( FD_UNLIKELY( comp_cnt>comp_max ) ) { errno = ENOSPC; return -1; }
  for( uint i=0U; i<comp_cnt; i++ ) {
    comp[ i ] = (fd_mlx5_tile_tx_comp_t) {
      .user_data = qp->tx_user_data[ (sq_cons+i) & (qp->tx_depth-1U) ],
      .opcode    = opcode
    };
  }
  qp->sq_cons = sq_cons+comp_cnt;
  cq->cons_idx = cq_cons+1U;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cq->dbrec[0] ) = fd_uint_bswap( (cq_cons+1U) & 0xffffffU );
  return (int)comp_cnt;
}

#ifndef FD_TILE_TEST

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_mlx5_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_mlx5_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(),
                                            (uint)ctx->hw.context.async_fd );
  return sock_filter_policy_fd_mlx5_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_mlx5_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = ctx->hw.context.cmd_fd;
  out_fds[ out_cnt++ ] = ctx->hw.context.async_fd;
  return out_cnt;
}

#endif

static uint
fd_mlx5_tile_if_ip4_addr( char const * if_name ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct ifreq ifr = { .ifr_addr.sa_family = AF_INET };
  fd_cstr_ncpy( ifr.ifr_name, if_name, sizeof(ifr.ifr_name) );
  if( FD_UNLIKELY( ioctl( fd, SIOCGIFADDR, &ifr ) ) ) {
    FD_LOG_ERR(( "could not get IP address of interface `%s` (%i-%s)",
                 if_name, errno, fd_io_strerror( errno ) ));
  }
  uint ip4_addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;

  if( FD_UNLIKELY( close( fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return ip4_addr;
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( FD_MLX5_PAGE_SZ,
                       fd_ulong_max( fd_ulong_max( alignof(fd_mlx5_tile_t), tx_free_align() ),
                                     fd_ulong_max( fd_netdev_tbl_align(), fd_fib4_align() ) ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  ulong const queue_footprint = fd_mlx5_queue_footprint( tile->mlx5.rx_queue_size,
                                                         tile->mlx5.tx_queue_size );
  if( FD_UNLIKELY( !queue_footprint ) ) return 0UL;
  l = FD_LAYOUT_APPEND( l, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  l = FD_LAYOUT_APPEND( l, FD_MLX5_PAGE_SZ, queue_footprint );
  l = FD_LAYOUT_APPEND( l, alignof(ulong), tile->mlx5.rx_queue_size*sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong), tile->mlx5.tx_queue_size*sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, tx_free_align(), tx_free_footprint( tile->mlx5.tx_queue_size ) );
  l = FD_LAYOUT_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );
  l = FD_LAYOUT_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
fd_mlx5_tile_rdma_port_contains_if( char const * rdma_name,
                                    uint         port,
                                    char const * if_name ) {
  char path[ PATH_MAX ];
  int path_sz = snprintf( path, sizeof(path), "/sys/class/infiniband/%s/ports/%u/gid_attrs/ndevs",
                          rdma_name, port );
  if( FD_UNLIKELY( path_sz<=0 || (ulong)path_sz>=sizeof(path) ) ) return 0;
  DIR * dir = opendir( path );
  if( FD_UNLIKELY( !dir ) ) return 0;
  struct dirent * entry;
  int found = 0;
  while( !found && (entry=readdir( dir )) ) {
    if( entry->d_name[0]=='.' ) continue;
    char ndev_path[ PATH_MAX ];
    int ndev_path_sz = snprintf( ndev_path, sizeof(ndev_path), "%s/%s", path, entry->d_name );
    if( ndev_path_sz<=0 || (ulong)ndev_path_sz>=sizeof(ndev_path) ) continue;
    int fd = open( ndev_path, O_RDONLY );
    if( fd<0 ) continue;
    char ndev[ IF_NAMESIZE+1 ];
    ssize_t n = read( fd, ndev, IF_NAMESIZE );
    close( fd );
    if( n<=0 ) continue;
    while( n>0 && (ndev[n-1]=='\n' || ndev[n-1]=='\r') ) n--;
    ndev[n] = '\0';
    found = !strcmp( ndev, if_name );
  }
  closedir( dir );
  return found;
}

static int
fd_mlx5_tile_rdma_port_matches_if( char const * rdma_name,
                                   uint         port,
                                   char const * if_name ) {
  if( fd_mlx5_tile_rdma_port_contains_if( rdma_name, port, if_name ) ) return 1;
  if( !fd_bonding_is_master( if_name ) ) return 0;
  fd_bonding_slave_iter_t iter_[1];
  fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, if_name );
  for( ; !fd_bonding_slave_iter_done( iter ); fd_bonding_slave_iter_next( iter ) )
    if( fd_mlx5_tile_rdma_port_contains_if( rdma_name, port, fd_bonding_slave_iter_ele( iter ) ) ) return 1;
  return 0;
}

static void
fd_mlx5_tile_rdma_dev_find( char                         rdma_name[ FD_MLX5_RDMA_NAME_MAX ],
                            uint *                       rdma_port,
                            fd_topo_tile_t const *       tile ) {
  DIR * dir = opendir( "/sys/class/infiniband" );
  if( FD_UNLIKELY( !dir ) )
    FD_LOG_ERR(( "opendir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  rdma_name[0] = '\0';
  *rdma_port = 0U;
  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    if( entry->d_name[0]=='.' ) continue;
    char ports_path[ PATH_MAX ];
    int ports_path_sz = snprintf( ports_path, sizeof(ports_path), "/sys/class/infiniband/%s/ports", entry->d_name );
    if( ports_path_sz<=0 || (ulong)ports_path_sz>=sizeof(ports_path) ) continue;
    DIR * ports = opendir( ports_path );
    if( !ports ) continue;
    struct dirent * port_entry;
    while( (port_entry=readdir( ports )) ) {
      char * end;
      ulong port = strtoul( port_entry->d_name, &end, 10 );
      if( !port || *end || port>255UL ) continue;
      if( !fd_mlx5_tile_rdma_port_matches_if( entry->d_name, (uint)port, tile->mlx5.if_name ) ) continue;
      if( FD_UNLIKELY( rdma_name[0] ) )
        FD_LOG_ERR(( "multiple RDMA ports match interface `%s` (`%s` port %u and `%s` port %lu)",
                     tile->mlx5.if_name, rdma_name, *rdma_port, entry->d_name, port ));
      fd_cstr_ncpy( rdma_name, entry->d_name, FD_MLX5_RDMA_NAME_MAX );
      *rdma_port = (uint)port;
    }
    closedir( ports );
  }
  if( FD_UNLIKELY( closedir( dir ) ) )
    FD_LOG_ERR(( "closedir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !rdma_name[0] ) )
    FD_LOG_ERR(( "RDMA device port for interface `%s` not found", tile->mlx5.if_name ));
}

static inline void
fd_mlx5_tile_rx_recycle( fd_mlx5_tile_t * ctx,
                         ulong            chunk ) {
  ctx->rx_pending[ --ctx->rx_pending_rem ].chunk = (uint)chunk;

  if( !ctx->rx_pending_rem ) {
    uint const recv_cnt = ctx->batch_size-ctx->rx_pending_rem;
    if( FD_UNLIKELY( fd_mlx5_tile_post_recv( ctx, recv_cnt ) ) )
      FD_LOG_ERR(( "direct mlx5 RX post failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    ctx->rx_pending_rem = ctx->batch_size;
  }
}

/* rxq_assign adds a routing rule.  All incoming IPv4 UDP ports with the
   specified dst port will be redirected to the first output link in the
   topology with the specified names.  frag_meta descriptors are annotated
   with the given 'dst_proto' value. */

static void
rxq_assign( fd_mlx5_tile_t *       ctx,
            fd_topo_t const *      topo,
            fd_topo_tile_t const * tile,
            ulong                  dst_proto,
            char const *           out_link,
            ushort                 dst_port,
            int                    required ) {
  if( FD_UNLIKELY( !dst_port ) ) return;
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, out_link, 0UL );
  if( FD_UNLIKELY( out_idx==ULONG_MAX ) ) {
    if( FD_UNLIKELY( required ) )
      FD_LOG_ERR(( "mlx5 output link `%s` is missing for UDP port %hu", out_link, dst_port ));
    return;
  }
  if( FD_UNLIKELY( ctx->dst_port_cnt>=FD_MLX5_FLOW_CAP ) ) {
    FD_LOG_ERR(( "mlx5 tile flow rule count exceeds max of %lu", FD_MLX5_FLOW_CAP ));
  }
  uint const idx = ctx->dst_port_cnt;
  ctx->dst_protos [ idx ] = (uchar)dst_proto;
  ctx->dst_ports  [ idx ] = dst_port;
  ctx->dst_out_idx[ idx ] = (uchar)out_idx;
  ctx->dst_port_cnt++;
}

static void
rxq_assign_all( fd_mlx5_tile_t *       ctx,
                fd_topo_t const *      topo,
                fd_topo_tile_t const * tile ) {
  ctx->rx_out_cnt     = (uchar)tile->out_cnt;
  ctx->repair_out_idx = UCHAR_MAX;
  rxq_assign( ctx, topo, tile, DST_PROTO_TPU_UDP,  "net_quic",   tile->mlx5.net.legacy_transaction_listen_port, 1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_TPU_QUIC, "net_quic",   tile->mlx5.net.quic_transaction_listen_port,   1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_SHRED,    "net_shred",  tile->mlx5.net.shred_listen_port,              1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_GOSSIP,   "net_gossvf", tile->mlx5.net.gossip_listen_port,             1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_REPAIR,   "net_shred",  tile->mlx5.net.repair_client_listen_port,      1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_RSERVE,   "net_rserve", tile->mlx5.net.repair_serve_listen_port,       0 );
  rxq_assign( ctx, topo, tile, DST_PROTO_SEND,     "net_txsend", tile->mlx5.net.txsend_src_port,                1 );

  if( tile->mlx5.net.repair_client_listen_port ) {
    ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "net_repair", 0UL );
    if( FD_UNLIKELY( out_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "mlx5 output link `net_repair` is missing for repair pings" ));
    ctx->repair_out_idx = (uchar)out_idx;
  }
}

/* privileged_init creates direct mlx5 resources through uverbs. */

FD_FN_UNUSED static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_mlx5_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  memset( ctx, 0, sizeof(fd_mlx5_tile_t) );
  ulong queue_footprint = fd_mlx5_queue_footprint( tile->mlx5.rx_queue_size,
                                                   tile->mlx5.tx_queue_size );
  void * queue_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_MLX5_PAGE_SZ, queue_footprint );
  ulong * rx_user_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),
                                                  tile->mlx5.rx_queue_size*sizeof(ulong) );
  ulong * tx_user_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),
                                                  tile->mlx5.tx_queue_size*sizeof(ulong) );
  ctx->batch_size = tile->mlx5.batch_size;

  /* Load up dcache containing UMEM */
  void * const dcache_mem  = fd_topo_obj_laddr( topo, tile->mlx5.umem_dcache_obj_id );
  void * const umem_dcache = fd_dcache_join( dcache_mem );
  FD_TEST( umem_dcache );
  ulong  const umem_dcache_data_sz = fd_dcache_data_sz( umem_dcache );
  ulong  const umem_frame_sz       = 2048UL;
  if( FD_UNLIKELY( !umem_dcache ) ) {
    FD_LOG_ERR(( "fd_dcache_join(mlx5.umem_dcache_obj_id failed" ));
  }

  /* Left shrink UMEM region to be 4096 byte aligned */
  void * const umem_frame0 = (void *)fd_ulong_align_up( (ulong)umem_dcache, 4096UL );
  ulong        umem_sz     = umem_dcache_data_sz - ((ulong)umem_frame0-(ulong)umem_dcache);
  umem_sz = fd_ulong_align_dn( umem_sz, umem_frame_sz );

  /* Derive chunk bounds */
  void * const umem_base   = fd_wksp_containing( dcache_mem );
  ulong  const umem_chunk0 = ((ulong)umem_frame0-(ulong)umem_base)>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark  = umem_chunk0 + ((umem_sz-umem_frame_sz)>>FD_CHUNK_LG_SZ);
  if( FD_UNLIKELY( umem_chunk0>UINT_MAX || umem_wmark>UINT_MAX || umem_chunk0>umem_wmark ) ) {
    FD_LOG_ERR(( "Calculated invalid UMEM bounds [%lu,%lu]", umem_chunk0, umem_wmark ));
  }
  if( FD_UNLIKELY( !umem_base   ) ) FD_LOG_ERR(( "UMEM dcache is not in a workspace" ));
  if( FD_UNLIKELY( !umem_dcache ) ) FD_LOG_ERR(( "Failed to join UMEM dcache" ));

  ctx->umem_base   = (uchar *)umem_base;
  ctx->umem_frame0 = umem_frame0;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;

  if( FD_UNLIKELY( tile->kind_id!=0 ) ) {
    /* FIXME support receive side scaling. */
    FD_LOG_ERR(( "Sorry, net.provider='mlx5' only supports layout.net_tile_count=1" ));
  }

  char rdma_name[ FD_MLX5_RDMA_NAME_MAX ];
  uint rdma_port;
  fd_mlx5_tile_rdma_dev_find( rdma_name, &rdma_port, tile );
  FD_LOG_INFO(( "Opening direct mlx5 device `%s` port %u", rdma_name, rdma_port ));
  if( FD_UNLIKELY( !fd_mlx5_init( &ctx->hw, rdma_name, rdma_port,
                                  queue_mem, tile->mlx5.rx_queue_size, tile->mlx5.tx_queue_size,
                                  rx_user_data, tx_user_data, umem_frame0, umem_sz ) ) )
    FD_LOG_ERR(( "direct mlx5 setup failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int async_fd    = ctx->hw.context.async_fd;
  int async_flags = fcntl( async_fd, F_GETFL );
  if( FD_UNLIKELY( 0!=fcntl( async_fd, F_SETFL, async_flags|O_NONBLOCK ) ) ) {
    FD_LOG_ERR(( "making mlx5 async fd non-blocking failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  uint if_idx = if_nametoindex( tile->mlx5.if_name );
  if( FD_UNLIKELY( !if_idx ) ) {
    FD_LOG_ERR(( "if_nametoindex(%s) failed (%i-%s)",
                 tile->mlx5.if_name, errno, fd_io_strerror( errno ) ));
  }
  ctx->r.if_virt         = if_idx;
  ctx->r.default_address = fd_mlx5_tile_if_ip4_addr( tile->mlx5.if_name );

  rxq_assign_all( ctx, topo, tile );
  for( ulong i=0UL; i<(ctx->dst_port_cnt); i++ ) {
    if( FD_UNLIKELY( fd_mlx5_flow_create_udp( &ctx->hw.qp,
                                              tile->mlx5.net.bind_address,
                                              ctx->dst_ports[ i ] ) ) )
      FD_LOG_ERR(( "fd_mlx5_flow_create_udp failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    FD_LOG_DEBUG(( "Created flow rule for ip4.dst_ip=" FD_IP4_ADDR_FMT " udp.dst_port:%hu",
                   FD_IP4_ADDR_FMT_ARGS( tile->mlx5.net.bind_address ),
                   ctx->dst_ports[ i ] ));
  }
  FD_LOG_INFO(( "Installed %u direct mlx5 flow rules", ctx->dst_port_cnt ));
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_mlx5_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  ulong queue_footprint = fd_mlx5_queue_footprint( tile->mlx5.rx_queue_size,
                                                   tile->mlx5.tx_queue_size );
  (void)FD_SCRATCH_ALLOC_APPEND( l, FD_MLX5_PAGE_SZ, queue_footprint );
  (void)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->mlx5.rx_queue_size*sizeof(ulong) );
  (void)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->mlx5.tx_queue_size*sizeof(ulong) );
  ctx->batch_size = tile->mlx5.batch_size;
  void * deque_mem       = FD_SCRATCH_ALLOC_APPEND( l, tx_free_align(), tx_free_footprint( tile->mlx5.tx_queue_size ) );
  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * fib_local_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );
  void * fib_main_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );

  /* chunk 0 is used as a sentinel value, so ensure actual chunk indices
     do not use that value. */
  FD_TEST( ctx->umem_chunk0>0 );

  ctx->rx_pending_rem = ctx->batch_size;

  /* Post RX descriptors */
  ulong frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong next_chunk   = ctx->umem_chunk0;
  FD_TEST( tile->mlx5.rx_queue_size>ctx->batch_size );
  ulong const rx_fill_cnt = tile->mlx5.rx_queue_size-ctx->batch_size;
  for( ulong i=0UL; i<rx_fill_cnt; i++ ) {
    fd_mlx5_tile_rx_recycle( ctx, next_chunk );
    next_chunk += frame_chunks;
  }

  /* Assign chunks to RX mcaches */
  for( ulong i=0UL; i<(tile->out_cnt); i++ ) {
    fd_frag_meta_t * mcache = topo->links[ tile->out_link_id[ i ] ].mcache;
    ulong const      depth  = fd_mcache_depth( mcache );
    for( ulong j=0UL; j<depth; j++ ) {
      mcache[ j ].chunk = (uint)next_chunk;
      mcache[ j ].seq   = fd_seq_dec( j, 1UL ); /* mark seq as invalid */
      next_chunk += frame_chunks;
    }
  }
  /* Init TX free list */
  ctx->tx_free = tx_free_join( tx_free_new( deque_mem, tile->mlx5.tx_queue_size ) );
  while( !tx_free_full( ctx->tx_free ) ) {
    tx_free_push_tail( ctx->tx_free, (uint)next_chunk );
    next_chunk += frame_chunks;
  }
  /* Init TX */
  if( FD_UNLIKELY( tile->in_cnt>FD_TOPO_MAX_TILE_IN_LINKS ) ) {
    FD_LOG_ERR(( "mlx5 tile in link count %lu exceeds max of %lu", tile->in_cnt, FD_TOPO_MAX_TILE_IN_LINKS ));
  }
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "iproute_out" ) ) {
      ctx->in_kind[ i ] = IN_KIND_IPROUTE;
    } else {
      ctx->in_kind[ i ] = IN_KIND_NET;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "mlx5 tile in link does not have a normal MTU" ));
    }

    ctx->txq[ i ].base   = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->txq[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->txq[ i ].base, link->dcache );
    ctx->txq[ i ].wmark  = fd_dcache_compact_wmark(  ctx->txq[ i ].base, link->dcache, link->mtu );
  }

  /* Join netbase objects */
  FD_TEST( fd_fib4_join( ctx->r.fib_local, fd_fib4_new( fib_local_mem, tile->mlx5.route_max, tile->mlx5.route_peer_max, tile->mlx5.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->r.fib_main,  fd_fib4_new( fib_main_mem,  tile->mlx5.route_max, tile->mlx5.route_peer_max, tile->mlx5.route_peer_seed ) ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->r.netdev_shared, fd_topo_obj_laddr( topo, tile->mlx5.netdev_tbl_obj_id ) ) );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->r.netdev_tbl, netdev_tbl_local ) );
  fd_netdev_tbl_copy( &ctx->r.netdev_tbl, &ctx->r.netdev_shared );
  ctx->r.bind_address = tile->mlx5.net.bind_address;

  ulong neigh4_obj_id = tile->mlx5.neigh4_obj_id;
  ulong ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) )
    FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join(
      ctx->r.neigh4,
      fd_topo_obj_laddr( topo, neigh4_obj_id ),
      ele_max,
      probe_max,
      seed ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  ulong net_netlnk_id = fd_topo_find_link( topo, "net_netlnk", 0UL );
  if( FD_LIKELY( net_netlnk_id!=ULONG_MAX ) ) {
    fd_topo_link_t const * net_netlnk = &topo->links[ net_netlnk_id ];
    if( FD_UNLIKELY( !net_netlnk->mcache ) ) FD_LOG_ERR(( "netlink request link not initialized" ));
    ctx->r.neigh4_solicit->mcache = net_netlnk->mcache;
    ctx->r.neigh4_solicit->depth  = fd_mcache_depth( ctx->r.neigh4_solicit->mcache );
    ctx->r.neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->r.neigh4_solicit->mcache ) );
  } else {
    FD_LOG_ERR(( "netlink request link not found" ));
  }

  /* Check if all chunks are in bound */
  if( FD_UNLIKELY( next_chunk>ctx->umem_wmark ) ) {
    FD_LOG_ERR(( "dcache is too small (topology bug)" ));
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)ctx+scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow" ));
  }
}

static inline void
metrics_write( fd_mlx5_tile_t * ctx ) {
  FD_MCNT_SET( MLX5, RX_PKT_CNT,     ctx->metrics.rx_pkt_cnt     );
  FD_MCNT_SET( MLX5, RX_BYTES_TOTAL, ctx->metrics.rx_bytes_total );
  FD_MCNT_SET( MLX5, TX_PKT_CNT,     ctx->metrics.tx_pkt_cnt     );
  FD_MCNT_SET( MLX5, TX_BYTES_TOTAL, ctx->metrics.tx_bytes_total );
}

static inline void
during_housekeeping( fd_mlx5_tile_t * ctx ) {
  for(;;) {
    struct ib_uverbs_async_event_desc event;
    ssize_t read_sz = read( ctx->hw.context.async_fd, &event, sizeof(event) );
    if( FD_LIKELY( read_sz<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ) ) break;
    if( FD_UNLIKELY( read_sz!=(ssize_t)sizeof(event) ) )
      FD_LOG_ERR(( "mlx5 async event read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    uint event_type = event.event_type;
    if( FD_UNLIKELY( event_type==FD_MLX5_EVENT_CQ_ERR        ||
                     event_type==FD_MLX5_EVENT_QP_FATAL      ||
                     event_type==FD_MLX5_EVENT_QP_REQ_ERR    ||
                     event_type==FD_MLX5_EVENT_QP_ACCESS_ERR ||
                     event_type==FD_MLX5_EVENT_DEVICE_FATAL  ||
                     event_type==FD_MLX5_EVENT_WQ_FATAL ) )
      FD_LOG_ERR(( "fatal mlx5 async event %u on element %lu", event_type, (ulong)event.element ));
    FD_LOG_INFO(( "mlx5 async event %u on element %lu", event_type, (ulong)event.element ));
  }
  if( FD_LIKELY( !fd_seqlock_locked_hint( &ctx->r.netdev_shared.hdr->seqlock ) ) ) {
    fd_netdev_tbl_copy( &ctx->r.netdev_tbl, &ctx->r.netdev_shared );
  }
}

static inline int
fd_mlx5_tile_rx_route( fd_mlx5_tile_t const * ctx,
                       ushort                 net_dport,
                       ulong                  sz,
                       ulong *                out_idx,
                       ulong *                proto ) {
  ulong rule_idx = ULONG_MAX;
  for( ulong i=0UL; i<ctx->dst_port_cnt; i++ ) {
    if( ctx->dst_ports[ i ]==net_dport ) {
      rule_idx = i;
      break;
    }
  }
  if( FD_UNLIKELY( rule_idx==ULONG_MAX ) ) return 0;

  *out_idx = ctx->dst_out_idx[ rule_idx ];
  *proto   = ctx->dst_protos [ rule_idx ];
  if( FD_UNLIKELY( *proto==DST_PROTO_REPAIR && sz==REPAIR_PING_SZ ) ) {
    if( FD_UNLIKELY( ctx->repair_out_idx==UCHAR_MAX ) ) return 0;
    *out_idx = ctx->repair_out_idx;
  }
  return *out_idx<ctx->rx_out_cnt;
}

/* fd_mlx5_tile_rx_pkt handles a direct mlx5 RX completion.  If the completion
   frees a frame, returns the chunk index.  Returns zero if no frame can
   be freed.

   The completion can either fail (immediately returns the chunk of the
   failed WQE for freeing), or succeed (posts a frag to tango, returns
   the shadowed chunk index for freeing). */

static inline ulong
fd_mlx5_tile_rx_pkt( fd_mlx5_tile_t *          ctx,
                     fd_stem_context_t *       stem,
                     ulong                     wr_id,
                     ulong                     byte_len,
                     uint                      opcode,
                     ulong                     tspub,
                     fd_mlx5_tile_rx_stats_t * stats ) {
  if( FD_UNLIKELY( opcode!=FD_MLX5_CQE_RESP_SEND ) ) return wr_id;

  ulong const chunk = wr_id;
  ulong const sz    = byte_len;

  if( FD_UNLIKELY( chunk<ctx->umem_chunk0 || chunk>ctx->umem_wmark ) ) {
    FD_LOG_CRIT(( "RX completion chunk %lu out of bounds [%u,%u]", chunk, ctx->umem_chunk0, ctx->umem_wmark ));
  }
  fd_eth_hdr_t const * l2 = fd_chunk_to_laddr_const( ctx->umem_base, chunk );
  fd_ip4_hdr_t const * l3 = (fd_ip4_hdr_t const *)(l2+1);
  fd_udp_hdr_t const * l4 = (fd_udp_hdr_t const *)( (uchar *)l3 + FD_IP4_GET_LEN( *l3 ) );
  ulong const dgram_off = (ulong)(l4+1) - (ulong)l2;

  /* Even though these are reads of uninitialized / untrusted data, this
     never actually goes beyond the bounds of a frame (FD_NET_MTU). */
  int const sz_ok = (sz<=FD_NET_MTU) & (FD_IP4_GET_LEN( *l3 )>=sizeof(fd_ip4_hdr_t)) & (dgram_off<=sz);
  int const hdr_ok =
    ( fd_ushort_bswap( l2->net_type )==FD_ETH_HDR_TYPE_IP ) &
    ( FD_IP4_GET_VERSION( *l3 )==4 ) &
    ( l3->protocol==FD_IP4_HDR_PROTOCOL_UDP );

  ushort const net_dport = fd_ushort_bswap( l4->net_dport );
  int const filter = sz_ok & hdr_ok;
  if( FD_UNLIKELY( !filter ) ) return wr_id;

  ulong out_idx;
  ulong proto;
  if( FD_UNLIKELY( !fd_mlx5_tile_rx_route( ctx, net_dport, sz, &out_idx, &proto ) ) ) return wr_id;

  /* FIXME: Since the order of wr_ids in CQEs mirrors those posted in
            WQEs, we could recover the shadowed wr_id/chunk without
            touching memory here ... */
  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong const      depth  = stem->depths [ out_idx ];
  ulong *          seqp   = &stem->seqs  [ out_idx ];
  ulong const      seq    = *seqp;

  ulong freed_chunk = mcache[ fd_mcache_line_idx( seq, depth ) ].chunk;

  ulong const sig    = fd_disco_netmux_sig( l3->saddr, l4->net_sport, 0U, proto, dgram_off );
  ulong const ctl    = 0UL;
  ulong const tsorig = 0UL;
  fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub );
  stats->pkt_cnt++;
  stats->bytes_total += sz;

  return freed_chunk;
}

/* fd_mlx5_tile_tx_recycle recycles the TX frame of a completed TX operation. */

static void
fd_mlx5_tile_tx_recycle( fd_mlx5_tile_t * ctx,
                         ulong            chunk ) {
  if( FD_UNLIKELY( (chunk<ctx->umem_chunk0) | (chunk>ctx->umem_wmark) ) ) {
    FD_LOG_ERR(( "TX completion chunk %lu out of bounds [%u,%u]", chunk, ctx->umem_chunk0, ctx->umem_wmark ));
  }
  if( FD_UNLIKELY( !tx_free_push_head( ctx->tx_free, (uint)chunk ) ) ) {
    FD_LOG_ERR(( "TX free list full" ));
  }
}

static inline void
fd_mlx5_tile_tx_flush( fd_mlx5_tile_t * ctx ) {
  uint const tx_pending_cnt = ctx->tx_pending_cnt;
  if( FD_UNLIKELY( fd_mlx5_tile_post_send( ctx, tx_pending_cnt ) ) )
    for( uint i=0U; i<tx_pending_cnt; i++ ) fd_mlx5_tile_tx_recycle( ctx, ctx->tx_pending[ i ].chunk );

  ctx->tx_pending_cnt  = 0U;
  ctx->tx_pending_idle = 0U;
}

static inline int
fd_mlx5_tile_poll_rx( fd_mlx5_tile_t *    ctx,
                      fd_stem_context_t * stem ) {
  fd_mlx5_tile_rx_comp_t comp[ FD_MLX5_BATCH_MAX ];
  int comp_cnt = fd_mlx5_tile_poll_rx_cq( &ctx->hw.qp, comp, ctx->batch_size );
  if( FD_UNLIKELY( comp_cnt<0 ) )
    FD_LOG_ERR(( "direct mlx5 RX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !comp_cnt ) ) return 0;

  ulong const tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mlx5_tile_rx_stats_t stats = {0};

  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    ulong const chunk = comp[ i ].user_data;
    if( FD_LIKELY( comp[ i ].opcode==FD_MLX5_CQE_RESP_SEND &&
                   chunk>=ctx->umem_chunk0 && chunk<=ctx->umem_wmark ) ) {
      __builtin_prefetch( fd_chunk_to_laddr_const( ctx->umem_base, chunk ), 0, 3 );
    }
  }

  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    ulong freed_chunk = fd_mlx5_tile_rx_pkt( ctx, stem, comp[ i ].user_data,
                                           comp[ i ].byte_len, comp[ i ].opcode, tspub, &stats );
    if( FD_UNLIKELY( !freed_chunk ) ) FD_LOG_CRIT(( "invalid chunk in mcache" ));
    fd_mlx5_tile_rx_recycle( ctx, freed_chunk );
  }
  ctx->metrics.rx_pkt_cnt     += stats.pkt_cnt;
  ctx->metrics.rx_bytes_total += stats.bytes_total;
  return 1;
}

static inline int
fd_mlx5_tile_poll_tx( fd_mlx5_tile_t * ctx ) {
  fd_mlx5_tile_tx_comp_t comp[ FD_MLX5_BATCH_MAX ];
  int busy = 0;
  for( uint poll_cnt=0U; poll_cnt<ctx->batch_size; poll_cnt++ ) {
    int batch_cnt = fd_mlx5_tile_poll_tx_cq( &ctx->hw.qp, comp, ctx->batch_size );
    if( FD_UNLIKELY( batch_cnt<0 ) )
      FD_LOG_ERR(( "direct mlx5 TX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !batch_cnt ) ) break;
    busy = 1;
    for( uint i=0U; i<(uint)batch_cnt; i++ ) {
      fd_mlx5_tile_send_wr_t meta = fd_mlx5_tile_tx_meta( comp[ i ].user_data );
      if( FD_LIKELY( comp[ i ].opcode==FD_MLX5_CQE_REQ ) ) {
        ctx->metrics.tx_pkt_cnt++;
        ctx->metrics.tx_bytes_total += meta.sz;
      }
      fd_mlx5_tile_tx_recycle( ctx, meta.chunk );
    }
  }
  return busy;
}

static inline void
before_credit( fd_mlx5_tile_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  int tx_submit_busy = 0;
  if( FD_UNLIKELY( ctx->tx_pending_cnt ) ) {
    if( ctx->tx_pending_idle ) {
      fd_mlx5_tile_tx_flush( ctx );
      tx_submit_busy = 1;
    }
    else                       ctx->tx_pending_idle = 1U;
  }
  int tx_complete_busy = !tx_free_full( ctx->tx_free ) && fd_mlx5_tile_poll_tx( ctx );
  *charge_busy |= tx_submit_busy | tx_complete_busy;
}

/* after_credit is called every run loop iteration, provided there is
   sufficient downstream credit for forwarding on all output links. */

static inline void
after_credit( fd_mlx5_tile_t *    ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  int rx_busy = fd_mlx5_tile_poll_rx( ctx, stem );
  *charge_busy |= rx_busy;
}

/* {before,during,after}_frag copy a packet received from an input link out
   to the direct mlx5 send queue. */

static inline int
before_frag( fd_mlx5_tile_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) {
  (void)seq;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) return 0;

  /* Find interface index of next packet */

  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_OUTGOING ) ) return 1;

  uint dst_ip = fd_disco_netmux_sig_ip( sig );
  if( FD_UNLIKELY( !fd_net_tx_route( &ctx->r, dst_ip, &ctx->tx_route ) ) ) return 1;
  if( FD_UNLIKELY( ctx->tx_route.use_gre ) ) return 1;

  /* Skip if TX is blocked */

  if( FD_UNLIKELY( tx_free_empty( ctx->tx_free ) ) ) {
    /* FIXME metric */
    return 1; /* ignore */
  }

  return 0; /* continue */
}

static inline void
during_frag( fd_mlx5_tile_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl ) {
  (void)seq; (void)sig; (void)ctl;

  fd_mlx5_tile_txq_t * txq = &ctx->txq[ in_idx ];
  if( FD_UNLIKELY( chunk<txq->chunk0 || chunk>txq->wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, txq->chunk0, txq->wmark ));
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    if( FD_UNLIKELY( sz!=sizeof(fd_iproute_msg_t) ) ) FD_LOG_ERR(( "invalid iproute message size %lu", sz ));
    fd_memcpy( &ctx->iproute_msg, fd_chunk_to_laddr_const( txq->base, chunk ), sizeof(fd_iproute_msg_t) );
    return;
  }
  if( FD_UNLIKELY( sz<34UL ) ) {
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", sz, in_idx ));
  }

  /* Speculatively copy frame into buffer */
  ulong        dst_chunk = *tx_free_peek_head( ctx->tx_free );
  void *       dst       = fd_chunk_to_laddr( ctx->umem_base, dst_chunk );
  void const * src       = fd_chunk_to_laddr_const( txq->base, chunk );
  fd_memcpy( dst, src, sz );
}

static void
after_frag( fd_mlx5_tile_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub; (void)stem;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    fd_iproute_msg_t const * msg = &ctx->iproute_msg;
    if( msg->op==FD_IPROUTE_OP_FLUSH ) {
      fd_fib4_clear( ctx->r.fib_local );
      fd_fib4_clear( ctx->r.fib_main );
      return;
    }
    fd_fib4_t * fib;
    if( msg->table_id==RT_TABLE_LOCAL ) fib = ctx->r.fib_local;
    else if( msg->table_id==RT_TABLE_MAIN ) fib = ctx->r.fib_main;
    else return;
    if( msg->op==FD_IPROUTE_OP_UPSERT && FD_UNLIKELY( !fd_fib4_insert( fib, msg->dst_addr, msg->prefix, msg->prio, &msg->hop ) ) ) {
      FD_LOG_WARNING(( "route update dropped: route table full (increase [net.max_routes] or [net.max_peer_routes])" ));
      fd_netlink_route4_sync( ctx->r.neigh4_solicit, fd_frag_meta_ts_comp( fd_tickcount() ) );
    } else if( msg->op==FD_IPROUTE_OP_DELETE ) {
      fd_fib4_remove( fib, msg->dst_addr, msg->prefix, msg->prio );
    }
    return;
  }

  /* Set Ethernet src and dst MAC addrs, optionally mangle IPv4 header to
     fill in source address (if it's missing). */
  ulong  chunk = *tx_free_peek_head( ctx->tx_free );
  void * frame = fd_chunk_to_laddr( ctx->umem_base, chunk );
  if( FD_UNLIKELY( !fd_net_tx_fill_addrs( &ctx->r, &ctx->tx_route, frame, sz ) ) ) return;

  /* Queue TX job */
  uint batch_idx = ctx->tx_pending_cnt;
  ctx->tx_pending[ batch_idx ] = (fd_mlx5_tile_send_wr_t) {
    .chunk = (uint)chunk,
    .sz    = (uint)sz
  };

  /* Consume frame */
  tx_free_pop_head( ctx->tx_free );
  ctx->tx_pending_cnt  = batch_idx+1U;
  ctx->tx_pending_idle = 0U;
  if( FD_UNLIKELY( ctx->tx_pending_cnt==ctx->batch_size ) ) fd_mlx5_tile_tx_flush( ctx );
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_mlx5_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_mlx5_tile_t)
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_BURST                  FD_MLX5_BATCH_MAX
#define STEM_LAZY                   130000UL /* 130us */
#include "../../stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_mlx5 = {
  .name                     = "mlx5",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
