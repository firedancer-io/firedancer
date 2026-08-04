/* The mlx5 tile translates Ethernet frames between mlx5 work/completion
   queues and fd_tango traffic.

   An mlx5 queue pair (QP) contains a send queue (SQ) and a receive queue
   (RQ).  Work queue entries (WQEs) encode posted work.  Completion
   queue entries (CQEs) report completed work through completion queues
   (CQs).  The mlx5 tile uses separate CQs for TX and RX, one each. */

#include "../fd_net_tile.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../fd_net_common.h"
#include "../../metrics/fd_metrics.h"
#include "../fd_net_router.h"
#include "../fd_linux_bond.h"
#include "../../topo/fd_topo.h"

#include "../../../waltz/ip/fd_iproute.h"
#include "../../../waltz/mlx5/fd_mlx5.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"
#include "../../../util/pod/fd_pod_format.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#include <dirent.h>
#include <rdma/ib_user_verbs.h>

#ifndef FD_TILE_TEST
#include "generated/fd_mlx5_tile_seccomp.h"
#endif

#define IN_KIND_NET     (0U)
#define IN_KIND_IPROUTE (1U)

/* Max number of flow rules */
#define FD_MLX5_FLOW_CAP (64UL)
/* Frequent mlx5 stat updates are unnecessary, therefore 1s interval */
#define FD_MLX5_STATS_INTERVAL_NS (1e9)

/* FD_MLX5_SQ_* are options in a SQ WQE to request certain NIC behaviour.
   SEND requests packet transmission.  CQ_UPDATE requests a CQE. */
#define FD_MLX5_SQ_SEND_PKT    (0x0aU) /* SEND */
#define FD_MLX5_SQ_REQUEST_CQE (0x08U) /* CQ_UPDATE */

/* FD_MLX5_CQE_* are mlx5 CQE opcodes used to classify TX and RX completions. */
#define FD_MLX5_CQE_TX_OK   ( 0U) /* REQ */
#define FD_MLX5_CQE_RX_OK   ( 2U) /* RESP_SEND */
#define FD_MLX5_CQE_TX_ERR  (13U) /* REQ_ERR */
#define FD_MLX5_CQE_RX_ERR  (14U) /* RESP_ERR */
#define FD_MLX5_CQE_INVALID (15U) /* INVALID, CQEs initialized to this. */

/* FD_MLX5_EVENT_* define ib_uverbs_async_event_desc.event_type values
   that are fatal to the mlx5 tile. */
#define FD_MLX5_EVENT_CQ_ERR        ( 0U)
#define FD_MLX5_EVENT_QP_FATAL      ( 1U)
#define FD_MLX5_EVENT_QP_REQ_ERR    ( 2U)
#define FD_MLX5_EVENT_QP_ACCESS_ERR ( 3U)
#define FD_MLX5_EVENT_DEVICE_FATAL  ( 8U)
#define FD_MLX5_EVENT_WQ_FATAL      (19U)

 /* The fd_mlx5_hw_* structs below define WQE and CQE formats in the
     mlx5 hardware interface.  The links show the corresponding definitions
     in the Linux mlx5 driver. */

/* https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/mlx5/qp.h#L205 */
struct __attribute__((packed)) fd_mlx5_hw_wqe_ctrl_seg {
  /* mlx5 packs opmod, WQE index, opcode, QP number, and WQE segment
     count into two big-endian 32-bit words. */
  uint  opmod_idx_opcode;
  uint  qpn_ds;
  uchar signature;
  uchar reserved[2];
  uchar flags;
  uint  imm;
};
typedef struct fd_mlx5_hw_wqe_ctrl_seg fd_mlx5_hw_wqe_ctrl_seg_t;

/* https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/mlx5/qp.h#L265 */
struct __attribute__((packed)) fd_mlx5_hw_wqe_eth_seg {
  uchar  reserved[12];
  ushort inline_hdr_sz;
  uchar  inline_hdr[2];
};
typedef struct fd_mlx5_hw_wqe_eth_seg fd_mlx5_hw_wqe_eth_seg_t;

/* https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/mlx5/qp.h#L364 */
struct __attribute__((packed)) fd_mlx5_hw_wqe_data_seg {
  uint  byte_cnt;
  uint  lkey;
  ulong addr;
};
typedef struct fd_mlx5_hw_wqe_data_seg fd_mlx5_hw_wqe_data_seg_t;

/* https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/mlx5/device.h#L824 */
struct __attribute__((packed,may_alias)) fd_mlx5_hw_cqe64 {
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
typedef struct fd_mlx5_hw_cqe64 fd_mlx5_hw_cqe64_t;

struct fd_mlx5_tile_rx_comp {
  ulong chunk;
  uint  byte_len;
  uint  opcode;
};
typedef struct fd_mlx5_tile_rx_comp fd_mlx5_tile_rx_comp_t;

struct fd_mlx5_tile_input_ctx {
  void * wksp_base;
  ulong  chunk0;
  ulong  wmark;
};
typedef struct fd_mlx5_tile_input_ctx fd_mlx5_tile_input_ctx_t;

/* fd_mlx5_tile_t is private tile state */
struct fd_mlx5_tile {
  /* SQ and RQ WQEs cannot be reused until CQ polling advances their
     consumer index.  The expected owner bit alternates whenever the
     CQ wraps, distinguishing newly written CQEs from stale entries.
     A CQE is handed to mlx5 tile by the NIC once the CQE's owner
     bit matches what is expected for the current CQ wrap. */
  fd_mlx5_t hw;
  uint      batch_size;
  uint      rx_pending_rem;
  long      stats_interval_ticks;
  long      next_stats_refresh_ticks;
  ulong     rx_out_of_buffer_prev_cnt;

  /* UMEM frame region within dcache */
  uchar * umem_base;   /* Workspace base */
  uchar * umem_frame0; /* First UMEM frame */

  /* UMEM chunk region within workspace */
  uint umem_chunk0; /* Lowest allowed chunk number */
  uint umem_wmark;  /* Highest allowed chunk number */
  uint tx_chunk0;   /* First TX buffer chunk */

  /* TX input links*/
  fd_mlx5_tile_input_ctx_t input_ctx[ FD_TOPO_MAX_TILE_IN_LINKS ];
  uchar                    in_kind  [ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_iproute_msg_t         iproute_msg;

  /* TX IP routing */
  fd_net_router_t   router;
  fd_net_tx_route_t tx_route;

  /* RX UDP destination port to RX out link */
  uint   dst_port_cnt;
  ushort dst_ports  [ FD_MLX5_FLOW_CAP ];
  uchar  dst_protos [ FD_MLX5_FLOW_CAP ];
  uchar  dst_out_idx[ FD_MLX5_FLOW_CAP ];
  uchar  repair_out_idx;

  /* Recycled RX buffers waiting for batched RQ reposting. */
  uint rx_pending[ FD_MLX5_BATCH_MAX ];

  /* Out links */
  uchar rx_out_cnt;

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_cqe_err_cnt;
    ulong rx_out_of_buffer_cnt;
    ulong rx_malformed_cnt;
    ulong rx_route_fail_cnt;
    ulong tx_pkt_cnt;
    ulong tx_bytes_total;
    ulong tx_cqe_err_cnt;
    ulong tx_no_buffer_cnt;
    ulong tx_gre_unsupported_cnt;
    ulong tx_submit_fail_cnt;
  } metrics;
};
typedef struct fd_mlx5_tile fd_mlx5_tile_t;

/* TX buffer i is permanently paired with SQ WQE i.  The buffer is
   reusable once sq_cons advances past that WQE. */
static inline uint
fd_mlx5_tile_tx_chunk( fd_mlx5_tile_t const * ctx,
                       uint                  sq_idx ) {
  return ctx->tx_chunk0 + (sq_idx & (ctx->hw.qp.tx_depth-1U))*(uint)(FD_NET_MTU>>FD_CHUNK_LG_SZ);
}

static inline void
fd_mlx5_hw_dma_to_device( void ) {
#if FD_HAS_X86
  FD_COMPILER_MFENCE();
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshst" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline void
fd_mlx5_hw_dma_from_device( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "lfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshld" ::: "memory" );
#else
  FD_HW_MFENCE();
#endif
}

static inline int
fd_mlx5_hw_init_tx_wqe( fd_mlx5_tx_wqe_t * wqe,
                        uint               sq_idx,
                        uint               qpn,
                        void const *       frame,
                        ulong              frame_sz,
                        uint               lkey,
                        ulong              tx_inline_sz ) {
  if( FD_UNLIKELY( !frame_sz || frame_sz>UINT_MAX || qpn>0xffffffU || tx_inline_sz>frame_sz ) ) return 0;
  fd_memset( wqe, 0, sizeof(*wqe) );
  uint const wqe_seg_cnt       = tx_inline_sz ? 4U : 3U;
  ulong const wqe_data_seg_off = tx_inline_sz ? 48UL : 32UL;

  fd_mlx5_hw_wqe_ctrl_seg_t * wqe_ctrl_seg = (fd_mlx5_hw_wqe_ctrl_seg_t *)wqe;
  fd_mlx5_hw_wqe_eth_seg_t *  wqe_eth_seg  = (fd_mlx5_hw_wqe_eth_seg_t *)(wqe->bytes+sizeof(*wqe_ctrl_seg));
  fd_mlx5_hw_wqe_data_seg_t * wqe_data_seg = (fd_mlx5_hw_wqe_data_seg_t *)(wqe->bytes+wqe_data_seg_off);

  wqe_ctrl_seg->opmod_idx_opcode = fd_uint_bswap( ((sq_idx & 0xffffU)<<8) | FD_MLX5_SQ_SEND_PKT );
  wqe_ctrl_seg->qpn_ds           = fd_uint_bswap( (qpn<<8) | wqe_seg_cnt );
  wqe_eth_seg->inline_hdr_sz = fd_ushort_bswap( (ushort)tx_inline_sz );
  if( tx_inline_sz ) fd_memcpy( wqe_eth_seg->inline_hdr, frame, tx_inline_sz );

  wqe_data_seg->byte_cnt = fd_uint_bswap( (uint)(frame_sz-tx_inline_sz) );
  wqe_data_seg->lkey     = fd_uint_bswap( lkey );
  wqe_data_seg->addr     = fd_ulong_bswap( (ulong)frame+tx_inline_sz );
  return 1;
}

static inline void
fd_mlx5_hw_init_rx_wqe( fd_mlx5_rx_wqe_t * wqe,
                        void *             frame,
                        ulong              frame_sz,
                        uint               lkey ) {
  fd_mlx5_hw_wqe_data_seg_t * wqe_data_seg = (fd_mlx5_hw_wqe_data_seg_t *)wqe;

  wqe_data_seg->byte_cnt = fd_uint_bswap( (uint)frame_sz );
  wqe_data_seg->lkey     = fd_uint_bswap( lkey );
  wqe_data_seg->addr     = fd_ulong_bswap( (ulong)frame );
}

static inline void
fd_mlx5_hw_ring_sq( fd_mlx5_qp_t *     qp,
                    fd_mlx5_tx_wqe_t * wqe ) {
  fd_mlx5_hw_wqe_ctrl_seg_t * wqe_ctrl_seg = (fd_mlx5_hw_wqe_ctrl_seg_t *)wqe;
  wqe_ctrl_seg->flags = FD_MLX5_SQ_REQUEST_CQE;
  fd_mlx5_hw_dma_to_device();
  FD_VOLATILE( qp->control->sq_prod ) = fd_uint_bswap( qp->sq_prod & 0xffffU );
  fd_mlx5_hw_dma_to_device();

  /* Ring the SQ through the non-cached UAR.  The NIC fetches the complete
     WQE from write-back SQ memory. */
  volatile ulong * doorbell_reg = (volatile ulong *)qp->uar->reg;
  doorbell_reg[0] = FD_LOAD( ulong, wqe->bytes );
  FD_COMPILER_MFENCE();
  qp->sq_posted = qp->sq_prod;
}

static inline int
fd_mlx5_hw_post_send( fd_mlx5_tile_t * ctx,
                      uint             frame_sz ) {
  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  uint const outstanding = qp->sq_prod-qp->sq_cons;
  if( FD_UNLIKELY( outstanding>=qp->tx_depth ) ) {
    errno = ENOSPC;
    return -1;
  }

  uint const sq_idx = qp->sq_prod;
  uint const chunk = fd_mlx5_tile_tx_chunk( ctx, sq_idx );
  fd_mlx5_tx_wqe_t * wqe = qp->sq+(sq_idx & (qp->tx_depth-1U));
  if( FD_UNLIKELY( !fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qp->qpn,
                                            fd_chunk_to_laddr( ctx->umem_base, chunk ), frame_sz,
                                            qp->lkey, qp->tx_inline_sz ) ) ) {
    errno = EINVAL;
    return -1;
  }
  qp->sq_pkt_sz[ sq_idx & (qp->tx_depth-1U) ] = frame_sz;
  qp->sq_prod++;
  return 0;
}

static inline int
fd_mlx5_hw_post_recv( fd_mlx5_tile_t * ctx,
                      uint             recv_cnt ) {
  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  uint const outstanding = qp->rq_prod-qp->rq_cons;
  if( FD_UNLIKELY( outstanding>qp->rx_depth || recv_cnt>qp->rx_depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }

  uint const rq_prod = qp->rq_prod;
  for( uint i=0U; i<recv_cnt; i++ ) {
    uint const chunk = ctx->rx_pending[ ctx->rx_pending_rem+i ];
    uint const rq_idx = rq_prod+i;
    fd_mlx5_hw_init_rx_wqe( qp->rq+(rq_idx & (qp->rx_depth-1U)),
                            fd_chunk_to_laddr( ctx->umem_base, chunk ), FD_NET_MTU, qp->lkey );
    qp->rq_chunk[ rq_idx & (qp->rx_depth-1U) ] = chunk;
  }
  qp->rq_prod += recv_cnt;
  fd_mlx5_hw_dma_to_device();
  FD_VOLATILE( qp->control->rq_prod ) = fd_uint_bswap( qp->rq_prod & 0xffffU );
  return 0;
}

static inline int
fd_mlx5_hw_poll_rx_cq( fd_mlx5_qp_t *           qp,
                       fd_mlx5_tile_rx_comp_t * comp,
                       uint                     comp_capacity ) {
  fd_mlx5_cq_t * rx_cq   = qp->rx_cq;
  uint const comp_limit  = fd_uint_min( comp_capacity, rx_cq->depth );
  uint cq_cons_idx       = rx_cq->cons_idx;
  uint rq_cons_idx       = qp->rq_cons;
  uint const rq_prod_idx = qp->rq_prod;
  if( FD_UNLIKELY( rq_prod_idx-rq_cons_idx>qp->rx_depth ) ) { errno = EPROTO; return -1; }

  uint comp_cnt    = 0U;
  int  poll_failed = 0;
  while( comp_cnt<comp_limit ) {
    fd_mlx5_hw_cqe64_t const * rx_cqe =
        (fd_mlx5_hw_cqe64_t const *)(rx_cq->entries+(cq_cons_idx & (rx_cq->depth-1U)));
    uchar const op_own = FD_VOLATILE_CONST( rx_cqe->op_own );
    uint const opcode = (uint)(op_own>>4);
    if( FD_LIKELY( opcode==FD_MLX5_CQE_INVALID ||
                   (op_own & 1U)!=!!(cq_cons_idx & rx_cq->depth) ) ) break;
    fd_mlx5_hw_dma_from_device();

    if( FD_UNLIKELY( opcode!=FD_MLX5_CQE_RX_OK && opcode!=FD_MLX5_CQE_RX_ERR ) ) {
      errno       = EINVAL;
      poll_failed = 1;
      break;
    }
    if( FD_UNLIKELY( opcode==FD_MLX5_CQE_RX_ERR ) )
      FD_LOG_INFO(( "mlx5 RX CQE error (syndrome 0x%02x, vendor syndrome 0x%02x, "
                   "WQE opcode/QPN 0x%08x, WQE counter %u)",
                   (uint)rx_cqe->syndrome, (uint)rx_cqe->vendor_err, fd_uint_bswap( rx_cqe->sop_drop_qpn ),
                   (uint)fd_ushort_bswap( rx_cqe->wqe_counter ) ));

    uint const wqe_counter = (uint)fd_ushort_bswap( rx_cqe->wqe_counter );
    if( FD_UNLIKELY( rq_cons_idx==rq_prod_idx || (ushort)wqe_counter!=(ushort)rq_cons_idx ) ) {
      errno       = EPROTO;
      poll_failed = 1;
      break;
    }

    comp[ comp_cnt++ ] = (fd_mlx5_tile_rx_comp_t) {
      .chunk    = qp->rq_chunk[ wqe_counter & (qp->rx_depth-1U) ],
      .byte_len = fd_uint_bswap( rx_cqe->byte_cnt ),
      .opcode   = opcode
    };
    rq_cons_idx++;
    cq_cons_idx++;
  }

  if( comp_cnt ) {
    qp->rq_cons     = rq_cons_idx;
    rx_cq->cons_idx = cq_cons_idx;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( rx_cq->control->consumer_idx ) = fd_uint_bswap( cq_cons_idx & 0xffffffU );
  }
  return poll_failed ? -1 : (int)comp_cnt;
}

static inline int
fd_mlx5_hw_poll_tx_cq( fd_mlx5_qp_t * qp,
                       ulong *        comp_bytes,
                       uint *         cqe_error_cnt ) {
  fd_mlx5_cq_t * tx_cq    = qp->tx_cq;
  uint const cq_cons_idx  = tx_cq->cons_idx;
  uint const cq_entry_idx = cq_cons_idx & (tx_cq->depth-1U);
  fd_mlx5_hw_cqe64_t const * tx_cqe = (fd_mlx5_hw_cqe64_t const *)(tx_cq->entries+cq_entry_idx);

  uchar const op_own = FD_VOLATILE_CONST( tx_cqe->op_own );
  uint const opcode  = (uint)(op_own>>4);
  if( FD_LIKELY( opcode==FD_MLX5_CQE_INVALID ||
                 (op_own & 1U)!=!!(cq_cons_idx & tx_cq->depth) ) ) return 0;
  fd_mlx5_hw_dma_from_device();

  if( FD_UNLIKELY( opcode!=FD_MLX5_CQE_TX_OK && opcode!=FD_MLX5_CQE_TX_ERR ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( opcode==FD_MLX5_CQE_TX_ERR ) )
    FD_LOG_INFO(( "mlx5 TX CQE error (syndrome 0x%02x, vendor syndrome 0x%02x, "
                 "WQE opcode/QPN 0x%08x, WQE counter %u)",
                 (uint)tx_cqe->syndrome, (uint)tx_cqe->vendor_err, fd_uint_bswap( tx_cqe->sop_drop_qpn ),
                 (uint)fd_ushort_bswap( tx_cqe->wqe_counter ) ));

  uint const sq_cons_idx = qp->sq_cons;
  uint const wqe_counter = (uint)fd_ushort_bswap( tx_cqe->wqe_counter );
  uint const outstanding = qp->sq_posted-sq_cons_idx;
  uint const comp_cnt    = (uint)(ushort)(wqe_counter-sq_cons_idx)+1U;
  if( FD_UNLIKELY( !outstanding || outstanding>qp->tx_depth || comp_cnt>outstanding ) ) {
    errno = EPROTO;
    return -1;
  }

  *cqe_error_cnt = (uint)(opcode==FD_MLX5_CQE_TX_ERR);
  *comp_bytes     = 0UL;
  uint const success_cnt = comp_cnt-*cqe_error_cnt;
  for( uint i=0U; i<success_cnt; i++ )
    *comp_bytes += qp->sq_pkt_sz[ (sq_cons_idx+i) & (qp->tx_depth-1U) ];
  qp->sq_cons     = sq_cons_idx+comp_cnt;
  tx_cq->cons_idx = cq_cons_idx+1U;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( tx_cq->control->consumer_idx ) = fd_uint_bswap( (cq_cons_idx+1U) & 0xffffffU );
  return (int)comp_cnt;
}

static inline void
fd_mlx5_tile_tx_flush( fd_mlx5_tile_t * ctx ) {
  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  if( FD_UNLIKELY( qp->sq_posted==qp->sq_prod ) ) return;
  uint const last_sq_idx = qp->sq_prod-1U;
  fd_mlx5_tx_wqe_t * last_wqe = qp->sq+(last_sq_idx & (qp->tx_depth-1U));
  fd_mlx5_hw_ring_sq( qp, last_wqe );
}

static inline void
fd_mlx5_tile_rx_recycle( fd_mlx5_tile_t * ctx,
                         ulong            chunk ) {
  ctx->rx_pending[ --ctx->rx_pending_rem ] = (uint)chunk;

  /* Hold partial recycle batches: at most batch_size-1 RQ buffers stay
     unposted, avoiding a device-ordering barrier and doorbell-record write
     per packet. */
  if( !ctx->rx_pending_rem ) {
    uint const recv_cnt = ctx->batch_size-ctx->rx_pending_rem;
    if( FD_UNLIKELY( fd_mlx5_hw_post_recv( ctx, recv_cnt ) ) )
      FD_LOG_ERR(( "direct mlx5 RX post failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    ctx->rx_pending_rem = ctx->batch_size;
  }
}

static inline int
fd_mlx5_tile_rx_dst_port_lookup( fd_mlx5_tile_t const * ctx,
                                 ushort                 net_dport,
                                 ulong                  frame_sz,
                                 ulong *                out_idx,
                                 ulong *                dst_proto ) {
  ulong rule_idx = ULONG_MAX;
  for( ulong i=0UL; i<ctx->dst_port_cnt; i++ ) {
    if( ctx->dst_ports[ i ]==net_dport ) {
      rule_idx = i;
      break;
    }
  }
  if( FD_UNLIKELY( rule_idx==ULONG_MAX ) ) return 0;

  *out_idx   = ctx->dst_out_idx[ rule_idx ];
  *dst_proto = ctx->dst_protos [ rule_idx ];
  if( FD_UNLIKELY( *dst_proto==DST_PROTO_REPAIR && frame_sz==REPAIR_PING_SZ ) ) {
    if( FD_UNLIKELY( ctx->repair_out_idx==UCHAR_MAX ) ) return 0;
    *out_idx = ctx->repair_out_idx;
  }
  return *out_idx<ctx->rx_out_cnt;
}

/* fd_mlx5_tile_rx_pkt publishes a validated successful RX completion and
   returns the chunk previously held by the destination mcache entry. */
static inline ulong
fd_mlx5_tile_rx_pkt( fd_mlx5_tile_t *    ctx,
                     fd_stem_context_t * stem,
                     ulong               chunk,
                     ulong               byte_len,
                     ulong               tspub ) {
  ulong const min_udp_frame_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( byte_len<min_udp_frame_sz || byte_len>FD_NET_MTU ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return chunk;
  }

  fd_eth_hdr_t const * eth_hdr = fd_chunk_to_laddr_const( ctx->umem_base, chunk );
  if( FD_UNLIKELY( fd_ushort_bswap( eth_hdr->net_type )!=FD_ETH_HDR_TYPE_IP ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return chunk;
  }

  fd_ip4_hdr_t const * ip4_hdr = (fd_ip4_hdr_t const *)(eth_hdr+1);
  ulong const ip4_hdr_sz = FD_IP4_GET_LEN( *ip4_hdr );
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4_hdr )!=4 ||
                   ip4_hdr->protocol!=FD_IP4_HDR_PROTOCOL_UDP ||
                   ip4_hdr_sz<sizeof(fd_ip4_hdr_t) ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return chunk;
  }

  ulong const udp_off   = sizeof(fd_eth_hdr_t)+ip4_hdr_sz;
  ulong const dgram_off = udp_off+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( dgram_off>byte_len ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return chunk;
  }

  fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)((uchar const *)eth_hdr+udp_off);
  ushort const net_dport = fd_ushort_bswap( udp_hdr->net_dport );
  ulong out_idx;
  ulong dst_proto;
  if( FD_UNLIKELY( !fd_mlx5_tile_rx_dst_port_lookup( ctx, net_dport, byte_len, &out_idx, &dst_proto ) ) ) {
    ctx->metrics.rx_route_fail_cnt++;
    return chunk;
  }

  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong const      depth  = stem->depths [ out_idx ];
  ulong const      seq    = stem->seqs[ out_idx ];

  ulong freed_chunk = mcache[ fd_mcache_line_idx( seq, depth ) ].chunk;

  ulong const sig    = fd_disco_netmux_sig( ip4_hdr->saddr, udp_hdr->net_sport, 0U, dst_proto, dgram_off );
  ulong const ctl    = 0UL;
  ulong const tsorig = 0UL;
  fd_stem_publish( stem, out_idx, sig, chunk, byte_len, ctl, tsorig, tspub );
  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += byte_len;

  return freed_chunk;
}

static inline int
fd_mlx5_tile_poll_rx( fd_mlx5_tile_t *    ctx,
                      fd_stem_context_t * stem ) {
  fd_mlx5_tile_rx_comp_t comp[ FD_MLX5_BATCH_MAX ];
  int comp_cnt = fd_mlx5_hw_poll_rx_cq( &ctx->hw.qp, comp, ctx->batch_size );
  if( FD_UNLIKELY( comp_cnt<0 ) )
    FD_LOG_ERR(( "direct mlx5 RX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !comp_cnt ) ) return 0;

  ulong const tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    ulong const chunk = comp[ i ].chunk;
    if( FD_UNLIKELY( chunk<ctx->umem_chunk0 || chunk>ctx->umem_wmark ) )
      FD_LOG_CRIT(( "RX completion chunk %lu out of bounds [%u,%u]", chunk, ctx->umem_chunk0, ctx->umem_wmark ));
    __builtin_prefetch( fd_chunk_to_laddr_const( ctx->umem_base, chunk ), 0, 3 );
  }

  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    ulong freed_chunk;
    if( FD_UNLIKELY( comp[ i ].opcode==FD_MLX5_CQE_RX_ERR ) ) {
      ctx->metrics.rx_cqe_err_cnt++;
      freed_chunk = comp[ i ].chunk;
    } else {
      freed_chunk = fd_mlx5_tile_rx_pkt( ctx, stem, comp[ i ].chunk, comp[ i ].byte_len, tspub );
    }
    if( FD_UNLIKELY( !freed_chunk ) ) FD_LOG_CRIT(( "invalid chunk in mcache" ));
    fd_mlx5_tile_rx_recycle( ctx, freed_chunk );
  }
  return 1;
}

static inline int
fd_mlx5_tile_poll_tx( fd_mlx5_tile_t * ctx ) {
  ulong tx_pkt_cnt     = 0UL;
  ulong tx_bytes_total = 0UL;
  ulong tx_cqe_err_cnt = 0UL;
  int busy = 0;
  for( uint poll_cnt=0U; poll_cnt<ctx->batch_size; poll_cnt++ ) {
    ulong tx_bytes;
    uint cqe_error_cnt;
    int comp_cnt = fd_mlx5_hw_poll_tx_cq( &ctx->hw.qp, &tx_bytes, &cqe_error_cnt );
    if( FD_UNLIKELY( comp_cnt<0 ) )
      FD_LOG_ERR(( "direct mlx5 TX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !comp_cnt ) ) break;
    busy = 1;
    tx_pkt_cnt     += (uint)comp_cnt-cqe_error_cnt;
    tx_bytes_total += tx_bytes;
    tx_cqe_err_cnt += cqe_error_cnt;
  }
  ctx->metrics.tx_pkt_cnt     += tx_pkt_cnt;
  ctx->metrics.tx_bytes_total += tx_bytes_total;
  ctx->metrics.tx_cqe_err_cnt += tx_cqe_err_cnt;
  return busy;
}

static inline void
before_credit( fd_mlx5_tile_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  if( qp->sq_cons!=qp->sq_posted )
    *charge_busy |= fd_mlx5_tile_poll_tx( ctx );
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

  /* Resolve the TX route for outgoing packets. */
  ulong dst_proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( dst_proto!=DST_PROTO_OUTGOING ) ) return 1;

  uint dst_ip = fd_disco_netmux_sig_ip( sig );
  if( FD_UNLIKELY( !fd_net_tx_route( &ctx->router, dst_ip, &ctx->tx_route ) ) ) return 1;
  if( FD_UNLIKELY( ctx->tx_route.use_gre ) ) {
    ctx->metrics.tx_gre_unsupported_cnt++;
    return 1;
  }

  /* Skip if TX is blocked */

  fd_mlx5_qp_t const * qp = &ctx->hw.qp;
  uint const outstanding = qp->sq_prod-qp->sq_cons;
  if( FD_UNLIKELY( outstanding>=qp->tx_depth ) ) {
    ctx->metrics.tx_no_buffer_cnt++;
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
             ulong            frame_sz,
             ulong            ctl ) {
  (void)seq; (void)sig; (void)ctl;

  fd_mlx5_tile_input_ctx_t * input_ctx = &ctx->input_ctx[ in_idx ];
  if( FD_UNLIKELY( chunk<input_ctx->chunk0 || chunk>input_ctx->wmark || frame_sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, frame_sz, input_ctx->chunk0, input_ctx->wmark ));
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    if( FD_UNLIKELY( frame_sz!=sizeof(fd_iproute_msg_t) ) ) FD_LOG_ERR(( "invalid iproute message size %lu", frame_sz ));
    fd_memcpy( &ctx->iproute_msg, fd_chunk_to_laddr_const( input_ctx->wksp_base, chunk ), sizeof(fd_iproute_msg_t) );
    return;
  }
  if( FD_UNLIKELY( frame_sz<34UL ) ) {
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", frame_sz, in_idx ));
  }

  /* Speculatively copy frame into buffer */
  ulong        dst_chunk = fd_mlx5_tile_tx_chunk( ctx, ctx->hw.qp.sq_prod );
  void *       dst       = fd_chunk_to_laddr( ctx->umem_base, dst_chunk );
  void const * src       = fd_chunk_to_laddr_const( input_ctx->wksp_base, chunk );
  fd_memcpy( dst, src, frame_sz );
}

static void
after_frag( fd_mlx5_tile_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               frame_sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub; (void)stem;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    fd_iproute_msg_t const * msg = &ctx->iproute_msg;
    if( msg->op==FD_IPROUTE_OP_FLUSH ) {
      fd_fib4_clear( ctx->router.fib_local );
      fd_fib4_clear( ctx->router.fib_main );
      return;
    }
    fd_fib4_t * fib;
    if( msg->table_id==RT_TABLE_LOCAL ) fib = ctx->router.fib_local;
    else if( msg->table_id==RT_TABLE_MAIN ) fib = ctx->router.fib_main;
    else return;
    if( msg->op==FD_IPROUTE_OP_UPSERT && FD_UNLIKELY( !fd_fib4_insert( fib, msg->dst_addr, msg->prefix, msg->prio, &msg->hop ) ) ) {
      FD_LOG_WARNING(( "route update dropped: route table full (increase [net.max_routes] or [net.max_peer_routes])" ));
      fd_netlink_route4_sync( ctx->router.neigh4_solicit, fd_frag_meta_ts_comp( fd_tickcount() ) );
    } else if( msg->op==FD_IPROUTE_OP_DELETE ) {
      fd_fib4_remove( fib, msg->dst_addr, msg->prefix, msg->prio );
    }
    return;
  }

  /* Set Ethernet src and dst MAC addrs, optionally mangle IPv4 header to
     fill in source address (if it's missing). */
  ulong  chunk = fd_mlx5_tile_tx_chunk( ctx, ctx->hw.qp.sq_prod );
  void * frame = fd_chunk_to_laddr( ctx->umem_base, chunk );
  if( FD_UNLIKELY( !fd_net_tx_fill_addrs( &ctx->router, &ctx->tx_route, frame, frame_sz ) ) ) return;

  if( FD_UNLIKELY( fd_mlx5_hw_post_send( ctx, (uint)frame_sz ) ) ) {
    ctx->metrics.tx_submit_fail_cnt++;
    return;
  }

  fd_mlx5_qp_t * qp = &ctx->hw.qp;
  if( qp->sq_prod-qp->sq_posted>=ctx->batch_size || qp->sq_prod-qp->sq_cons>=qp->tx_depth )
    fd_mlx5_tile_tx_flush( ctx );
}

static inline void
metrics_write( fd_mlx5_tile_t * ctx ) {
  fd_mlx5_qp_t const * qp = &ctx->hw.qp;
  ulong const rx_buffer_idle_cnt = fd_ulong_min( (ulong)(qp->rq_prod-qp->rq_cons), qp->rx_depth );
  ulong const rx_buffer_busy_cnt = qp->rx_depth-rx_buffer_idle_cnt;
  ulong const tx_buffer_busy_cnt = fd_ulong_min( (ulong)(qp->sq_prod-qp->sq_cons), qp->tx_depth );
  ulong const tx_buffer_idle_cnt = qp->tx_depth-tx_buffer_busy_cnt;

  FD_MCNT_SET(   MLX5, RX_PKT_CNT,           ctx->metrics.rx_pkt_cnt           );
  FD_MCNT_SET(   MLX5, RX_BYTES_TOTAL,       ctx->metrics.rx_bytes_total       );
  FD_MCNT_SET(   MLX5, RX_CQE_ERR_CNT,       ctx->metrics.rx_cqe_err_cnt       );
  FD_MCNT_SET(   MLX5, RX_OUT_OF_BUFFER_CNT, ctx->metrics.rx_out_of_buffer_cnt );
  FD_MCNT_SET(   MLX5, RX_MALFORMED_CNT,     ctx->metrics.rx_malformed_cnt     );
  FD_MCNT_SET(   MLX5, RX_ROUTE_FAIL_CNT,    ctx->metrics.rx_route_fail_cnt    );
  FD_MGAUGE_SET( MLX5, RX_BUFFER_BUSY,       rx_buffer_busy_cnt                );
  FD_MGAUGE_SET( MLX5, RX_BUFFER_IDLE,       rx_buffer_idle_cnt                );

  FD_MCNT_SET(   MLX5, TX_PKT_CNT,                 ctx->metrics.tx_pkt_cnt             );
  FD_MCNT_SET(   MLX5, TX_BYTES_TOTAL,             ctx->metrics.tx_bytes_total         );
  FD_MCNT_SET(   MLX5, TX_CQE_ERR_CNT,             ctx->metrics.tx_cqe_err_cnt         );
  FD_MCNT_SET(   MLX5, TX_NO_BUFFER_CNT,           ctx->metrics.tx_no_buffer_cnt       );
  FD_MCNT_SET(   MLX5, TX_ROUTE_FAIL_CNT,          ctx->router.metrics.tx_route_fail_cnt );
  FD_MCNT_SET(   MLX5, TX_NEIGHBOR_UNRESOLVED_CNT, ctx->router.metrics.tx_neigh_fail_cnt );
  FD_MCNT_SET(   MLX5, TX_GRE_UNSUPPORTED_CNT,     ctx->metrics.tx_gre_unsupported_cnt );
  FD_MCNT_SET(   MLX5, TX_SUBMIT_FAIL_CNT,         ctx->metrics.tx_submit_fail_cnt     );
  FD_MGAUGE_SET( MLX5, TX_BUFFER_BUSY,             tx_buffer_busy_cnt                  );
  FD_MGAUGE_SET( MLX5, TX_BUFFER_IDLE,             tx_buffer_idle_cnt                  );
}

static inline void
during_housekeeping( fd_mlx5_tile_t * ctx ) {
  /* Refresh the mlx5 out_of_buffer QP counter periodically. */
  long const now_ticks = fd_tickcount();
  if( FD_UNLIKELY( now_ticks>ctx->next_stats_refresh_ticks ) ) {
    ctx->next_stats_refresh_ticks = now_ticks+ctx->stats_interval_ticks;

    ulong rx_out_of_buffer_cnt;
    if( FD_UNLIKELY( fd_mlx5_qp_stats_read( &ctx->hw.qp_stats, &rx_out_of_buffer_cnt ) ) )
      FD_LOG_ERR(( "reading mlx5 QP counters failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ulong const rx_out_of_buffer_delta = rx_out_of_buffer_cnt>=ctx->rx_out_of_buffer_prev_cnt
                                         ? rx_out_of_buffer_cnt-ctx->rx_out_of_buffer_prev_cnt
                                         : rx_out_of_buffer_cnt;
    ctx->metrics.rx_out_of_buffer_cnt += rx_out_of_buffer_delta;
    ctx->rx_out_of_buffer_prev_cnt     = rx_out_of_buffer_cnt;
  }

  /* Drain pending uverbs async events. */
  int const async_event_fd = ctx->hw.context.async_fd;
  for(;;) {
    struct ib_uverbs_async_event_desc async_event;
    ssize_t const async_event_read_sz = read( async_event_fd, &async_event, sizeof(async_event) );
    if( FD_LIKELY( async_event_read_sz<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ) ) break;
    if( FD_UNLIKELY( async_event_read_sz!=(ssize_t)sizeof(async_event) ) )
      FD_LOG_ERR(( "mlx5 async event read failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    uint const async_event_type = async_event.event_type;
    ulong const async_event_element = (ulong)async_event.element;
    if( FD_UNLIKELY( async_event_type==FD_MLX5_EVENT_CQ_ERR        ||
                     async_event_type==FD_MLX5_EVENT_QP_FATAL      ||
                     async_event_type==FD_MLX5_EVENT_QP_REQ_ERR    ||
                     async_event_type==FD_MLX5_EVENT_QP_ACCESS_ERR ||
                     async_event_type==FD_MLX5_EVENT_DEVICE_FATAL  ||
                     async_event_type==FD_MLX5_EVENT_WQ_FATAL ) )
      FD_LOG_ERR(( "fatal mlx5 async event %u on element %lu", async_event_type, async_event_element ));
    FD_LOG_INFO(( "mlx5 async event %u on element %lu", async_event_type, async_event_element ));
  }

  /* Refresh the netdev snapshot when its shared state is stable. */
  if( FD_LIKELY( !fd_seqlock_locked_hint( &ctx->router.netdev_shared.hdr->seqlock ) ) ) {
    fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
  }
}

/* Initialization and Linux integration */
static uint
fd_mlx5_tile_if_ip4_addr( char const * if_name ) {
  int sock_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock_fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct ifreq ifr = { .ifr_addr.sa_family = AF_INET };
  fd_cstr_ncpy( ifr.ifr_name, if_name, sizeof(ifr.ifr_name) );
  if( FD_UNLIKELY( ioctl( sock_fd, SIOCGIFADDR, &ifr ) ) ) {
    FD_LOG_ERR(( "could not get IP address of interface `%s` (%i-%s)",
                 if_name, errno, fd_io_strerror( errno ) ));
  }
  uint ip4_addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;

  if( FD_UNLIKELY( close( sock_fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return ip4_addr;
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( FD_MLX5_PAGE_SZ,
                       fd_ulong_max( alignof(fd_mlx5_tile_t),
                                     fd_ulong_max( fd_netdev_tbl_align(), fd_fib4_align() ) ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong layout = FD_LAYOUT_INIT;
  ulong const queue_footprint = fd_mlx5_queue_footprint( tile->mlx5.rx_queue_size,
                                                         tile->mlx5.tx_queue_size );
  if( FD_UNLIKELY( !queue_footprint ) ) return 0UL;
  layout = FD_LAYOUT_APPEND( layout, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  layout = FD_LAYOUT_APPEND( layout, FD_MLX5_PAGE_SZ, queue_footprint );
  layout = FD_LAYOUT_APPEND( layout, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );
  return FD_LAYOUT_FINI( layout, scratch_align() );
}

static int
fd_mlx5_tile_rdma_port_contains_if( char const * rdma_name,
                                    uint         port,
                                    char const * if_name ) {
  char netdev_dir_path[ PATH_MAX ];
  int path_sz = snprintf( netdev_dir_path, sizeof(netdev_dir_path),
                          "/sys/class/infiniband/%s/ports/%u/gid_attrs/ndevs", rdma_name, port );
  if( FD_UNLIKELY( path_sz<=0 || (ulong)path_sz>=sizeof(netdev_dir_path) ) ) return 0;
  DIR * netdev_dir = opendir( netdev_dir_path );
  if( FD_UNLIKELY( !netdev_dir ) ) return 0;
  struct dirent * netdev_entry;
  int netdev_found = 0;
  while( !netdev_found && (netdev_entry=readdir( netdev_dir )) ) {
    if( netdev_entry->d_name[0]=='.' ) continue;
    char netdev_name_path[ PATH_MAX ];
    int netdev_name_path_sz = snprintf( netdev_name_path, sizeof(netdev_name_path),
                                        "%s/%s", netdev_dir_path, netdev_entry->d_name );
    if( netdev_name_path_sz<=0 || (ulong)netdev_name_path_sz>=sizeof(netdev_name_path) ) continue;
    int netdev_fd = open( netdev_name_path, O_RDONLY );
    if( netdev_fd<0 ) continue;
    char netdev_name[ IF_NAMESIZE+1 ];
    ssize_t read_sz = read( netdev_fd, netdev_name, IF_NAMESIZE );
    close( netdev_fd );
    if( read_sz<=0 ) continue;
    while( read_sz>0 && (netdev_name[read_sz-1]=='\n' || netdev_name[read_sz-1]=='\r') ) read_sz--;
    netdev_name[read_sz] = '\0';
    netdev_found = !strcmp( netdev_name, if_name );
  }
  closedir( netdev_dir );
  return netdev_found;
}

static int
fd_mlx5_tile_rdma_port_matches_if( char const * rdma_name,
                                   uint         port,
                                   char const * if_name ) {
  if( fd_mlx5_tile_rdma_port_contains_if( rdma_name, port, if_name ) ) return 1;
  if( !fd_bonding_is_master( if_name ) ) return 0;
  fd_bonding_slave_iter_t bond_iter_mem[1];
  fd_bonding_slave_iter_t * bond_iter = fd_bonding_slave_iter_init( bond_iter_mem, if_name );
  for( ; !fd_bonding_slave_iter_done( bond_iter ); fd_bonding_slave_iter_next( bond_iter ) )
    if( fd_mlx5_tile_rdma_port_contains_if( rdma_name, port, fd_bonding_slave_iter_ele( bond_iter ) ) ) return 1;
  return 0;
}

/* Linux represents the NIC in two places: as a network interface and as an
   RDMA device with numbered ports.  This finds the RDMA device and port for
   the configured interface or one of its bond slave interfaces. */
static void
fd_mlx5_tile_rdma_dev_find( char                   rdma_device_name[ FD_MLX5_RDMA_NAME_MAX ],
                            uint *                 rdma_port_num,
                            fd_topo_tile_t const * tile ) {
  char const * interface_name = tile->mlx5.if_name;
  DIR * infiniband_dir = opendir( "/sys/class/infiniband" );
  if( FD_UNLIKELY( !infiniband_dir ) )
    FD_LOG_ERR(( "opendir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  rdma_device_name[0] = '\0';
  *rdma_port_num = 0U;

  struct dirent * device_entry;
  /* Iterate RDMA devices under /sys/class/infiniband. */
  while( (device_entry=readdir( infiniband_dir )) ) {
    if( device_entry->d_name[0]=='.' ) continue;

    char device_ports_path[ PATH_MAX ];
    int const device_ports_path_sz = snprintf( device_ports_path, sizeof(device_ports_path),
                                               "/sys/class/infiniband/%s/ports", device_entry->d_name );
    if( device_ports_path_sz<=0 || (ulong)device_ports_path_sz>=sizeof(device_ports_path) ) continue;
    DIR * ports_dir = opendir( device_ports_path );
    if( !ports_dir ) continue;

    struct dirent * port_entry;
    /* Iterate the device's numbered ports. */
    while( (port_entry=readdir( ports_dir )) ) {
      char * port_end;
      ulong const port_num = strtoul( port_entry->d_name, &port_end, 10 );
      if( !port_num || *port_end || port_num>(ulong)UCHAR_MAX ) continue;

      if( !fd_mlx5_tile_rdma_port_matches_if( device_entry->d_name, (uint)port_num, interface_name ) ) continue;

      if( FD_UNLIKELY( rdma_device_name[0] ) )
        FD_LOG_ERR(( "multiple RDMA ports match interface `%s` (`%s` port %u and `%s` port %lu)",
                     interface_name, rdma_device_name, *rdma_port_num, device_entry->d_name, port_num ));
      fd_cstr_ncpy( rdma_device_name, device_entry->d_name, FD_MLX5_RDMA_NAME_MAX );
      *rdma_port_num = (uint)port_num;
    }
    closedir( ports_dir );
  }

  if( FD_UNLIKELY( closedir( infiniband_dir ) ) )
    FD_LOG_ERR(( "closedir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !rdma_device_name[0] ) )
    FD_LOG_ERR(( "RDMA device port for interface `%s` not found", interface_name ));
}

/* fd_mlx5_tile_rx_dst_port_add maps an IPv4 UDP destination port to the
   first output link with the requested name.  Published fragments encode
   dst_proto in their netmux signatures. */
static void
fd_mlx5_tile_rx_dst_port_add( fd_mlx5_tile_t *       ctx,
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
  uint const rule_idx = ctx->dst_port_cnt;
  ctx->dst_protos [ rule_idx ] = (uchar)dst_proto;
  ctx->dst_ports  [ rule_idx ] = dst_port;
  ctx->dst_out_idx[ rule_idx ] = (uchar)out_idx;
  ctx->dst_port_cnt++;
}

static void
fd_mlx5_tile_rx_dst_ports_init( fd_mlx5_tile_t *       ctx,
                                fd_topo_t const *      topo,
                                fd_topo_tile_t const * tile ) {
  ctx->rx_out_cnt     = (uchar)tile->out_cnt;
  ctx->repair_out_idx = UCHAR_MAX;
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_TPU_UDP,  "net_quic",   tile->mlx5.net.legacy_transaction_listen_port, 1 );
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_TPU_QUIC, "net_quic",   tile->mlx5.net.quic_transaction_listen_port,   1 );
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_SHRED,    "net_shred",  tile->mlx5.net.shred_listen_port,              1 );
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_GOSSIP,   "net_gossvf", tile->mlx5.net.gossip_listen_port,             1 );
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_REPAIR,   "net_shred",  tile->mlx5.net.repair_client_listen_port,      1 );
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_RSERVE,   "net_rserve", tile->mlx5.net.repair_serve_listen_port,       0 );
  fd_mlx5_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_SEND,     "net_txsend", tile->mlx5.net.txsend_src_port,                1 );

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
  /* Allocate tile state and NIC queue memory. */
  FD_SCRATCH_ALLOC_INIT( scratch, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_mlx5_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  memset( ctx, 0, sizeof(fd_mlx5_tile_t) );
  ulong const queue_memory_sz = fd_mlx5_queue_footprint( tile->mlx5.rx_queue_size,
                                                         tile->mlx5.tx_queue_size );
  void * const queue_memory = FD_SCRATCH_ALLOC_APPEND( scratch, FD_MLX5_PAGE_SZ, queue_memory_sz );
  ctx->batch_size = tile->mlx5.batch_size;

  /* Derive the page-aligned packet-memory region and chunk bounds. */
  void * const umem_dcache_memory = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const umem_dcache        = fd_dcache_join( umem_dcache_memory );
  if( FD_UNLIKELY( !umem_dcache ) ) FD_LOG_ERR(( "Failed to join UMEM dcache" ));
  ulong const umem_dcache_data_sz = fd_dcache_data_sz( umem_dcache );
  ulong const umem_frame_sz       = FD_NET_MTU;

  void * const umem_frame0 = (void *)fd_ulong_align_up( (ulong)umem_dcache, FD_MLX5_PAGE_SZ );
  ulong const umem_region_sz = fd_ulong_align_dn( umem_dcache_data_sz - ((ulong)umem_frame0-(ulong)umem_dcache),
                                                  umem_frame_sz );

  void * const workspace_base = fd_wksp_containing( umem_dcache_memory );
  if( FD_UNLIKELY( !workspace_base ) ) FD_LOG_ERR(( "UMEM dcache is not in a workspace" ));
  ulong const first_umem_chunk = ((ulong)umem_frame0-(ulong)workspace_base)>>FD_CHUNK_LG_SZ;
  ulong const last_umem_chunk  = first_umem_chunk + ((umem_region_sz-umem_frame_sz)>>FD_CHUNK_LG_SZ);
  if( FD_UNLIKELY( first_umem_chunk>UINT_MAX || last_umem_chunk>UINT_MAX || first_umem_chunk>last_umem_chunk ) ) {
    FD_LOG_ERR(( "Calculated invalid UMEM bounds [%lu,%lu]", first_umem_chunk, last_umem_chunk ));
  }
  ctx->umem_base   = (uchar *)workspace_base;
  ctx->umem_frame0 = umem_frame0;
  ctx->umem_chunk0 = (uint)first_umem_chunk;
  ctx->umem_wmark  = (uint)last_umem_chunk;

  if( FD_UNLIKELY( tile->kind_id!=0 ) ) {
    /* FIXME support receive side scaling. */
    FD_LOG_ERR(( "Sorry, net.provider='mlx5' currently only supports layout.net_tile_count=1" ));
  }

  /* Open the device and create its uverbs resources. */
  char rdma_device_name[ FD_MLX5_RDMA_NAME_MAX ];
  uint rdma_port_num;
  fd_mlx5_tile_rdma_dev_find( rdma_device_name, &rdma_port_num, tile );
  FD_LOG_INFO(( "Opening direct mlx5 device `%s` port %u", rdma_device_name, rdma_port_num ));
  if( FD_UNLIKELY( !fd_mlx5_init( &ctx->hw, rdma_device_name, rdma_port_num,
                                  queue_memory, tile->mlx5.rx_queue_size, tile->mlx5.tx_queue_size,
                                  umem_frame0, umem_region_sz ) ) )
    FD_LOG_ERR(( "direct mlx5 setup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_mlx5_qp_stats_read( &ctx->hw.qp_stats, &ctx->rx_out_of_buffer_prev_cnt ) ) )
    FD_LOG_ERR(( "reading mlx5 QP counters failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Configure asynchronous device events. */
  int const async_event_fd    = ctx->hw.context.async_fd;
  int const async_event_flags = fcntl( async_event_fd, F_GETFL );
  if( FD_UNLIKELY( async_event_flags<0 ||
                   fcntl( async_event_fd, F_SETFL, async_event_flags|O_NONBLOCK )<0 ) ) {
    FD_LOG_ERR(( "making mlx5 async fd non-blocking failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Resolve the netdev and install RX flow steering. */
  uint const interface_idx = if_nametoindex( tile->mlx5.if_name );
  if( FD_UNLIKELY( !interface_idx ) ) {
    FD_LOG_ERR(( "if_nametoindex(%s) failed (%i-%s)",
                 tile->mlx5.if_name, errno, fd_io_strerror( errno ) ));
  }
  ctx->router.if_virt         = interface_idx;
  ctx->router.default_address = fd_mlx5_tile_if_ip4_addr( tile->mlx5.if_name );

  fd_mlx5_tile_rx_dst_ports_init( ctx, topo, tile );
  for( ulong flow_idx=0UL; flow_idx<ctx->dst_port_cnt; flow_idx++ ) {
    if( FD_UNLIKELY( fd_mlx5_flow_create_udp( &ctx->hw.qp,
                                              tile->mlx5.net.bind_address,
                                              ctx->dst_ports[ flow_idx ] ) ) )
      FD_LOG_ERR(( "fd_mlx5_flow_create_udp failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    FD_LOG_DEBUG(( "Created flow rule for ip4.dst_ip=" FD_IP4_ADDR_FMT " udp.dst_port:%hu",
                   FD_IP4_ADDR_FMT_ARGS( tile->mlx5.net.bind_address ),
                   ctx->dst_ports[ flow_idx ] ));
  }
  FD_LOG_INFO(( "Installed %u direct mlx5 flow rules", ctx->dst_port_cnt ));
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( scratch, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_mlx5_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  ulong queue_footprint = fd_mlx5_queue_footprint( tile->mlx5.rx_queue_size,
                                                   tile->mlx5.tx_queue_size );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, FD_MLX5_PAGE_SZ, queue_footprint );
  ctx->batch_size = tile->mlx5.batch_size;
  ctx->stats_interval_ticks = (long)( FD_MLX5_STATS_INTERVAL_NS*fd_tempo_tick_per_ns( NULL ) );
  ctx->next_stats_refresh_ticks = fd_tickcount()+ctx->stats_interval_ticks;
  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( scratch, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * fib_local_mem    = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );
  void * fib_main_mem     = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(), fd_fib4_footprint( tile->mlx5.route_max, tile->mlx5.route_peer_max ) );

  /* chunk 0 is used as a sentinel value, so ensure actual chunk indices
     do not use that value. */
  FD_TEST( ctx->umem_chunk0>0 );

  ctx->rx_pending_rem = ctx->batch_size;

  /* Post RQ WQEs */
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
  /* Assign one TX buffer to each SQ WQE. */
  ctx->tx_chunk0 = (uint)next_chunk;
  next_chunk += (ulong)tile->mlx5.tx_queue_size*frame_chunks;
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

    ctx->input_ctx[ i ].wksp_base = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->input_ctx[ i ].chunk0    = fd_dcache_compact_chunk0( ctx->input_ctx[ i ].wksp_base, link->dcache );
    ctx->input_ctx[ i ].wmark     = fd_dcache_compact_wmark(  ctx->input_ctx[ i ].wksp_base, link->dcache, link->mtu );
  }

  /* Join netbase objects */
  FD_TEST( fd_fib4_join( ctx->router.fib_local, fd_fib4_new( fib_local_mem, tile->mlx5.route_max, tile->mlx5.route_peer_max, tile->mlx5.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->router.fib_main,  fd_fib4_new( fib_main_mem,  tile->mlx5.route_max, tile->mlx5.route_peer_max, tile->mlx5.route_peer_seed ) ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_shared, fd_topo_obj_laddr( topo, tile->mlx5.netdev_tbl_obj_id ) ) );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_tbl, netdev_tbl_local ) );
  fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
  ctx->router.bind_address = tile->mlx5.net.bind_address;

  ulong neigh4_obj_id = tile->mlx5.neigh4_obj_id;
  ulong ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) )
    FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join(
      ctx->router.neigh4,
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
    ctx->router.neigh4_solicit->mcache = net_netlnk->mcache;
    ctx->router.neigh4_solicit->depth  = fd_mcache_depth( ctx->router.neigh4_solicit->mcache );
    ctx->router.neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->router.neigh4_solicit->mcache ) );
  } else {
    FD_LOG_ERR(( "netlink request link not found" ));
  }

  /* Check if all chunks are in bound */
  if( FD_UNLIKELY( next_chunk>ctx->umem_wmark ) ) {
    FD_LOG_ERR(( "dcache is too small (topology bug)" ));
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( scratch, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)ctx+scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow" ));
  }
}

#ifndef FD_TILE_TEST

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_mlx5_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_mlx5_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(),
                                            (uint)ctx->hw.context.async_fd,
                                            (uint)ctx->hw.qp_stats.fd );
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
  out_fds[ out_cnt++ ] = ctx->hw.qp_stats.fd;
  return out_cnt;
}

#endif

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
#define STEM_LAZY                   270000UL /* 270us */
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
