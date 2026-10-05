#define _GNU_SOURCE

#include "../fd_net_tile.h"
#include "../fd_net_tile_private.h"
#include "fd_iavf_private.h"
#include "../fd_net_router.h"
#include "../../topo/fd_topo.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <linux/futex.h>
#include <linux/if_bonding.h>

#include "../../../util/pod/fd_pod_format.h"
#include "generated/fd_iavf_tile_seccomp.h"

#define FD_IAVF_TX_FLUSH_TIMEOUT_NS (20000L)
#define FD_IAVF_LO_TX_TIMEOUT_NS    (500000L)
#define FD_IAVF_ADMINQ_IOVA         (0x100000000UL)
#define FD_IAVF_QUEUE_IOVA          (0x100100000UL)
#define FD_IAVF_PACKET_IOVA         (0x200000000UL)

#define FD_IAVF_HW_TX_DESC_DONE              (0xfUL)
#define FD_IAVF_HW_TX_DESC_CMD_SHIFT         (4)
#define FD_IAVF_HW_TX_DESC_CMD_EOP           (1UL)
#define FD_IAVF_HW_TX_DESC_CMD_REPORT_STATUS (2UL)
#define FD_IAVF_HW_TX_DESC_CMD_ICRC          (4UL)
#define FD_IAVF_HW_TX_DESC_BUFFER_SHIFT      (34)
#define FD_IAVF_HW_TX_DESC_BUFFER_MAX        (0x3fffUL)

#define FD_IAVF_HW_RX_DESC_DONE              (1UL<<0)
#define FD_IAVF_HW_RX_DESC_END_OF_PACKET     (1UL<<1)
#define FD_IAVF_HW_RX_DESC_RXE               (1UL<<19)
#define FD_IAVF_HW_RX_DESC_LENGTH_SHIFT      (38)
#define FD_IAVF_HW_RX_DESC_LENGTH_MASK       (0x3fffUL)

FD_STATIC_ASSERT( FD_NET_MTU<=FD_IAVF_HW_TX_DESC_BUFFER_MAX, iavf_tx_frame_sz );

struct fd_iavf_hw_rx_comp {
  uint  chunk;
  uint  error_flags;
  ulong frame_sz;
};
typedef struct fd_iavf_hw_rx_comp fd_iavf_hw_rx_comp_t;

/* fd_iavf_tile_vf owns this tile's queues on one VF. */
struct fd_iavf_tile_vf {
  fd_iavf_vfio_t    vfio;
  fd_iavf_adminq_t  adminq;
  fd_iavf_vf_info_t vf_info;
  fd_iavf_queue_t   queue;
  uint *            rx_desc_buf_chunk;
  uint *            tx_desc_buf_chunk;
  ushort *          tx_desc_frame_sz;
  uint              rx_pending_chunk[ FD_IAVF_BATCH_SIZE ];
  uint              rx_pending_cnt;
  uint              if_idx;
  ulong             packet_iova0;
  long              tx_flush_deadline_ticks;
};
typedef struct fd_iavf_tile_vf fd_iavf_tile_vf_t;

/* fd_iavf_tile is private tile state. */
struct __attribute__((aligned(64UL))) fd_iavf_tile {
  fd_iavf_tile_vf_t     vfs[ FD_IAVF_MEMBER_MAX ];
  ulong                 vf_cnt;
  ulong                 tx_vf;
  ulong                 rx_next_vf;
  uint                  prepared;
  uint                  batch_size;
  long                  tx_flush_timeout_ticks;
  long                  lo_tx_timeout_ticks;
  long                  lo_tx_deadline_ticks;
  int                   lo_tx_sock;
  uint                  lo_tx_cnt;
  fd_net_tile_t         net;
  fd_net_router_t       router;

  struct mmsghdr     lo_tx_msg [ FD_IAVF_BATCH_SIZE ];
  struct iovec       lo_tx_iov [ FD_IAVF_BATCH_SIZE ];
  struct sockaddr_in lo_tx_addr[ FD_IAVF_BATCH_SIZE ];
  uchar              lo_tx_buf [ FD_IAVF_BATCH_SIZE ][ FD_NET_MTU ];

  struct {
    ulong tx_no_buffer_cnt;
    ulong tx_no_link_cnt;
    ulong rx_no_link_cnt;
  } metrics;
};
typedef struct fd_iavf_tile fd_iavf_tile_t;

static void *
fd_iavf_hw_join_queues( fd_iavf_tile_t *       ctx,
                        fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( scratch, ctx );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  ulong queue_sz   = fd_iavf_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size );
  ulong tx_ring_sz = fd_ulong_align_up( tile->iavf.tx_queue_size*sizeof(fd_iavf_tx_desc_t), FD_IAVF_PAGE_SZ );
  ulong rx_ring_sz = fd_ulong_align_up( tile->iavf.rx_queue_size*sizeof(fd_iavf_rx_desc_t), FD_IAVF_PAGE_SZ );
  for( ulong i=0UL; i<tile->iavf.member_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    vf->adminq.dma_memory      = FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint() );
    vf->queue.dma_memory       = FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, queue_sz                   );
    vf->queue.tx_ring          = vf->queue.dma_memory;
    vf->queue.rx_ring          = (fd_iavf_rx_desc_t *)((uchar *)vf->queue.dma_memory + tx_ring_sz);
    vf->queue.tx_comp_ring     = (ulong *)((uchar *)vf->queue.dma_memory + tx_ring_sz + rx_ring_sz);
    vf->rx_desc_buf_chunk      = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint),   tile->iavf.rx_queue_size*sizeof(uint)   );
    vf->tx_desc_buf_chunk      = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint),   tile->iavf.tx_queue_size*sizeof(uint)   );
    vf->tx_desc_frame_sz       = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );
  }
  return (void *)FD_SCRATCH_ALLOC_FINI( scratch, 1UL );
}

static inline ulong
fd_iavf_hw_buffer_iova( fd_iavf_tile_t const *    ctx,
                        fd_iavf_tile_vf_t const * vf,
                        ulong                     chunk ) {
  return vf->packet_iova0 + ((chunk-ctx->net.pkt_buf_chunk0)<<FD_CHUNK_LG_SZ);
}

static int
fd_iavf_hw_rx_enqueue( fd_iavf_tile_t *    ctx,
                       fd_iavf_tile_vf_t * vf,
                       uint                recv_cnt ) {
  fd_iavf_queue_t * queue       = &vf->queue;
  ulong const       outstanding = queue->rx_prod-queue->rx_cons;

  FD_TEST( recv_cnt<=FD_IAVF_BATCH_SIZE );
  if( FD_UNLIKELY( outstanding>=queue->rx_depth || recv_cnt>=queue->rx_depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }

  for( uint i=0U; i<recv_cnt; i++ ) {
    uint const          chunk    = vf->rx_pending_chunk[i];
    uint const          desc_idx = (uint)((queue->rx_prod+i) & (queue->rx_depth-1U));
    fd_iavf_rx_desc_t * desc     = queue->rx_ring + desc_idx;

    desc->qword[0] = fd_iavf_hw_buffer_iova( ctx, vf, chunk );
    desc->qword[1] = 0UL;
    desc->qword[2] = 0UL;
    desc->qword[3] = 0UL;

    vf->rx_desc_buf_chunk[ desc_idx ] = chunk;
  }
  queue->rx_prod += recv_cnt;

  fd_iavf_hw_dma_to_device();
  *queue->rx_tail = (uint)(queue->rx_prod & (queue->rx_depth-1U));
  FD_COMPILER_MFENCE();
  queue->rx_posted = queue->rx_prod;
  return 0;
}

static void
fd_iavf_hw_tx_enqueue( fd_iavf_tile_t *    ctx,
                       fd_iavf_tile_vf_t * vf,
                       ulong               frame_sz ) {
  fd_iavf_queue_t * queue = &vf->queue;

  FD_TEST( queue->tx_prod-queue->tx_cons<queue->tx_depth-1UL );

  uint idx                 = (uint)(queue->tx_prod & (queue->tx_depth-1U));
  fd_iavf_tx_desc_t * desc = queue->tx_ring + idx;
  desc->buffer_iova        = fd_iavf_hw_buffer_iova( ctx, vf, vf->tx_desc_buf_chunk[idx] );
  desc->cmd_type_offset_buffer_sz =
      ((FD_IAVF_HW_TX_DESC_CMD_EOP | FD_IAVF_HW_TX_DESC_CMD_ICRC)<<FD_IAVF_HW_TX_DESC_CMD_SHIFT) |
      (frame_sz<<FD_IAVF_HW_TX_DESC_BUFFER_SHIFT);
  vf->tx_desc_frame_sz[idx] = (ushort)frame_sz;
  queue->tx_prod++;
}

static void
fd_iavf_hw_tx_flush( fd_iavf_queue_t * queue ) {
  if( FD_UNLIKELY( queue->tx_posted==queue->tx_prod ) ) return;

  ulong const         tx_end   = queue->tx_prod;
  uint const          desc_idx = (uint)((tx_end-1UL) & (queue->tx_depth-1U));
  fd_iavf_tx_desc_t * desc     = queue->tx_ring + desc_idx;
  desc->cmd_type_offset_buffer_sz |= FD_IAVF_HW_TX_DESC_CMD_REPORT_STATUS<<FD_IAVF_HW_TX_DESC_CMD_SHIFT;
  queue->tx_comp_ring[ queue->tx_comp_prod & (queue->tx_depth-1U) ] = tx_end;
  queue->tx_comp_prod++;

  fd_iavf_hw_dma_to_device();
  *queue->tx_tail = (uint)(tx_end & (queue->tx_depth-1U));
  FD_COMPILER_MFENCE();
  queue->tx_posted = tx_end;
}

static ulong
fd_iavf_hw_poll_tx( fd_iavf_tile_vf_t * vf,
                    ulong *             comp_bytes ) {
  fd_iavf_queue_t * queue = &vf->queue;
  ulong tx_cons   = queue->tx_cons;
  ulong comp_cons = queue->tx_comp_cons;
  while( comp_cons<queue->tx_comp_prod ) {
    ulong const         tx_end   = queue->tx_comp_ring[ comp_cons & (queue->tx_depth-1U) ];
    uint const          desc_idx = (uint)((tx_end-1UL) & (queue->tx_depth-1U));
    fd_iavf_tx_desc_t * desc     = queue->tx_ring + desc_idx;
    ulong               cmd      = FD_VOLATILE_CONST( desc->cmd_type_offset_buffer_sz );
    if( (cmd & 0xfUL)!=FD_IAVF_HW_TX_DESC_DONE ) break;
    tx_cons = tx_end;
    comp_cons++;
  }
  ulong const comp_cnt = tx_cons-queue->tx_cons;
  *comp_bytes = 0UL;
  if( comp_cnt ) {
    fd_iavf_hw_dma_from_device();
    for( ulong i=queue->tx_cons; i<tx_cons; i++ ) {
      *comp_bytes += vf->tx_desc_frame_sz[ i & (queue->tx_depth-1U) ];
    }
    queue->tx_cons      = tx_cons;
    queue->tx_comp_cons = comp_cons;
  }
  return comp_cnt;
}

static int
fd_iavf_hw_poll_rx( fd_iavf_tile_vf_t *    vf,
                    fd_iavf_hw_rx_comp_t * comp,
                    uint                   comp_capacity ) {
  fd_iavf_queue_t * queue = &vf->queue;
  if( FD_UNLIKELY( !queue->enabled || !comp || !comp_capacity ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong      rx_cons    = queue->rx_cons;
  uint const comp_limit = fd_uint_min( comp_capacity, queue->rx_depth );
  uint       comp_cnt   = 0U;
  while( comp_cnt<comp_limit && rx_cons<queue->rx_posted ) {
    uint const          desc_idx = (uint)(rx_cons & (queue->rx_depth-1U));
    fd_iavf_rx_desc_t * desc     = queue->rx_ring + desc_idx;
    ulong const         status   = FD_VOLATILE_CONST( desc->qword[1] );
    if( !(status & FD_IAVF_HW_RX_DESC_DONE) ) break;

    uint error_flags  = (uint)!!(status & FD_IAVF_HW_RX_DESC_RXE) | queue->rx_discard;
    queue->rx_discard = (uint)!(status & FD_IAVF_HW_RX_DESC_END_OF_PACKET);
    error_flags |= queue->rx_discard;
    comp[ comp_cnt++ ] = (fd_iavf_hw_rx_comp_t) {
      .chunk       = vf->rx_desc_buf_chunk[ desc_idx ],
      .error_flags = error_flags,
      .frame_sz    = (status>>FD_IAVF_HW_RX_DESC_LENGTH_SHIFT) & FD_IAVF_HW_RX_DESC_LENGTH_MASK
    };
    rx_cons++;
  }
  if( comp_cnt ) {
    fd_iavf_hw_dma_from_device();
    queue->rx_cons = rx_cons;
  }
  return (int)comp_cnt;
}

static inline ulong
fd_iavf_tile_tx_chunk( fd_iavf_tile_t const * ctx,
                       ulong                  tx_idx ) {
  fd_iavf_tile_vf_t const * vf = &ctx->vfs[ ctx->tx_vf ];
  return vf->tx_desc_buf_chunk[ tx_idx & (vf->queue.tx_depth-1U) ];
}

static inline void
fd_iavf_tile_rx_recycle( fd_iavf_tile_t *    ctx,
                         fd_iavf_tile_vf_t * vf,
                         ulong               chunk ) {
  vf->rx_pending_chunk[ vf->rx_pending_cnt++ ] = (uint)chunk;
  if( vf->rx_pending_cnt==ctx->batch_size ) {
    FD_TEST( !fd_iavf_hw_rx_enqueue( ctx, vf, vf->rx_pending_cnt ) );
    vf->rx_pending_cnt = 0U;
  }
}

static inline int
fd_iavf_tile_vf_active( fd_iavf_tile_t *          ctx,
                        fd_iavf_tile_vf_t const * vf,
                        uchar                     actor_state ) {
  if( !vf->vf_info.link_state_valid || !vf->vf_info.link_up ) return 0;
  fd_netdev_t const * master = fd_netdev_tbl_query( &ctx->router.netdev_tbl, ctx->router.if_virt );
  fd_netdev_t const * dev    = fd_netdev_tbl_query( &ctx->router.netdev_tbl, vf->if_idx );
  if( !master || !dev || master->oper_status!=FD_OPER_STATUS_UP || dev->oper_status!=FD_OPER_STATUS_UP ) return 0;
  if( vf->if_idx==ctx->router.if_virt ) return 1;
  return master->bond_mode==BOND_MODE_8023AD && master->bond_aggregator_id &&
         dev->master_idx==(int)ctx->router.if_virt &&
         dev->bond_aggregator_id==master->bond_aggregator_id &&
         !!(dev->bond_actor_state & actor_state);
}

static ulong
fd_iavf_tile_select_tx_vf( fd_iavf_tile_t * ctx,
                           ulong            hash ) {
  ulong available[ FD_IAVF_MEMBER_MAX ];
  ulong available_cnt = 0UL;
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    if( fd_iavf_tile_vf_active( ctx, &ctx->vfs[i], LACP_STATE_DISTRIBUTING ) ) available[ available_cnt++ ] = i;
  }
  return available_cnt ? available[ hash%available_cnt ] : ULONG_MAX;
}

static inline int
fd_iavf_tile_poll_rx( fd_iavf_tile_t *    ctx,
                      fd_stem_context_t * stem ) {
  int busy        = 0;
  ulong start     = ctx->rx_next_vf;
  ctx->rx_next_vf = (start+1UL)%ctx->vf_cnt;
  for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[ (start+vf_idx)%ctx->vf_cnt ];
    fd_iavf_hw_rx_comp_t comp[ FD_IAVF_BATCH_SIZE ];
    int comp_cnt = fd_iavf_hw_poll_rx( vf, comp, ctx->batch_size );
    if( FD_UNLIKELY( comp_cnt<0 ) ) FD_LOG_ERR(( "IAVF RX poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( !comp_cnt ) continue;
    busy        = 1;
    int active  = fd_iavf_tile_vf_active( ctx, vf, LACP_STATE_COLLECTING );
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    for( uint i=0U; i<(uint)comp_cnt; i++ ) {
      ulong chunk = comp[i].chunk;
      if( FD_UNLIKELY( chunk<ctx->net.pkt_buf_chunk0 || chunk>ctx->net.pkt_buf_wmark ) ) {
        FD_LOG_CRIT(( "RX completion chunk %lu is out of bounds", chunk ));
      }
      ulong freed_chunk = chunk;
      if( FD_UNLIKELY( !active ) ) ctx->metrics.rx_no_link_cnt++;
      else if( FD_UNLIKELY( comp[i].error_flags ) ) ctx->net.metrics.rx_malformed_cnt++;
      else fd_net_rx_pkt( &ctx->net, stem, chunk, comp[i].frame_sz, tspub, &freed_chunk );
      if( FD_UNLIKELY( !freed_chunk ) ) FD_LOG_CRIT(( "invalid RX chunk in mcache" ));
      fd_iavf_tile_rx_recycle( ctx, vf, freed_chunk );
    }
  }
  return busy;
}

static inline int
fd_iavf_tile_poll_tx( fd_iavf_tile_t *    ctx,
                      fd_iavf_tile_vf_t * vf ) {
  ulong comp_bytes;
  ulong comp_cnt = fd_iavf_hw_poll_tx( vf, &comp_bytes );
  ctx->net.metrics.tx_bytes_total += comp_bytes;
  ctx->net.metrics.tx_pkt_cnt += comp_cnt;
  return !!comp_cnt;
}

/* fd_iavf_tile_lo_tx_flush makes one nonblocking send attempt per batch,
   unsent packets are dropped. */
static void
fd_iavf_tile_lo_tx_flush( fd_iavf_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->lo_tx_cnt ) ) return;
  int const  send_cnt = sendmmsg( ctx->lo_tx_sock, ctx->lo_tx_msg, ctx->lo_tx_cnt, MSG_DONTWAIT );
  uint const sent_cnt = send_cnt<0 ? 0U : (uint)send_cnt;
  for( uint i=0U; i<sent_cnt; i++ ) ctx->net.metrics.tx_bytes_total += sizeof(fd_eth_hdr_t)+ctx->lo_tx_iov[ i ].iov_len;
  ctx->net.metrics.tx_pkt_cnt += sent_cnt;
  ctx->lo_tx_cnt = 0U;
}

static void
fd_iavf_tile_lo_tx_enqueue( fd_iavf_tile_t *     ctx,
                            fd_ip4_hdr_t const * ip4,
                            ulong                ip_sz ) {
  uint const           batch_idx = ctx->lo_tx_cnt;
  struct mmsghdr *     msg       = ctx->lo_tx_msg  + batch_idx;
  struct sockaddr_in * sa        = ctx->lo_tx_addr + batch_idx;
  struct iovec *       iov       = ctx->lo_tx_iov  + batch_idx;
  uchar *              buf       = ctx->lo_tx_buf[ batch_idx ];

  *iov = (struct iovec) {
    .iov_base = buf,
    .iov_len  = ip_sz,
  };
  sa->sin_family      = AF_INET;
  sa->sin_addr.s_addr = ip4->daddr;
  sa->sin_port        = 0; /* ignored */

  *msg = (struct mmsghdr) {
    .msg_hdr = {
      .msg_name    = sa,
      .msg_namelen = sizeof(struct sockaddr_in),
      .msg_iov     = iov,
      .msg_iovlen  = 1UL
    }
  };

  fd_memcpy( buf, ip4, ip_sz );
  ctx->lo_tx_cnt++;
  if( ctx->lo_tx_cnt==FD_IAVF_BATCH_SIZE ) fd_iavf_tile_lo_tx_flush( ctx );
  else if( ctx->lo_tx_cnt==1U ) ctx->lo_tx_deadline_ticks = fd_tickcount()+ctx->lo_tx_timeout_ticks;
}

static inline void
before_credit( fd_iavf_tile_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  fd_net_router_solicit( &ctx->router, stem );
  long now = fd_tickcount();
  if( ctx->lo_tx_cnt && now>=ctx->lo_tx_deadline_ticks ) {
    fd_iavf_tile_lo_tx_flush( ctx );
    *charge_busy = 1;
  }
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf    = &ctx->vfs[i];
    fd_iavf_queue_t *   queue = &vf->queue;
    if( queue->tx_prod!=queue->tx_posted && now>=vf->tx_flush_deadline_ticks ) {
      fd_iavf_hw_tx_flush( queue );
      *charge_busy = 1;
    }
    if( queue->tx_cons!=queue->tx_posted ) *charge_busy |= fd_iavf_tile_poll_tx( ctx, vf );
  }
}

static inline void
after_credit( fd_iavf_tile_t *    ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  *charge_busy |= fd_iavf_tile_poll_rx( ctx, stem );
}

/* before_frag resolves the TX route and checks the descriptor ring. */
static inline int
before_frag( fd_iavf_tile_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) {
  (void)seq;
  if( FD_UNLIKELY( ctx->net.in_kind[ in_idx ]==FD_NET_IN_KIND_IPROUTE ) ) return 0;

  /* Resolve the TX route for outgoing packets */
  ulong dst_proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( dst_proto!=DST_PROTO_OUTGOING ) ) return 1;

  ulong const hash       = fd_disco_netmux_sig_hash( sig );
  ulong       target_idx = hash % ctx->net.tile_cnt;
  ulong const kind_id    = ctx->net.kind_id;
  if( kind_id!=0UL && kind_id!=target_idx ) return 1;

  uint                dst_ip = fd_disco_netmux_sig_ip( sig );
  fd_net_tx_route_t * route  = &ctx->net.tx_route;
  if( FD_UNLIKELY( !fd_net_tx_route( &ctx->router, &ctx->net, dst_ip, route ) ) ) return 1;
  if( FD_UNLIKELY( route->use_gre ) ) {
    fd_net_tx_route_t outer_route;
    uint const inner_src_ip = route->src_ip;
    uint const outer_src_ip = route->gre_outer_src_ip;
    uint const outer_dst_ip = route->gre_outer_dst_ip;

    if( FD_UNLIKELY( !inner_src_ip || !outer_dst_ip ||
                     !fd_net_tx_route( &ctx->router, &ctx->net, outer_dst_ip, &outer_route ) ||
                     outer_route.use_gre || outer_route.use_loopback ) ) {
      ctx->net.metrics.tx_gre_route_fail_cnt++;
      return 1;
    }
    *route                  = outer_route;
    route->src_ip           = inner_src_ip;
    route->gre_outer_src_ip = fd_uint_if( !outer_src_ip, outer_route.src_ip, outer_src_ip );
    route->gre_outer_dst_ip = outer_dst_ip;
    route->use_gre          = 1U;
  }

  if( route->use_loopback ) target_idx = 0UL;
  if( kind_id!=target_idx ) return 1;

  ctx->tx_vf = route->use_loopback ? 0UL : fd_iavf_tile_select_tx_vf( ctx, hash );
  if( FD_UNLIKELY( ctx->tx_vf==ULONG_MAX ) ) {
    ctx->metrics.tx_no_link_cnt++;
    return 1;
  }
  fd_iavf_queue_t const * queue = &ctx->vfs[ ctx->tx_vf ].queue;
  if( FD_UNLIKELY( !route->use_loopback && queue->tx_prod-queue->tx_cons>=queue->tx_depth-1UL ) ) {
    ctx->metrics.tx_no_buffer_cnt++;
    return 1;
  }

  return 0; /* continue */
}

/* during_frag validates and stages the input packet or route update */
static inline void
during_frag( fd_iavf_tile_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig,
             ulong            chunk,
             ulong            frame_sz,
             ulong            ctl ) {
  (void)seq; (void)sig; (void)ctl;
  fd_net_in_frag_validate( &ctx->net, in_idx, chunk, frame_sz );

  if( FD_UNLIKELY( fd_net_iproute_msg_stage( &ctx->net, in_idx, chunk, frame_sz ) ) ) return;

  ulong   dst_chunk = fd_iavf_tile_tx_chunk( ctx, ctx->vfs[ ctx->tx_vf ].queue.tx_prod );
  uchar * dst       = fd_chunk_to_laddr( ctx->net.pkt_buf_wksp_base, dst_chunk );
  /* Speculatively copy frame from in link into buffer */
  fd_net_tx_pkt_cpy( &ctx->net, dst, chunk, frame_sz, in_idx );
}

/* after_frag applies a route update or completes and submits the staged packet */
static void
after_frag( fd_iavf_tile_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               frame_sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub;

  if( FD_UNLIKELY( ctx->net.in_kind[ in_idx ]==FD_NET_IN_KIND_IPROUTE ) ) {
    fd_iproute_msg_t const * msg = &ctx->net.iproute_msg;
    if( msg->op==FD_IPROUTE_OP_FLUSH ) {
      fd_fib4_clear( ctx->router.fib_local );
      fd_fib4_clear( ctx->router.fib_main );
      return;
    }

    fd_fib4_t * fib;
    if( msg->table_id==RT_TABLE_LOCAL )     fib = ctx->router.fib_local;
    else if( msg->table_id==RT_TABLE_MAIN ) fib = ctx->router.fib_main;
    else return;

    if( msg->op==FD_IPROUTE_OP_UPSERT && FD_UNLIKELY( !fd_fib4_insert( fib, msg->dst_addr, msg->prefix, msg->prio, &msg->hop ) ) ) {
      FD_LOG_WARNING(( "route update dropped: route table full (increase [net.max_routes] or [net.max_peer_routes])" ));
      fd_stem_publish( stem, ctx->router.netlnk_out_idx, FD_NETLINK_ROUTE4_SYNC_SIG, 0UL, 0UL, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    } else if( msg->op==FD_IPROUTE_OP_DELETE ) {
      fd_fib4_remove( fib, msg->dst_addr, msg->prefix, msg->prio );
    }
    return;
  }

  ulong               chunk = fd_iavf_tile_tx_chunk( ctx, ctx->vfs[ ctx->tx_vf ].queue.tx_prod );
  uchar *             frame = fd_chunk_to_laddr( ctx->net.pkt_buf_wksp_base, chunk );
  fd_iavf_tile_vf_t * vf    = &ctx->vfs[ ctx->tx_vf ];
  fd_iavf_queue_t *   queue = &vf->queue;

  if( FD_UNLIKELY( !fd_net_tx_pkt_prep( &ctx->net, frame, &frame_sz, in_idx ) ) ) return;

  if( FD_UNLIKELY( ctx->net.tx_route.use_loopback ) ) {
    fd_eth_hdr_t const * eth_hdr   = (fd_eth_hdr_t const *)frame;
    fd_ip4_hdr_t const * ip4       = (fd_ip4_hdr_t const *)(eth_hdr+1);
    ulong const          ip_hdr_sz = FD_IP4_GET_LEN( *ip4 );
    ulong const          ip_sz     = fd_ushort_bswap( ip4->net_tot_len );
    if( FD_UNLIKELY( ip4->protocol!=FD_IP4_HDR_PROTOCOL_UDP ||
                     ip4->daddr!=fd_disco_netmux_sig_ip( sig ) ||
                     (fd_ushort_bswap( ip4->net_frag_off ) & ~FD_IP4_HDR_FRAG_OFF_DF) ||
                     ip_sz<ip_hdr_sz+sizeof(fd_udp_hdr_t) ||
                     ip_sz>frame_sz-sizeof(fd_eth_hdr_t) ) ) {
      ctx->net.metrics.tx_invalid_cnt++;
      return;
    }
    fd_udp_hdr_t const * udp    = (fd_udp_hdr_t const *)((uchar const *)ip4+ip_hdr_sz);
    ulong const          udp_sz = fd_ushort_bswap( udp->net_len );
    if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) || udp_sz>ip_sz-ip_hdr_sz ) ) {
      ctx->net.metrics.tx_invalid_cnt++;
      return;
    }

    int owned = 0;
    if( !ctx->router.bind_address || ctx->router.bind_address==ip4->daddr ) {
      ushort const dst_port = fd_ushort_bswap( udp->net_dport );
      for( ulong i=0UL; i<ctx->net.dst_port_cnt; i++ ) owned |= ctx->net.dst_ports[ i ]==dst_port;
    }
    if( !owned ) {
      fd_iavf_tile_lo_tx_enqueue( ctx, ip4, ip_sz );
      return;
    }

    ulong freed_chunk;
    if( fd_net_rx_pkt( &ctx->net, stem, chunk, frame_sz, (ulong)fd_frag_meta_ts_comp( fd_tickcount() ), &freed_chunk ) ) {
      vf->tx_desc_buf_chunk[ queue->tx_prod & (queue->tx_depth-1U) ] = (uint)freed_chunk;
    }
    ctx->net.metrics.tx_pkt_cnt++;
    ctx->net.metrics.tx_bytes_total += frame_sz;
    return;
  }

  fd_iavf_hw_tx_enqueue( ctx, vf, frame_sz );
  ctx->net.metrics.tx_gre_cnt += (ulong)ctx->net.tx_route.use_gre;
  ulong pending = queue->tx_prod-queue->tx_posted;
  if( pending>=ctx->batch_size || queue->tx_prod-queue->tx_cons>=queue->tx_depth-1UL ) {
    fd_iavf_hw_tx_flush( queue );
  } else if( pending==1UL ) {
    vf->tx_flush_deadline_ticks = fd_tickcount()+ctx->tx_flush_timeout_ticks;
  }
}

static inline void
metrics_write( fd_iavf_tile_t * ctx ) {

  ulong rx_buffer_idle_cnt = 0UL;
  ulong rx_buffer_busy_cnt = 0UL;
  ulong tx_buffer_idle_cnt = 0UL;
  ulong tx_buffer_busy_cnt = 0UL;
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_queue_t const * queue   = &ctx->vfs[i].queue;
    ulong                   rx_idle = fd_ulong_min( queue->rx_prod-queue->rx_cons, queue->rx_depth );
    ulong                   tx_busy = fd_ulong_min( queue->tx_prod-queue->tx_cons, queue->tx_depth );
    rx_buffer_idle_cnt += rx_idle;
    rx_buffer_busy_cnt += queue->rx_depth-rx_idle;
    tx_buffer_busy_cnt += tx_busy;
    tx_buffer_idle_cnt += queue->tx_depth-tx_busy;
  }
  FD_MCNT_SET(   IAVF, PKT_RX,             ctx->net.metrics.rx_pkt_cnt           );
  FD_MCNT_SET(   IAVF, PKT_RX_BYTES,       ctx->net.metrics.rx_bytes_total       );
  FD_MCNT_SET(   IAVF, PKT_RX_MALFORMED,   ctx->net.metrics.rx_malformed_cnt     );
  FD_MCNT_SET(   IAVF, PKT_RX_ROUTE_FAIL,  ctx->net.metrics.rx_route_fail_cnt    );
  FD_MCNT_SET(   IAVF, PKT_RX_NO_LINK,     ctx->metrics.rx_no_link_cnt           );
  FD_MCNT_SET(   IAVF, GRE_PKT_RX,         ctx->net.metrics.rx_gre_cnt           );
  FD_MCNT_SET(   IAVF, GRE_PKT_RX_INVALID, ctx->net.metrics.rx_gre_invalid_cnt   );
  FD_MCNT_SET(   IAVF, GRE_PKT_RX_IGNORED, ctx->net.metrics.rx_gre_ignored_cnt   );
  FD_MGAUGE_SET( IAVF, RX_BUFFER_BUSY,     rx_buffer_busy_cnt                    );
  FD_MGAUGE_SET( IAVF, RX_BUFFER_IDLE,     rx_buffer_idle_cnt                    );

  FD_MCNT_SET(   IAVF, PKT_TX_COMPLETED,      ctx->net.metrics.tx_pkt_cnt            );
  FD_MCNT_SET(   IAVF, PKT_TX_BYTES,          ctx->net.metrics.tx_bytes_total        );
  FD_MCNT_SET(   IAVF, PKT_TX_NO_BUFFER,      ctx->metrics.tx_no_buffer_cnt          );
  FD_MCNT_SET(   IAVF, PKT_TX_NO_LINK,        ctx->metrics.tx_no_link_cnt            );
  FD_MCNT_ENUM_COPY( IAVF, PKT_TX_ROUTE_FAIL, ctx->net.metrics.tx_route_fail_cnt     );
  FD_MCNT_SET(   IAVF, PKT_TX_INVALID,        ctx->net.metrics.tx_invalid_cnt        );
  FD_MCNT_SET(   IAVF, PKT_TX_NO_NEIGHBOR,    ctx->router.metrics.tx_neigh_fail_cnt  );
  FD_MCNT_SET(   IAVF, GRE_PKT_TX_SUBMITTED,  ctx->net.metrics.tx_gre_cnt            );
  FD_MCNT_SET(   IAVF, GRE_PKT_TX_NO_ROUTE,   ctx->net.metrics.tx_gre_route_fail_cnt );
  FD_MGAUGE_SET( IAVF, TX_BUFFER_BUSY,        tx_buffer_busy_cnt                     );
  FD_MGAUGE_SET( IAVF, TX_BUFFER_IDLE,        tx_buffer_idle_cnt                     );
}

static inline void
during_housekeeping( fd_iavf_tile_t * ctx ) {
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    int changed;
    if( FD_UNLIKELY( fd_iavf_virtchnl_poll_link( &vf->vfio, &vf->adminq, &vf->vf_info, &changed ) ) ) {
      FD_LOG_ERR(( "VF link event or reset failure (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( changed ) FD_LOG_INFO(( "VF %lu link %s", i, vf->vf_info.link_up ? "up" : "down" ));
  }
  if( FD_LIKELY( !fd_seqlock_locked_hint( &ctx->router.netdev_shared.hdr->seqlock ) ) ) {
    fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
    fd_net_gre_tunnels_refresh( &ctx->net, &ctx->router.netdev_tbl );
  }
}

static uint
fd_iavf_tile_if_ip4_addr( char const * if_name ) {
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

/* fd_iavf_tile_lo_tx_socket uses IPPROTO_RAW for send only IP_HDRINCL
   transmission, preserving the source address and UDP source port. */
static int
fd_iavf_tile_lo_tx_socket( void ) {
  int sock = socket( AF_INET, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_RAW );
  if( FD_UNLIKELY( sock<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_RAW,IPPROTO_RAW) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( 0!=setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", sizeof("lo") ) ) ) {
    FD_LOG_ERR(( "setsockopt(SO_BINDTODEVICE,lo) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return sock;
}

static ulong
scratch_align( void ) {
  return FD_IAVF_PAGE_SZ;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong queue_sz = fd_iavf_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size );
  if( FD_UNLIKELY( !queue_sz || !tile->iavf.member_cnt || tile->iavf.member_cnt>FD_IAVF_MEMBER_MAX ) ) return 0UL;
  ulong layout = FD_LAYOUT_INIT;
  layout       = FD_LAYOUT_APPEND( layout, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  for( ulong i=0UL; i<tile->iavf.member_cnt; i++ ) {
    layout = FD_LAYOUT_APPEND( layout, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint()              );
    layout = FD_LAYOUT_APPEND( layout, FD_IAVF_PAGE_SZ, queue_sz                                );
    layout = FD_LAYOUT_APPEND( layout, alignof(uint),   tile->iavf.rx_queue_size*sizeof(uint)   );
    layout = FD_LAYOUT_APPEND( layout, alignof(uint),   tile->iavf.tx_queue_size*sizeof(uint)   );
    layout = FD_LAYOUT_APPEND( layout, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );
  }
  layout = FD_LAYOUT_APPEND( layout, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX )               );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(),       fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(),       fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  return FD_LAYOUT_FINI( layout, scratch_align() );
}

fd_fib4_t *
fd_iavf_tile_fib4_join( fd_fib4_t *            out,
                        fd_topo_t const *      topo,
                        fd_topo_tile_t const * tile,
                        int                    main_table ) {
  FD_SCRATCH_ALLOC_INIT( scratch, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  ulong queue_sz = fd_iavf_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size );
  for( ulong i=0UL; i<tile->iavf.member_cnt; i++ ) {
    (void)FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint()              );
    (void)FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, queue_sz                                );
    (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint),   tile->iavf.rx_queue_size*sizeof(uint)   );
    (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint),   tile->iavf.tx_queue_size*sizeof(uint)   );
    (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );
  }
  (void)FD_SCRATCH_ALLOC_APPEND( scratch,              fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX )               );
  void * local_mem = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(),       fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  void * main_mem  = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(),       fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  return fd_fib4_join( out, main_table ? main_mem : local_mem );
}

static void
fd_iavf_tile_packet_memory( fd_topo_t const *      topo,
                            fd_topo_tile_t const * tile,
                            fd_iavf_tile_t *       ctx,
                            void **                map_memory,
                            ulong *                map_memory_sz ) {
  void * dcache = fd_dcache_join( fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id ) );
  FD_TEST( dcache );
  void * wksp_base = fd_wksp_containing( dcache );
  FD_TEST( wksp_base );
  ulong data_sz = fd_ulong_align_dn( fd_dcache_data_sz( dcache ), FD_NET_MTU );
  FD_TEST( data_sz>=FD_NET_MTU && (ulong)dcache<=ULONG_MAX-data_sz-FD_IAVF_PAGE_SZ );
  ulong chunk0 = ((ulong)dcache-(ulong)wksp_base)>>FD_CHUNK_LG_SZ;
  ulong wmark  = chunk0 + ((data_sz-FD_NET_MTU)>>FD_CHUNK_LG_SZ);
  if( FD_UNLIKELY( !chunk0 || chunk0>UINT_MAX || wmark>UINT_MAX || chunk0>wmark ) ) FD_LOG_ERR(( "invalid packet buffer bounds" ));
  ulong map_start            = fd_ulong_align_dn( (ulong)dcache, FD_IAVF_PAGE_SZ );
  ulong map_end              = fd_ulong_align_up( (ulong)dcache+data_sz, FD_IAVF_PAGE_SZ );
  ctx->net.pkt_buf_wksp_base = wksp_base;
  ctx->net.pkt_buf_chunk0    = chunk0;
  ctx->net.pkt_buf_wmark     = wmark;
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    ctx->vfs[i].packet_iova0 = FD_IAVF_PACKET_IOVA + (ulong)dcache-map_start;
  }
  if( map_memory ) *map_memory = (void *)map_start;
  if( map_memory_sz ) *map_memory_sz = map_end-map_start;
}

FD_FN_UNUSED static void
fd_iavf_tile_init_buffers( fd_topo_t const *      topo,
                           fd_topo_tile_t const * tile,
                           fd_iavf_tile_t *       ctx ) {
  ulong frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong next_chunk   = ctx->net.pkt_buf_chunk0;
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    for( ulong j=0UL; j<tile->iavf.rx_queue_size-ctx->batch_size; j++ ) {
      fd_iavf_tile_rx_recycle( ctx, vf, next_chunk );
      next_chunk += frame_chunks;
    }
    if( vf->rx_pending_cnt ) {
      FD_TEST( !fd_iavf_hw_rx_enqueue( ctx, vf, vf->rx_pending_cnt ) );
      vf->rx_pending_cnt = 0U;
    }
    for( ulong j=0UL; j<tile->iavf.tx_queue_size; j++ ) {
      vf->tx_desc_buf_chunk[j] = (uint)next_chunk;
      next_chunk += frame_chunks;
    }
  }
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link   = &topo->links[ tile->out_link_id[i] ];
    fd_frag_meta_t *       mcache = fd_mcache_join( fd_topo_obj_laddr( topo, link->mcache_obj_id ) );
    FD_TEST( mcache );
    ulong depth = fd_mcache_depth( mcache );
    for( ulong j=0UL; j<depth; j++ ) {
      mcache[j].chunk = (uint)next_chunk;
      mcache[j].seq   = fd_seq_dec( j, 1UL );
      next_chunk += frame_chunks;
    }
  }
  if( FD_UNLIKELY( next_chunk-frame_chunks>ctx->net.pkt_buf_wmark ) ) FD_LOG_ERR(( "packet dcache is too small" ));
}

FD_FN_UNUSED static void
fd_iavf_tile_vf_pci( char const * pf_if,
                     char         vf_pci[ FD_IAVF_PCI_ADDR_SZ ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/virtfn0", pf_if ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) FD_LOG_ERR(( "VF 0 lookup for %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  char const * pci = strrchr( resolved, '/' );
  if( FD_UNLIKELY( !pci || strlen(pci+1)!=FD_IAVF_PCI_ADDR_SZ-1UL ) ) FD_LOG_ERR(( "invalid VF PCI address" ));
  fd_cstr_ncpy( vf_pci, pci+1, FD_IAVF_PCI_ADDR_SZ );
}

FD_FN_UNUSED static void
fd_iavf_tile_join_obj_workspace( fd_topo_t * topo,
                                 ulong       obj_id ) {
  fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[obj_id].wksp_id ];
  if( !wksp->wksp ) fd_topo_join_workspace( topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, 0 );
}

#ifndef FD_TILE_TEST
void
fd_topo_install_iavf( fd_topo_t *     topo,
                      fd_iavf_fds_t * fds ) {
  if( FD_UNLIKELY( fd_topo_tile_name_cnt( topo, "iavf" )!=1UL ) ) FD_LOG_ERR(( "IAVF currently requires one net tile" ));
  ulong tile_id = fd_topo_find_tile( topo, "iavf", 0UL );
  FD_TEST( tile_id!=ULONG_MAX );
  fd_topo_tile_t const * tile = &topo->tiles[tile_id];
  fd_iavf_tile_join_obj_workspace( topo, tile->tile_obj_id );
  fd_iavf_tile_join_obj_workspace( topo, tile->net.umem_dcache_obj_id );
  for( ulong i=0UL; i<tile->out_cnt; i++ ) fd_iavf_tile_join_obj_workspace( topo, topo->links[ tile->out_link_id[i] ].mcache_obj_id );
  fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->vf_cnt     = tile->iavf.member_cnt;
  ctx->batch_size = FD_IAVF_BATCH_SIZE;
  (void)fd_iavf_hw_join_queues( ctx, tile );
  void * packet_memory;
  ulong  packet_memory_sz;
  fd_iavf_tile_packet_memory( topo, tile, ctx, &packet_memory, &packet_memory_sz );
  fd_net_rx_dst_ports_init( &ctx->net, topo, tile );
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
    fd_iavf_tile_vf_pci( tile->iavf.members[i], vf_pci );
    fd_iavf_pci_info_t pci;
    if( FD_UNLIKELY( fd_iavf_pci_probe( &pci, vf_pci ) || fd_iavf_vfio_init( &vf->vfio, &pci ) ) ) {
      FD_LOG_ERR(( "VFIO setup for %s failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
    }
    void * adminq_memory = vf->adminq.dma_memory;
    if( FD_UNLIKELY( fd_iavf_adminq_init( &vf->vfio, &vf->adminq, adminq_memory,
                                          fd_iavf_adminq_footprint(), FD_IAVF_ADMINQ_IOVA ) ||
                     fd_iavf_virtchnl_version( &vf->vfio, &vf->adminq ) ||
                     fd_iavf_virtchnl_get_resources( &vf->vfio, &vf->adminq, &vf->vf_info ) ) ) {
      FD_LOG_ERR(( "VF resource setup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    void * queue_memory = vf->queue.dma_memory;
    if( FD_UNLIKELY( fd_iavf_virtchnl_configure_queue( &vf->vfio, &vf->adminq, &vf->vf_info,
                                                       &vf->queue, queue_memory,
                                                       fd_iavf_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size ),
                                                       FD_IAVF_QUEUE_IOVA, tile->iavf.tx_queue_size, tile->iavf.rx_queue_size,
                                                       FD_NET_MTU, FD_NET_MTU ) ||
                     fd_iavf_virtchnl_add_mac( &vf->vfio, &vf->adminq, &vf->vf_info ) ||
                     fd_iavf_virtchnl_configure_rss( &vf->vfio, &vf->adminq, &vf->vf_info, 1U ) ||
                     fd_iavf_vfio_dma_map( &vf->vfio, packet_memory, packet_memory_sz, FD_IAVF_PACKET_IOVA ) ) ) {
      FD_LOG_ERR(( "VF queue setup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
  fd_iavf_tile_init_buffers( topo, tile, ctx );
  if( fds ) fds->member_cnt = ctx->vf_cnt;
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    if( FD_UNLIKELY( fd_iavf_virtchnl_enable_queue( &vf->vfio, &vf->adminq, &vf->vf_info, &vf->queue ) ) ) {
      FD_LOG_ERR(( "VF queue enable failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( fds ) {
      fds->container_fd[ i ] = vf->vfio.container_fd;
      fds->group_fd    [ i ] = vf->vfio.group_fd;
      fds->device_fd   [ i ] = vf->vfio.device_fd;
    }
    if( FD_UNLIKELY( munmap( (void *)vf->vfio.bar0, FD_IAVF_BAR0_MAP_SZ ) ) ) {
      FD_LOG_ERR(( "VF BAR unmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    vf->vfio.bar0     = NULL;
    vf->queue.tx_tail = NULL;
    vf->queue.rx_tail = NULL;
  }
  ctx->prepared = 1U;
}
#endif

FD_FN_UNUSED static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( !ctx->prepared ) {
#ifndef FD_TILE_TEST
    fd_topo_install_iavf( (fd_topo_t *)topo, NULL );
#endif
  }
  (void)fd_iavf_hw_join_queues( ctx, tile );
  fd_iavf_tile_packet_memory( topo, tile, ctx, NULL, NULL );
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    if( FD_UNLIKELY( fd_iavf_vfio_map_bar( &vf->vfio ) ) ) FD_LOG_ERR(( "VF BAR mapping failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    vf->queue.tx_tail = (volatile uint *)(vf->vfio.bar0 + FD_IAVF_TX_TAIL( 0U ));
    vf->queue.rx_tail = (volatile uint *)(vf->vfio.bar0 + FD_IAVF_RX_TAIL( 0U ));
    vf->if_idx        = if_nametoindex( tile->iavf.members[i] );
    if( FD_UNLIKELY( !vf->if_idx ) ) FD_LOG_ERR(( "PF interface lookup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->router.if_virt = if_nametoindex( tile->iavf.if_name );
  if( FD_UNLIKELY( !ctx->router.if_virt ) ) FD_LOG_ERR(( "interface lookup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ctx->router.default_address = fd_iavf_tile_if_ip4_addr( tile->iavf.if_name );
  ctx->lo_tx_sock             = tile->kind_id ? -1 : fd_iavf_tile_lo_tx_socket();
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_iavf_tile_t * ctx          = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  void *           after_queues = fd_iavf_hw_join_queues( ctx, tile );
  FD_SCRATCH_ALLOC_INIT( scratch, after_queues );
  ctx->batch_size             = FD_IAVF_BATCH_SIZE;
  ctx->tx_flush_timeout_ticks = (long)(FD_IAVF_TX_FLUSH_TIMEOUT_NS*fd_tempo_tick_per_ns( NULL ));
  ctx->lo_tx_timeout_ticks    = (long)(FD_IAVF_LO_TX_TIMEOUT_NS*fd_tempo_tick_per_ns( NULL ));
  ctx->lo_tx_cnt              = 0U;
  ctx->net.kind_id            = tile->kind_id;
  ctx->net.tile_cnt           = fd_topo_tile_name_cnt( topo, tile->name );

  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( scratch, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX )               );
  void * fib_local_mem    = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(),       fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  void * fib_main_mem     = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(),       fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );

  /* chunk 0 is used as a sentinel value, so ensure actual chunk indices
     do not use that value. */
  FD_TEST( ctx->net.pkt_buf_chunk0>0UL );

  /* Init TX */
  if( FD_UNLIKELY( tile->in_cnt>FD_NET_IN_MAX ) ) {
    FD_LOG_ERR(( "iavf tile in link count %lu exceeds max of %lu", tile->in_cnt, FD_NET_IN_MAX ));
  }
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "iproute_out" ) ) {
      ctx->net.in_kind[ i ] = FD_NET_IN_KIND_IPROUTE;
    } else {
      ctx->net.in_kind[ i ] = FD_NET_IN_KIND_TX;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "iavf tile in link does not have a normal MTU" ));
    }

    ctx->net.in_dcache_ctx[ i ].wksp_base = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->net.in_dcache_ctx[ i ].chunk0    = fd_dcache_compact_chunk0( ctx->net.in_dcache_ctx[ i ].wksp_base, link->dcache );
    ctx->net.in_dcache_ctx[ i ].wmark     = fd_dcache_compact_wmark(  ctx->net.in_dcache_ctx[ i ].wksp_base, link->dcache, link->mtu );
  }

  /* Join netbase objects */
  FD_TEST( fd_fib4_join( ctx->router.fib_local, fd_fib4_new( fib_local_mem, tile->iavf.route_max, tile->iavf.route_peer_max, tile->iavf.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->router.fib_main,  fd_fib4_new( fib_main_mem,  tile->iavf.route_max, tile->iavf.route_peer_max, tile->iavf.route_peer_seed ) ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_shared, fd_topo_obj_laddr( topo, tile->iavf.netdev_tbl_obj_id ) )                                        );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX )                                                                               );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_tbl, netdev_tbl_local )                                                                                  );

  fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
  fd_net_gre_tunnels_refresh( &ctx->net, &ctx->router.netdev_tbl );
  ctx->router.bind_address = tile->iavf.net.bind_address;
  ctx->net.bind_address    = tile->iavf.net.bind_address;

  ulong neigh4_obj_id = tile->iavf.neigh4_obj_id;
  ulong ele_max       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max     = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed          = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) ) {
    FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  }
  if( FD_UNLIKELY( !fd_neigh4_hmap_join( ctx->router.neigh4, fd_topo_obj_laddr( topo, neigh4_obj_id ), ele_max, probe_max, seed ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  ctx->router.netlnk_out_idx = fd_topo_find_tile_out_link( topo, tile, "net_netlnk", tile->kind_id );
  if( FD_UNLIKELY( ctx->router.netlnk_out_idx==ULONG_MAX ) ) FD_LOG_ERR(( "netlink request link not found" ));
  ctx->router.solicit_ip = 0U;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( scratch, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)ctx+scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow" ));
  }
}

FD_FN_UNUSED static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_iavf_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->lo_tx_sock );
  return sock_filter_policy_fd_iavf_tile_instr_cnt;
}

FD_FN_UNUSED static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<4UL+3UL*ctx->vf_cnt ) ) FD_LOG_ERR(( "allowed FD array is too small" ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( fd_log_private_logfile_fd()!=-1 ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    out_fds[ out_cnt++ ] = ctx->vfs[i].vfio.container_fd;
    out_fds[ out_cnt++ ] = ctx->vfs[i].vfio.group_fd;
    out_fds[ out_cnt++ ] = ctx->vfs[i].vfio.device_fd;
  }
  if( ctx->lo_tx_sock>=0 ) out_fds[ out_cnt++ ] = ctx->lo_tx_sock;
  return out_cnt;
}

static inline long
next_deadline( fd_iavf_tile_t * ctx ) {
  long deadline = fd_tickcount() + ctx->tx_flush_timeout_ticks;
  if( ctx->lo_tx_cnt ) deadline = fd_long_min( deadline, ctx->lo_tx_deadline_ticks );
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t const * vf = &ctx->vfs[i];
    if( vf->queue.tx_prod!=vf->queue.tx_posted ) deadline = fd_long_min( deadline, vf->tx_flush_deadline_ticks );
  }
  return deadline;
}

#define STEM_CALLBACK_CONTEXT_TYPE        fd_iavf_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_iavf_tile_t)
#define STEM_CALLBACK_BEFORE_CREDIT        before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG          before_frag
#define STEM_CALLBACK_DURING_FRAG          during_frag
#define STEM_CALLBACK_AFTER_FRAG           after_frag
#define STEM_CALLBACK_METRICS_WRITE        metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING  during_housekeeping
#define STEM_CALLBACK_NEXT_DEADLINE        next_deadline
#define STEM_BURST (FD_IAVF_MEMBER_MAX*FD_IAVF_BATCH_SIZE+1UL)
#define STEM_LAZY                         270000UL
#include "../../stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_iavf = {
  .name                     = "iavf",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
