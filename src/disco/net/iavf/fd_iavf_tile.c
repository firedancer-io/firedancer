#define _GNU_SOURCE
/* The iavf tile translates Ethernet frames between Intel VF descriptor
   rings and fd_tango traffic. Each tile owns one RX/TX pair per VF, with
   completions written into the descriptor rings themselves.

   Separate Admin Queues carry configuration requests to the PF driver.
   Tile 0 consumes PF events for all tiles. */

#include "../fd_net_tile.h"
#include "../fd_net_tile_private.h"
#include "fd_iavf_private.h"
#include "../fd_net_router.h"
#include "../../topo/fd_topo.h"

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <linux/if_bonding.h>

#include "../../../util/pod/fd_pod_format.h"
#include "generated/fd_iavf_tile_seccomp.h"

#define FD_IAVF_TX_FLUSH_TIMEOUT_NS (20000L)
#define FD_IAVF_LO_TX_TIMEOUT_NS    (500000L)

#define FD_IAVF_TX_DESC_TYPE_MASK         (0xfUL)    /* IAVF_TXD_QW1_DTYPE_MASK */
#define FD_IAVF_TX_DESC_DONE              (0xfUL)    /* IAVF_TX_DESC_DTYPE_DESC_DONE */
#define FD_IAVF_TX_DESC_CMD_SHIFT         (4)        /* IAVF_TXD_QW1_CMD_SHIFT */
#define FD_IAVF_TX_DESC_CMD_EOP           (1UL)      /* IAVF_TX_DESC_CMD_EOP */
#define FD_IAVF_TX_DESC_CMD_REPORT_STATUS (2UL)      /* IAVF_TX_DESC_CMD_RS */
#define FD_IAVF_TX_DESC_CMD_ICRC          (4UL)      /* IAVF_TX_DESC_CMD_ICRC */
#define FD_IAVF_TX_DESC_BUFFER_SHIFT      (34)       /* IAVF_TXD_QW1_TX_BUF_SZ_SHIFT */
#define FD_IAVF_TX_DESC_BUFFER_MAX        (0x3fffUL) /* IAVF_TXD_QW1_TX_BUF_SZ_MASK >> 34 */

#define FD_IAVF_RX_DESC_DONE              (1UL<<0)   /* IAVF_RXD_LEGACY_DD_M */
#define FD_IAVF_RX_DESC_END_OF_PACKET     (1UL<<1)   /* IAVF_RXD_LEGACY_EOP_M */
#define FD_IAVF_RX_DESC_MAC_ERR           (1UL<<19)  /* IAVF_RXD_LEGACY_RXE_M */
#define FD_IAVF_RX_DESC_LENGTH_SHIFT      (38)       /* Low bit of IAVF_RXD_LEGACY_LENGTH_M */
#define FD_IAVF_RX_DESC_LENGTH_MASK       (0x3fffUL) /* IAVF_RXD_LEGACY_LENGTH_M >> 38 */

FD_STATIC_ASSERT( FD_NET_MTU<=FD_IAVF_TX_DESC_BUFFER_MAX, iavf_tx_frame_sz );

struct fd_iavf_tile_rx_comp {
  uint  chunk;
  uint  discard;
  uint  end_of_packet;
  ulong frame_sz;
};
typedef struct fd_iavf_tile_rx_comp fd_iavf_tile_rx_comp_t;

/* fd_iavf_tile_vf is private tile state for a single VF */
struct fd_iavf_tile_vf {
  fd_iavf_vfio_t    vfio;
  fd_iavf_adminq_t  adminq;
  fd_iavf_vf_info_t vf_info;
  fd_iavf_queue_t   rx_queue;
  fd_iavf_queue_t   tx_queue;
  void *            queue_memory;
  uint *            rx_desc_buf_chunk;
  uint *            tx_desc_buf_chunk;
  /* A Report Status completion can cover several frames. Keep each frame's
     length to count the bytes in a completed batch. */
  ushort *          tx_desc_frame_sz;
  uint              rx_pending_chunk[ FD_IAVF_BATCH_SIZE ];
  uint              rx_pending_cnt;
  uint              if_idx;
  long              tx_flush_deadline_ticks;
};
typedef struct fd_iavf_tile_vf fd_iavf_tile_vf_t;

/* fd_iavf_tile is private tile state */
struct __attribute__((aligned(64UL))) fd_iavf_tile {
  fd_iavf_tile_vf_t     vfs[ FD_IAVF_MEMBER_MAX ];
  ulong                 vf_cnt;
  ulong                 tx_vf_idx;
  ulong                 rx_next_vf;
  /* vf_link_usable shares tile 0's PF link decision with the other tiles. */
  ulong                 vf_link_usable[ FD_IAVF_MEMBER_MAX ];
  ulong const *         vf_link_usable_shared;
  uint                  prepared;
  uint                  batch_size;
  long                  tx_flush_timeout_ticks;
  long                  lo_tx_timeout_ticks;
  long                  lo_tx_deadline_ticks;
  int                   lo_tx_sock;
  uint                  lo_tx_cnt;
  fd_net_tile_t         net;
  fd_net_router_t       router;
  ulong                 netdev_seq;

  struct mmsghdr     lo_tx_msg [ FD_IAVF_BATCH_SIZE ];
  struct iovec       lo_tx_iov [ FD_IAVF_BATCH_SIZE ];
  struct sockaddr_in lo_tx_addr[ FD_IAVF_BATCH_SIZE ];
  uchar              lo_tx_buf [ FD_IAVF_BATCH_SIZE ][ FD_NET_MTU ];

  struct {
    ulong tx_no_buffer_cnt;
    ulong tx_no_link_cnt;
    ulong tx_loopback_fail_cnt;
    ulong rx_no_link_cnt;
  } metrics;
};
typedef struct fd_iavf_tile fd_iavf_tile_t;

static void *
fd_iavf_hw_join_queues( fd_iavf_tile_t *       ctx,
                        fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( scratch, ctx );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  ulong const queue_sz   = fd_iavf_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size );
  ulong const tx_ring_sz = fd_ulong_align_up( tile->iavf.tx_queue_size*sizeof(fd_iavf_tx_desc_t), FD_IAVF_PAGE_SZ );
  ulong const rx_ring_sz = fd_ulong_align_up( tile->iavf.rx_queue_size*sizeof(fd_iavf_hw_rx_desc_t), FD_IAVF_PAGE_SZ );

  for( ulong vf_idx=0UL; vf_idx<tile->iavf.member_cnt; vf_idx++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[vf_idx];
    /* Only tile 0 needs Admin Queue memory */
    vf->adminq.dma_memory = NULL;
    if( !tile->kind_id ) {
      vf->adminq.dma_memory = FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint() );
    }

    vf->queue_memory       = FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, queue_sz );
    vf->tx_queue.ring      = vf->queue_memory;
    vf->rx_queue.ring      = (uchar *)vf->queue_memory + tx_ring_sz;
    vf->tx_queue.depth     = tile->iavf.tx_queue_size;
    vf->rx_queue.depth     = tile->iavf.rx_queue_size;
    vf->tx_queue.comp_ring = (ulong *)((uchar *)vf->queue_memory + tx_ring_sz + rx_ring_sz);

    vf->rx_desc_buf_chunk = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint),   tile->iavf.rx_queue_size*sizeof(uint)   );
    vf->tx_desc_buf_chunk = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint),   tile->iavf.tx_queue_size*sizeof(uint)   );
    vf->tx_desc_frame_sz  = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );
  }
  return (void *)FD_SCRATCH_ALLOC_FINI( scratch, 1UL );
}

static int
fd_iavf_hw_map_regs( fd_iavf_tile_vf_t * vf,
                     ulong               queue_id ) {
  if( FD_UNLIKELY( fd_iavf_vfio_map_bar( &vf->vfio ) ) ) return -1;
  vf->tx_queue.tail = (volatile uint *)(vf->vfio.bar0 + FD_IAVF_TX_TAIL( queue_id ));
  vf->rx_queue.tail = (volatile uint *)(vf->vfio.bar0 + FD_IAVF_RX_TAIL( queue_id ));
  return 0;
}

static int
fd_iavf_hw_rx_enqueue( fd_iavf_tile_vf_t * vf,
                       uint                recv_cnt ) {
  fd_iavf_queue_t * rx_queue    = &vf->rx_queue;
  ulong const       outstanding = rx_queue->prod-rx_queue->cons;

  if( FD_UNLIKELY( outstanding>=rx_queue->depth || recv_cnt>=rx_queue->depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }

  for( uint i=0U; i<recv_cnt; i++ ) {
    uint const            chunk    = vf->rx_pending_chunk[i];
    uint const            desc_idx = (uint)((rx_queue->prod+i) & (rx_queue->depth-1U));
    fd_iavf_hw_rx_desc_t * desc     = (fd_iavf_hw_rx_desc_t *)rx_queue->ring + desc_idx;

    desc->qword[0] = (ulong)chunk<<FD_CHUNK_LG_SZ;
    desc->qword[1] = 0UL;
    desc->qword[2] = 0UL;
    desc->qword[3] = 0UL;

    vf->rx_desc_buf_chunk[ desc_idx ] = chunk;
  }
  rx_queue->prod += recv_cnt;

  fd_iavf_hw_dma_to_device();
  *rx_queue->tail = (uint)(rx_queue->prod & (rx_queue->depth-1U));
  FD_COMPILER_MFENCE();
  rx_queue->posted = rx_queue->prod;
  return 0;
}

static void
fd_iavf_hw_tx_enqueue( fd_iavf_tile_vf_t * vf,
                       ulong               frame_sz ) {
  fd_iavf_queue_t * tx_queue = &vf->tx_queue;

  FD_TEST( tx_queue->prod-tx_queue->cons<tx_queue->depth-1UL );

  uint const desc_idx     = (uint)(tx_queue->prod & (tx_queue->depth-1U));
  uint const chunk        = vf->tx_desc_buf_chunk[desc_idx];
  ulong const frame_iova  = (ulong)chunk<<FD_CHUNK_LG_SZ;
  fd_iavf_tx_desc_t * desc = (fd_iavf_tx_desc_t *)tx_queue->ring + desc_idx;
  desc->buffer_iova        = frame_iova;
  desc->cmd_type_offset_buffer_sz =
      ((FD_IAVF_TX_DESC_CMD_EOP | FD_IAVF_TX_DESC_CMD_ICRC)<<FD_IAVF_TX_DESC_CMD_SHIFT) |
      (frame_sz<<FD_IAVF_TX_DESC_BUFFER_SHIFT);
  vf->tx_desc_frame_sz[desc_idx] = (ushort)frame_sz;
  tx_queue->prod++;
}

static void
fd_iavf_hw_tx_flush( fd_iavf_queue_t * tx_queue ) {
  if( FD_UNLIKELY( tx_queue->posted==tx_queue->prod ) ) return;

  ulong const         tx_end   = tx_queue->prod;
  uint const          desc_idx = (uint)((tx_end-1UL) & (tx_queue->depth-1U));
  fd_iavf_tx_desc_t * desc     = (fd_iavf_tx_desc_t *)tx_queue->ring + desc_idx;
  /* Request completion on the batch's last descriptor */
  desc->cmd_type_offset_buffer_sz |= FD_IAVF_TX_DESC_CMD_REPORT_STATUS<<FD_IAVF_TX_DESC_CMD_SHIFT;
  tx_queue->comp_ring[ tx_queue->comp_prod & (tx_queue->depth-1U) ] = tx_end;
  tx_queue->comp_prod++;

  fd_iavf_hw_dma_to_device();
  *tx_queue->tail = (uint)(tx_end & (tx_queue->depth-1U));
  FD_COMPILER_MFENCE();
  tx_queue->posted = tx_end;
}

static ulong
fd_iavf_hw_poll_tx( fd_iavf_tile_vf_t * vf,
                    ulong *             comp_bytes ) {
  fd_iavf_queue_t * tx_queue = &vf->tx_queue;
  *comp_bytes = 0UL;
  ulong const comp_cons = tx_queue->comp_cons;
  if( comp_cons==tx_queue->comp_prod ) return 0UL;

  ulong const         tx_end   = tx_queue->comp_ring[ comp_cons & (tx_queue->depth-1U) ];
  uint const          desc_idx = (uint)((tx_end-1UL) & (tx_queue->depth-1U));
  fd_iavf_tx_desc_t * desc     = (fd_iavf_tx_desc_t *)tx_queue->ring + desc_idx;
  ulong const         cmd      = FD_VOLATILE_CONST( desc->cmd_type_offset_buffer_sz );
  if( FD_LIKELY( (cmd & FD_IAVF_TX_DESC_TYPE_MASK)!=FD_IAVF_TX_DESC_DONE ) ) return 0UL;
  FD_COMPILER_MFENCE();

  ulong const tx_cons  = tx_queue->cons;
  ulong const comp_cnt = tx_end-tx_cons;
  for( ulong i=tx_cons; i<tx_end; i++ ) {
    *comp_bytes += vf->tx_desc_frame_sz[ i & (tx_queue->depth-1U) ];
  }
  tx_queue->cons      = tx_end;
  tx_queue->comp_cons = comp_cons+1UL;
  return comp_cnt;
}

static int
fd_iavf_hw_poll_rx( fd_iavf_tile_vf_t *      vf,
                    fd_iavf_tile_rx_comp_t * comp,
                    uint                     comp_capacity ) {
  fd_iavf_queue_t * rx_queue = &vf->rx_queue;
  ulong      rx_cons    = rx_queue->cons;
  uint const comp_limit = fd_uint_min( comp_capacity, rx_queue->depth );
  uint       comp_cnt   = 0U;
  while( comp_cnt<comp_limit && rx_cons<rx_queue->posted ) {
    uint const             desc_idx = (uint)(rx_cons & (rx_queue->depth-1U));
    fd_iavf_hw_rx_desc_t * desc     = (fd_iavf_hw_rx_desc_t *)rx_queue->ring + desc_idx;
    ulong const            status   = FD_VOLATILE_CONST( desc->qword[1] );
    if( !(status & FD_IAVF_RX_DESC_DONE) ) break;

    /* Drop frames that do not fit in one RX buffer. */
    uint const end_of_packet = (uint)(0!=(status & FD_IAVF_RX_DESC_END_OF_PACKET));
    uint const discard       = rx_queue->discard || !end_of_packet || (0!=(status & FD_IAVF_RX_DESC_MAC_ERR));
    rx_queue->discard        = !end_of_packet;
    comp[ comp_cnt++ ] = (fd_iavf_tile_rx_comp_t) {
      .chunk         = vf->rx_desc_buf_chunk[ desc_idx ],
      .discard       = discard,
      .end_of_packet = end_of_packet,
      .frame_sz      = (status>>FD_IAVF_RX_DESC_LENGTH_SHIFT) & FD_IAVF_RX_DESC_LENGTH_MASK
    };
    rx_cons++;
  }
  if( comp_cnt ) {
    fd_iavf_hw_dma_from_device();
    rx_queue->cons = rx_cons;
  }
  return (int)comp_cnt;
}

/* fd_iavf_tile_tx_chunk returns the buffer paired with TX descriptor tx_idx.
   The buffer is reusable once tx_queue.cons advances past that descriptor. */
static inline ulong
fd_iavf_tile_tx_chunk( fd_iavf_tile_t const * ctx,
                       ulong                  tx_idx ) {
  fd_iavf_tile_vf_t const * vf = &ctx->vfs[ ctx->tx_vf_idx ];
  return vf->tx_desc_buf_chunk[ tx_idx & (vf->tx_queue.depth-1U) ];
}

static inline void
fd_iavf_tile_rx_recycle( fd_iavf_tile_t *    ctx,
                         fd_iavf_tile_vf_t * vf,
                         ulong               chunk ) {
  vf->rx_pending_chunk[ vf->rx_pending_cnt++ ] = (uint)chunk;
  /* Hold partial recycle batches, at most batch_size-1 RX buffers stay
     unposted, avoiding a device-ordering barrier and RX tail write per packet. */
  if( vf->rx_pending_cnt==ctx->batch_size ) {
    FD_TEST( !fd_iavf_hw_rx_enqueue( vf, vf->rx_pending_cnt ) );
    vf->rx_pending_cnt = 0U;
  }
}

static inline int
fd_iavf_tile_vf_usable( fd_iavf_tile_t *          ctx,
                        fd_iavf_tile_vf_t const * vf,
                        uchar                     actor_state ) {
  if( !vf->vf_info.link_usable ) return 0;

  fd_netdev_t const * interface = fd_netdev_tbl_query( &ctx->router.netdev_tbl, ctx->router.if_virt );
  fd_netdev_t const * pf        = fd_netdev_tbl_query( &ctx->router.netdev_tbl, vf->if_idx );
  if( !interface || !pf ) return 0;
  if( interface->oper_status!=FD_OPER_STATUS_UP || pf->oper_status!=FD_OPER_STATUS_UP ) return 0;
  if( vf->if_idx==ctx->router.if_virt ) return 1;

  /* An up VF must still follow its PF's LACP state */
  return interface->bond_mode==BOND_MODE_8023AD && interface->bond_aggregator_id &&
         pf->master_idx==(int)ctx->router.if_virt &&
         pf->bond_aggregator_id==interface->bond_aggregator_id &&
         (0!=(pf->bond_actor_state & actor_state));
}

static ulong
fd_iavf_tile_select_tx_vf( fd_iavf_tile_t * ctx,
                           ulong            hash ) {
  ulong available[ FD_IAVF_MEMBER_MAX ];
  ulong available_cnt = 0UL;
  for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
    if( fd_iavf_tile_vf_usable( ctx, &ctx->vfs[vf_idx], LACP_STATE_DISTRIBUTING ) ) {
      available[ available_cnt++ ] = vf_idx;
    }
  }
  return available_cnt ? available[ hash%available_cnt ] : ULONG_MAX;
}

static inline int
fd_iavf_tile_poll_rx( fd_iavf_tile_t *    ctx,
                      fd_stem_context_t * stem ) {
  int busy                 = 0;
  ulong const start_vf_idx  = ctx->rx_next_vf;
  ctx->rx_next_vf           = (start_vf_idx+1UL)%ctx->vf_cnt;
  for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
    ulong const         actual_vf_idx = (start_vf_idx+vf_idx)%ctx->vf_cnt;
    fd_iavf_tile_vf_t * vf            = &ctx->vfs[ actual_vf_idx ];

    fd_iavf_tile_rx_comp_t comp[ FD_IAVF_BATCH_SIZE ];
    int comp_cnt = fd_iavf_hw_poll_rx( vf, comp, ctx->batch_size );
    if( !comp_cnt ) continue;
    busy = 1;

    int   active = fd_iavf_tile_vf_usable( ctx, vf, LACP_STATE_COLLECTING );
    ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

    for( uint i=0U; i<(uint)comp_cnt; i++ ) {
      ulong chunk = comp[i].chunk;
      if( FD_UNLIKELY( chunk<ctx->net.pkt_buf_chunk0 || chunk>ctx->net.pkt_buf_wmark ) ) {
        FD_LOG_CRIT(( "VF %lu RX completion chunk %lu out of bounds [%lu,%lu]",
                      actual_vf_idx, chunk, ctx->net.pkt_buf_chunk0, ctx->net.pkt_buf_wmark ));
      }
      ulong freed_chunk = chunk;
      if( FD_UNLIKELY( !active ) ) ctx->metrics.rx_no_link_cnt += comp[i].end_of_packet;
      else if( FD_UNLIKELY( comp[i].discard ) ) ctx->net.metrics.rx_malformed_cnt += comp[i].end_of_packet;
      else fd_net_rx_pkt( &ctx->net, stem, chunk, 0UL, comp[i].frame_sz, tspub, &freed_chunk );
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
  ctx->net.metrics.tx_pkt_cnt     += comp_cnt;
  ctx->net.metrics.tx_bytes_total += comp_bytes;
  return !!comp_cnt;
}

/* fd_iavf_tile_lo_tx_flush drops unsent packets so socket backpressure
   cannot stall RX or VF TX. */
static void
fd_iavf_tile_lo_tx_flush( fd_iavf_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->lo_tx_cnt ) ) return;
  int const  send_cnt = sendmmsg( ctx->lo_tx_sock, ctx->lo_tx_msg, ctx->lo_tx_cnt, MSG_DONTWAIT );
  uint const sent_cnt = send_cnt<0 ? 0U : (uint)send_cnt;
  for( uint i=0U; i<sent_cnt; i++ ) ctx->net.metrics.tx_bytes_total += sizeof(fd_eth_hdr_t)+ctx->lo_tx_iov[ i ].iov_len;
  ctx->net.metrics.tx_pkt_cnt += sent_cnt;
  ctx->metrics.tx_loopback_fail_cnt += ctx->lo_tx_cnt-sent_cnt;
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
  sa->sin_port        = 0; /* Linux raw sockets ignore sin_port */

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
    fd_iavf_tile_vf_t * vf       = &ctx->vfs[i];
    fd_iavf_queue_t *   tx_queue = &vf->tx_queue;
    if( tx_queue->prod!=tx_queue->posted && now>=vf->tx_flush_deadline_ticks ) {
      fd_iavf_hw_tx_flush( tx_queue );
      *charge_busy = 1;
    }
    if( tx_queue->cons!=tx_queue->posted ) *charge_busy |= fd_iavf_tile_poll_tx( ctx, vf );
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

/* before_frag resolves the TX route and checks for space in the TX descriptor ring. */
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

  uint const dst_ip = fd_disco_netmux_sig_ip( sig );
  if( kind_id!=target_idx ) {
    /* Tile 0 probes for loopback without counting another tile's route failures. */
    fd_fib4_hop_t hop[2];
    hop[0] = fd_fib4_lookup( ctx->router.fib_local, dst_ip, 0UL );
    hop[1] = fd_fib4_lookup( ctx->router.fib_main,  dst_ip, 0UL );
    fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );
    if( next_hop->rtype!=FD_FIB4_RTYPE_LOCAL && next_hop->rtype!=FD_FIB4_RTYPE_UNICAST ) return 1;
    uint const if_idx = next_hop->rtype==FD_FIB4_RTYPE_LOCAL ? 1U : next_hop->if_idx;
    fd_netdev_t const * netdev = fd_netdev_tbl_query( &ctx->router.netdev_tbl, if_idx );
    if( !netdev || netdev->dev_type!=ARPHRD_LOOPBACK ) return 1;
  }

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

  ctx->tx_vf_idx = route->use_loopback ? 0UL : fd_iavf_tile_select_tx_vf( ctx, hash );
  if( FD_UNLIKELY( ctx->tx_vf_idx==ULONG_MAX ) ) {
    ctx->metrics.tx_no_link_cnt++;
    return 1;
  }
  fd_iavf_queue_t const * tx_queue = &ctx->vfs[ ctx->tx_vf_idx ].tx_queue;
  if( FD_UNLIKELY( !route->use_loopback && tx_queue->prod-tx_queue->cons>=tx_queue->depth-1UL ) ) {
    ctx->metrics.tx_no_buffer_cnt++;
    return 1;
  }

  return 0;
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

  ulong   dst_chunk = fd_iavf_tile_tx_chunk( ctx, ctx->vfs[ ctx->tx_vf_idx ].tx_queue.prod );
  uchar * dst       = fd_chunk_to_laddr( ctx->net.pkt_buf_wksp_base, dst_chunk );
  /* Speculatively copy frame from in link into buffer */
  fd_net_tx_pkt_cpy( &ctx->net, dst, chunk, frame_sz, in_idx );
}

/* after_frag enqueues the staged frame or applies the route update only
   after stem checks that the input was not overwritten during the copy. */
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

  ulong               chunk    = fd_iavf_tile_tx_chunk( ctx, ctx->vfs[ ctx->tx_vf_idx ].tx_queue.prod );
  uchar *             frame    = fd_chunk_to_laddr( ctx->net.pkt_buf_wksp_base, chunk );
  fd_iavf_tile_vf_t * vf       = &ctx->vfs[ ctx->tx_vf_idx ];
  fd_iavf_queue_t *   tx_queue = &vf->tx_queue;

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

    int owns_udp_dst = 0;
    if( !ctx->router.bind_address || ctx->router.bind_address==ip4->daddr ) {
      ushort const dst_port = fd_ushort_bswap( udp->net_dport );
      for( ulong i=0UL; i<ctx->net.dst_port_cnt; i++ ) owns_udp_dst |= ctx->net.dst_ports[ i ]==dst_port;
    }
    if( !owns_udp_dst ) {
      fd_iavf_tile_lo_tx_enqueue( ctx, ip4, ip_sz );
      return;
    }

    ulong freed_chunk;
    if( fd_net_rx_pkt( &ctx->net, stem, chunk, 0UL, frame_sz, (ulong)fd_frag_meta_ts_comp( fd_tickcount() ), &freed_chunk ) ) {
      vf->tx_desc_buf_chunk[ tx_queue->prod & (tx_queue->depth-1U) ] = (uint)freed_chunk;
    }
    ctx->net.metrics.tx_pkt_cnt++;
    ctx->net.metrics.tx_bytes_total += frame_sz;
    return;
  }

  fd_iavf_hw_tx_enqueue( vf, frame_sz );
  ctx->net.metrics.tx_gre_cnt += (ulong)ctx->net.tx_route.use_gre;
  ulong const pending_desc_cnt = tx_queue->prod-tx_queue->posted;
  if( pending_desc_cnt>=ctx->batch_size || tx_queue->prod-tx_queue->cons>=tx_queue->depth-1UL ) {
    fd_iavf_hw_tx_flush( tx_queue );
  } else if( pending_desc_cnt==1UL ) {
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
    fd_iavf_queue_t const * rx_queue = &ctx->vfs[i].rx_queue;
    fd_iavf_queue_t const * tx_queue = &ctx->vfs[i].tx_queue;
    ulong const             tx_capacity = tx_queue->depth-1UL;
    ulong                   rx_idle = fd_ulong_min( rx_queue->prod-rx_queue->cons, rx_queue->depth );
    ulong                   tx_busy = fd_ulong_min( tx_queue->prod-tx_queue->cons, tx_capacity );
    rx_buffer_idle_cnt += rx_idle;
    rx_buffer_busy_cnt += rx_queue->depth-rx_idle;
    tx_buffer_busy_cnt += tx_busy;
    tx_buffer_idle_cnt += tx_capacity-tx_busy;
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
  FD_MCNT_SET(   IAVF, PKT_TX_LOOPBACK_FAILED, ctx->metrics.tx_loopback_fail_cnt      );
  FD_MCNT_ENUM_COPY( IAVF, PKT_TX_ROUTE_FAIL, ctx->net.metrics.tx_route_fail_cnt     );
  FD_MCNT_SET(   IAVF, PKT_TX_INVALID,        ctx->net.metrics.tx_invalid_cnt        );
  FD_MCNT_SET(   IAVF, PKT_TX_NO_NEIGHBOR,    ctx->router.metrics.tx_neigh_fail_cnt  );
  FD_MCNT_SET(   IAVF, GRE_PKT_TX_SUBMITTED,  ctx->net.metrics.tx_gre_cnt            );
  FD_MCNT_SET(   IAVF, GRE_PKT_TX_NO_ROUTE,   ctx->net.metrics.tx_gre_route_fail_cnt );
  FD_MGAUGE_SET( IAVF, TX_BUFFER_BUSY,        tx_buffer_busy_cnt                     );
  FD_MGAUGE_SET( IAVF, TX_BUFFER_IDLE,        tx_buffer_idle_cnt                     );
}

static inline void
fd_iavf_tile_publish_vf_link( fd_iavf_tile_t * ctx,
                              ulong            vf_idx ) {
  ulong const usable = (ulong)ctx->vfs[vf_idx].vf_info.link_usable;
  __atomic_store_n( &ctx->vf_link_usable[vf_idx], usable, __ATOMIC_RELEASE );
}

static inline void
fd_iavf_tile_refresh_vf_links( fd_iavf_tile_t * ctx ) {
  /* Other tiles read tile 0's link decisions */
  if( ctx->net.kind_id ) {
    for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
      ctx->vfs[vf_idx].vf_info.link_usable = (int)__atomic_load_n( &ctx->vf_link_usable_shared[vf_idx], __ATOMIC_ACQUIRE );
    }
    return;
  }

  /* Only tile 0 consumes PF events */
  for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[vf_idx];
    int changed;
    if( FD_UNLIKELY( fd_iavf_virtchnl_poll_link( &vf->vfio, &vf->adminq, &vf->vf_info, &changed ) ) ) {
      FD_LOG_ERR(( "PF member %lu VF link event or reset failure (%i-%s)", vf_idx, errno, fd_io_strerror( errno ) ));
    }
    if( changed ) {
      fd_iavf_tile_publish_vf_link( ctx, vf_idx );
      FD_LOG_INFO(( "PF member %lu VF link %s", vf_idx, vf->vf_info.link_usable ? "up" : "down" ));
    }
  }
}

static inline void
during_housekeeping( fd_iavf_tile_t * ctx ) {
  fd_iavf_tile_refresh_vf_links( ctx );

  if( FD_UNLIKELY( fd_netdev_tbl_refresh( &ctx->router.netdev_tbl, &ctx->router.netdev_shared, &ctx->netdev_seq ) ) ) {
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
  if( FD_UNLIKELY( !queue_sz ) ) return 0UL;
  ulong layout = FD_LAYOUT_INIT;
  layout       = FD_LAYOUT_APPEND( layout, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  for( ulong i=0UL; i<tile->iavf.member_cnt; i++ ) {
    if( !tile->kind_id ) layout = FD_LAYOUT_APPEND( layout, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint() );
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
    if( !tile->kind_id ) (void)FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint() );
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

/* fd_iavf_tile_join_pkt_bufs uses workspace offsets for packet IOVAs so
   descriptors can address buffers directly as chunk<<FD_CHUNK_LG_SZ. */
static void
fd_iavf_tile_join_pkt_bufs( fd_topo_t const *      topo,
                            fd_topo_tile_t const * tile,
                            fd_iavf_tile_t *       ctx,
                            void **                packet_memory,
                            ulong *                packet_memory_sz,
                            ulong *                packet_iova ) {
  void * const packet_dcache_memory = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const packet_dcache        = fd_dcache_join( packet_dcache_memory );
  FD_TEST( packet_dcache );
  ulong const packet_dcache_data_sz = fd_dcache_data_sz( packet_dcache );
  ulong const frame_sz              = FD_NET_MTU;
  ulong const frame_region_sz       = fd_ulong_align_dn( packet_dcache_data_sz, frame_sz );
  FD_TEST( frame_region_sz>=frame_sz && frame_region_sz<=ULONG_MAX-FD_IAVF_PAGE_SZ &&
           (ulong)packet_dcache<=ULONG_MAX-frame_region_sz-FD_IAVF_PAGE_SZ );

  void * const workspace_base = fd_wksp_containing( packet_dcache_memory );
  FD_TEST( workspace_base );
  ulong const pkt_buf_chunk0 = ((ulong)packet_dcache-(ulong)workspace_base)>>FD_CHUNK_LG_SZ;
  ulong const pkt_buf_wmark  = pkt_buf_chunk0 + ((frame_region_sz-frame_sz)>>FD_CHUNK_LG_SZ);
  if( FD_UNLIKELY( !pkt_buf_chunk0 || pkt_buf_chunk0>UINT_MAX || pkt_buf_wmark>UINT_MAX || pkt_buf_chunk0>pkt_buf_wmark ) ) {
    FD_LOG_ERR(( "Calculated invalid packet buffer bounds [%lu,%lu]", pkt_buf_chunk0, pkt_buf_wmark ));
  }

  ctx->net.pkt_buf_wksp_base = workspace_base;
  ctx->net.pkt_buf_chunk0    = pkt_buf_chunk0;
  ctx->net.pkt_buf_wmark     = pkt_buf_wmark;
  if( packet_memory    ) *packet_memory    = packet_dcache;
  /* VFIO_IOMMU_MAP_DMA requires whole pages. */
  if( packet_memory_sz ) *packet_memory_sz = fd_ulong_align_up( frame_region_sz, FD_IAVF_PAGE_SZ );
  if( packet_iova      ) *packet_iova      = (ulong)packet_dcache-(ulong)workspace_base;
}

FD_FN_UNUSED static void
fd_iavf_tile_init_pkt_bufs( fd_topo_t const *      topo,
                            fd_topo_tile_t const * tile,
                            fd_iavf_tile_t *       ctx ) {
  ulong frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong next_chunk   = ctx->net.pkt_buf_chunk0;
  FD_TEST( tile->iavf.rx_queue_size>ctx->batch_size );
  ulong const rx_fill_cnt = tile->iavf.rx_queue_size-ctx->batch_size;
  for( ulong i=0UL; i<ctx->vf_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
    /* Post initial RX buffers */
    for( ulong j=0UL; j<rx_fill_cnt; j++ ) {
      fd_iavf_tile_rx_recycle( ctx, vf, next_chunk );
      next_chunk += frame_chunks;
    }

    /* Reserve one packet buffer per TX descriptor */
    for( ulong j=0UL; j<tile->iavf.tx_queue_size; j++ ) {
      vf->tx_desc_buf_chunk[j] = (uint)next_chunk;
      next_chunk += frame_chunks;
    }
  }

  /* Reserve packet buffers for output mcache entries */
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
  if( FD_UNLIKELY( next_chunk-frame_chunks>ctx->net.pkt_buf_wmark ) ) {
    ulong const required_sz  = (next_chunk-ctx->net.pkt_buf_chunk0)<<FD_CHUNK_LG_SZ;
    ulong const available_sz = ((ctx->net.pkt_buf_wmark-ctx->net.pkt_buf_chunk0)<<FD_CHUNK_LG_SZ)+FD_NET_MTU;
    FD_LOG_ERR(( "packet dcache needs %lu bytes, available %lu", required_sz, available_sz ));
  }
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
  ulong const tile_cnt = fd_topo_tile_name_cnt( topo, "iavf" );
  if( FD_UNLIKELY( !tile_cnt || tile_cnt>FD_IAVF_TILE_MAX ) ) {
    FD_LOG_ERR(( "IAVF net tile count %lu must be in [1,%lu]", tile_cnt, FD_IAVF_TILE_MAX ));
  }
  fd_iavf_tile_t *       ctxs  [ FD_IAVF_TILE_MAX ];
  fd_topo_tile_t const * tiles [ FD_IAVF_TILE_MAX ];
  fd_iavf_vfio_tile_t    queues[ FD_IAVF_MEMBER_MAX ][ FD_IAVF_TILE_MAX ];

  /* Prepare tile memory and collect queue pairs by VF */
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    ulong const tile_id = fd_topo_find_tile( topo, "iavf", tile_idx );
    FD_TEST( tile_id!=ULONG_MAX );
    fd_topo_tile_t const * tile = &topo->tiles[tile_id];
    tiles[tile_idx] = tile;

    fd_iavf_tile_join_obj_workspace( topo, tile->tile_obj_id );
    fd_iavf_tile_join_obj_workspace( topo, tile->net.umem_dcache_obj_id );
    for( ulong out_idx=0UL; out_idx<tile->out_cnt; out_idx++ ) {
      fd_iavf_tile_join_obj_workspace( topo, topo->links[ tile->out_link_id[out_idx] ].mcache_obj_id );
    }
    fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
    ctxs[tile_idx] = ctx;
    fd_memset( ctx, 0, sizeof(*ctx) );
    ctx->vf_cnt                = tile->iavf.member_cnt;
    ctx->batch_size            = FD_IAVF_BATCH_SIZE;
    ctx->net.kind_id           = tile_idx;
    ctx->net.tile_cnt          = tile_cnt;
    ctx->vf_link_usable_shared = ctxs[0]->vf_link_usable;
    fd_iavf_hw_join_queues( ctx, tile );

    void * packet_memory;
    ulong  packet_memory_sz;
    ulong  packet_iova;
    fd_iavf_tile_join_pkt_bufs( topo, tile, ctx, &packet_memory, &packet_memory_sz, &packet_iova );
    for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
      fd_iavf_tile_vf_t * vf = &ctx->vfs[vf_idx];
      queues[vf_idx][tile_idx] = (fd_iavf_vfio_tile_t) {
        .tx_queue         = &vf->tx_queue,
        .rx_queue         = &vf->rx_queue,
        .queue_memory     = vf->queue_memory,
        .queue_memory_sz  = fd_iavf_queue_footprint( vf->tx_queue.depth, vf->rx_queue.depth ),
        .packet_memory    = packet_memory,
        .packet_memory_sz = packet_memory_sz,
        .packet_iova      = packet_iova
      };
    }
    fd_net_rx_dst_ports_init( &ctx->net, topo, tile );
  }

  /* Configure VFs through tile 0's Admin Queues */
  fd_topo_tile_t const * first_tile = tiles[0];
  fd_iavf_tile_t *       owner      = ctxs[0];
  for( ulong vf_idx=0UL; vf_idx<owner->vf_cnt; vf_idx++ ) {
    fd_iavf_tile_vf_t * vf = &owner->vfs[vf_idx];
    char const * pf_if = first_tile->iavf.members[vf_idx];
    char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
    if( FD_UNLIKELY( fd_iavf_get_last_vf( pf_if, NULL, vf_pci ) ) ) {
      FD_LOG_ERR(( "VF lookup for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( fd_iavf_init( &vf->vfio, &vf->adminq, &vf->vf_info,
                                   queues[vf_idx], (uint)tile_cnt, vf_pci, FD_NET_MTU, FD_NET_MTU ) ) ) {
      FD_LOG_ERR(( "VF %s setup failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
    }
  }

  /* Fill RX descriptors before enabling reception */
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    fd_iavf_tile_init_pkt_bufs( topo, tiles[tile_idx], ctxs[tile_idx] );
  }

  /* Enable queues and distribute VF state to all tiles */
  if( fds ) fds->member_cnt = owner->vf_cnt;
  for( ulong vf_idx=0UL; vf_idx<owner->vf_cnt; vf_idx++ ) {
    fd_iavf_tile_vf_t * vf = &owner->vfs[vf_idx];
    char const * pf_if = first_tile->iavf.members[vf_idx];
    if( FD_UNLIKELY( fd_iavf_virtchnl_enable_queues( &vf->vfio, &vf->adminq, &vf->vf_info, queues[vf_idx], (uint)tile_cnt ) ) ) {
      FD_LOG_ERR(( "VF queue enable for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
    }
    fd_iavf_tile_publish_vf_link( owner, vf_idx );

    /* Save VFIO descriptors for child launch */
    if( fds ) {
      fds->container_fd[ vf_idx ] = vf->vfio.container_fd;
      fds->group_fd    [ vf_idx ] = vf->vfio.group_fd;
      fds->device_fd   [ vf_idx ] = vf->vfio.device_fd;
    }

    /* Each tile remaps BAR0 at launch */
    if( FD_UNLIKELY( fd_iavf_vfio_unmap_bar( &vf->vfio ) ) ) {
      FD_LOG_ERR(( "VF BAR unmap for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
    }

    /* Copy VF resources while retaining each tile's queues */
    for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
      fd_iavf_tile_vf_t * tile_vf = &ctxs[tile_idx]->vfs[vf_idx];
      tile_vf->vfio          = vf->vfio;
      tile_vf->vf_info       = vf->vf_info;
      tile_vf->tx_queue.tail = NULL;
      tile_vf->rx_queue.tail = NULL;
    }
  }
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) ctxs[tile_idx]->prepared = 1U;
}
#endif

FD_FN_UNUSED static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  /* Prepare VFs if the launcher has not done so */
  fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( !ctx->prepared ) {
    fd_topo_install_iavf( (fd_topo_t *)topo, NULL );
  }

  /* Join this tile's queue and packet memory */
  fd_iavf_hw_join_queues( ctx, tile );
  fd_iavf_tile_join_pkt_bufs( topo, tile, ctx, NULL, NULL, NULL );

  /* Use tile 0's VF link decisions */
  ulong const owner_tile_id = fd_topo_find_tile( topo, "iavf", 0UL );
  FD_TEST( owner_tile_id!=ULONG_MAX );
  fd_iavf_tile_t const * owner = fd_topo_obj_laddr( topo, topo->tiles[ owner_tile_id ].tile_obj_id );
  ctx->vf_link_usable_shared = owner->vf_link_usable;

  /* Queue IDs match IAVF tile indices */
  for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
    fd_iavf_tile_vf_t * vf = &ctx->vfs[vf_idx];
    char const * pf_if = tile->iavf.members[vf_idx];

    if( FD_UNLIKELY( fd_iavf_hw_map_regs( vf, tile->kind_id ) ) ) {
      FD_LOG_ERR(( "VF register mapping for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
    }

    vf->if_idx = if_nametoindex( pf_if );
    if( FD_UNLIKELY( !vf->if_idx ) ) {
      FD_LOG_ERR(( "PF interface %s lookup failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
    }
  }

  /* Routing interface and default source IP */
  uint const interface_idx = if_nametoindex( tile->iavf.if_name );
  if( FD_UNLIKELY( !interface_idx ) ) {
    FD_LOG_ERR(( "interface %s lookup failed (%i-%s)",
                 tile->iavf.if_name, errno, fd_io_strerror( errno ) ));
  }
  ctx->router.if_virt         = interface_idx;
  ctx->router.default_address = fd_iavf_tile_if_ip4_addr( tile->iavf.if_name );

  /* Only tile 0 sends loopback traffic */
  ctx->lo_tx_sock = 0UL==tile->kind_id ? fd_iavf_tile_lo_tx_socket() : -1;
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  /* Tile state and scratch memory */
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

  /* Input links and buffer bounds */
  if( FD_UNLIKELY( tile->in_cnt>FD_NET_IN_MAX ) ) {
    FD_LOG_ERR(( "iavf tile in link count %lu exceeds max of %lu", tile->in_cnt, FD_NET_IN_MAX ));
  }
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "iproute_out" ) ) {
      ctx->net.in_kind[ i ] = FD_NET_IN_KIND_IPROUTE;
    } else {
      ctx->net.in_kind[ i ] = FD_NET_IN_KIND_TX;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "iavf tile in link %s MTU %lu, expected %lu", link->name, link->mtu, (ulong)FD_NET_MTU ));
    }

    ctx->net.in_dcache_ctx[ i ].wksp_base = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->net.in_dcache_ctx[ i ].chunk0    = fd_dcache_compact_chunk0( ctx->net.in_dcache_ctx[ i ].wksp_base, link->dcache );
    ctx->net.in_dcache_ctx[ i ].wmark     = fd_dcache_compact_wmark(  ctx->net.in_dcache_ctx[ i ].wksp_base, link->dcache, link->mtu );
  }

  /* Join fib4 tables */
  FD_TEST( fd_fib4_join( ctx->router.fib_local, fd_fib4_new( fib_local_mem, tile->iavf.route_max, tile->iavf.route_peer_max, tile->iavf.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->router.fib_main,  fd_fib4_new( fib_main_mem,  tile->iavf.route_max, tile->iavf.route_peer_max, tile->iavf.route_peer_seed ) ) );

  /* Join shared netdev table */
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_shared, fd_topo_obj_laddr( topo, tile->iavf.netdev_tbl_obj_id ) )                                        );

  /* Create and join local netdev table */
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX )                                                                               );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_tbl, netdev_tbl_local )                                                                                  );

  /* Copy a consistent interface table for routing */
  ctx->netdev_seq = fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
  fd_net_gre_tunnels_refresh( &ctx->net, &ctx->router.netdev_tbl );
  ctx->router.bind_address = tile->iavf.net.bind_address;
  ctx->net.bind_address    = tile->iavf.net.bind_address;

  /* Join shared neighbor table */
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

  /* Netlink requests for missing neighbors */
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
  if( FD_UNLIKELY( out_fds_cnt<4UL+3UL*ctx->vf_cnt ) ) FD_LOG_ERR(( "allowed FD array capacity %lu, expected at least %lu", out_fds_cnt, 4UL+3UL*ctx->vf_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( fd_log_private_logfile_fd()!=-1 ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  for( ulong vf_idx=0UL; vf_idx<ctx->vf_cnt; vf_idx++ ) {
    fd_iavf_vfio_t const * vfio = &ctx->vfs[vf_idx].vfio;
    out_fds[ out_cnt++ ] = vfio->container_fd;
    out_fds[ out_cnt++ ] = vfio->group_fd;
    out_fds[ out_cnt++ ] = vfio->device_fd;
  }
  if( ctx->lo_tx_sock>=0 ) out_fds[ out_cnt++ ] = ctx->lo_tx_sock;
  return out_cnt;
}

#define STEM_CALLBACK_CONTEXT_TYPE        fd_iavf_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_iavf_tile_t)
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_NEVER_PARK                   1
/* Reserve output credit for one RX batch per VF and one direct loopback
   delivery in the same stem iteration. */
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
