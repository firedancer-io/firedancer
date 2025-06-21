/* The ibeth tile translates Ethernet frames between InfiniBand devices
   in 'raw packet' mode and fd_tango traffic.  Works best on Mellanox
   ConnectX. */

#include "../fd_net_router.h"
#include "../../metrics/fd_metrics.h"
#include "../../topo/fd_topo.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"
#include <errno.h>
#include <dirent.h>
#include <net/if.h>
#include <fcntl.h>
#include <poll.h>
#include <infiniband/verbs.h>

#define FD_IBETH_UDP_PORT_MAX  (8UL)
#define FD_IBETH_TXQ_MAX      (32UL)
#define FD_IBETH_PENDING_MAX  (14UL)

#define DEQUE_NAME tx_free
#define DEQUE_T    uint
#include "../../../util/tmpl/fd_deque_dynamic.c"

/* fd_ibeth_tile_t is private tile state */

struct fd_ibeth_txq {
  void * base;
  ulong  chunk0;
  ulong  wmark;
};
typedef struct fd_ibeth_txq fd_ibeth_txq_t;

struct fd_ibeth_recv_wr {
  struct ibv_recv_wr wr [1];
  struct ibv_sge     sge[1];
};
typedef struct fd_ibeth_recv_wr fd_ibeth_recv_wr_t;

struct fd_ibeth_tile {
  /* ibverbs resources */
  struct ibv_context * ibv_ctx;
  struct ibv_cq_ex *   cq; /* completion queue */
  struct ibv_qp *      qp; /* queue pair */
  uint                 mr_lkey;
  uint                 rx_pending_rem;

  /* UMEM frame region within dcache */
  uchar *  umem_base;   /* Workspace base */
  uchar *  umem_frame0; /* First UMEM frame */
  ulong    umem_sz;     /* Usable UMEM size starting at frame0 */

  /* UMEM chunk region within workspace */
  uint     umem_chunk0; /* Lowest allowed chunk number */
  uint     umem_wmark;  /* Highest allowed chunk number */

  /* TX */
  ulong          txq_cnt;
  fd_ibeth_txq_t txq[ FD_IBETH_TXQ_MAX ];

  /* TX free ring */
  uint * tx_free;

  /* Router */
  fd_net_router_t r;
  uint main_if_idx;

  /* Port matcher */
  uint   dst_port_cnt;
  ushort dst_ports  [ FD_IBETH_UDP_PORT_MAX ];
  uchar  dst_protos [ FD_IBETH_UDP_PORT_MAX ];
  uchar  dst_out_idx[ FD_IBETH_UDP_PORT_MAX ];

  /* Batch RX work requests */
  fd_ibeth_recv_wr_t rx_pending[ FD_IBETH_PENDING_MAX ];

  /* Out links */
  uchar rx_link_cnt;
  uchar rx_link_out_idx[ FD_IBETH_UDP_PORT_MAX ];

  /* RX frame range */
  uint rx_chunk0;
  uint rx_chunk1;

  /* TX frame range */
  uint tx_chunk0;
  uint tx_chunk1;

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong tx_pkt_cnt;
    ulong tx_bytes_total;
  } metrics;
};
typedef struct fd_ibeth_tile fd_ibeth_tile_t;

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_ibeth_tile_t), tx_free_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ibeth_tile_t), sizeof(fd_ibeth_tile_t) );
  l = FD_LAYOUT_APPEND( l, tx_free_align(), tx_free_footprint( tile->ibeth.tx_queue_size ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* fd_ibeth_dev_contains_if returns 1 if the PCIe device backing an ibverbs
   device manages the specified interface, 0 otherwise.  Useful as a quick
   way to find which Linux interface corresponds to which ibverbs device. */

static int
fd_ibeth_dev_contains_if( struct ibv_device * dev,
                          char const *        ifname ) {
  char sysfs_net[ PATH_MAX ];
  if( FD_UNLIKELY( strlen( dev->ibdev_path )+11+1 > PATH_MAX ) ) {
    return 0;
  }
  char * p = fd_cstr_init( sysfs_net );
  p = fd_cstr_append_cstr( p, dev->ibdev_path );
  p = fd_cstr_append_cstr( p, "/device/net" );
  fd_cstr_fini( p );

  DIR * dir = opendir( sysfs_net );
  if( FD_UNLIKELY( !dir ) ) {
    FD_LOG_WARNING(( "opeendir(%s) failed (%i-%s), skipping ibverbs device %s",
                      sysfs_net, errno, fd_io_strerror( errno ), dev->name ));
  }
  int found = 0;
  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    if( entry->d_name[0] == '.' ) continue;
    if( 0==strcmp( entry->d_name, ifname ) ) {
      found = 1;
      break;
    }
  }
  if( FD_UNLIKELY( 0!=closedir( dir ) ) ) {
    FD_LOG_ERR(( "closedir(%s) failed (%i-%s)", sysfs_net, errno, fd_io_strerror( errno ) ));
  }
  return found;
}

/* fd_ibeth_dev_open attempts to open an ibv_context for the device
   specified by tile configuration. */

static struct ibv_context *
fd_ibeth_dev_open( fd_topo_tile_t const * tile ) {
  int device_cnt = 0;
  struct ibv_device ** dev_list = ibv_get_device_list( &device_cnt );
  if( FD_UNLIKELY( !dev_list ) ) {
    FD_LOG_ERR(( "ibv_get_device_list_failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( !device_cnt ) ) {
    FD_LOG_ERR(( "No ibverbs devices found" ));
  }
  FD_LOG_DEBUG(( "Found %i ibverbs devices", device_cnt ));

  /* Scan device list for interface */
  struct ibv_device * dev = NULL;
  for( int i=0; i<device_cnt; i++ ) {
    struct ibv_device * dev_candidate = dev_list[ i ];
    if( FD_UNLIKELY( !dev_candidate ) ) break;
    if( fd_ibeth_dev_contains_if( dev_candidate, tile->ibeth.if_name ) ) {
      dev = dev_candidate;
      break;
    }
  }
  if( FD_UNLIKELY( !dev ) ) {
    FD_LOG_ERR(( "ibverbs device for interface `%s` not found", tile->ibeth.if_name ));
  }

  FD_LOG_NOTICE(( "Opening ibverbs device `%s`", dev->name ));

  struct ibv_context * ibv_context = ibv_open_device( dev );
  if( FD_UNLIKELY( !ibv_context ) ) {
    FD_LOG_ERR(( "ibv_open_device(%s) failed", dev->name ));
  }

  ibv_free_device_list( dev_list );
  return ibv_context;
}

/* fd_ibeth_rx_recycle sends a RX work request to the queue pair.  It
   contains a packet buffer that the NIC eventually fills. */

static inline void
fd_ibeth_rx_recycle( fd_ibeth_tile_t * ctx,
                     ulong             chunk,
                     int               flush ) {
  fd_ibeth_recv_wr_t * verb = &ctx->rx_pending[ --ctx->rx_pending_rem ];
  verb->sge[0] = (struct ibv_sge) {
    .addr   = (ulong)fd_chunk_to_laddr( ctx->umem_base, chunk ),
    .length = FD_NET_MTU,
    .lkey   = ctx->mr_lkey
  };
  verb->wr[0].wr_id = chunk;

  if( !ctx->rx_pending_rem || flush ) {
    struct ibv_recv_wr * bad_wr;
    if( FD_UNLIKELY( ibv_post_recv( ctx->qp, verb->wr, &bad_wr ) ) ) {
      FD_LOG_ERR(( "ibv_post_recv failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ctx->rx_pending_rem = FD_IBETH_PENDING_MAX;
  }
}

/* rxq_assign adds a routing rule.  All incoming IPv4 UDP ports with the
   specified dst port will be redirected to the first output link in the
   topology with the specified names.  frag_meta descriptors are annotated
   with the given 'dst_proto' value. */

static void
rxq_assign( fd_ibeth_tile_t * ctx,
            fd_topo_t *       topo,
            fd_topo_tile_t *  tile,
            ulong             dst_proto,
            char const *      out_link,
            ushort            dst_port ) {
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, out_link, 0UL );
  if( FD_UNLIKELY( out_idx==ULONG_MAX || !dst_port ) ) return;
  if( FD_UNLIKELY( ctx->dst_port_cnt >= FD_IBETH_UDP_PORT_MAX ) ) {
    FD_LOG_ERR(( "ibeth tile rxq link count exceeds max of %lu", FD_IBETH_UDP_PORT_MAX ));
  }
  uint const idx = ctx->dst_port_cnt;
  ctx->dst_protos [ idx ] = (uchar)dst_proto;
  ctx->dst_ports  [ idx ] = dst_port;
  ctx->dst_out_idx[ idx ] = (uchar)out_idx;
  ctx->dst_port_cnt++;

  for( ulong i=0UL; i<ctx->rx_link_cnt; i++ ) {
    if( ctx->rx_link_out_idx[ i ]==out_idx ) {
      goto registered;
    }
  }
  FD_TEST( ctx->rx_link_cnt < FD_IBETH_UDP_PORT_MAX );
  ctx->rx_link_out_idx[ ctx->rx_link_cnt++ ] = (uchar)out_idx;
registered:
  if(0){}
}

/* privileged_init does various ibverbs configuration via userspace verbs
   (/dev/interface/uverbs*). */

FD_FN_UNUSED static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_ibeth_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_ibeth_tile_t) );

  /* Load up dcache containing UMEM */
  void * const dcache_mem  = fd_topo_obj_laddr( topo, tile->ibeth.umem_dcache_obj_id );
  void * const umem_dcache = fd_dcache_join( dcache_mem );
  FD_TEST( umem_dcache );
  ulong  const umem_dcache_data_sz = fd_dcache_data_sz( umem_dcache );
  ulong  const umem_frame_sz       = 2048UL;
  if( FD_UNLIKELY( !umem_dcache ) ) {
    FD_LOG_ERR(( "fd_dcache_join(ibeth.umem_dcache_obj_id failed" ));
  }

  /* Left shrink UMEM region to be 4096 byte aligned */
  void * const umem_frame0 = (void *)fd_ulong_align_up( (ulong)umem_dcache, 4096UL );
  ulong        umem_sz     = umem_dcache_data_sz - ((ulong)umem_frame0 - (ulong)umem_dcache);
  umem_sz = fd_ulong_align_dn( umem_sz, umem_frame_sz );

  /* Derive chunk bounds */
  void * const umem_base   = fd_wksp_containing( dcache_mem );
  ulong  const umem_chunk0 = ( (ulong)umem_frame0 - (ulong)umem_base )>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark  = umem_chunk0 + ( ( umem_sz-umem_frame_sz )>>FD_CHUNK_LG_SZ );
  if( FD_UNLIKELY( umem_chunk0>UINT_MAX || umem_wmark>UINT_MAX || umem_chunk0>umem_wmark ) ) {
    FD_LOG_ERR(( "Calculated invalid UMEM bounds [%lu,%lu]", umem_chunk0, umem_wmark ));
  }
  if( FD_UNLIKELY( !umem_base   ) ) FD_LOG_ERR(( "UMEM dcache is not in a workspace" ));
  if( FD_UNLIKELY( !umem_dcache ) ) FD_LOG_ERR(( "Failed to join UMEM dcache" ));

  ctx->umem_base   = (uchar *)umem_base;
  ctx->umem_frame0 = umem_frame0;
  ctx->umem_sz     = umem_sz;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;

  if( FD_UNLIKELY( tile->kind_id!=0 ) ) {
    /* FIXME support receive side scaling using ibv_create_rwq_ind_table
             and ibv_rx_hash_conf. */
    FD_LOG_ERR(( "Sorry, net.provider='ibeth' only supports layout.net_tile_count=1" ));
  }

  struct ibv_context * ibv_context = fd_ibeth_dev_open( tile );
  ctx->ibv_ctx = ibv_context;

  /* Receive async events non-blocking */
  int async_fd    = ibv_context->async_fd;
  int async_flags = fcntl( async_fd, F_GETFL );
  if( FD_UNLIKELY( 0!=fcntl( async_fd, F_SETFL, async_flags|O_NONBLOCK) ) ) {
    FD_LOG_ERR(( "Failed to make ibv_context->async_fd non-blocking (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }

  uint if_idx = if_nametoindex( tile->ibeth.if_name );
  if( FD_UNLIKELY( !if_idx ) ) {
    FD_LOG_ERR(( "if_nametoindex(%s) failed (%i-%s)",
                 tile->ibeth.if_name, errno, fd_io_strerror( errno ) ));
  }
  ctx->main_if_idx = if_idx;

  /* Create protection domain */
  struct ibv_pd * pd = ibv_alloc_pd( ibv_context );
  if( FD_UNLIKELY( !pd ) ) {
    FD_LOG_ERR(( "ibv_alloc_pd failed" ));
  }

  /* Add buffer to protection domain */
  struct ibv_mr * mr = ibv_reg_mr( pd, umem_frame0, umem_sz, IBV_ACCESS_LOCAL_WRITE );
  if( FD_UNLIKELY( !mr ) ) {
    FD_LOG_ERR(( "ibv_reg_mr failed" ));
  }
  ctx->mr_lkey = mr->lkey;

  /* Create completion queue */
  struct ibv_cq_init_attr_ex cq_attr = {
    .cqe       = tile->ibeth.rx_queue_size + tile->ibeth.tx_queue_size,
    .wc_flags  = IBV_WC_EX_WITH_BYTE_LEN,
    .comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS,
    .flags     = IBV_CREATE_CQ_ATTR_SINGLE_THREADED
  };
  ctx->cq = ibv_create_cq_ex( ibv_context, &cq_attr );
  if( FD_UNLIKELY( !ctx->cq ) ) {
    FD_LOG_ERR(( "ibv_create_cq failed" ));
  }

  /* Create queue pair */
  struct ibv_qp_init_attr qp_init_attr = {
    .qp_context = NULL,
    .recv_cq = ibv_cq_ex_to_cq( ctx->cq ),
    .send_cq = ibv_cq_ex_to_cq( ctx->cq ),
    .cap = {
      .max_recv_wr  = tile->ibeth.rx_queue_size,
      .max_recv_sge = 1,
      .max_send_wr  = tile->ibeth.tx_queue_size,
      .max_send_sge = 1
    },
    .qp_type = IBV_QPT_RAW_PACKET
  };
  ctx->qp = ibv_create_qp( pd, &qp_init_attr );
  if( FD_UNLIKELY( !ctx->qp ) ) {
    FD_LOG_ERR(( "ibv_create_qp(.cap.max_recv_wr=%u) failed",
                 tile->ibeth.rx_queue_size ));
  }

  /* Set QP to INIT state, assign port */
  struct ibv_qp_attr qp_attr;
  memset( &qp_attr, 0, sizeof(qp_attr) );
  qp_attr.qp_state = IBV_QPS_INIT;
  qp_attr.port_num = 1; /* FIXME support multi-port NICs */
  int modify_err;
  if( FD_UNLIKELY( (modify_err = ibv_modify_qp( ctx->qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT )) ) ) {
    FD_LOG_ERR(( "ibv_modify_qp(IBV_QP_INIT,port_num=1,IBV_QP_STATE|IBV_QP_PORT) failed (%i-%s)",
                 modify_err, fd_io_strerror( modify_err ) ));
  }

  /* Set QP to "Ready to Receive" state */
  memset( &qp_attr, 0, sizeof(qp_attr) );
  qp_attr.qp_state = IBV_QPS_RTR;
  if( FD_UNLIKELY( (modify_err = ibv_modify_qp( ctx->qp, &qp_attr, IBV_QP_STATE )) ) ) {
    FD_LOG_ERR(( "ibv_modify_qp(IBV_QPS_RTR,IBV_QP_STATE) failed (%i-%s)", modify_err, fd_io_strerror( modify_err ) ));
  }

  /* Set QP to "Ready to Send" state */
  memset( &qp_attr, 0, sizeof(qp_attr) );
  qp_attr.qp_state = IBV_QPS_RTS;
  if( FD_UNLIKELY( (modify_err = ibv_modify_qp( ctx->qp, &qp_attr, IBV_QP_STATE )) ) ) {
    FD_LOG_ERR(( "ibv_modify_qp(IBV_QPS_RTS,IBV_QP_STATE) failed (%i-%s)", modify_err, fd_io_strerror( modify_err ) ));
  }

  /* Setup flow steering */
  rxq_assign( ctx, topo, tile, DST_PROTO_TPU_UDP,  "net_quic",   tile->ibeth.net.legacy_transaction_listen_port );
  rxq_assign( ctx, topo, tile, DST_PROTO_TPU_QUIC, "net_quic",   tile->ibeth.net.quic_transaction_listen_port   );
  rxq_assign( ctx, topo, tile, DST_PROTO_SHRED,    "net_shred",  tile->ibeth.net.shred_listen_port              );
  rxq_assign( ctx, topo, tile, DST_PROTO_GOSSIP,   "net_gossip", tile->ibeth.net.gossip_listen_port             );
  rxq_assign( ctx, topo, tile, DST_PROTO_REPAIR,   "net_shred",  tile->ibeth.net.repair_intake_listen_port      );
  rxq_assign( ctx, topo, tile, DST_PROTO_REPAIR,   "net_repair", tile->ibeth.net.repair_serve_listen_port       );
  struct __attribute__((packed,aligned(8))) {
    struct ibv_flow_attr         attr;
    struct ibv_flow_spec_eth     eth;
    struct ibv_flow_spec_ipv4    ipv4;
    struct ibv_flow_spec_tcp_udp udp;
  } flow_rule;
  for( ulong i=0UL; i<(ctx->dst_port_cnt); i++ ) {
    flow_rule.attr = (struct ibv_flow_attr) {
      .comp_mask    = 0,
      .type         = IBV_FLOW_ATTR_NORMAL,
      .size         = sizeof flow_rule,
      .priority     = 0,
      .num_of_specs = 3,
      .port         = 1,
      .flags        = 0
    };
    flow_rule.eth = (struct ibv_flow_spec_eth) {
      .type = IBV_FLOW_SPEC_ETH,
      .size = sizeof(struct ibv_flow_spec_eth),
      .val = {
        .ether_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
      },
      .mask = {
        .ether_type = USHORT_MAX
      }
    };
    flow_rule.ipv4 = (struct ibv_flow_spec_ipv4) {
      .type = IBV_FLOW_SPEC_IPV4,
      .size = sizeof(struct ibv_flow_spec_ipv4),
      .val = {
        .dst_ip = tile->ibeth.net.bind_address
      },
      .mask = {
        .dst_ip = tile->ibeth.net.bind_address ? UINT_MAX : 0U
      }
    };
    flow_rule.udp = (struct ibv_flow_spec_tcp_udp) {
      .type = IBV_FLOW_SPEC_UDP,
      .size = sizeof(struct ibv_flow_spec_tcp_udp),
      .val = {
        .dst_port = fd_ushort_bswap( ctx->dst_ports[ i ] )
      },
      .mask = {
        .dst_port = USHORT_MAX
      }
    };

    struct ibv_flow * flow = ibv_create_flow( ctx->qp, fd_type_pun( &flow_rule ) );
    if( FD_UNLIKELY( !flow ) ) {
      FD_LOG_ERR(( "ibv_create_flow failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    FD_LOG_DEBUG(( "Created flow rule for ip4.dst_ip=" FD_IP4_ADDR_FMT " udp.dst_port:%hu",
                   FD_IP4_ADDR_FMT_ARGS( tile->ibeth.net.bind_address ),
                   ctx->dst_ports[ i ] ));
  }
  FD_LOG_NOTICE(( "Installed %u ibv_flow rules", ctx->dst_port_cnt ));
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_ibeth_tile_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ibeth_tile_t), sizeof(fd_ibeth_tile_t) );
  void *            deque_mem = FD_SCRATCH_ALLOC_APPEND( l, tx_free_align(), tx_free_footprint( tile->ibeth.tx_queue_size ) );

  /* chunk 0 is used as a sentinel value, so ensure actual chunk indices
     do not use that value. */
  FD_TEST( ctx->umem_chunk0 > 0 );


  /* Prepare RX WR batching */
  for( uint i=0U; i<FD_IBETH_PENDING_MAX; i++ ) {
    fd_ibeth_recv_wr_t * verb = &ctx->rx_pending[ i ];
    memset( verb, 0, sizeof(fd_ibeth_recv_wr_t) );
    verb->wr->next    = (i<(FD_IBETH_PENDING_MAX-1)) ? ctx->rx_pending[i+1].wr : NULL;
    verb->wr->sg_list = verb->sge;
    verb->wr->num_sge = 1;
  }
  ctx->rx_pending_rem = FD_IBETH_PENDING_MAX;

  /* Post RX descriptors */
  ulong frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong next_chunk   = ctx->umem_chunk0;
  ctx->rx_chunk0     = (uint)next_chunk;
  ulong const rx_fill_cnt = tile->ibeth.rx_queue_size;
  for( ulong i=0UL; i<rx_fill_cnt; i++ ) {
    fd_ibeth_rx_recycle( ctx, next_chunk, 1 );
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
  ctx->rx_chunk1 = (uint)next_chunk;

  /* Init TX free list */
  ctx->tx_chunk0 = (uint)next_chunk;
  ctx->tx_free = tx_free_join( tx_free_new( deque_mem, tile->ibeth.tx_queue_size ) );
  while( !tx_free_full( ctx->tx_free ) ) {
    tx_free_push_tail( ctx->tx_free, (uint)next_chunk );
    next_chunk += frame_chunks;
  }
  ctx->tx_chunk1 = (uint)next_chunk;

  /* Init TX */
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "ibeth tile in link does not have a normal MTU" ));

    ctx->txq[ i ].base   = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->txq[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->txq[ i ].base, link->dcache );
    ctx->txq[ i ].wmark  = fd_dcache_compact_wmark(  ctx->txq[ i ].base, link->dcache, link->mtu );
  }

  /* Join netbase objects */
  FD_TEST( fd_fib4_join( ctx->fib_local, fd_topo_obj_laddr( topo, tile->xdp.fib4_local_obj_id ) ) );
  FD_TEST( fd_fib4_join( ctx->fib_main, fd_topo_obj_laddr( topo, tile->xdp.fib4_main_obj_id  ) ) );

  ulong neigh4_obj_id = tile->xdp.neigh4_obj_id;
  ulong ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) )
    FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join(
      ctx->neigh4,
      fd_topo_obj_laddr( topo, neigh4_obj_id ),
      ele_max,
      probe_max,
      seed ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  ulong net_netlnk_id = fd_topo_find_link( topo, "net_netlnk", 0UL );
  if( FD_UNLIKELY( net_netlnk_id!=ULONG_MAX ) ) {
    fd_topo_link_t * net_netlnk = &topo->links[ net_netlnk_id ];
    ctx->r.neigh4_solicit->mcache = net_netlnk->mcache;
    ctx->r.neigh4_solicit->depth  = fd_mcache_depth( ctx->r.neigh4_solicit->mcache );
    ctx->r.neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->r.neigh4_solicit->mcache ) );
  }

  /* Check if all chunks are in bound */
  if( FD_UNLIKELY( next_chunk > ctx->umem_wmark ) ) {
    FD_LOG_ERR(( "dcache is too small (topology bug)" ));
  }
}

static inline void
metrics_write( fd_ibeth_tile_t * ctx ) {
  FD_MCNT_SET( IBETH, RX_PKT_CNT,     ctx->metrics.rx_pkt_cnt     );
  FD_MCNT_SET( IBETH, RX_BYTES_TOTAL, ctx->metrics.rx_bytes_total );
  FD_MCNT_SET( IBETH, TX_PKT_CNT,     ctx->metrics.tx_pkt_cnt     );
  FD_MCNT_SET( IBETH, TX_BYTES_TOTAL, ctx->metrics.tx_bytes_total );
}

static void
handle_async_event( struct ibv_async_event * event ) {
  FD_LOG_NOTICE(( "Async event: %u-%s", event->event_type, ibv_event_type_str( event->event_type ) ));
  switch( event->event_type ) {
  case IBV_EVENT_CQ_ERR:
    FD_LOG_ERR(( "CQ error" ));
    break;
  case IBV_EVENT_QP_FATAL:
    FD_LOG_ERR(( "QP fatal error" ));
    break;
  default:
    break;
  }
  ibv_ack_async_event( event );
}

static void
poll_async_events( fd_ibeth_tile_t * ctx ) {
  for(;;) {
    struct pollfd pfd[1] = {{
      .fd     = ctx->ibv_ctx->async_fd,
      .events = POLLIN
    }};
    int ret = poll( pfd, 1, 0 );
    if( ret<0 || !( pfd->revents & POLLIN ) ) break;
    struct ibv_async_event event;
    if( 0==ibv_get_async_event( ctx->ibv_ctx, &event ) ) {
      handle_async_event( &event );
    }
  }
}

static inline void
during_housekeeping( fd_ibeth_tile_t * ctx ) {
  poll_async_events( ctx );
}

/* fd_ibeth_rx_pkt handles an ibverbs RX completion.  If the completion
   frees a frame, returns the chunk index.  Returns zero if no frame can
   be freed.

   The completion can either fail (immediately returns the chunk of the
   failed WQE for freeing), or succeed (posts a frag to tango, returns
   the shadowed chunk index for freeing). */

static inline ulong
fd_ibeth_rx_pkt( fd_ibeth_tile_t *   ctx,
                 fd_stem_context_t * stem,
                 ulong               wr_id,
                 ulong               byte_len,
                 enum ibv_wc_status  status ) {
  if( FD_UNLIKELY( status!=IBV_WC_SUCCESS ) ) return wr_id;

  ulong const chunk = wr_id;
  ulong const sz    = byte_len;

  if( FD_UNLIKELY( chunk<ctx->umem_chunk0 || chunk>ctx->umem_wmark ) ) {
    FD_LOG_CRIT(( "ibv_wc wr_id %lu out of bounds [%u,%u]", chunk, ctx->umem_chunk0, ctx->umem_wmark ));
  }
  fd_eth_hdr_t const * l2 = fd_chunk_to_laddr_const( ctx->umem_base, chunk );
  fd_ip4_hdr_t const * l3 = (fd_ip4_hdr_t const *)(l2+1);
  fd_udp_hdr_t const * l4 = (fd_udp_hdr_t const *)( (uchar *)l3 + FD_IP4_GET_LEN( *l3 ) );
  ulong const dgram_off = (ulong)(l4+1) - (ulong)l2;

  /* Even though these are reads of uninitialized / untrusted data, this
     never actually goes beyond the bounds of a frame (FD_NET_MTU). */
  int const sz_ok = dgram_off<=sz;
  int const hdr_ok =
    ( fd_ushort_bswap( l2->net_type )==FD_ETH_HDR_TYPE_IP ) &
    ( FD_IP4_GET_VERSION( *l3 )==4 ) &
    ( l3->protocol==FD_IP4_HDR_PROTOCOL_UDP );

  ushort const net_dport = fd_ushort_bswap( l4->net_dport );
  int out_idx = -1;
  for( ulong i=0UL; i<FD_IBETH_UDP_PORT_MAX; i++ ) {
    if( ctx->dst_ports[ i ]==net_dport ) {
      out_idx = ctx->dst_out_idx[ i ];
      break;
    }
  }
  int const match_ok =
    (out_idx >= 0) &
    (out_idx < (int)ctx->dst_port_cnt);

  int const filter = sz_ok & hdr_ok & match_ok;
  if( FD_UNLIKELY( !filter ) ) return wr_id;

  /* FIXME: Since the order of wr_ids in CQEs mirrors those posted in
            WQEs, we could recover the shadowed wr_id/chunk without
            touching memory here ... */
  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong const      depth  = stem->depths [ out_idx ];
  ulong *          seqp   = &stem->seqs  [ out_idx ];
  ulong const      seq    = *seqp;

  ulong freed_chunk = mcache[ fd_mcache_line_idx( seq, depth ) ].chunk;

  ulong const proto  = ctx->dst_protos[ out_idx ];
  ulong const sig    = fd_disco_netmux_sig( l3->saddr, l4->net_sport, 0U, proto, dgram_off );
  ulong const ctl    = 0UL;
  ulong const tsorig = 0UL;
  ulong const tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

  fd_mcache_publish_sse( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += sz;

  return freed_chunk;
}

/* fd_ibeth_tx_recycle recycles the TX frame of a completed TX operation. */

static void
fd_ibeth_tx_recycle( fd_ibeth_tile_t * ctx,
                     ulong             chunk ) {
  if( FD_UNLIKELY( (chunk<ctx->umem_chunk0) | (chunk>ctx->umem_wmark) ) ) {
    FD_LOG_ERR(( "TX completion chunk %lu out of bounds [%u,%u]", chunk, ctx->umem_chunk0, ctx->umem_wmark ));
    return;
  }
  if( FD_UNLIKELY( !tx_free_push_head( ctx->tx_free, (uint)chunk ) ) ) {
    FD_LOG_ERR(( "TX free list full" ));
  }
}

/* after_credit is called every run loop iteration, provided there is
   sufficient downstream credit for forwarding on all output links.
   Receives up to one packet. */

static inline void
after_credit( fd_ibeth_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;

  /* Poll for new event */
  struct ibv_cq_ex *      cq      = ctx->cq;
  struct ibv_poll_cq_attr cq_attr = {0};
  int poll_err = ibv_start_poll( cq, &cq_attr );
  if( poll_err ) goto poll_err;
  *charge_busy = 1;
  uint cqe_avail = 1024u; /* FIXME */
  do {
    ulong              wr_id    = cq->wr_id;
    enum ibv_wc_status status   = cq->status;
    ulong              byte_len = ibv_wc_read_byte_len( cq );
    enum ibv_wc_opcode opcode   = ibv_wc_read_opcode( cq );

    if( FD_LIKELY( opcode==IBV_WC_RECV ) ) {
      ulong freed_chunk = fd_ibeth_rx_pkt( ctx, stem, wr_id, byte_len, status );
      if( FD_UNLIKELY( !freed_chunk ) ) FD_LOG_CRIT(( "invalid chunk in mcache" ));
      fd_ibeth_rx_recycle( ctx, freed_chunk, 0 );
    } else if( FD_LIKELY( opcode==IBV_WC_SEND ) ) {
      if( FD_LIKELY( status==IBV_WC_SUCCESS ) ) {
        ctx->metrics.tx_pkt_cnt++;
        ctx->metrics.tx_bytes_total += byte_len;
      }
      fd_ibeth_tx_recycle( ctx, wr_id );
    } else {
      FD_LOG_WARNING(( "ibv_wc opcode %u status %u not supported", opcode, status ));
    }

    poll_err = ibv_next_poll( cq );
  } while( !poll_err && --cqe_avail );
  ibv_end_poll( cq );
poll_err:
  if( FD_UNLIKELY( poll_err && poll_err!=ENOENT ) ) {
    FD_LOG_ERR(( "ibv_cq_ex poll failed (%i)", poll_err ));
  }
}

/* {before,during,after}_frag copy a packet received from an input link out
   to an ibverbs queue pair for TX. */

static inline int
before_frag( fd_ibeth_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)in_idx; (void)seq;

  /* Find interface index of next packet */

  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_OUTGOING ) ) return 1;

  uint dst_ip = fd_disco_netmux_sig_dst_ip( sig );
  if( FD_UNLIKELY( !fd_net_tx_route( &ctx->r, dst_ip ) ) ) return 1;

  uint const next_hop_if_idx = ctx->r.tx_op.if_idx;
  if( FD_UNLIKELY( next_hop_if_idx==1 ) ) {
    /* Sorry, loopback not supported yet */
    return 1;
  } else {
    /* "Real" interface */
    uint const main_if_idx = ctx->main_if_idx;
    if( FD_UNLIKELY( main_if_idx != next_hop_if_idx ) ) {
      /* Unreachable for now, since only the main_if_idx has a neighbor
         table, therefore fd_net_tx_route would abort before this is
         reached */
      return 1; /* ignore */
    }
  }

  /* Skip if TX is blocked */

  if( FD_UNLIKELY( tx_free_empty( ctx->tx_free ) ) ) {
    /* FIXME metric */
    return 1; /* ignore */
  }

  return 0; /* continue */
}

static inline void
during_frag( fd_ibeth_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  (void)seq; (void)sig; (void)ctl;

  fd_ibeth_txq_t * txq = &ctx->txq[ in_idx ];
  if( FD_UNLIKELY( chunk < txq->chunk0 || chunk > txq->wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, txq->chunk0, txq->wmark ));
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
after_frag( fd_ibeth_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)tsorig; (void)tspub; (void)stem;

  /* Set Ethernet src and dst MAC addrs, optionally mangle IPv4 header to
     fill in source address (if it's missing). */
  ulong  chunk = *tx_free_peek_head( ctx->tx_free );
  void * frame = fd_chunk_to_laddr( ctx->umem_base, chunk );
  if( FD_UNLIKELY( !fd_net_tx_fill_addrs( &ctx->r, frame, sz ) ) ) return;

  /* Submit TX job */
  struct ibv_sge sge = {
    .addr   = (ulong)frame,
    .length = (uint)sz,
    .lkey   = ctx->mr_lkey
  };
  struct ibv_send_wr wr = {
    .wr_id      = chunk,
    .sg_list    = &sge,
    .num_sge    = 1,
    .opcode     = IBV_WR_SEND,
    .send_flags = IBV_SEND_SIGNALED
  };

  errno = 0;
  struct ibv_send_wr * bad_wr;
  int send_err = ibv_post_send( ctx->qp, &wr, &bad_wr );
  if( FD_UNLIKELY( send_err ) ) {
    return; /* send failed, recycle frame */
  }

  /* Consume frame */
  tx_free_pop_head( ctx->tx_free );
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_ibeth_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_ibeth_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_BURST                  1UL /* ignored */
#define STEM_LAZY                   130000UL /* 130us */
#include "../../stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_ibeth = {
  .name                     = "ibeth",
  //.populate_allowed_seccomp = populate_allowed_seccomp,
  //.populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
