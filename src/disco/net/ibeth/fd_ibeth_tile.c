/* The ibeth tile translates Ethernet frames between InfiniBand devices
   in 'raw packet' mode and fd_tango traffic.  Works best on Mellanox
   ConnectX. */

#include "../../topo/fd_topo.h"
#include "../../../util/net/fd_eth.h"
#include <errno.h>
#include <dirent.h>
#include <infiniband/verbs.h>

struct fd_ibeth_tile {
  /* ibverbs resources */
  struct ibv_cq * cq; /* completion queue */
  struct ibv_qp * qp; /* queue pair */
  uint            mr_lkey;

  /* UMEM frame region within dcache */
  uchar *  umem_base;   /* Workspace base */
  uchar *  umem_frame0; /* First UMEM frame */
  ulong    umem_sz;     /* Usable UMEM size starting at frame0 */

  /* UMEM chunk region within workspace */
  uint     umem_chunk0; /* Lowest allowed chunk number */
  uint     umem_wmark;  /* Highest allowed chunk number */

  struct {
    ulong rx_enqueue_cnt;
  } metrics;
};

typedef struct fd_ibeth_tile fd_ibeth_tile_t;

static ulong
scratch_align( void ) {
  return alignof(fd_ibeth_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_ibeth_tile_t);
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

static inline void
fd_ibeth_rx_enqueue( fd_ibeth_tile_t * ctx,
                     ulong             chunk ) {
  struct ibv_sge sge = {
    .addr   = (ulong)fd_chunk_to_laddr( ctx->umem_base, chunk ),
    .length = FD_NET_MTU,
    .lkey   = ctx->mr_lkey
  };
  struct ibv_recv_wr wr = {
    .wr_id   = chunk,
    .sg_list = &sge,
    .num_sge = 1
  };
  struct ibv_recv_wr * bad_wr;
  if( FD_UNLIKELY( ibv_post_recv( ctx->qp, &wr, &bad_wr ) ) ) {
    FD_LOG_ERR(( "ibv_post_recv failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->metrics.rx_enqueue_cnt++;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_ibeth_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_ibeth_tile_t) );

  /* Load up dcache containing UMEM */
  void * const dcache_mem          = fd_topo_obj_laddr( topo, tile->xdp.umem_dcache_obj_id );
  void * const umem_dcache         = fd_dcache_join( dcache_mem );
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
  int cqe = 128;
  ctx->cq = ibv_create_cq( ibv_context, cqe, NULL, NULL, 0 );
  if( FD_UNLIKELY( !ctx->cq ) ) {
    FD_LOG_ERR(( "ibv_create_cq failed" ));
  }

  /* Create queue pair */
  struct ibv_qp_init_attr qp_init_attr = {
    .qp_context = NULL,
    .send_cq = ctx->cq,
    .recv_cq = ctx->cq,
    .cap = {
      .max_recv_wr  = tile->ibeth.rx_queue_size,
      .max_recv_sge = 1
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

  /* Setup flow steering */
  ushort const udp_dst_ports[] = {
    (ushort)tile->sock.net.legacy_transaction_listen_port,
    (ushort)tile->sock.net.quic_transaction_listen_port,
    (ushort)tile->sock.net.shred_listen_port,
    (ushort)tile->sock.net.gossip_listen_port,
    (ushort)tile->sock.net.repair_intake_listen_port,
    (ushort)tile->sock.net.repair_serve_listen_port,
  };
  ulong const udp_dst_port_cnt = sizeof(udp_dst_ports)/sizeof(ushort);
  struct __attribute__((packed,aligned(8))) {
    struct ibv_flow_attr         attr;
    struct ibv_flow_spec_eth     eth;
    struct ibv_flow_spec_ipv4    ipv4;
    struct ibv_flow_spec_tcp_udp udp;
  } flow_rule;
  for( ulong i=0UL; i<udp_dst_port_cnt; i++ ) {
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
        .dst_port = fd_ushort_bswap( udp_dst_ports[ i ] )
      },
      .mask = {
        .dst_port = USHORT_MAX
      }
    };

    struct ibv_flow * flow = ibv_create_flow( ctx->qp, fd_type_pun( &flow_rule ) );
    if( FD_UNLIKELY( !flow ) ) {
      FD_LOG_ERR(( "ibv_create_flow failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_ibeth_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /* Post RX descriptors */
  ulong chunk = ctx->umem_chunk0;
  ulong const rx_fill_cnt = tile->ibeth.rx_queue_size;
  for( ulong i=0UL; i<rx_fill_cnt; i++ ) {
    fd_ibeth_rx_enqueue( ctx, chunk );
    chunk += FD_NET_MTU>>FD_CHUNK_LG_SZ;
  }

  struct ibv_qp_init_attr qp_init_attr = {0};
  struct ibv_qp_attr qp_attr = {0};
  ibv_query_qp( ctx->qp, &qp_attr, 0, &qp_init_attr );
  FD_LOG_NOTICE(( "QP state: %u, port_num: %u", qp_attr.qp_state, qp_attr.port_num ));
}

static inline void
after_credit( fd_ibeth_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  struct ibv_wc wc;
  int poll_res = ibv_poll_cq( ctx->cq, 1, &wc );
  if( FD_UNLIKELY( poll_res<0 ) ) {
    FD_LOG_ERR(( "ibv_poll_cq failed (%i)", poll_res ));
  }
  if( poll_res==0 ) return;
  
  /* FIXME read wc.status */
  (void)stem;
  fd_ibeth_rx_enqueue( ctx, wc.wr_id );
  *charge_busy = 1;
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_ibeth_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_ibeth_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_BURST 1UL
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
