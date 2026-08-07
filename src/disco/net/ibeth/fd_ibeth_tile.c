/* The ibeth tile translates Ethernet frames between InfiniBand devices
   in 'raw packet' mode and fd_tango traffic.  Works best on Mellanox
   ConnectX. */

#include "../fd_net_router.h"
#include "../fd_linux_bond.h"
#include "../fd_net_common.h"
#include "../../metrics/fd_metrics.h"
#include "../../topo/fd_topo.h"
#include "../../../waltz/ip/fd_iproute.h"
#include "../../../waltz/mlx5/fd_mlx5.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"
#include "../../../util/pod/fd_pod_format.h"
#include <errno.h>
#include <dirent.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <rdma/ib_user_verbs.h>
#include <linux/rtnetlink.h>

#ifndef FD_TILE_TEST
#include "generated/fd_ibeth_tile_seccomp.h"
#endif

#define FD_IBETH_FLOW_CAP  (64UL)
#define FD_IBETH_BATCH_CAP (64UL)

#define IN_KIND_NET     (0U)
#define IN_KIND_IPROUTE (1U)

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
  uint chunk;
};
typedef struct fd_ibeth_recv_wr fd_ibeth_recv_wr_t;

struct fd_ibeth_send_wr {
  uint chunk;
  uint sz;
};
typedef struct fd_ibeth_send_wr fd_ibeth_send_wr_t;

static inline ulong
fd_ibeth_tx_user_data( fd_ibeth_send_wr_t meta ) {
  return ((ulong)meta.sz<<32) | (ulong)meta.chunk;
}

static inline fd_ibeth_send_wr_t
fd_ibeth_tx_meta( ulong user_data ) {
  return (fd_ibeth_send_wr_t) { .chunk=(uint)user_data, .sz=(uint)(user_data>>32) };
}

struct fd_ibeth_rx_cqe {
  ulong byte_len;
  uint  chunk;
  uint  opcode;
};
typedef struct fd_ibeth_rx_cqe fd_ibeth_rx_cqe_t;

#define FD_IBETH_MLX5_CONTEXT (1U<<0)
#define FD_IBETH_MLX5_UAR     (1U<<1)
#define FD_IBETH_MLX5_RX_CQ   (1U<<2)
#define FD_IBETH_MLX5_TX_CQ   (1U<<3)
#define FD_IBETH_MLX5_PD      (1U<<4)
#define FD_IBETH_MLX5_MR      (1U<<5)
#define FD_IBETH_MLX5_QP      (1U<<6)

struct fd_ibeth_mlx5 {
  fd_mlx5_context_t context;
  fd_mlx5_uar_t     uar;
  fd_mlx5_pd_t      pd;
  fd_mlx5_mr_t      mr;
  fd_mlx5_cq_t      rx_cq;
  fd_mlx5_cq_t      tx_cq;
  fd_mlx5_qp_t      qp;
  fd_mlx5_flow_t    flows[ FD_IBETH_FLOW_CAP ];
  uint               initialized;
  uint               flow_cnt;
};
typedef struct fd_ibeth_mlx5 fd_ibeth_mlx5_t;

struct fd_ibeth_tile {
  fd_ibeth_mlx5_t        hw;
  fd_mlx5_queue_layout_t queue_layout;
  void *                 queue_mem;
  ulong *                rx_user_data;
  ulong *                tx_user_data;
  uint                   mr_lkey;
  uint                   batch_size;
  uint                   flow_rule_max;
  uint                 rx_pending_rem;
  uint                 tx_pending_cnt;
  uint                 tx_pending_idle;

  /* UMEM frame region within dcache */
  uchar *  umem_base;   /* Workspace base */
  uchar *  umem_frame0; /* First UMEM frame */
  ulong    umem_sz;     /* Usable UMEM size starting at frame0 */

  /* UMEM chunk region within workspace */
  uint     umem_chunk0; /* Lowest allowed chunk number */
  uint     umem_wmark;  /* Highest allowed chunk number */

  /* TX */
  ulong          txq_cnt;
  fd_ibeth_txq_t txq[ FD_TOPO_MAX_TILE_IN_LINKS ];
  uchar          in_kind[ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_iproute_msg_t iproute_msg;

  /* TX free ring */
  uint * tx_free;

  /* Router */
  fd_net_router_t r;
  fd_net_tx_route_t tx_route;

  /* Port matcher */
  uint   dst_port_cnt;
  ushort dst_ports  [ FD_IBETH_FLOW_CAP ];
  uchar  dst_protos [ FD_IBETH_FLOW_CAP ];
  uchar  dst_out_idx[ FD_IBETH_FLOW_CAP ];
  uchar  repair_out_idx;

  /* Batched work requests */
  fd_ibeth_recv_wr_t rx_pending[ FD_IBETH_BATCH_CAP ];
  fd_ibeth_send_wr_t tx_pending[ FD_IBETH_BATCH_CAP ];

  /* Out links */
  uchar rx_out_cnt;
  uchar rx_link_cnt;
  uchar rx_link_out_idx[ FD_IBETH_FLOW_CAP ];

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

#ifndef FD_TILE_TEST

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_ibeth_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_ibeth_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(),
                                             (uint)ctx->hw.context.async_fd );
  return sock_filter_policy_fd_ibeth_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_ibeth_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
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
fd_ibeth_if_ip4_addr( char const * if_name ) {
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
                       fd_ulong_max( fd_ulong_max( alignof(fd_ibeth_tile_t), tx_free_align() ),
                                     fd_ulong_max( fd_netdev_tbl_align(), fd_fib4_align() ) ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  ulong const queue_footprint = fd_mlx5_queue_footprint( tile->ibeth.rx_queue_size,
                                                         tile->ibeth.tx_queue_size );
  if( FD_UNLIKELY( !queue_footprint ) ) return 0UL;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ibeth_tile_t), sizeof(fd_ibeth_tile_t) );
  l = FD_LAYOUT_APPEND( l, FD_MLX5_PAGE_SZ, queue_footprint );
  l = FD_LAYOUT_APPEND( l, alignof(ulong), tile->ibeth.rx_queue_size*sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong), tile->ibeth.tx_queue_size*sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, tx_free_align(), tx_free_footprint( tile->ibeth.tx_queue_size ) );
  l = FD_LAYOUT_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->ibeth.route_max, tile->ibeth.route_peer_max ) );
  l = FD_LAYOUT_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->ibeth.route_max, tile->ibeth.route_peer_max ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
fd_ibeth_rdma_port_contains_if( char const * rdma_name,
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
fd_ibeth_rdma_port_matches_if( char const * rdma_name,
                               uint         port,
                               char const * if_name ) {
  if( fd_ibeth_rdma_port_contains_if( rdma_name, port, if_name ) ) return 1;
  if( !fd_bonding_is_master( if_name ) ) return 0;
  fd_bonding_slave_iter_t iter_[1];
  fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, if_name );
  for( ; !fd_bonding_slave_iter_done( iter ); fd_bonding_slave_iter_next( iter ) )
    if( fd_ibeth_rdma_port_contains_if( rdma_name, port, fd_bonding_slave_iter_ele( iter ) ) ) return 1;
  return 0;
}

static void
fd_ibeth_rdma_dev_find( char                         rdma_name[ FD_MLX5_RDMA_NAME_MAX ],
                        uint *                       rdma_port,
                        fd_topo_tile_t const * tile ) {
  DIR * dir = opendir( "/sys/class/infiniband" );
  if( FD_UNLIKELY( !dir ) )
    FD_LOG_ERR(( "opendir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  rdma_name[0] = '\0';
  *rdma_port = 0U;
  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    if( entry->d_name[0]=='.' ) continue;
    if( strcmp( tile->ibeth.rdma_device, "auto" ) &&
        strcmp( tile->ibeth.rdma_device, entry->d_name ) ) continue;
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
      if( tile->ibeth.rdma_port && port!=tile->ibeth.rdma_port ) continue;
      if( !fd_ibeth_rdma_port_matches_if( entry->d_name, (uint)port, tile->ibeth.if_name ) ) continue;
      if( FD_UNLIKELY( rdma_name[0] ) )
        FD_LOG_ERR(( "multiple RDMA ports match interface `%s` (`%s` port %u and `%s` port %lu)",
                     tile->ibeth.if_name, rdma_name, *rdma_port, entry->d_name, port ));
      fd_cstr_ncpy( rdma_name, entry->d_name, FD_MLX5_RDMA_NAME_MAX );
      *rdma_port = (uint)port;
    }
    closedir( ports );
  }
  if( FD_UNLIKELY( closedir( dir ) ) )
    FD_LOG_ERR(( "closedir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !rdma_name[0] ) )
    FD_LOG_ERR(( "RDMA device port for interface `%s` not found", tile->ibeth.if_name ));
}

static inline void
fd_ibeth_rx_recycle( fd_ibeth_tile_t * ctx,
                     ulong             chunk ) {
  ctx->rx_pending[ --ctx->rx_pending_rem ].chunk = (uint)chunk;

  if( !ctx->rx_pending_rem ) {
    fd_mlx5_recv_t recv[ FD_IBETH_BATCH_CAP ];
    uint const recv_cnt = ctx->batch_size-ctx->rx_pending_rem;
    for( uint i=0U; i<recv_cnt; i++ ) {
      uint rx_chunk = ctx->rx_pending[ ctx->rx_pending_rem+i ].chunk;
      recv[ i ] = (fd_mlx5_recv_t) {
        .frame    = fd_chunk_to_laddr( ctx->umem_base, rx_chunk ),
        .frame_sz = FD_NET_MTU,
        .user_data   = rx_chunk,
        .lkey     = ctx->mr_lkey
      };
    }
    if( FD_UNLIKELY( fd_mlx5_qp_post_recv_batch( &ctx->hw.qp, recv, recv_cnt ) ) )
      FD_LOG_ERR(( "fd_mlx5_qp_post_recv_batch failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    ctx->rx_pending_rem = ctx->batch_size;
  }
}

/* rxq_assign adds a routing rule.  All incoming IPv4 UDP ports with the
   specified dst port will be redirected to the first output link in the
   topology with the specified names.  frag_meta descriptors are annotated
   with the given 'dst_proto' value. */

static void
rxq_register_out( fd_ibeth_tile_t * ctx,
                  ulong             out_idx ) {
  for( ulong i=0UL; i<ctx->rx_link_cnt; i++ )
    if( ctx->rx_link_out_idx[ i ]==out_idx ) return;
  FD_TEST( ctx->rx_link_cnt < ctx->flow_rule_max );
  ctx->rx_link_out_idx[ ctx->rx_link_cnt++ ] = (uchar)out_idx;
}

static void
rxq_assign( fd_ibeth_tile_t *      ctx,
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
      FD_LOG_ERR(( "ibeth output link `%s` is missing for UDP port %hu", out_link, dst_port ));
    return;
  }
  if( FD_UNLIKELY( ctx->dst_port_cnt>=ctx->flow_rule_max ) ) {
    FD_LOG_ERR(( "ibeth tile flow rule count exceeds configured max of %u", ctx->flow_rule_max ));
  }
  uint const idx = ctx->dst_port_cnt;
  ctx->dst_protos [ idx ] = (uchar)dst_proto;
  ctx->dst_ports  [ idx ] = dst_port;
  ctx->dst_out_idx[ idx ] = (uchar)out_idx;
  ctx->dst_port_cnt++;
  rxq_register_out( ctx, out_idx );
}

static void
rxq_assign_all( fd_ibeth_tile_t *       ctx,
                fd_topo_t const *       topo,
                fd_topo_tile_t const *  tile ) {
  ctx->rx_out_cnt = (uchar)tile->out_cnt;
  ctx->repair_out_idx = UCHAR_MAX;
  rxq_assign( ctx, topo, tile, DST_PROTO_TPU_UDP,  "net_quic",   tile->ibeth.net.legacy_transaction_listen_port, 1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_TPU_QUIC, "net_quic",   tile->ibeth.net.quic_transaction_listen_port,   1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_SHRED,    "net_shred",  tile->ibeth.net.shred_listen_port,              1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_GOSSIP,   "net_gossvf", tile->ibeth.net.gossip_listen_port,             1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_REPAIR,   "net_shred",  tile->ibeth.net.repair_client_listen_port,      1 );
  rxq_assign( ctx, topo, tile, DST_PROTO_RSERVE,   "net_rserve", tile->ibeth.net.repair_serve_listen_port,       0 );
  rxq_assign( ctx, topo, tile, DST_PROTO_SEND,     "net_txsend", tile->ibeth.net.txsend_src_port,                1 );

  if( tile->ibeth.net.repair_client_listen_port ) {
    ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "net_repair", 0UL );
    if( FD_UNLIKELY( out_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "ibeth output link `net_repair` is missing for repair pings" ));
    ctx->repair_out_idx = (uchar)out_idx;
    rxq_register_out( ctx, out_idx );
  }
}

static int
fd_ibeth_mlx5_fini( fd_ibeth_tile_t * ctx ) {
  while( ctx->hw.flow_cnt ) {
    if( FD_UNLIKELY( !fd_mlx5_flow_fini( &ctx->hw.flows[ ctx->hw.flow_cnt-1U ] ) ) ) return -1;
    ctx->hw.flow_cnt--;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_QP ) {
    if( FD_UNLIKELY( !fd_mlx5_qp_fini( &ctx->hw.qp ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_QP;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_MR ) {
    if( FD_UNLIKELY( !fd_mlx5_mr_fini( &ctx->hw.mr ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_MR;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_PD ) {
    if( FD_UNLIKELY( !fd_mlx5_pd_fini( &ctx->hw.pd ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_PD;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_TX_CQ ) {
    if( FD_UNLIKELY( !fd_mlx5_cq_fini( &ctx->hw.tx_cq ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_TX_CQ;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_RX_CQ ) {
    if( FD_UNLIKELY( !fd_mlx5_cq_fini( &ctx->hw.rx_cq ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_RX_CQ;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_UAR ) {
    if( FD_UNLIKELY( !fd_mlx5_uar_fini( &ctx->hw.uar ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_UAR;
  }
  if( ctx->hw.initialized & FD_IBETH_MLX5_CONTEXT ) {
    if( FD_UNLIKELY( !fd_mlx5_context_fini( &ctx->hw.context ) ) ) return -1;
    ctx->hw.initialized &= ~FD_IBETH_MLX5_CONTEXT;
  }
  return 0;
}

static void
fd_ibeth_mlx5_fail( fd_ibeth_tile_t * ctx,
                    char const *       what ) {
  int err = errno;
  if( FD_UNLIKELY( fd_ibeth_mlx5_fini( ctx ) ) )
    FD_LOG_WARNING(( "direct mlx5 cleanup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_LOG_ERR(( "%s failed (%i-%s)", what, err, fd_io_strerror( err ) ));
}

/* privileged_init creates direct mlx5 resources through uverbs. */

FD_FN_UNUSED static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_ibeth_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ibeth_tile_t), sizeof(fd_ibeth_tile_t) );
  memset( ctx, 0, sizeof(fd_ibeth_tile_t) );
  ulong queue_footprint = fd_mlx5_queue_footprint( tile->ibeth.rx_queue_size,
                                                   tile->ibeth.tx_queue_size );
  ctx->queue_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_MLX5_PAGE_SZ, queue_footprint );
  ctx->rx_user_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),
                                            tile->ibeth.rx_queue_size*sizeof(ulong) );
  ctx->tx_user_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),
                                            tile->ibeth.tx_queue_size*sizeof(ulong) );
  ctx->batch_size   = tile->ibeth.batch_size;
  ctx->flow_rule_max = tile->ibeth.flow_rule_max;

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
    /* FIXME support receive side scaling. */
    FD_LOG_ERR(( "Sorry, net.provider='ibverbs' only supports layout.net_tile_count=1" ));
  }

  char rdma_name[ FD_MLX5_RDMA_NAME_MAX ];
  uint rdma_port;
  fd_ibeth_rdma_dev_find( rdma_name, &rdma_port, tile );
  FD_LOG_INFO(( "Opening direct mlx5 device `%s` port %u", rdma_name, rdma_port ));
  if( FD_UNLIKELY( !fd_mlx5_context_init( &ctx->hw.context, rdma_name, rdma_port ) ) )
    fd_ibeth_mlx5_fail( ctx, "fd_mlx5_context_init" );
  ctx->hw.initialized |= FD_IBETH_MLX5_CONTEXT;

  int async_fd    = ctx->hw.context.async_fd;
  int async_flags = fcntl( async_fd, F_GETFL );
  if( FD_UNLIKELY( 0!=fcntl( async_fd, F_SETFL, async_flags|O_NONBLOCK) ) ) {
    fd_ibeth_mlx5_fail( ctx, "making mlx5 async fd non-blocking" );
  }

  uint if_idx = if_nametoindex( tile->ibeth.if_name );
  if( FD_UNLIKELY( !if_idx ) ) {
    FD_LOG_ERR(( "if_nametoindex(%s) failed (%i-%s)",
                 tile->ibeth.if_name, errno, fd_io_strerror( errno ) ));
  }
  ctx->r.if_virt = if_idx;
  ctx->r.default_address = fd_ibeth_if_ip4_addr( tile->ibeth.if_name );

  if( FD_UNLIKELY( !fd_mlx5_queue_layout_init( &ctx->queue_layout, &ctx->hw.context,
                                               tile->ibeth.rx_queue_size,
                                               tile->ibeth.tx_queue_size ) ||
                   !fd_mlx5_queue_mem_init( ctx->queue_mem, &ctx->queue_layout ) ) )
    fd_ibeth_mlx5_fail( ctx, "direct mlx5 queue layout" );
  if( FD_UNLIKELY( !fd_mlx5_uar_init( &ctx->hw.uar, &ctx->hw.context ) ) )
    fd_ibeth_mlx5_fail( ctx, "fd_mlx5_uar_init" );
  ctx->hw.initialized |= FD_IBETH_MLX5_UAR;
  if( FD_UNLIKELY( !fd_mlx5_cq_init( &ctx->hw.rx_cq, &ctx->hw.context, &ctx->hw.uar,
                                     (uchar *)ctx->queue_mem+ctx->queue_layout.rx_cq_off,
                                     (uint *)((uchar *)ctx->queue_mem+ctx->queue_layout.rx_cq_db_off),
                                     tile->ibeth.rx_queue_size ) ) ) fd_ibeth_mlx5_fail( ctx, "fd_mlx5_cq_init(rx)" );
  ctx->hw.initialized |= FD_IBETH_MLX5_RX_CQ;
  if( FD_UNLIKELY( !fd_mlx5_cq_init( &ctx->hw.tx_cq, &ctx->hw.context, &ctx->hw.uar,
                                     (uchar *)ctx->queue_mem+ctx->queue_layout.tx_cq_off,
                                     (uint *)((uchar *)ctx->queue_mem+ctx->queue_layout.tx_cq_db_off),
                                     tile->ibeth.tx_queue_size ) ) ) fd_ibeth_mlx5_fail( ctx, "fd_mlx5_cq_init(tx)" );
  ctx->hw.initialized |= FD_IBETH_MLX5_TX_CQ;
  if( FD_UNLIKELY( !fd_mlx5_pd_init( &ctx->hw.pd, &ctx->hw.context ) ) ) fd_ibeth_mlx5_fail( ctx, "fd_mlx5_pd_init" );
  ctx->hw.initialized |= FD_IBETH_MLX5_PD;
  if( FD_UNLIKELY( !fd_mlx5_mr_init( &ctx->hw.mr, &ctx->hw.pd, umem_frame0, umem_sz ) ) )
    fd_ibeth_mlx5_fail( ctx, "fd_mlx5_mr_init" );
  ctx->hw.initialized |= FD_IBETH_MLX5_MR;
  ctx->mr_lkey = ctx->hw.mr.lkey;
  if( FD_UNLIKELY( !fd_mlx5_qp_init( &ctx->hw.qp, &ctx->hw.pd, &ctx->hw.rx_cq, &ctx->hw.tx_cq, &ctx->hw.uar,
                                     (uchar *)ctx->queue_mem+ctx->queue_layout.rq_off,
                                     (uchar *)ctx->queue_mem+ctx->queue_layout.sq_off,
                                     ctx->rx_user_data, ctx->tx_user_data,
                                     (uint *)((uchar *)ctx->queue_mem+ctx->queue_layout.qp_db_off), 0U ) ) )
    fd_ibeth_mlx5_fail( ctx, "fd_mlx5_qp_init" );
  ctx->hw.initialized |= FD_IBETH_MLX5_QP;
  if( FD_UNLIKELY( !fd_mlx5_qp_start( &ctx->hw.qp ) ) ) fd_ibeth_mlx5_fail( ctx, "fd_mlx5_qp_start" );

  rxq_assign_all( ctx, topo, tile );
  for( ulong i=0UL; i<(ctx->dst_port_cnt); i++ ) {
    if( FD_UNLIKELY( !fd_mlx5_flow_init_udp( &ctx->hw.flows[ ctx->hw.flow_cnt ], &ctx->hw.qp,
                                             tile->ibeth.net.bind_address,
                                             ctx->dst_ports[ i ] ) ) )
      fd_ibeth_mlx5_fail( ctx, "fd_mlx5_flow_init_udp" );
    ctx->hw.flow_cnt++;
    FD_LOG_DEBUG(( "Created flow rule for ip4.dst_ip=" FD_IP4_ADDR_FMT " udp.dst_port:%hu",
                   FD_IP4_ADDR_FMT_ARGS( tile->ibeth.net.bind_address ),
                   ctx->dst_ports[ i ] ));
  }
  FD_LOG_INFO(( "Installed %u direct mlx5 flow rules", ctx->hw.flow_cnt ));
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_ibeth_tile_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ibeth_tile_t), sizeof(fd_ibeth_tile_t) );
  ulong queue_footprint = fd_mlx5_queue_footprint( tile->ibeth.rx_queue_size,
                                                   tile->ibeth.tx_queue_size );
  ctx->queue_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_MLX5_PAGE_SZ, queue_footprint );
  ctx->rx_user_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),
                                               tile->ibeth.rx_queue_size*sizeof(ulong) );
  ctx->tx_user_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),
                                               tile->ibeth.tx_queue_size*sizeof(ulong) );
  ctx->batch_size    = tile->ibeth.batch_size;
  ctx->flow_rule_max = tile->ibeth.flow_rule_max;
  void *            deque_mem = FD_SCRATCH_ALLOC_APPEND( l, tx_free_align(), tx_free_footprint( tile->ibeth.tx_queue_size ) );
  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * fib_local_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->ibeth.route_max, tile->ibeth.route_peer_max ) );
  void * fib_main_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->ibeth.route_max, tile->ibeth.route_peer_max ) );

  /* chunk 0 is used as a sentinel value, so ensure actual chunk indices
     do not use that value. */
  FD_TEST( ctx->umem_chunk0 > 0 );


  ctx->rx_pending_rem = ctx->batch_size;

  /* Post RX descriptors */
  ulong frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong next_chunk   = ctx->umem_chunk0;
  ctx->rx_chunk0     = (uint)next_chunk;
  FD_TEST( tile->ibeth.rx_queue_size>ctx->batch_size );
  ulong const rx_fill_cnt = tile->ibeth.rx_queue_size-ctx->batch_size;
  for( ulong i=0UL; i<rx_fill_cnt; i++ ) {
    fd_ibeth_rx_recycle( ctx, next_chunk );
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
  if( FD_UNLIKELY( tile->in_cnt>FD_TOPO_MAX_TILE_IN_LINKS ) ) {
    FD_LOG_ERR(( "ibeth tile in link count %lu exceeds max of %lu", tile->in_cnt, FD_TOPO_MAX_TILE_IN_LINKS ));
  }
  ctx->txq_cnt = tile->in_cnt;
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "iproute_out" ) ) {
      ctx->in_kind[ i ] = IN_KIND_IPROUTE;
    } else {
      ctx->in_kind[ i ] = IN_KIND_NET;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "ibeth tile in link does not have a normal MTU" ));
    }

    ctx->txq[ i ].base   = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->txq[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->txq[ i ].base, link->dcache );
    ctx->txq[ i ].wmark  = fd_dcache_compact_wmark(  ctx->txq[ i ].base, link->dcache, link->mtu );
  }

  /* Join netbase objects */
  FD_TEST( fd_fib4_join( ctx->r.fib_local, fd_fib4_new( fib_local_mem, tile->ibeth.route_max, tile->ibeth.route_peer_max, tile->ibeth.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->r.fib_main,  fd_fib4_new( fib_main_mem,  tile->ibeth.route_max, tile->ibeth.route_peer_max, tile->ibeth.route_peer_seed ) ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->r.netdev_shared, fd_topo_obj_laddr( topo, tile->ibeth.netdev_tbl_obj_id ) ) );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->r.netdev_tbl, netdev_tbl_local ) );
  fd_netdev_tbl_copy( &ctx->r.netdev_tbl, &ctx->r.netdev_shared );
  ctx->r.bind_address = tile->ibeth.net.bind_address;

  ulong neigh4_obj_id = tile->ibeth.neigh4_obj_id;
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
  if( FD_UNLIKELY( next_chunk > ctx->umem_wmark ) ) {
    FD_LOG_ERR(( "dcache is too small (topology bug)" ));
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)ctx+scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow" ));
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
poll_async_events( fd_ibeth_tile_t * ctx ) {
  for(;;) {
    struct ib_uverbs_async_event_desc event;
    ssize_t read_sz = read( ctx->hw.context.async_fd, &event, sizeof(event) );
    if( FD_LIKELY( read_sz<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ) ) break;
    if( FD_UNLIKELY( read_sz!=(ssize_t)sizeof(event) ) )
      FD_LOG_ERR(( "mlx5 async event read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    FD_LOG_INFO(( "mlx5 async event %u on element %lu", event.event_type, (ulong)event.element ));
    if( FD_UNLIKELY( event.event_type<=1U ) )
      FD_LOG_ERR(( "fatal mlx5 CQ/QP async event %u", event.event_type ));
  }
}

static inline void
during_housekeeping( fd_ibeth_tile_t * ctx ) {
  poll_async_events( ctx );
  if( FD_LIKELY( !fd_seqlock_locked_hint( &ctx->r.netdev_shared.hdr->seqlock ) ) ) {
    fd_netdev_tbl_copy( &ctx->r.netdev_tbl, &ctx->r.netdev_shared );
  }
}

static inline int
fd_ibeth_rx_route( fd_ibeth_tile_t const * ctx,
                   ushort                  net_dport,
                   ulong                   sz,
                   ulong *                 out_idx,
                   ulong *                 proto ) {
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

/* fd_ibeth_rx_pkt handles a direct mlx5 RX completion.  If the completion
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
                 uint                opcode ) {
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
  if( FD_UNLIKELY( !fd_ibeth_rx_route( ctx, net_dport, sz, &out_idx, &proto ) ) ) return wr_id;

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
  ulong const tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

  fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub );
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

static inline int
fd_ibeth_tx_flush( fd_ibeth_tile_t * ctx ) {
  uint const tx_pending_cnt = ctx->tx_pending_cnt;
  if( FD_UNLIKELY( !tx_pending_cnt ) ) return 0;

  fd_mlx5_send_t send[ FD_IBETH_BATCH_CAP ];
  for( uint i=0U; i<tx_pending_cnt; i++ ) {
    fd_ibeth_send_wr_t meta = ctx->tx_pending[ i ];
    send[ i ] = (fd_mlx5_send_t) {
      .frame        = fd_chunk_to_laddr( ctx->umem_base, meta.chunk ),
      .frame_sz     = meta.sz,
      .user_data       = fd_ibeth_tx_user_data( meta ),
      .lkey         = ctx->mr_lkey,
      .tx_inline_sz = ctx->hw.context.eth_min_inline_sz
    };
  }
  if( FD_UNLIKELY( fd_mlx5_qp_post_send_batch( &ctx->hw.qp, send, tx_pending_cnt ) ) )
    for( uint i=0U; i<tx_pending_cnt; i++ ) fd_ibeth_tx_recycle( ctx, ctx->tx_pending[ i ].chunk );

  ctx->tx_pending_cnt  = 0U;
  ctx->tx_pending_idle = 0U;
  return 1;
}

static inline int
fd_ibeth_poll_rx( fd_ibeth_tile_t *   ctx,
                  fd_stem_context_t * stem ) {
  fd_ibeth_rx_cqe_t batch[ FD_IBETH_BATCH_CAP ];
  fd_mlx5_rx_comp_t comp[ FD_IBETH_BATCH_CAP ];
  int batch_cnt = fd_mlx5_qp_poll_rx( &ctx->hw.qp, comp, ctx->batch_size );
  if( FD_UNLIKELY( batch_cnt<0 ) )
    FD_LOG_ERR(( "direct mlx5 RX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !batch_cnt ) ) return 0;

  for( uint i=0U; i<(uint)batch_cnt; i++ ) {
    batch[ i ] = (fd_ibeth_rx_cqe_t) {
      .byte_len = comp[ i ].byte_len,
      .chunk    = (uint)comp[ i ].user_data,
      .opcode   = comp[ i ].opcode
    };
  }

  for( uint i=0U; i<(uint)batch_cnt; i++ ) {
    ulong const chunk = batch[ i ].chunk;
    if( FD_LIKELY( batch[ i ].opcode==FD_MLX5_CQE_RESP_SEND &&
                   chunk>=ctx->umem_chunk0 && chunk<=ctx->umem_wmark ) ) {
      __builtin_prefetch( fd_chunk_to_laddr_const( ctx->umem_base, chunk ), 0, 3 );
    }
  }

  for( uint i=0U; i<(uint)batch_cnt; i++ ) {
    fd_ibeth_rx_cqe_t const * cqe = batch+i;
    ulong freed_chunk = fd_ibeth_rx_pkt( ctx, stem, cqe->chunk, cqe->byte_len, cqe->opcode );
    if( FD_UNLIKELY( !freed_chunk ) ) FD_LOG_CRIT(( "invalid chunk in mcache" ));
    fd_ibeth_rx_recycle( ctx, freed_chunk );
  }
  return 1;
}

static inline int
fd_ibeth_poll_tx( fd_ibeth_tile_t * ctx ) {
  fd_mlx5_tx_comp_t comp[ FD_IBETH_BATCH_CAP ];
  int busy = 0;
  for( uint poll_cnt=0U; poll_cnt<ctx->batch_size; poll_cnt++ ) {
    int batch_cnt = fd_mlx5_qp_poll_tx( &ctx->hw.qp, comp, ctx->batch_size );
    if( FD_UNLIKELY( batch_cnt<0 ) )
      FD_LOG_ERR(( "direct mlx5 TX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !batch_cnt ) ) break;
    busy = 1;
    for( uint i=0U; i<(uint)batch_cnt; i++ ) {
      fd_ibeth_send_wr_t meta = fd_ibeth_tx_meta( comp[ i ].user_data );
      if( FD_LIKELY( comp[ i ].opcode==FD_MLX5_CQE_REQ ) ) {
        ctx->metrics.tx_pkt_cnt++;
        ctx->metrics.tx_bytes_total += meta.sz;
      }
      fd_ibeth_tx_recycle( ctx, meta.chunk );
    }
  }
  return busy;
}

static inline void
before_credit( fd_ibeth_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  int tx_submit_busy = 0;
  if( FD_UNLIKELY( ctx->tx_pending_cnt ) ) {
    if( ctx->tx_pending_idle ) tx_submit_busy = fd_ibeth_tx_flush( ctx );
    else                       ctx->tx_pending_idle = 1U;
  }
  int tx_complete_busy = !tx_free_full( ctx->tx_free ) && fd_ibeth_poll_tx( ctx );
  *charge_busy |= tx_submit_busy | tx_complete_busy;
}

/* after_credit is called every run loop iteration, provided there is
   sufficient downstream credit for forwarding on all output links. */

static inline void
after_credit( fd_ibeth_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
  int *               charge_busy ) {
  (void)poll_in;
  int rx_busy = fd_ibeth_poll_rx( ctx, stem );
  *charge_busy |= rx_busy;
}

/* {before,during,after}_frag copy a packet received from an input link out
   to the direct mlx5 send queue. */

static inline int
before_frag( fd_ibeth_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
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
after_frag( fd_ibeth_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)tsorig; (void)tspub; (void)stem;

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
  ctx->tx_pending[ batch_idx ] = (fd_ibeth_send_wr_t) {
    .chunk = (uint)chunk,
    .sz    = (uint)sz
  };

  /* Consume frame */
  tx_free_pop_head( ctx->tx_free );
  ctx->tx_pending_cnt  = batch_idx+1U;
  ctx->tx_pending_idle = 0U;
  if( FD_UNLIKELY( ctx->tx_pending_cnt==ctx->batch_size ) ) fd_ibeth_tx_flush( ctx );
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_ibeth_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_ibeth_tile_t)
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_BURST                  FD_IBETH_BATCH_CAP
#define STEM_LAZY                   130000UL /* 130us */
#include "../../stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_ibeth = {
  .name                     = "ibeth",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
