#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <stdlib.h>
#include "fd_xdp_tile.c"
#include "../../../disco/topo/fd_topob.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../waltz/ip/fd_fib4.h"
#include "../../../util/tmpl/fd_map.h"
#include "../../../tango/dcache/fd_dcache.h"
#include "../../../tango/mcache/fd_mcache.h"

#if defined(__GNUC__) && (__GNUC__ >= 9)
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

#define WKSP_TAG  1UL
#define SHRED_PORT ((ushort)4242)
#define SCRATCH_MAX (5242880UL) // 5MB
uchar wksp_scratch[ SCRATCH_MAX ] __attribute__((aligned((FD_SHMEM_NORMAL_PAGE_SZ))));

#define IF_IDX_LO   1U
#define IF_IDX_ETH0 7U
#define IF_IDX_ETH1 8U
#define IF_IDX_GRE0 33U
#define IF_IDX_GRE1 34U

/* Network configuration */
static uint const banned_ip              = FD_IP4_ADDR( 7,0,0,1 );      /* blackholed at the route table */
static uint const default_src_ip         = FD_IP4_ADDR( 64,130,35,241 ); /* default src ip */
static uint const random_ip              = FD_IP4_ADDR( 64,130,35,240 ); /* some random ip */
static uint const gw_ip                  = FD_IP4_ADDR( 192,168,1,1 );  /* gateway */
static uint const gre0_src_ip            = FD_IP4_ADDR( 192,168,123,1 );
static uint const gre0_dst_ip            = FD_IP4_ADDR( 192,168,123,6 );
static uint const gre0_outer_src_ip      = FD_IP4_ADDR( 10,0,0,1 );
static uint const gre0_outer_dst_ip      = FD_IP4_ADDR( 10,0,0,2 );
static uint const gre0_outer_src_ip_fake = FD_IP4_ADDR( 10,0,0,3 );
static uint const gre1_src_ip            = FD_IP4_ADDR( 193,169,123,1 );
static uint const gre1_dst_ip            = FD_IP4_ADDR( 193,169,123,6 );
static uint const gre1_outer_src_ip      = FD_IP4_ADDR( 11,1,0,1 );
static uint const gre1_outer_dst_ip      = FD_IP4_ADDR( 11,1,0,2 );

static uchar eth0_dst_mac_addr[6] = {0xa,0xb,0xc,0xd,0xe,0xf};
static uchar eth0_src_mac_addr[6] = {0x1,0x2,0x3,0x4,0x5,0x6};
static uchar eth1_dst_mac_addr[6] = {0x12,0x34,0x56,0x78,0x9a,0xbc};
static uchar eth1_src_mac_addr[6] = {0xde,0xf1,0x23,0x45,0x67,0x89};

/* Declare XDP fill and RX cons and prod sequence numbers */
static uint xdp_rx_ring_cons = 0;
static uint xdp_rx_ring_prod = 0;
static uint xdp_tx_ring_cons = 0;
static uint xdp_tx_ring_prod = 0;
static uint xdp_tx_flags     = 0;
static uint xdp_fr_ring_cons = 0;
static uint xdp_fr_ring_prod = 0;
static uint xdp_cr_ring_cons = 0;
static uint xdp_cr_ring_prod = 0;

static ulong const  rxq_depth       = 128UL;
static ulong const  txq_depth       = 128UL;
static ulong        link_depth      = 128UL;
static uint  const  ring_fr_depth   = 128U * 2; // depth for fill ring
static uint  const  xsk_rings_depth = 128U;     // depth for rx, tx, and completion ring

static void * umem_base     = wksp_scratch;
static ulong const frame_sz = 2048UL;


static void
add_neighbor( fd_neigh4_hmap_t * join,
              uint               ip4_addr,
              uchar mac0, uchar mac1, uchar mac2,
              uchar mac3, uchar mac4, uchar mac5 ) {
  fd_neigh4_hmap_query_t query[1];
  int prepare_res = fd_neigh4_hmap_prepare( join, &ip4_addr, NULL, query, FD_MAP_FLAG_BLOCKING );
  FD_TEST( prepare_res==FD_MAP_SUCCESS );
  fd_neigh4_entry_t * ele = fd_neigh4_hmap_query_ele( query );
  ele->state    = FD_NEIGH4_STATE_ACTIVE;
  ele->ip4_addr = ip4_addr;
  ele->mac_addr[0] = mac0; ele->mac_addr[1] = mac1; ele->mac_addr[2] = mac2;
  ele->mac_addr[3] = mac3; ele->mac_addr[4] = mac4; ele->mac_addr[5] = mac5;
  fd_neigh4_hmap_publish( query );
}

static void
setup_routing_table( fd_net_ctx_t * ctx,
                     void * fib4_local_mem,
                     void * fib4_main_mem ) {
  /* Basic routing tables */
  fd_fib4_t * fib_local = ctx->fib_local;
  fd_fib4_t * fib_main = ctx->fib_main;
  FD_TEST( fd_fib4_join( fib_local, fib4_local_mem ) );
  FD_TEST( fd_fib4_join( fib_main, fib4_main_mem ) );

  fd_fib4_hop_t hop1 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_LO,
    .ip4_src = FD_IP4_ADDR( 127,0,0,1 ),
    .rtype   = FD_FIB4_RTYPE_LOCAL
  };
  fd_fib4_hop_t hop2 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH1,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = default_src_ip,
    .ip4_gw  = gw_ip
  };
  fd_fib4_hop_t hop3 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre0_outer_src_ip_fake
  };
  fd_fib4_hop_t hop4 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_GRE0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre0_src_ip
  };
  fd_fib4_hop_t hop5 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_BLACKHOLE
  };
  fd_fib4_hop_t hop6 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_GRE1,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre1_src_ip
  };
  fd_fib4_hop_t hop7 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH1,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre1_outer_src_ip
  };

  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,0,1 ), 32, 0U, &hop1 ) );
  FD_TEST( fd_fib4_insert( fib_main,  FD_IP4_ADDR( 0,0,0,0 ), 0, 0U, &hop2 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre0_outer_dst_ip, 32, 0U, &hop3 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre0_dst_ip, 32, 0U, &hop4 ) );
  FD_TEST( fd_fib4_insert( fib_main,  banned_ip, 32, 0U, &hop5 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre1_dst_ip, 32, 0U, &hop6 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre1_outer_dst_ip, 32, 0U, &hop7 ) );
}

static void
setup_netdev_table( fd_net_ctx_t * ctx ) {
  /* GRE interfaces */
  ctx->netdev_tbl.dev_tbl[IF_IDX_GRE0] = (fd_netdev_t) {
    .if_idx = IF_IDX_GRE0,
    .dev_type = ARPHRD_IPGRE,
    .gre_dst_ip = gre0_outer_dst_ip,
    .gre_src_ip = gre0_outer_src_ip
  };
  ctx->netdev_tbl.dev_tbl[IF_IDX_GRE1] = (fd_netdev_t) {
    .if_idx = IF_IDX_GRE1,
    .dev_type = ARPHRD_IPGRE,
    .gre_dst_ip = gre1_outer_dst_ip,
  };
  /* Eth0 interface */
  ctx->netdev_tbl.dev_tbl[IF_IDX_ETH0] = (fd_netdev_t) {
    .if_idx = IF_IDX_ETH0,
    .dev_type = ARPHRD_ETHER,
  };
  /* Eth1 interface */
  ctx->netdev_tbl.dev_tbl[IF_IDX_ETH1] = (fd_netdev_t) {
    .if_idx = IF_IDX_ETH1,
    .dev_type = ARPHRD_ETHER,
  };
  /* Lo interface */
  ctx->netdev_tbl.dev_tbl[IF_IDX_LO] = (fd_netdev_t) {
    .if_idx = IF_IDX_LO,
    .dev_type = ARPHRD_LOOPBACK,
  };
  fd_memcpy( (fd_netdev_t *)ctx->netdev_tbl.dev_tbl[IF_IDX_ETH0].mac_addr, eth0_src_mac_addr, 6 );
  fd_memcpy( (fd_netdev_t *)ctx->netdev_tbl.dev_tbl[IF_IDX_ETH1].mac_addr, eth1_src_mac_addr, 6 );
  ctx->netdev_tbl.hdr->dev_cnt = IF_IDX_GRE1 + 1;
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  ulong part_max = fd_wksp_part_max_est( SCRATCH_MAX, 64UL );
  ulong data_max = fd_wksp_data_max_est( SCRATCH_MAX, part_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( wksp_scratch, "wksp", 1234U, part_max, data_max ) );
  FD_TEST( wksp );
  fd_shmem_join_anonymous( "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_scratch, FD_SHMEM_NORMAL_PAGE_SZ, sizeof(wksp_scratch)>>FD_SHMEM_NORMAL_LG_PAGE_SZ );

  /* Mock a topology */
  static fd_topo_t topo[1];
  fd_topob_wksp( topo, "wksp" );
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "net", "wksp", "wksp", cpu_idx, 0, 0 );
  topo_tile->xdp.xdp_rx_queue_size = (uint)rxq_depth;
  topo_tile->xdp.xdp_tx_queue_size = (uint)txq_depth;
  topo_tile->xdp.free_ring_depth   = (uint)txq_depth;
  topo->workspaces[topo_tile->tile_obj_id].wksp = wksp;
  fd_memcpy(topo_tile->xdp.xdp_mode, "skb", 4);
  FD_TEST( topo_tile->tile_obj_id == topo->tile_cnt - 1 );

  /* Allocate tile memory */
  fd_topo_tile_t * net_tile = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( topo_tile ), WKSP_TAG );
  FD_TEST( net_tile );
  memset( net_tile, 0, sizeof(fd_topo_net_tile_t) );
  topo->objs[ topo_tile->tile_obj_id ].offset = (ulong)net_tile - (ulong)wksp;
  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->tile_obj_id )==net_tile );


  /* Net tile UMEM/dcache */
  ulong const umem_dcache_depth   =
      rxq_depth +       /* RX mcache */
      ring_fr_depth +   /* XDP fill ring */
      xsk_rings_depth + /* XDP RX ring */
      xsk_rings_depth;  /* XDP TX ring */
  ulong const umem_dcache_data_sz = fd_dcache_req_data_sz( FD_NET_MTU, umem_dcache_depth, 1UL, 1 );
  void *      umem_dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( umem_dcache_data_sz, 0UL ), WKSP_TAG );
  FD_TEST( fd_dcache_join( fd_dcache_new( umem_dcache_mem, umem_dcache_data_sz, 0UL ) ) );
  fd_topo_obj_t * umem_dcache_obj          = fd_topob_obj( topo, "dcache", "wksp" );
  topo->objs[ umem_dcache_obj->id ].offset = (ulong)umem_dcache_mem - (ulong)wksp;
  topo_tile->net.umem_dcache_obj_id   = umem_dcache_obj->id;
  FD_TEST( fd_topo_obj_laddr( topo, umem_dcache_obj->id )==umem_dcache_mem );

  /* Mock an RX link */
  fd_topo_link_t * const rx_link = fd_topob_link( topo, "net_shred", "wksp", rxq_depth, FD_NET_MTU, 1UL );
  FD_TEST( rx_link->id == topo->link_cnt - 1 );
  void * rx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( rxq_depth, 0UL ), WKSP_TAG );
  rx_link->mcache      = fd_mcache_join( fd_mcache_new( rx_mcache_mem, rxq_depth, 0UL, 0UL ) );
  FD_TEST( rx_link->mcache );
  topo->objs[ rx_link->mcache_obj_id ].offset = (ulong)rx_mcache_mem - (ulong)wksp;
  rx_link->dcache_obj_id = umem_dcache_obj->id;

  /* Mock a TX link */
  fd_topo_link_t * const tx_link = fd_topob_link( topo, "shred_net", "wksp", txq_depth, FD_NET_MTU, 1UL );
  void *  tx_mcache_mem  = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( txq_depth, 0UL ), WKSP_TAG );
  FD_TEST( tx_mcache_mem );
  tx_link->mcache = fd_mcache_join( fd_mcache_new( tx_mcache_mem, txq_depth, 0UL, 0UL ) );
  FD_TEST( tx_link->mcache );
  ulong  app_tx_dcache_data_sz = fd_dcache_req_data_sz( FD_NET_MTU, txq_depth, 1UL, 1 );
  void * app_tx_dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( app_tx_dcache_data_sz, 0UL ), WKSP_TAG );
  tx_link->dcache = fd_dcache_join( fd_dcache_new( app_tx_dcache_mem, app_tx_dcache_data_sz, 0UL ) );
  FD_TEST( tx_link->dcache );

  ulong       tx_seq    = 0UL;
  ulong const tx_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( app_tx_dcache_mem ), tx_link->dcache );
  ulong const tx_wmark  = fd_dcache_compact_wmark( fd_wksp_containing( app_tx_dcache_mem ), tx_link->dcache, FD_NET_MTU );
  ulong       tx_chunk  = tx_chunk0;

  /* Fib4 Routing Table setup */
  ulong const fib4_max      = 16UL;
  void * fib4_local_mem     = fd_wksp_alloc_laddr( wksp, fd_fib4_align(), fd_fib4_footprint( fib4_max,fib4_max  ), WKSP_TAG );
  void * fib4_main_mem      = fd_wksp_alloc_laddr( wksp, fd_fib4_align(), fd_fib4_footprint( fib4_max, fib4_max ), WKSP_TAG );
  FD_TEST( fd_fib4_new( fib4_local_mem, fib4_max, fib4_max, 12345UL ) );
  FD_TEST( fd_fib4_new( fib4_main_mem,  fib4_max, fib4_max, 12345UL ) );
  fd_topo_obj_t * topo_fib4_local  = fd_topob_obj( topo, "fib4", "wksp" );
  fd_topo_obj_t * topo_fib4_main   = fd_topob_obj( topo, "fib4", "wksp" );
  topo_fib4_local->offset          = (ulong)fib4_local_mem - (ulong)wksp;
  topo_fib4_main->offset           = (ulong)fib4_main_mem  - (ulong)wksp;
  topo_tile->xdp.fib4_local_obj_id = topo_fib4_local->id;
  topo_tile->xdp.fib4_main_obj_id  = topo_fib4_main->id;


  /* Neigh4 table setup */
  ulong const neigh4_ele_max   = 16UL;
  ulong const neigh4_probe_max =  8UL;
  ulong const neigh4_lock_max  =  4UL;
  void * neigh4_hmap_mem = fd_wksp_alloc_laddr( wksp, fd_neigh4_hmap_align(), fd_neigh4_hmap_footprint( neigh4_ele_max, neigh4_lock_max, neigh4_probe_max ), WKSP_TAG );
  void * neigh4_ele_mem  = fd_wksp_alloc_laddr( wksp, alignof(fd_neigh4_entry_t), neigh4_ele_max*sizeof(fd_neigh4_entry_t), WKSP_TAG );
  FD_TEST( fd_neigh4_hmap_new( neigh4_hmap_mem, neigh4_ele_max, neigh4_lock_max, neigh4_probe_max, 1UL ) );
  fd_topo_obj_t * topo_neigh4_hmap = fd_topob_obj( topo, "neigh4_hmap", "wksp" );
  fd_topo_obj_t * topo_neigh4_ele  = fd_topob_obj( topo, "opaque",      "wksp" );
  topo_neigh4_hmap->offset = (ulong)neigh4_hmap_mem - (ulong)wksp;
  topo_neigh4_ele->offset  = (ulong)neigh4_ele_mem  - (ulong)wksp;
  topo_tile->xdp.neigh4_obj_id     = topo_neigh4_hmap->id;
  topo_tile->xdp.neigh4_ele_obj_id = topo_neigh4_ele->id;
  fd_neigh4_hmap_t neigh4_hmap_[1];
  fd_neigh4_hmap_t * neigh4_hmap   = fd_neigh4_hmap_join( neigh4_hmap_, neigh4_hmap_mem, neigh4_ele_mem );
  FD_TEST( neigh4_hmap );

  /* Netdev table double buffer setup */
  ulong           netdev_mtu               = fd_netdev_tbl_footprint(NETDEV_MAX, BOND_MASTER_MAX);
  fd_topo_obj_t * topo_netdev_dbl_buf_obj  = fd_topob_obj( topo, "dbl_buf", "wksp" );
  void *          netdev_dbl_buf_mem       = fd_wksp_alloc_laddr( wksp, fd_dbl_buf_align(), fd_dbl_buf_footprint( netdev_mtu ), WKSP_TAG );
  FD_TEST( netdev_dbl_buf_mem );
  FD_TEST( fd_dbl_buf_new( netdev_dbl_buf_mem, netdev_mtu, 0 ) );
  topo->workspaces[topo_netdev_dbl_buf_obj->wksp_id].wksp = wksp;
  topo->objs[ topo_netdev_dbl_buf_obj->id ].offset = (ulong)netdev_dbl_buf_mem - (ulong)wksp;
  FD_TEST( fd_topo_obj_laddr(topo, topo_netdev_dbl_buf_obj->id)==netdev_dbl_buf_mem );
  topo_tile->xdp.netdev_dbl_buf_obj_id     = topo_netdev_dbl_buf_obj->id;

  /* Attach links to tile */
  fd_topob_tile_out( topo, "net", 0UL, "net_shred", 0UL );
  fd_topob_tile_in( topo, "net", 0UL, "wksp", "shred_net", 0UL, 0, 1 );

  /* Manual "privileged_init/unprivileged init" */
  void * scratch      = fd_topo_obj_laddr( topo, topo_tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );
  fd_memset( ctx, 0, sizeof(fd_net_ctx_t) );
  ctx->net_tile_cnt = 1;
  ctx->free_tx.queue  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), topo_tile->xdp.free_ring_depth * sizeof(ulong) );
  ctx->free_tx.depth  = topo_tile->xdp.free_ring_depth;
  ctx->netdev_buf     = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), ctx->netdev_buf_sz );

  init_device_table( ctx, netdev_dbl_buf_mem );

  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->net.umem_dcache_obj_id )==umem_dcache_mem );
  void * const umem          = fd_dcache_join( umem_dcache_mem );
  FD_TEST( umem );
  ulong  const umem_frame_sz = 2048UL;

  ulong umem_sz = fd_ulong_align_dn( umem_dcache_data_sz, umem_frame_sz );

  ulong  const umem_chunk0    = ( (ulong)umem - (ulong)umem_base )>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark     = umem_chunk0 + ( ( umem_sz-umem_frame_sz )>>FD_CHUNK_LG_SZ );

  ctx->umem        = umem;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;
  ctx->umem_sz     = umem_sz;

  ctx->shred_listen_port = SHRED_PORT;
  ctx->shred_out->mcache = rx_link->mcache;
  ctx->shred_out->sync   = fd_mcache_seq_laddr( ctx->shred_out->mcache );
  ctx->shred_out->depth  = fd_mcache_depth( ctx->shred_out->mcache );
  ctx->shred_out->seq    = fd_mcache_seq_query( ctx->shred_out->sync );

  /* Initialize out link mcache chunks (RX links) */
  ulong frame_off = 0UL;
  for( ulong j=0UL; j<fd_mcache_depth( rx_link->mcache ); j++ ) {
    rx_link->mcache[ j ].chunk = (uint)( ctx->umem_chunk0 + (frame_off>>FD_CHUNK_LG_SZ) );
    frame_off += frame_sz;
  }

  /* Initialize the free_tx ring */
  ulong const tx_depth  = ctx->free_tx.depth;
  for( ulong j=0; j<tx_depth; j++ ) {
    ctx->free_tx.queue[ j ] = (ulong)ctx->umem + frame_off;
    frame_off += frame_sz;
  }
  ctx->free_tx.prod = tx_depth;
  ctx->xsk_cnt = 1U;
  fd_xsk_t * xsk = &ctx->xsk[0];

  /* Initialize xsk rx_ring */
  xsk->ring_rx.packet_ring = fd_wksp_alloc_laddr( wksp, alignof(struct xdp_desc), xsk_rings_depth * sizeof(struct xdp_desc), WKSP_TAG );;
  FD_TEST( xsk->ring_rx.packet_ring );
  fd_memset( xsk->ring_rx.packet_ring, 0, xsk_rings_depth * sizeof(struct xdp_desc) );
  xsk->ring_rx.prod        = &xdp_rx_ring_prod;
  xsk->ring_rx.cons        = &xdp_rx_ring_cons;
  xsk->ring_rx.cached_prod = xdp_rx_ring_prod;
  xsk->ring_rx.cached_cons = xdp_rx_ring_cons;

  /* Initialize xsk tx ring */
  xsk->ring_tx.packet_ring = fd_wksp_alloc_laddr( wksp, alignof(struct xdp_desc), xsk_rings_depth * sizeof(struct xdp_desc), WKSP_TAG );
  FD_TEST( xsk->ring_tx.packet_ring );
  fd_memset( xsk->ring_tx.packet_ring, 0, xsk_rings_depth * sizeof(struct xdp_desc) );
  xsk->ring_tx.prod  = &xdp_tx_ring_prod;
  xsk->ring_tx.cons  = &xdp_tx_ring_cons;
  xsk->ring_tx.flags = &xdp_tx_flags;       // turn off tx flushing
  xsk->ring_tx.depth = xsk_rings_depth;

  /* Initialize xsk fill ring */
  xsk->ring_fr.frame_ring       = fd_wksp_alloc_laddr( wksp, alignof(ulong), ring_fr_depth * sizeof(ulong), WKSP_TAG );
  FD_TEST( xsk->ring_fr.frame_ring );
  fd_memset( xsk->ring_fr.frame_ring, 0, ring_fr_depth * sizeof(ulong) );
  xsk->ring_fr.depth            = ring_fr_depth;
  xsk->ring_fr.cached_prod      = 0;
  xsk->ring_fr.cached_cons      = 0;
  xsk->ring_fr.prod             = &xdp_fr_ring_prod;
  xsk->ring_fr.cons             = &xdp_fr_ring_cons;
  ulong * fr_frame_ring         = xsk->ring_fr.frame_ring;
  /* Allocate free frames for fill ring */
  for( ulong j=0UL; j<(ring_fr_depth/2UL); j++ ) {
    fr_frame_ring[ j ] = frame_off;
    frame_off         += frame_sz;
  }
  xdp_fr_ring_prod         += (ring_fr_depth/2U);
  xsk->ring_fr.cached_prod += (ring_fr_depth/2U);

  /* Initialize completion ring */
  xsk->ring_cr.frame_ring = fd_wksp_alloc_laddr( wksp, alignof(ulong), xsk_rings_depth * sizeof(ulong), WKSP_TAG );
  FD_TEST( xsk->ring_cr.frame_ring );
  fd_memset( xsk->ring_cr.frame_ring, 0, xsk_rings_depth * sizeof(ulong) );
  xsk->ring_cr.depth = xsk_rings_depth;
  xsk->ring_cr.prod  = &xdp_cr_ring_prod;
  xsk->ring_cr.cons  = &xdp_cr_ring_cons;

  /* Routing table */
  setup_routing_table( ctx, fib4_local_mem, fib4_main_mem );

  /* Ensure initial (fake) device table is valid */
  FD_TEST( net_check_gre_interface_exists( ctx )==0 );
  uint is_gre_inf = 0U;
  FD_TEST( net_tx_route( ctx, FD_IP4_ADDR( 1,1,1,1 ), &is_gre_inf )==0 );

  /* Neighbor table */
  add_neighbor( neigh4_hmap, gre0_outer_dst_ip, eth0_dst_mac_addr[0], eth0_dst_mac_addr[1], eth0_dst_mac_addr[2], eth0_dst_mac_addr[3], eth0_dst_mac_addr[4], eth0_dst_mac_addr[5] );
  add_neighbor( neigh4_hmap, gre1_outer_dst_ip, eth1_dst_mac_addr[0], eth1_dst_mac_addr[1], eth1_dst_mac_addr[2], eth1_dst_mac_addr[3], eth1_dst_mac_addr[4], eth1_dst_mac_addr[5] );
  add_neighbor( neigh4_hmap, gw_ip,     eth1_dst_mac_addr[0], eth1_dst_mac_addr[1], eth1_dst_mac_addr[2], eth1_dst_mac_addr[3], eth1_dst_mac_addr[4], eth1_dst_mac_addr[5] );
  FD_TEST( fd_neigh4_hmap_join(
    ctx->neigh4,
    fd_topo_obj_laddr( topo, topo_tile->xdp.neigh4_obj_id ),
    fd_topo_obj_laddr( topo, topo_tile->xdp.neigh4_ele_obj_id ) ) );

  /* Netdev table */
  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->xdp.netdev_dbl_buf_obj_id )==netdev_dbl_buf_mem );
  ctx->netdev_dbl_buf = fd_dbl_buf_join( netdev_dbl_buf_mem );
  ctx->netdev_buf_sz  = fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX );
  ctx->netdev_buf     = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), ctx->netdev_buf_sz );
  fd_netdev_tbl_new( ctx->netdev_buf, NETDEV_MAX, BOND_MASTER_MAX );
  FD_TEST( fd_netdev_tbl_join( &ctx->netdev_tbl, ctx->netdev_buf ) );
  setup_netdev_table( ctx );
  ctx->has_gre_interface = 1;

  /* ctx->in */
  ctx->in[ 0 ].mem    = fd_wksp_containing( app_tx_dcache_mem );
  ctx->in[ 0 ].chunk0 = tx_chunk0;
  ctx->in[ 0 ].wmark  = tx_wmark;

  /* Start testing */

  /* Stem publish context for RX */
  ulong cr_avail    = ULONG_MAX;
  fd_stem_context_t stem[1] = {{
    .mcaches             = &rx_link->mcache,
    .seqs                = &ctx->shred_out->seq,
    .depths              = &link_depth,
    .cr_avail            = &cr_avail,
    .cr_decrement_amount = 0UL
  }};

  struct __attribute__((packed)) {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } rx_pkt_gre = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .outer_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_GRE,
      .net_tot_len = fd_ushort_bswap( 28 )
    },
    .gre = {
      .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
      .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };

  struct __attribute__((packed)) {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } rx_pkt = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };

  uchar eth_mac_addrs_before_frag_gre[12];
  uchar eth_mac_addrs_before_frag[12];
  fd_memcpy( eth_mac_addrs_before_frag,     eth1_dst_mac_addr, 6 );
  fd_memcpy( eth_mac_addrs_before_frag + 6, eth1_src_mac_addr, 6 );

  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } tx_pkt_before_frag_gre = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 ),
      .daddr       = gre0_dst_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };

  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } tx_pkt_during_frag_gre = {
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 ),
      .daddr       = gre0_dst_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };

  struct __attribute__((packed)) {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } tx_pkt_before_during_frag = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
      .dst      = {0xff,0xff,0xff,0xff,0xff,0xff},
      .src      = {0xff,0xff,0xff,0xff,0xff,0xff}
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 ),
      .daddr       = random_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };

  struct __attribute__((packed)) {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } tx_pkt_after_frag_gre = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .outer_ip4 = {
      .verihl       = FD_IP4_VERIHL( 4, 5 ),
      .ttl          = 64,
      .protocol     = FD_IP4_HDR_PROTOCOL_GRE,
      .net_tot_len  = fd_ushort_bswap( sizeof(fd_ip4_hdr_t) + sizeof(fd_gre_hdr_t) + 31 ),
      .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
      .saddr        = gre0_outer_src_ip,
      .daddr        = gre0_outer_dst_ip
    },
    .gre = {
      .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
      .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 ),
      .saddr       = gre0_src_ip,
      .daddr       = gre0_dst_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };

  struct __attribute__((packed)) {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
    uchar        data[3];
  } tx_pkt_after_frag = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 ),
      .saddr       = default_src_ip,
      .daddr       = random_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    },
    .data = {0xFF, 0xFF, 0}
  };
  fd_memcpy( tx_pkt_after_frag.eth.dst, eth1_dst_mac_addr, 6 );
  fd_memcpy( tx_pkt_after_frag.eth.src, eth1_src_mac_addr, 6 );
  FD_STORE( ushort, &tx_pkt_after_frag.ip4.check, fd_ip4_hdr_check( &tx_pkt_after_frag.ip4 ) );

  /*
    The test loop tests the XDP tile's packet processing during before_credit,
    before_frag, during_frag, and after_frag. The loop runs 6 iterations,
    cycling through 3 different packet configurations twice:
    - Case 0 (GRE tunnel 0): ETH0 interface with GRE encapsulation
    - Case 1 (GRE tunnel 1): ETH1 interface with GRE encapsulation
    - Case 2 (Non-GRE): ETH1 interface with standard packet processing
  */

  for( uint i=0; i<6; ++i ) {
    int charge_busy            = 1;
    ctx->rr_idx = 0U;

    rx_pkt_gre.data[2]                = (uchar)i;
    rx_pkt.data[2]                    = (uchar)i;
    tx_pkt_before_frag_gre.data[2]    = (uchar)i;
    tx_pkt_during_frag_gre.data[2]    = (uchar)i;
    tx_pkt_before_during_frag.data[2] = (uchar)i;
    tx_pkt_after_frag_gre.data[2]     = (uchar)i;
    tx_pkt_after_frag.data[2]         = (uchar)i;

    /* before_credit */
    void * before_credit_input;
    ulong  before_credit_input_sz;
    void * before_credit_expected;
    ulong  before_credit_expected_sz;

    uint   before_frag_dst_ip;
    ulong  before_frag_hdr_sz;
    void * before_frag_expected_mac_addr;
    uint   before_frag_expected_src_ip;

    ulong gre_outer_src_ip = 0;
    ulong gre_outer_dst_ip = 0;
    ulong use_gre = 0;

    void * during_frag_src;
    ulong  during_frag_src_sz;
    ulong  during_frag_expected_sz;
    void * during_frag_expected;

    void * after_frag_expected;
    ulong  after_frag_expected_sz;


    switch (i % 3) {
      case 0: { // gre0
        fd_memcpy( eth_mac_addrs_before_frag_gre,     eth0_dst_mac_addr, 6 );
        fd_memcpy( eth_mac_addrs_before_frag_gre + 6, eth0_src_mac_addr, 6 );

        xsk->if_idx = ctx->if_virt = IF_IDX_ETH0;
        before_credit_input       = &rx_pkt_gre;
        before_credit_input_sz    = sizeof(rx_pkt_gre);
        before_credit_expected    = &rx_pkt;
        before_credit_expected_sz = sizeof(rx_pkt);

        tx_pkt_before_frag_gre.inner_ip4.daddr = gre0_dst_ip;
        before_frag_dst_ip                     = gre0_dst_ip;
        before_frag_hdr_sz                     = sizeof(tx_pkt_before_frag_gre);
        before_frag_expected_mac_addr          = eth_mac_addrs_before_frag_gre;
        before_frag_expected_src_ip            = gre0_src_ip;
        gre_outer_src_ip                       = gre0_outer_src_ip;
        gre_outer_dst_ip                       = gre0_outer_dst_ip;
        use_gre                                = 1;

        tx_pkt_during_frag_gre.inner_ip4.daddr = gre1_dst_ip;
        during_frag_src                        = &tx_pkt_before_frag_gre;
        during_frag_src_sz                     = sizeof(tx_pkt_before_frag_gre);
        during_frag_expected                   = &tx_pkt_during_frag_gre;

        after_frag_expected    = &tx_pkt_after_frag_gre;
        after_frag_expected_sz = sizeof(tx_pkt_after_frag_gre);
        tx_pkt_after_frag_gre.inner_ip4.saddr = gre0_src_ip;
        tx_pkt_after_frag_gre.inner_ip4.daddr = gre0_dst_ip;
        tx_pkt_after_frag_gre.outer_ip4.saddr = gre0_outer_src_ip;
        tx_pkt_after_frag_gre.outer_ip4.daddr = gre0_outer_dst_ip;
        tx_pkt_after_frag_gre.inner_ip4.check = 0;
        tx_pkt_after_frag_gre.outer_ip4.check = 0;
        fd_memcpy( tx_pkt_after_frag_gre.eth.dst, eth0_dst_mac_addr, 6 );
        fd_memcpy( tx_pkt_after_frag_gre.eth.src, eth0_src_mac_addr, 6 );

        FD_STORE( ushort, &tx_pkt_after_frag_gre.outer_ip4.check, fd_ip4_hdr_check_fast( &tx_pkt_after_frag_gre.outer_ip4 ) );
        FD_STORE( ushort, &tx_pkt_after_frag_gre.inner_ip4.check, fd_ip4_hdr_check( &tx_pkt_after_frag_gre.inner_ip4 ) );
        break;
      }
      case 1: { // gre1
        fd_memcpy( eth_mac_addrs_before_frag_gre,     eth1_dst_mac_addr, 6 );
        fd_memcpy( eth_mac_addrs_before_frag_gre + 6, eth1_src_mac_addr, 6 );

        xsk->if_idx = ctx->if_virt = IF_IDX_ETH1;

        before_credit_input       = &rx_pkt_gre;
        before_credit_input_sz    = sizeof(rx_pkt_gre);
        before_credit_expected    = &rx_pkt;
        before_credit_expected_sz = sizeof(rx_pkt);

        tx_pkt_before_frag_gre.inner_ip4.daddr = gre1_dst_ip;
        before_frag_dst_ip                     = gre1_dst_ip;
        before_frag_hdr_sz                     = sizeof(tx_pkt_before_frag_gre);
        before_frag_expected_mac_addr          = eth_mac_addrs_before_frag_gre;
        before_frag_expected_src_ip            = gre1_src_ip;
        gre_outer_src_ip                       = gre1_outer_src_ip;
        gre_outer_dst_ip                       = gre1_outer_dst_ip;
        use_gre                                = 1;

        tx_pkt_during_frag_gre.inner_ip4.daddr = gre1_dst_ip;
        during_frag_src                        = &tx_pkt_before_frag_gre;
        during_frag_src_sz                     = sizeof(tx_pkt_before_frag_gre);
        during_frag_expected                   = &tx_pkt_during_frag_gre;

        after_frag_expected                   = &tx_pkt_after_frag_gre;
        after_frag_expected_sz                = sizeof(tx_pkt_after_frag_gre);
        tx_pkt_after_frag_gre.inner_ip4.saddr = gre1_src_ip;
        tx_pkt_after_frag_gre.inner_ip4.daddr = gre1_dst_ip;
        tx_pkt_after_frag_gre.outer_ip4.saddr = gre1_outer_src_ip;
        tx_pkt_after_frag_gre.outer_ip4.daddr = gre1_outer_dst_ip;
        tx_pkt_after_frag_gre.inner_ip4.check = 0;
        tx_pkt_after_frag_gre.outer_ip4.check = 0;
        fd_memcpy( tx_pkt_after_frag_gre.eth.dst, eth1_dst_mac_addr, 6 );
        fd_memcpy( tx_pkt_after_frag_gre.eth.src, eth1_src_mac_addr, 6 );

        FD_STORE( ushort, &tx_pkt_after_frag_gre.outer_ip4.check, fd_ip4_hdr_check_fast( &tx_pkt_after_frag_gre.outer_ip4 ) );
        FD_STORE( ushort, &tx_pkt_after_frag_gre.inner_ip4.check, fd_ip4_hdr_check( &tx_pkt_after_frag_gre.inner_ip4 ) );
        break;
      }
      case 2: { // non-gre
        xsk->if_idx = ctx->if_virt = IF_IDX_ETH1;

        before_credit_input       = &rx_pkt;
        before_credit_input_sz    = sizeof(rx_pkt);
        before_credit_expected    = &rx_pkt;
        before_credit_expected_sz = sizeof(rx_pkt);

        before_frag_dst_ip            = random_ip;
        before_frag_hdr_sz            = sizeof(tx_pkt_before_during_frag);
        before_frag_expected_mac_addr = eth_mac_addrs_before_frag;
        before_frag_expected_src_ip   = default_src_ip;
        use_gre                       = 0;

        during_frag_src         = &tx_pkt_before_during_frag;
        during_frag_src_sz      = sizeof(tx_pkt_before_during_frag);
        during_frag_expected_sz = sizeof(tx_pkt_before_during_frag);
        during_frag_expected    = &tx_pkt_before_during_frag;

        after_frag_expected    = &tx_pkt_after_frag;
        after_frag_expected_sz = sizeof(tx_pkt_after_frag);
        break;
      }
      default: __builtin_unreachable();
    }

    /* before credit -  test rx path ***********************************

       When the NIC receives a packet, the kernel moves a frame from
       FILL to RX.  Then the net tile before_credit callback moves the
       frame from RX to mcache. */

    /* Pop frame off FILL ring */
    FD_TEST( xdp_fr_ring_prod!=xdp_fr_ring_cons );
    ulong const rx_frame_off = fr_frame_ring[ xdp_fr_ring_cons & (ring_fr_depth-1) ];
    xdp_fr_ring_cons++;

    /* Write packet into frame */
    uchar * rx_ring_pkt = (uchar *)ctx->umem + rx_frame_off;
    fd_memcpy( rx_ring_pkt, before_credit_input, before_credit_input_sz );

    /* Push frame into RX ring */
    xsk->ring_rx.packet_ring[ xdp_rx_ring_prod ].addr = rx_frame_off;
    xsk->ring_rx.packet_ring[ xdp_rx_ring_prod ].len  = (uint)before_credit_input_sz;
    xdp_rx_ring_prod++;

    /* Get net tile to move RX frame->mline */
    fd_frag_meta_t const * mline = rx_link->mcache + fd_mcache_line_idx( stem->seqs[0], fd_mcache_depth( rx_link->mcache ) );
    before_credit( ctx, stem, &charge_busy );

    /* Validate produced mline:  Check that the mline points to the same
       frame as the XDP packet we fed in.  The pointer might move
       a few bytes up, as we remove the GRE header. */
    uchar const * rx_mline_frame = (uchar const *)fd_chunk_to_laddr_const( umem_base, mline->chunk ) + mline->ctl;
    if( use_gre ) {
      /* Accounting for 24 byte GRE overhead removed */
      rx_ring_pkt += 24;
    }
    FD_TEST( (ulong)rx_mline_frame == (ulong)rx_ring_pkt );
    FD_TEST( mline->sz==before_credit_expected_sz );
    FD_TEST( fd_memeq( rx_mline_frame, before_credit_expected, before_credit_expected_sz ) );

    /* before_frag - test tx routing **********************************/

    ulong sig = fd_disco_netmux_sig( 0, SHRED_PORT, before_frag_dst_ip, DST_PROTO_OUTGOING, before_frag_hdr_sz );
    FD_TEST( before_frag( ctx, 0, tx_seq, sig ) == 0 ) ;
    FD_TEST( ctx->tx_op.frame );
    FD_TEST( fd_memeq( ctx->tx_op.mac_addrs, before_frag_expected_mac_addr, 12 ) );
    FD_TEST( ctx->tx_op.src_ip==before_frag_expected_src_ip );
    FD_TEST( ctx->tx_op.use_gre == use_gre                  );
    if( use_gre ) {
      FD_TEST( ctx->tx_op.gre_outer_src_ip==gre_outer_src_ip  );
      FD_TEST( ctx->tx_op.gre_outer_dst_ip==gre_outer_dst_ip  );
    }

    /* during_frag */
    uchar * src = fd_chunk_to_laddr( ctx->in[ 0 ].mem, tx_chunk );
    fd_memcpy( src, during_frag_src, during_frag_src_sz );
    during_frag( ctx, 0, tx_seq, 0, tx_chunk, during_frag_src_sz, 0 );
    FD_TEST( fd_memeq( ctx->tx_op.frame, during_frag_expected, during_frag_expected_sz ) );

    /* after_frag */
    ulong tx_metric_before = ctx->metrics.tx_submit_cnt;
    after_frag( ctx, 0, tx_seq, 0, during_frag_expected_sz, 0, 0, NULL );
    ulong tx_metric_after  = ctx->metrics.tx_submit_cnt;
    FD_TEST( tx_metric_before+1==tx_metric_after ); /* assert that XDP tile published a TX frame */
    ulong tx_prod = xsk->ring_tx.cached_prod;
    struct xdp_desc * tx_ring_entry = &xsk->ring_tx.packet_ring[tx_prod-1];
    FD_TEST( tx_ring_entry->len==after_frag_expected_sz );
    void * after_frag_output = (void *)((ulong)tx_ring_entry->addr + (ulong)ctx->umem);
    FD_TEST( fd_memeq( after_frag_output, after_frag_expected, after_frag_expected_sz ) );
    tx_seq++;
    tx_chunk = fd_dcache_compact_next( tx_chunk, during_frag_expected_sz, tx_chunk0, tx_wmark );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
