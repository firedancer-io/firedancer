#include <linux/if_arp.h>
#include <linux/if_link.h>
#include "fd_xdp_tile.c"
#include "../../../disco/topo/fd_topob.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../waltz/ip/fd_fib4.h"
#include "../../../util/tmpl/fd_map.h"
#include "../../../tango/dcache/fd_dcache.h"
#include "../../../tango/mcache/fd_mcache.h"

#define WKSP_TAG  1UL
#define SHRED_PORT ((ushort)4242)
#define SCRATCH_MAX (5242880UL) // 5MB
uchar wksp_scratch[ SCRATCH_MAX ] __attribute__((aligned((4096UL))));

#define IF_IDX_LO   1U
#define IF_IDX_ETH0 7U
#define IF_IDX_ETH1 8U
#define IF_IDX_GRE  34U

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  ulong const  rxq_depth       = 128UL;
  ulong const  txq_depth       = 128UL;
  ulong        link_depth      = 128UL;
  uint  const  ring_fr_depth   = 128U * 2; // depth for fill ring
  uint  const  xsk_rings_depth = 128U;     // depth for rx, tx, and completion ring

  ulong part_max = fd_wksp_part_max_est( SCRATCH_MAX, 64UL );
  ulong data_max = fd_wksp_data_max_est( SCRATCH_MAX, part_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( wksp_scratch, "wksp", 1234U, part_max, data_max ) );
  FD_TEST( wksp );

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
  ulong const dcache_depth   = rxq_depth+txq_depth+xsk_rings_depth*3+ring_fr_depth;
  ulong const dcache_data_sz = fd_dcache_req_data_sz( FD_NET_MTU, dcache_depth, 1UL, 1 );
  void *      dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), WKSP_TAG );
  FD_TEST( fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) ) );
  fd_topo_obj_t * dcache_obj          = fd_topob_obj( topo, "dcache", "wksp" );
  topo->objs[ dcache_obj->id ].offset = (ulong)dcache_mem - (ulong)wksp;
  topo_tile->net.umem_dcache_obj_id   = dcache_obj->id;
  FD_TEST( fd_topo_obj_laddr( topo, dcache_obj->id )==dcache_mem );

  /* Mock an RX link */
  fd_topo_link_t * rx_link = fd_topob_link( topo, "shred_net", "wksp", rxq_depth, FD_NET_MTU, 1UL );
  FD_TEST( rx_link->id == topo->link_cnt - 1 );
  void * rx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( rxq_depth, 0UL ), WKSP_TAG );
  rx_link->mcache      = fd_mcache_join( fd_mcache_new( rx_mcache_mem, rxq_depth, 0UL, 0UL ) );
  FD_TEST( rx_link->mcache );
  topo->objs[ rx_link->mcache_obj_id ].offset = (ulong)rx_mcache_mem - (ulong)wksp;
  topo_tile->in_cnt                           = 1;
  rx_link->dcache_obj_id                      = dcache_obj->id;

  /* Mock a TX link */
  fd_topo_link_t * tx_link        = fd_topob_link( topo, "net_shred", "wksp", txq_depth, FD_NET_MTU, 1UL );
  void *           tx_mcache_mem  = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( txq_depth, 0UL ), WKSP_TAG );
  FD_TEST( tx_mcache_mem );
  tx_link->mcache                 = fd_mcache_join( fd_mcache_new( tx_mcache_mem, txq_depth, 0UL, 0UL ) );
  FD_TEST( tx_link->mcache );

  /* Fib4 Routing Table setup */
  ulong const fib4_max      = 16UL;
  void * fib4_local_mem     = fd_wksp_alloc_laddr( wksp, fd_fib4_align(), fd_fib4_footprint( fib4_max,fib4_max  ), WKSP_TAG );
  void * fib4_main_mem      = fd_wksp_alloc_laddr( wksp, fd_fib4_align(), fd_fib4_footprint( fib4_max, fib4_max ), WKSP_TAG );
  FD_TEST( fd_fib4_new( fib4_local_mem, fib4_max, fib4_max, 12345UL ) );
  FD_TEST( fd_fib4_new( fib4_main_mem,  fib4_max, fib4_max, 12345UL ) );
  fd_topo_obj_t * topo_fib4_local = fd_topob_obj( topo, "fib4", "wksp" );
  fd_topo_obj_t * topo_fib4_main  = fd_topob_obj( topo, "fib4", "wksp" );
  topo_fib4_local->offset = (ulong)fib4_local_mem - (ulong)wksp;
  topo_fib4_main->offset  = (ulong)fib4_main_mem  - (ulong)wksp;
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
  ctx->free_tx.queue  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), topo_tile->xdp.free_ring_depth * sizeof(ulong) );
  ctx->free_tx.depth  = topo_tile->xdp.free_ring_depth;
  ctx->netdev_buf     = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), ctx->netdev_buf_sz );


  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->net.umem_dcache_obj_id )==dcache_mem );
  void * const umem_dcache         = fd_dcache_join( dcache_mem );
  FD_TEST( umem_dcache );
  ulong  const umem_dcache_data_sz = fd_dcache_data_sz( umem_dcache );
  ulong  const umem_frame_sz       = 2048UL;

  void * const umem_frame0 = (void *)fd_ulong_align_up( (ulong)umem_dcache, 4096UL );
  ulong        umem_sz     = umem_dcache_data_sz - ( (ulong)umem_frame0 - (ulong)umem_dcache );
  umem_sz                  = fd_ulong_align_dn( umem_sz, umem_frame_sz );

  void * const umem_base      = wksp_scratch;
  ulong  const umem_chunk0    = ( (ulong)umem_frame0 - (ulong)umem_base )>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark     = umem_chunk0 + ( ( umem_sz-umem_frame_sz )>>FD_CHUNK_LG_SZ );

  ctx->umem_frame0 = umem_frame0;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;
  ctx->umem_sz     = umem_sz;

  ctx->shred_listen_port = SHRED_PORT;
  ctx->shred_out->mcache = tx_link->mcache;
  ctx->shred_out->sync   = fd_mcache_seq_laddr( ctx->shred_out->mcache );
  ctx->shred_out->depth  = fd_mcache_depth( ctx->shred_out->mcache );
  ctx->shred_out->seq    = fd_mcache_seq_query( ctx->shred_out->sync );

  /* Initialize out link mcache chunks */
  ulong const frame_sz  = 2048UL;
  ulong       frame_off = 0UL;
  uint        chunk     = (uint) umem_chunk0;
  for( ulong i=0UL; i<(topo_tile->out_cnt); i++ ) {
    fd_topo_link_t * out_link = &topo->links[ topo_tile->out_link_id[ i ] ];
    fd_frag_meta_t * mcache   = out_link->mcache;
    for( ulong j=0UL; j<fd_mcache_depth( mcache ); j++ ) {
      mcache[ j ].chunk = (uint)( ctx->umem_chunk0 + (frame_off>>FD_CHUNK_LG_SZ) );
      frame_off        += frame_sz;
      chunk            += 1;
      FD_TEST( chunk < umem_wmark );
    }
  }

  /* Initialize the free_tx ring */
  ulong const tx_depth  = ctx->free_tx.depth;
  for( ulong j=0; j<tx_depth; j++ ) {
    ctx->free_tx.queue[ j ] = (ulong)ctx->umem_frame0 + frame_off;
    frame_off += frame_sz;
    chunk+=1;
  }
  ctx->free_tx.prod = tx_depth;
  ctx->xsk_cnt = 1U;
  fd_xsk_t * xsk = &ctx->xsk[0];
  xsk->if_idx = IF_IDX_ETH0;

  /* Declare XDP fill and RX cons and prod sequence numbers */
  uint xdp_rx_ring_cons   = 0;
  uint xdp_rx_ring_prod   = 1;
  uint xdp_tx_ring_cons   = 0;
  uint xdp_tx_ring_prod   = 0;
  uint xdp_fr_ring_cons   = 0;
  uint xdp_fr_ring_prod   = 0;
  uint xdp_cr_ring_cons   = 0;
  uint xdp_cr_ring_prod   = 0;

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
    chunk             += 1;
    FD_TEST( chunk < umem_wmark );
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

  /* Network configuration */
  uint const banned_ip4_addr       = FD_IP4_ADDR( 7,0,0,1 );      /* blackholed at the route table */
  uint const gw_ip4_addr           = FD_IP4_ADDR( 192,168,1,1 );  /* gateway */
  uint const gre_src_ip            = FD_IP4_ADDR( 192,168,123,1 );
  uint const gre_dst_ip            = FD_IP4_ADDR( 192,168,123,6 );
  uint const gre_outer_src_ip      = FD_IP4_ADDR( 10,0,0,1 );
  uint const gre_outer_dst_ip      = FD_IP4_ADDR( 10,0,0,2 );
  uint const gre_outer_src_ip_fake = FD_IP4_ADDR( 10,0,0,3 ); /* Go into the fib4 table, should be overwritten by the src ip in netdev tbl */
  uchar eth0_dst_mac_addr[6]       = {0xa,0xb,0xc,0xd,0xe,0xf};
  uchar eth0_src_mac_addr[6]       = {0x1,0x2,0x3,0x4,0x5,0x6};
  uchar eth1_dst_mac_addr[6]       = {0x12,0x34,0x56,0x78,0x9a,0xbc};
  uchar eth1_src_mac_addr[6]       = {0xde,0xf1,0x23,0x45,0x67,0x89};

  /* Basic routing tables */
  fd_fib4_t * fib_local = fd_fib4_join( fib4_local_mem ); FD_TEST( fib_local );
  fd_fib4_t * fib_main  = fd_fib4_join( fib4_main_mem  ); FD_TEST( fib_main  );

  fd_fib4_hop_t hop1 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_LO,
    .ip4_src = FD_IP4_ADDR( 127,0,0,1 ),
    .rtype   = FD_FIB4_RTYPE_LOCAL
  };
  fd_fib4_hop_t hop2 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH1,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_gw  = gw_ip4_addr
  };
  fd_fib4_hop_t hop3 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre_outer_src_ip_fake
  };
  fd_fib4_hop_t hop4 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_GRE,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre_src_ip
  };
  fd_fib4_hop_t hop5 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_BLACKHOLE
  };

  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,0,1 ), 32, 0U, &hop1 ) );
  FD_TEST( fd_fib4_insert( fib_main,  FD_IP4_ADDR( 0,0,0,0 ), 0, 0U, &hop2 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre_outer_dst_ip, 32, 0U, &hop3 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre_dst_ip, 32, 0U, &hop4 ) );
  FD_TEST( fd_fib4_insert( fib_main,  banned_ip4_addr, 32, 0U, &hop5 ) );
  ctx->fib_local = fib_local;
  ctx->fib_main = fib_main;

  /* Neighbor table */
  add_neighbor( neigh4_hmap, gre_outer_dst_ip, eth0_dst_mac_addr[0], eth0_dst_mac_addr[1], eth0_dst_mac_addr[2], eth0_dst_mac_addr[3], eth0_dst_mac_addr[4], eth0_dst_mac_addr[5] );
  add_neighbor( neigh4_hmap, gw_ip4_addr,     eth1_dst_mac_addr[0], eth1_dst_mac_addr[1], eth1_dst_mac_addr[2], eth1_dst_mac_addr[3], eth1_dst_mac_addr[4], eth1_dst_mac_addr[5] );
  FD_TEST( fd_neigh4_hmap_join(
    ctx->neigh4,
    fd_topo_obj_laddr( topo, topo_tile->xdp.neigh4_obj_id ),
    fd_topo_obj_laddr( topo, topo_tile->xdp.neigh4_ele_obj_id ) ) );

  /* Netdev table */
  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->xdp.netdev_dbl_buf_obj_id )==netdev_dbl_buf_mem );
  ctx->netdev_dbl_handle = fd_dbl_buf_join( netdev_dbl_buf_mem );
  ctx->netdev_buf_sz     = fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX );
  ctx->netdev_buf        = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), ctx->netdev_buf_sz );
  fd_netdev_tbl_new( ctx->netdev_buf, NETDEV_MAX, BOND_MASTER_MAX );
  FD_TEST( fd_netdev_tbl_join( &ctx->netdev_tbl_handle, ctx->netdev_buf ) );
  /* GRE interface */
  ctx->netdev_tbl_handle.dev_tbl[IF_IDX_GRE] = (fd_netdev_t) {
    .if_idx = IF_IDX_GRE,
    .dev_type = ARPHRD_IPGRE,
    .gre_dst_ip = gre_outer_dst_ip,
    .gre_src_ip = gre_outer_src_ip
  };
  /* Eth0 interface */
  ctx->netdev_tbl_handle.dev_tbl[IF_IDX_ETH0] = (fd_netdev_t) {
    .if_idx = IF_IDX_ETH0,
    .dev_type = ARPHRD_ETHER,
  };
  /* Eth1 interface */
  ctx->netdev_tbl_handle.dev_tbl[IF_IDX_ETH1] = (fd_netdev_t) {
    .if_idx = IF_IDX_ETH1,
    .dev_type = ARPHRD_ETHER,
  };
  /* Lo interface */
  ctx->netdev_tbl_handle.dev_tbl[IF_IDX_LO] = (fd_netdev_t) {
    .if_idx = IF_IDX_LO,
    .dev_type = ARPHRD_LOOPBACK,
  };
  fd_memcpy( (fd_netdev_t *)ctx->netdev_tbl_handle.dev_tbl[IF_IDX_ETH0].mac_addr, eth0_src_mac_addr, 6 );
  fd_memcpy( (fd_netdev_t *)ctx->netdev_tbl_handle.dev_tbl[IF_IDX_ETH1].mac_addr, eth1_src_mac_addr, 6 );
  ctx->netdev_tbl_handle.hdr->dev_cnt = IF_IDX_GRE + 1;

  /* ctx->in*/
  rx_link->dcache = umem_frame0;
  rx_link->mtu   = FD_NET_MTU;
  ctx->in[ 0 ].mem    = topo->workspaces[ topo->objs[ rx_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->in[ 0 ].chunk0 = umem_chunk0;
  ctx->in[ 0 ].wmark  = umem_wmark;

  /* Start testing */

  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
  } const tx_pkt = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 ),
      .daddr       = gre_dst_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 8 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };

  /* Stem publish context for RX */
  ulong tx_link_mcache_seq = 0;

  ulong stem_seq[1] = {0};
  ulong cr_avail    = ULONG_MAX;
  fd_stem_context_t stem[1] = {{
    .mcaches             = &rx_link->mcache,
    .seqs                = stem_seq,
    .depths              = &link_depth,
    .cr_avail            = &cr_avail,
    .cr_decrement_amount = 0UL
  }};
  int charge_busy   = 1;

  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
  } const rx_pkt_gre = {
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
      .net_len   = fd_ushort_bswap( 8 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };

  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
  } const rx_pkt_parsed = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 8 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };
  uint   xdp_fr_ring_prod_prev                      = xdp_fr_ring_prod;
  uint   xdp_rx_ring_cons_prev                      = xdp_rx_ring_cons;
  xdp_fr_ring_cons                                 += 1;      /* "kernel" has used one frame */
  xsk->ring_rx.packet_ring[xdp_rx_ring_prod-1].addr = frame_off;
  xsk->ring_rx.packet_ring[xdp_rx_ring_prod-1].len  = sizeof(rx_pkt_gre);
  char * rx_packet                                  = (char *)ctx->umem_frame0 + frame_off;
  fd_memcpy( rx_packet, &rx_pkt_gre, sizeof(rx_pkt_gre) );
  ctx->rr_idx = 0U;
  ctx->has_gre_interface = 1;
  before_credit(ctx,stem,&charge_busy);
  fd_frag_meta_t const *mline = tx_link->mcache + fd_mcache_line_idx( tx_link_mcache_seq, fd_mcache_depth(tx_link->mcache) );
  FD_TEST( mline );
  FD_TEST( mline->sz==sizeof(rx_pkt_parsed) );
  void * published = (char *)fd_chunk_to_laddr_const(umem_base, mline->chunk) + mline->ctl;
  FD_TEST( published );
  FD_TEST( fd_memeq( published, &rx_pkt_parsed, sizeof(rx_pkt_parsed) ) );
  FD_TEST( xdp_fr_ring_prod == xdp_fr_ring_prod_prev + 1 );     // tx_link has exchanged one frame with fill ring
  FD_TEST( xdp_rx_ring_cons == xdp_rx_ring_cons_prev + 1 );     // net tile have consumed one rx packet
  tx_link_mcache_seq++;

  /* before_frag */
  ulong sig = fd_disco_netmux_sig( 0, SHRED_PORT, gre_dst_ip, DST_PROTO_OUTGOING, sizeof(tx_pkt) );
  uchar eth_mac_addrs[12];
  fd_memcpy( eth_mac_addrs,     eth0_dst_mac_addr, 6 );
  fd_memcpy( eth_mac_addrs + 6, eth0_src_mac_addr, 6 );
  ctx->net_tile_cnt = 1;

  FD_TEST( before_frag( ctx, 0, 0, sig ) == 0 ) ;
  FD_TEST( ctx->tx_op.frame );
  FD_TEST( fd_memeq( ctx->tx_op.mac_addrs, eth_mac_addrs, 12 ) );
  FD_TEST( ctx->tx_op.use_gre == 1 );
  FD_TEST( ctx->tx_op.src_ip==gre_src_ip );
  FD_TEST( ctx->tx_op.gre_outer_src_ip==gre_outer_src_ip );
  FD_TEST( ctx->tx_op.gre_outer_dst_ip==gre_outer_dst_ip );
  uchar * src = fd_chunk_to_laddr( ctx->in[ 0 ].mem, chunk );
  fd_memcpy( src, &tx_pkt, sizeof(tx_pkt) );
  fd_memset( ctx->tx_op.frame, 0, frame_sz );

  /* during_frag */
  during_frag( ctx, 0, 0, 0, chunk, sizeof(tx_pkt), 0 );

  /* after_frag */
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
  } tx_pkt_during_frag = {
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 ),
      .daddr       = gre_dst_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 8 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };

  FD_TEST( fd_memeq( ctx->tx_op.frame, &tx_pkt_during_frag, sizeof(tx_pkt_during_frag) ) );

  /* after_frag */
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
  } tx_pkt_after_frag = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .outer_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .ttl         = 64,
      .protocol    = FD_IP4_HDR_PROTOCOL_GRE,
      .net_tot_len = fd_ushort_bswap( sizeof(fd_ip4_hdr_t) + sizeof(fd_gre_hdr_t) + 28 ),
      .saddr       = gre_outer_src_ip,
      .daddr       = gre_outer_dst_ip
    },
    .gre = {
      .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
      .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 ),
      .saddr       = gre_src_ip,
      .daddr       = gre_dst_ip
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 8 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };
  fd_memcpy( tx_pkt_after_frag.eth.dst, eth0_dst_mac_addr, 6 );
  fd_memcpy( tx_pkt_after_frag.eth.src, eth0_src_mac_addr, 6 );
  FD_STORE( ushort, &tx_pkt_after_frag.outer_ip4.check, fd_ip4_hdr_check( &tx_pkt_after_frag.outer_ip4 ) );
  FD_STORE( ushort, &tx_pkt_after_frag.inner_ip4.check, fd_ip4_hdr_check( &tx_pkt_after_frag.inner_ip4 ) );
  after_frag( ctx, 0, 0, 0, sizeof(tx_pkt), 0, 0, NULL );
  struct xdp_desc * tx_ring_entry = &xsk->ring_tx.packet_ring[0];
  FD_TEST( tx_ring_entry );
  FD_TEST( tx_ring_entry->len==sizeof(tx_pkt_after_frag) );
  FD_TEST( fd_memeq( (const void *)((ulong)tx_ring_entry->addr + (ulong)ctx->umem_frame0), &tx_pkt_after_frag, sizeof(tx_pkt_after_frag) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
