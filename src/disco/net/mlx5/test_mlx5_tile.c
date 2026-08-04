/* test_mlx5_tile.c runs parts of the mlx5 tile against mock direct
   mlx5 queues. */

#define FD_TILE_TEST 1
#include "fd_mlx5_tile.c"
#include "../fd_net_tile.h"
#include "../../../disco/topo/fd_topob.h"

#define SET_NAME frame_track
#include "../../../util/tmpl/fd_set_dynamic.c"

#define WKSP_TAG  1UL
#define MR_LKEY  42UL

static void
test_rx_routes( void ) {
  static fd_topo_t topo[1];
  FD_TEST( fd_topob_new( topo, "test_mlx5_rx_routes" ) );
  fd_topob_wksp( topo, "net_umem" );

  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "mlx5", "net_umem", "net_umem", 0UL, 0, 0, 0 );
  fd_topo_obj_t * umem_obj = fd_topob_obj( topo, "dcache", "net_umem" );
  fd_pod_insert_cstr( topo->props, "net.provider", "mlx5" );
  fd_pod_insertf_ulong( topo->props, umem_obj->id, "net.%lu.umem", 0UL );
  topo_tile->mlx5.batch_size = 8U;
  topo_tile->mlx5.net.shred_listen_port        = 8000U;
  topo_tile->mlx5.net.gossip_listen_port       = 8001U;
  topo_tile->mlx5.net.repair_client_listen_port = 8002U;
  topo_tile->mlx5.net.repair_serve_listen_port = 8003U;
  topo_tile->mlx5.net.txsend_src_port          = 8004U;

  fd_topos_net_rx_link( topo, "net_shred",  0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_gossvf", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_repair", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_rserve", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_txsend", 0UL, 128UL );
  for( ulong i=0UL; i<topo_tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ topo_tile->out_link_id[ i ] ];
    FD_TEST( link->dcache_obj_id==umem_obj->id );
    FD_TEST( link->burst==8UL );
  }

  fd_mlx5_tile_t tile[1];
  fd_memset( tile, 0, sizeof(tile) );
  rxq_assign_all( tile, topo, topo_tile );
  FD_TEST( tile->dst_port_cnt==5U );

  ulong out_idx;
  ulong proto;
  FD_TEST( fd_mlx5_tile_rx_route( tile, 8001U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_gossvf", 0UL ) );
  FD_TEST( proto==DST_PROTO_GOSSIP );

  FD_TEST( fd_mlx5_tile_rx_route( tile, 8002U, 128UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_shred", 0UL ) );
  FD_TEST( proto==DST_PROTO_REPAIR );
  FD_TEST( fd_mlx5_tile_rx_route( tile, 8002U, REPAIR_PING_SZ, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_repair", 0UL ) );
  FD_TEST( proto==DST_PROTO_REPAIR );

  FD_TEST( fd_mlx5_tile_rx_route( tile, 8003U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_rserve", 0UL ) );
  FD_TEST( proto==DST_PROTO_RSERVE );

  FD_TEST( fd_mlx5_tile_rx_route( tile, 8004U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_txsend", 0UL ) );
  FD_TEST( proto==DST_PROTO_SEND );
  FD_TEST( !fd_mlx5_tile_rx_route( tile, 9999U, 64UL, &out_idx, &proto ) );
}
#define SHRED_PORT ((ushort)4242)

#define IF_IDX_LO   1U
#define IF_IDX_ETH0 7U
#define IF_IDX_ETH1 8U

struct fd_mlx5_tile_mock {
  uint rq_nic_cons;
  uint sq_nic_cons;
  uint rx_cq_prod;
  uint tx_cq_prod;
  uchar bf[512] __attribute__((aligned(64)));
};
typedef struct fd_mlx5_tile_mock fd_mlx5_tile_mock_t;

static inline uint
test_rx_wq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return tile->hw.qp.rq_prod-mock->rq_nic_cons;
}

static inline uint
test_tx_wq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return tile->hw.qp.sq_prod-mock->sq_nic_cons;
}

static inline uint
test_rx_cq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return mock->rx_cq_prod-tile->hw.rx_cq.cons_idx;
}

static inline uint
test_tx_cq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return mock->tx_cq_prod-tile->hw.tx_cq.cons_idx;
}

static void
test_cqe_push( fd_mlx5_cq_t * cq,
               uint            prod,
               uint            opcode,
               uint            wqe_counter,
               uint            byte_cnt ) {
  FD_TEST( prod-cq->cons_idx<cq->depth );
  fd_mlx5_cqe_t * cqe = cq->entries+(prod & (cq->depth-1U));
  fd_memset( cqe, 0, sizeof(*cqe) );
  FD_STORE( uint,   cqe->bytes+44, fd_uint_bswap( byte_cnt ) );
  FD_STORE( ushort, cqe->bytes+60, fd_ushort_bswap( (ushort)wqe_counter ) );
  cqe->bytes[63] = (uchar)((opcode<<4) | !!(prod & cq->depth));
}

/* chunk_to_frame_idx converts a tango chunk index (64 byte stride) to a
   frame index (MTU multiple of 64 bytes). */

static inline ulong
chunk_to_frame_idx( ulong chunk ) {
  return chunk / (FD_NET_MTU / FD_CHUNK_SZ);
}

static inline ulong
test_rx_chunk1( fd_mlx5_tile_t const *   tile,
                fd_stem_context_t const * stem ) {
  ulong frame_cnt = tile->hw.qp.rx_depth-tile->batch_size;
  for( ulong out_idx=0UL; out_idx<tile->rx_out_cnt; out_idx++ )
    frame_cnt += fd_mcache_depth( stem->mcaches[ out_idx ] );
  return tile->umem_chunk0 + frame_cnt*(FD_NET_MTU/FD_CHUNK_SZ);
}

static inline ulong
test_tx_chunk1( fd_mlx5_tile_t const *   tile,
                fd_stem_context_t const * stem ) {
  return test_rx_chunk1( tile, stem ) + tile->hw.qp.tx_depth*(FD_NET_MTU/FD_CHUNK_SZ);
}

/* verify_rx_balance verifies that:
   - no frame is allocated twice
   - no frame is allocated out-of-bounds
   - no frame disappeared (memory leak) */

static void
verify_rx_balance( fd_mlx5_tile_t const * tile,
                   fd_stem_context_t const *   stem,
                   fd_mlx5_tile_mock_t const *  mock,
                   frame_track_t *             frame_track ) {
  ulong const frame_max = frame_track_max( frame_track );
  ulong const rx_frame0 = chunk_to_frame_idx( tile->umem_chunk0 );
  ulong const rx_frame1 = chunk_to_frame_idx( test_rx_chunk1( tile, stem ) );
  FD_TEST( rx_frame0<rx_frame1 && rx_frame1<=frame_max );
  frame_track_range( frame_track, rx_frame0, rx_frame1 );

#define CHECK( chunk ) do {                                            \
    ulong const frame_idx = chunk_to_frame_idx( chunk );               \
    FD_TEST( frame_idx>=rx_frame0 && frame_idx<rx_frame1 );            \
    FD_TEST( frame_track_test( frame_track, frame_idx ) );             \
    frame_track_remove( frame_track, frame_idx );                      \
  } while(0)

  /* RX pending batch */
  FD_TEST( tile->rx_pending_rem <= tile->batch_size );
  ulong const pending_cnt = tile->batch_size - tile->rx_pending_rem;
  for( ulong i=0UL; i<pending_cnt; i++ ) {
    CHECK( tile->rx_pending[ tile->batch_size-i-1UL ].chunk );
  }

  for( uint idx=mock->rq_nic_cons; idx<tile->hw.qp.rq_prod; idx++ ) {
    CHECK( (uint)tile->hw.qp.rx_user_data[ idx & (tile->hw.qp.rx_depth-1U) ] );
  }

  for( uint idx=tile->hw.rx_cq.cons_idx; idx<mock->rx_cq_prod; idx++ ) {
    uint wqe_counter = tile->hw.qp.rq_cons + idx-tile->hw.rx_cq.cons_idx;
    CHECK( (uint)tile->hw.qp.rx_user_data[ wqe_counter & (tile->hw.qp.rx_depth-1U) ] );
  }

  /* Out links */
  for( ulong out_idx=0UL; out_idx<tile->rx_out_cnt; out_idx++ ) {
    fd_frag_meta_t const * mcache = stem->mcaches[ out_idx ];
    FD_TEST( mcache );
    ulong const depth = fd_mcache_depth( mcache );
    for( ulong j=0UL; j<depth; j++ ) {
      fd_frag_meta_t const * mline = mcache+j;
      CHECK( mline->chunk );
    }
  }

  /* Check for memory leaks */
  FD_TEST( frame_track_is_null( frame_track ) );

#undef CHECK
}

/* verify_tx_balance is like verify_rx_balance, just for TX.
   TX frames are distributed across:
   - TX work queue entries
   - Completion queue entries */

static void
verify_tx_balance( fd_mlx5_tile_t const * tile,
                   fd_stem_context_t const * stem,
                   fd_mlx5_tile_mock_t const *  mock,
                   ulong *                     frame_track ) {
  (void)mock;
  ulong const frame_max = frame_track_max( frame_track );
  ulong const tx_frame0 = chunk_to_frame_idx( test_rx_chunk1( tile, stem ) );
  ulong const tx_frame1 = chunk_to_frame_idx( test_tx_chunk1( tile, stem ) );
  FD_TEST( tx_frame0<tx_frame1 && tx_frame1<=frame_max );
  frame_track_range( frame_track, tx_frame0, tx_frame1 );

#define CHECK( chunk ) do {                                            \
    ulong const frame_idx = chunk_to_frame_idx( chunk );               \
    FD_TEST( frame_idx>=tx_frame0 && frame_idx<tx_frame1 );            \
    FD_TEST( frame_track_test( frame_track, frame_idx ) );             \
    frame_track_remove( frame_track, frame_idx );                      \
  } while(0)

  /* TX free list */
  for( tx_free_iter_t iter = tx_free_iter_init( tile->tx_free );
       !tx_free_iter_done( tile->tx_free, iter );
       iter = tx_free_iter_next( tile->tx_free, iter ) ) {
    uint const chunk = *tx_free_iter_ele_const( tile->tx_free, iter );
    CHECK( chunk );
  }

  /* TX pending batch */
  FD_TEST( tile->tx_pending_cnt<=tile->batch_size );
  for( uint i=0U; i<tile->tx_pending_cnt; i++ ) {
    CHECK( tile->tx_pending[ i ].chunk );
  }

  for( uint idx=tile->hw.qp.sq_cons; idx<tile->hw.qp.sq_prod; idx++ ) {
    CHECK( fd_mlx5_tile_tx_meta( tile->hw.qp.tx_user_data[ idx & (tile->hw.qp.tx_depth-1U) ] ).chunk );
  }

  /* Check for memory leaks */
  FD_TEST( frame_track_is_null( frame_track ) );

#undef CHECK
}

/* verify_balances ensures that packet frames are correctly allocated
   across rings. */

static void
verify_balances( fd_mlx5_tile_t const * tile,
                 fd_stem_context_t const *   stem,
                 fd_mlx5_tile_mock_t const *  mock,
                 frame_track_t *             frame_track ) {
  verify_rx_balance( tile, stem, mock, frame_track );
  verify_tx_balance( tile, stem, mock, frame_track );
}

/* rx_complete_one moves one RX work request to a completion. */

static ulong
rx_complete_one( fd_mlx5_tile_mock_t * mock,
                 fd_mlx5_tile_t * tile,
                 uint                  opcode,
                 ulong                 sz ) {
  uint wqe_counter = mock->rq_nic_cons++;
  FD_TEST( wqe_counter<tile->hw.qp.rq_prod );
  uint chunk = (uint)tile->hw.qp.rx_user_data[ wqe_counter & (tile->hw.qp.rx_depth-1U) ];
  test_cqe_push( &tile->hw.rx_cq, mock->rx_cq_prod++, opcode, wqe_counter, (uint)sz );
  return chunk;
}

/* tx_complete_one moves one TX work request to a completion. */

static ulong
tx_complete_batch( fd_mlx5_tile_mock_t * mock,
                   fd_mlx5_tile_t * tile,
                   uint                  opcode,
                   uint                  wqe_cnt ) {
  FD_TEST( wqe_cnt );
  uint wqe_counter = mock->sq_nic_cons+wqe_cnt-1U;
  FD_TEST( wqe_counter<tile->hw.qp.sq_prod );
  mock->sq_nic_cons += wqe_cnt;
  fd_mlx5_tile_send_wr_t meta = fd_mlx5_tile_tx_meta( tile->hw.qp.tx_user_data[ wqe_counter & (tile->hw.qp.tx_depth-1U) ] );
  test_cqe_push( &tile->hw.tx_cq, mock->tx_cq_prod++, opcode, wqe_counter, 0U );
  return meta.chunk;
}

static ulong
tx_complete_one( fd_mlx5_tile_mock_t * mock,
                 fd_mlx5_tile_t * tile,
                 uint                  opcode ) {
  return tx_complete_batch( mock, tile, opcode, 1U );
}

static void
add_neighbor( fd_neigh4_hmap_t * join,
              uint               ip4_addr,
              uchar mac0, uchar mac1, uchar mac2,
              uchar mac3, uchar mac4, uchar mac5 ) {
  fd_neigh4_entry_t * ele = fd_neigh4_hmap_upsert( join, &ip4_addr );
  FD_TEST( ele );
  ulong suppress_until = ele->probe_suppress_until;
  fd_neigh4_entry_t to_insert = (fd_neigh4_entry_t) {
    .ip4_addr             = ip4_addr,
    .state                = FD_NEIGH4_STATE_ACTIVE,
    .mac_addr             = { mac0, mac1, mac2, mac3, mac4, mac5 },
    .probe_suppress_until = suppress_until&FD_NEIGH4_PROBE_SUPPRESS_MASK
  };
  fd_neigh4_entry_atomic_st( ele, &to_insert );
}

static void
add_netdev( fd_netdev_tbl_join_t * tbl,
            fd_netdev_t            netdev ) {
  ushort idx = tbl->hdr->dev_cnt;
  FD_TEST( idx<tbl->hdr->dev_max );
  tbl->dev_tbl[ idx ] = netdev;
  tbl->hdr->dev_cnt = (ushort)(idx+1U);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_rx_routes();

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "gigantic"                   );
  ulong const  page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 1UL                          );
  ulong const  numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong const  rxq_depth  = 2048UL;
  ulong const  txq_depth  = 1024UL;
  uint  const  batch_size =    8U;
  ulong        link_depth =  128UL;
  ulong const  route_max      = 8UL;
  ulong const  route_peer_max = 8UL;
  ulong const  route_seed     = 1UL;

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_mlx5_tile_mock_t mock[1] = {{0}};

  /* Mock a topology */
  static fd_topo_t topo[1];
  FD_TEST( fd_topob_new( topo, "test_mlx5_tile" ) );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "mlx5", "wksp", "wksp", cpu_idx, 0, 0, 0 );
  topo_tile->mlx5.rx_queue_size = (uint)rxq_depth;
  topo_tile->mlx5.tx_queue_size = (uint)txq_depth;
  topo_tile->mlx5.batch_size    = batch_size;
  topo_tile->mlx5.route_max      = route_max;
  topo_tile->mlx5.route_peer_max = route_peer_max;
  topo_tile->mlx5.route_peer_seed = route_seed;
  topo_tile->mlx5.net.shred_listen_port = SHRED_PORT;

  /* Mock an RX output link */
  fd_topo_link_t * rx_link = fd_topob_link( topo, "net_shred", "wksp", link_depth, 0UL, batch_size );
  void * rx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), WKSP_TAG );
  rx_link->mcache = fd_mcache_join( fd_mcache_new( rx_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( rx_link->mcache );
  topo->objs[ rx_link->mcache_obj_id ].offset = (ulong)rx_mcache_mem - (ulong)wksp;

  /* Allocate tile memory */
  fd_mlx5_tile_t * tile = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( topo_tile ), WKSP_TAG );
  FD_TEST( tile );
  memset( tile, 0, sizeof(fd_mlx5_tile_t) );
  tile->batch_size    = batch_size;
  topo->objs[ topo_tile->tile_obj_id ].offset = (ulong)tile - (ulong)wksp;
  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->tile_obj_id )==tile );
  FD_TEST( rx_link->mcache );

  /* UMEM */
  ulong const dcache_depth   = rxq_depth+txq_depth+link_depth;
  ulong const dcache_data_sz = fd_dcache_req_data_sz( FD_NET_MTU, dcache_depth, 1UL, 1 );
  FD_TEST( dcache_data_sz );
  void *  rx_dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), WKSP_TAG );
  uchar * rx_dcache     = fd_dcache_join( fd_dcache_new( rx_dcache_mem, dcache_data_sz, 0UL ) );
  fd_topo_obj_t * dcache_obj = fd_topob_obj( topo, "dcache", "wksp" );
  topo->objs[ dcache_obj->id ].offset = (ulong)rx_dcache_mem - (ulong)wksp;
  topo_tile->mlx5.umem_dcache_obj_id = dcache_obj->id;
  tile->umem_base   = (uchar *)rx_dcache_mem;
  tile->umem_frame0 = rx_dcache;
  tile->umem_chunk0 = (uint)fd_laddr_to_chunk( wksp, rx_dcache );
  tile->umem_wmark  = (uint)fd_dcache_compact_wmark( wksp, rx_dcache, FD_NET_MTU );

  /* Mock a TX input link */
  fd_topo_link_t * tx_link = fd_topob_link( topo, "shred_net", "wksp", link_depth, FD_NET_MTU, 1UL );
  void * tx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), WKSP_TAG );
  tx_link->mcache = fd_mcache_join( fd_mcache_new( tx_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( tx_link->mcache );
  void * tx_dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), WKSP_TAG );
  tx_link->dcache = fd_dcache_join( fd_dcache_new( tx_dcache_mem, dcache_data_sz, 0UL ) );
  FD_TEST( tx_link->dcache );

  /* Mock the neighbor solicitation link */
  fd_topo_link_t * neigh_link = fd_topob_link( topo, "net_netlnk", "wksp", link_depth, 0UL, 0UL );
  void * neigh_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( link_depth, 0UL ), WKSP_TAG );
  neigh_link->mcache = fd_mcache_join( fd_mcache_new( neigh_mcache_mem, link_depth, 0UL, 0UL ) );
  FD_TEST( neigh_link->mcache );
  topo->objs[ neigh_link->mcache_obj_id ].offset = (ulong)neigh_mcache_mem - (ulong)wksp;

  FD_SCRATCH_ALLOC_INIT( scratch, tile );
  FD_TEST( FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) )==tile );
  ulong queue_footprint = fd_mlx5_queue_footprint( (uint)rxq_depth, (uint)txq_depth );
  void * queue_mem = FD_SCRATCH_ALLOC_APPEND( scratch, FD_MLX5_PAGE_SZ, queue_footprint );
  ulong * rx_user_data = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ulong), rxq_depth*sizeof(ulong) );
  ulong * tx_user_data = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ulong), txq_depth*sizeof(ulong) );
  fd_mlx5_cqe_t *    rx_cq = queue_mem;
  fd_mlx5_cqe_t *    tx_cq = rx_cq + rxq_depth;
  fd_mlx5_rx_wqe_t * rq    = (fd_mlx5_rx_wqe_t *)(tx_cq + txq_depth);
  fd_mlx5_tx_wqe_t * sq    = (fd_mlx5_tx_wqe_t *)(rq + rxq_depth);
  uint *              dbrec = (uint *)(sq + txq_depth);
  for( ulong i=0UL; i<rxq_depth; i++ ) rx_cq[ i ].bytes[ 63 ] = (uchar)(FD_MLX5_CQE_INVALID<<4);
  for( ulong i=0UL; i<txq_depth; i++ ) tx_cq[ i ].bytes[ 63 ] = (uchar)(FD_MLX5_CQE_INVALID<<4);
  tile->hw.uar.reg = mock->bf;
  tile->hw.rx_cq = (fd_mlx5_cq_t) {
    .entries=rx_cq, .dbrec=dbrec, .depth=(uint)rxq_depth };
  tile->hw.tx_cq = (fd_mlx5_cq_t) {
    .entries=tx_cq, .dbrec=dbrec+2, .depth=(uint)txq_depth };
  tile->hw.qp = (fd_mlx5_qp_t) {
    .ctx=&tile->hw.context, .uar=&tile->hw.uar, .rx_cq=&tile->hw.rx_cq, .tx_cq=&tile->hw.tx_cq,
    .rq=rq, .sq=sq,
    .rx_user_data=rx_user_data, .tx_user_data=tx_user_data,
    .dbrec=dbrec+4,
    .rx_depth=(uint)rxq_depth, .tx_depth=(uint)txq_depth, .qpn=1U,
    .lkey=MR_LKEY, .bf_reg_size=sizeof(mock->bf) };

  /* Netbase objects */
  ulong const neigh4_ele_max   = 16UL;
  ulong const neigh4_probe_max =  8UL;
  ulong const neigh4_seed      =  1UL;
  void * neigh4_hmap_mem = fd_wksp_alloc_laddr( wksp, fd_neigh4_hmap_align(), fd_neigh4_hmap_footprint( neigh4_ele_max ), WKSP_TAG );
  FD_TEST( fd_neigh4_hmap_new( neigh4_hmap_mem, neigh4_ele_max, (int)neigh4_seed ) );
  fd_topo_obj_t * topo_neigh4_hmap = fd_topob_obj( topo, "neigh4_hmap", "wksp" );
  topo_neigh4_hmap->offset = (ulong)neigh4_hmap_mem - (ulong)wksp;
  topo_tile->mlx5.neigh4_obj_id = topo_neigh4_hmap->id;
  fd_pod_insertf_ulong( topo->props, neigh4_ele_max,   "obj.%lu.ele_max",   topo_neigh4_hmap->id );
  fd_pod_insertf_ulong( topo->props, neigh4_probe_max, "obj.%lu.probe_max", topo_neigh4_hmap->id );
  fd_pod_insertf_ulong( topo->props, neigh4_seed,      "obj.%lu.seed",      topo_neigh4_hmap->id );
  fd_neigh4_hmap_t neigh4_hmap_[1];
  fd_neigh4_hmap_t * neigh4_hmap = fd_neigh4_hmap_join( neigh4_hmap_, neigh4_hmap_mem, neigh4_ele_max, neigh4_probe_max, neigh4_seed );
  FD_TEST( neigh4_hmap );

  void * netdev_tbl_mem = fd_wksp_alloc_laddr( wksp, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ), WKSP_TAG );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_mem, NETDEV_MAX, BOND_MASTER_MAX ) );
  fd_topo_obj_t * topo_netdev_tbl = fd_topob_obj( topo, "netdev_tbl", "wksp" );
  topo_netdev_tbl->offset = (ulong)netdev_tbl_mem - (ulong)wksp;
  topo_tile->mlx5.netdev_tbl_obj_id = topo_netdev_tbl->id;
  fd_netdev_tbl_join_t netdev_tbl[1];
  FD_TEST( fd_netdev_tbl_join( netdev_tbl, netdev_tbl_mem ) );
  add_netdev( netdev_tbl, (fd_netdev_t) { .if_idx=IF_IDX_LO,   .dev_type=ARPHRD_LOOPBACK } );
  add_netdev( netdev_tbl, (fd_netdev_t) { .if_idx=IF_IDX_ETH0, .dev_type=ARPHRD_ETHER    } );
  add_netdev( netdev_tbl, (fd_netdev_t) { .if_idx=IF_IDX_ETH1, .dev_type=ARPHRD_ETHER    } );

  /* Network configuration */
  uint const public_ip4_addr = FD_IP4_ADDR( 203,0,113,88 ); /* our default source address */
  uint const site_ip4_addr   = FD_IP4_ADDR( 203,0,113,89 ); /* our site address */
  uint const banned_ip4_addr = FD_IP4_ADDR( 7,0,0,1 );      /* blackholed at the route table */
  uint const path2_ip4_addr  = FD_IP4_ADDR( 7,20,0,1 );     /* routed via a different interface */
  uint const neigh1_ip4_addr = FD_IP4_ADDR( 192,168,1,11 ); /* missing a neighbor table entry */
  uint const neigh2_ip4_addr = FD_IP4_ADDR( 192,168,1,12 ); /* can send packets via this guy */
  uint const gw_ip4_addr     = FD_IP4_ADDR( 192,168,1,1 );  /* gateway */

  /* Neighbor table */
  add_neighbor( neigh4_hmap, neigh2_ip4_addr, 0x01,0x23,0x45,0x67,0x89,0xab );
  add_neighbor( neigh4_hmap, gw_ip4_addr,     0xff,0x23,0x45,0x67,0x89,0xab );

  /* Stem publish context for RX */
  ulong stem_seq[1] = {0};
  ulong cr_avail = ULONG_MAX;
  int out_reliable[1] = {0};
  fd_stem_context_t stem[1] = {{
    .mcaches      = &rx_link->mcache,
    .seqs         = stem_seq,
    .depths       = &link_depth,
    .cr_avail     = &cr_avail,
    .out_reliable = out_reliable,
    .cr_decrement_amount = 0UL
  }};

  /* Attach links to tile */
  fd_topob_tile_out( topo, "mlx5", 0UL, "net_shred", 0UL );
  fd_topob_tile_in( topo, "mlx5", 0UL, "wksp", "shred_net", 0UL, 0, 1 );

  /* Initialize tile state (assigns frames) */
  rxq_assign_all( tile, topo, topo_tile );
  unprivileged_init( topo, topo_tile );
  ulong const rx_fill_cnt = rxq_depth-batch_size;

  tile->r.if_virt         = IF_IDX_ETH0;
  tile->r.default_address = public_ip4_addr;
  fd_fib4_hop_t hop = { .if_idx=IF_IDX_LO, .ip4_src=FD_IP4_ADDR( 127,0,0,1 ), .rtype=FD_FIB4_RTYPE_LOCAL };
  FD_TEST( fd_fib4_insert( tile->r.fib_local, FD_IP4_ADDR( 127,0,0,1 ), 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH0, .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_gw=gw_ip4_addr };
  FD_TEST( fd_fib4_insert( tile->r.fib_main, FD_IP4_ADDR( 0,0,0,0 ), 0, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH0, .rtype=FD_FIB4_RTYPE_BLACKHOLE };
  FD_TEST( fd_fib4_insert( tile->r.fib_main, banned_ip4_addr, 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH1, .rtype=FD_FIB4_RTYPE_UNICAST };
  FD_TEST( fd_fib4_insert( tile->r.fib_main, path2_ip4_addr, 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH0, .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_src=site_ip4_addr };
  FD_TEST( fd_fib4_insert( tile->r.fib_main, FD_IP4_ADDR( 192,168,1,0 ), 24, 0U, &hop ) );

  /* Allocate bit set tracking frames */
  ulong const chunk_max = test_tx_chunk1( tile, stem );
  ulong const frame_max = chunk_to_frame_idx( chunk_max );
  void * frame_track_mem = fd_wksp_alloc_laddr( wksp, frame_track_align(), frame_track_footprint( frame_max ), 1UL );
  frame_track_t * frame_track = frame_track_join( frame_track_new( frame_track_mem, frame_max ) );
  FD_TEST( frame_track );

  /* Verify initial assignment */
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt );
  FD_TEST( !test_tx_wq_cnt( mock, tile ) );
  FD_TEST( !test_rx_cq_cnt( mock, tile ) );
  FD_TEST( !test_tx_cq_cnt( mock, tile ) );
  FD_TEST( tile->rx_pending_rem==batch_size );
  FD_TEST( stem_seq[0]==0UL );

  /* A partial RX batch remains pending until the configured batch is full. */
  for( ulong i=1UL; i<batch_size; i++ ) {
    rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_ERR, 0UL );
  }
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt-batch_size+1UL );
  FD_TEST( test_rx_cq_cnt( mock, tile )==batch_size-1U );
  verify_balances( tile, stem, mock, frame_track );
  int poll_in     = 1;
  int charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==1 );
  FD_TEST( tile->rx_pending_rem==1U );
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt-batch_size+1UL );
  verify_balances( tile, stem, mock, frame_track );

  rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_ERR, 0UL );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( tile->rx_pending_rem==batch_size );
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt );
  verify_balances( tile, stem, mock, frame_track );

  /* No op */
  charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==0 );

  /* RX packet undersz */
  ulong rx_seq = 0UL;
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_SEND, 0UL );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

  /* RX packet valid */
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
  } const rx_pkt_templ = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 8 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  ulong   rx_chunk  = rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_SEND, sizeof(rx_pkt_templ) );
  uchar * rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_eq( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( fd_disco_netmux_sig_proto( rx_link->mcache[ fd_mcache_line_idx( rx_seq, link_depth ) ].sig )==DST_PROTO_SHRED );
  rx_seq++;

  /* A second port rule can share an output without changing its protocol */
  tile->dst_ports  [ 1 ] = 9999U;
  tile->dst_protos [ 1 ] = DST_PROTO_GOSSIP;
  tile->dst_out_idx[ 1 ] = 0U;
  tile->dst_port_cnt = 2U;
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_chunk  = rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_SEND, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_dport ),
            fd_ushort_bswap( 9999 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_eq( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( fd_disco_netmux_sig_proto( rx_link->mcache[ fd_mcache_line_idx( rx_seq, link_depth ) ].sig )==DST_PROTO_GOSSIP );
  rx_seq++;

  /* RX packet with unknown dst port */
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_chunk  = rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_SEND, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_dport ),
            fd_ushort_bswap( 9998 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

  /* RX packet with unsupported IP version */
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_chunk  = rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_SEND, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( uchar, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.verihl ),
            FD_IP4_VERIHL( 6,5 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

  /* RX packet with invalid Ethertype */
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_SEND, 64UL ) );
  fd_memset( rx_packet, 0, FD_NET_MTU );
  fd_eth_hdr_t eth_hdr = { .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP ) };
  FD_STORE( fd_eth_hdr_t, rx_packet, eth_hdr );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

  /* Leave the first completion after the poll budget queued for the next poll. */
  for( ulong i=0UL; i<(ulong)batch_size+1UL; i++ )
    rx_complete_one( mock, tile, FD_MLX5_CQE_RESP_ERR, 0UL );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( test_rx_cq_cnt( mock, tile )==1U );
  verify_balances( tile, stem, mock, frame_track );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( !test_rx_cq_cnt( mock, tile ) );
  verify_balances( tile, stem, mock, frame_track );

  ulong const tx_chunk0 = fd_dcache_compact_chunk0( wksp, tx_link->dcache );
  ulong const tx_wmark  = fd_dcache_compact_wmark( wksp, tx_link->dcache, FD_NET_MTU );
  ulong       tx_seq    = 0UL;
  ulong       tx_chunk  = tx_chunk0;

  /* TX packet with invalid sig */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, 0U, DST_PROTO_SHRED, 0UL ) ) );

  /* TX packet with non-routable IP */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, banned_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );

  /* TX packet with loopback destination */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, FD_IP4_ADDR( 127,0,0,1 ), DST_PROTO_OUTGOING, 0UL ) ) );

  /* TX packet targeting unsupported interface */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, path2_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );

  /* TX packet targeting unknown neighbor */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, neigh1_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );
  verify_balances( tile, stem, mock, frame_track );

  /* TX packet targeting resolved neighbor */
  memset( &tile->tx_route, 0, sizeof(tile->tx_route) );
  ulong tx_sig = fd_disco_netmux_sig( 0U, 0, neigh2_ip4_addr, DST_PROTO_OUTGOING, 0UL );
  FD_TEST( 0==before_frag( tile, 0UL, tx_seq, tx_sig ) );
  FD_TEST( tile->tx_route.if_idx==IF_IDX_ETH0 );
  FD_TEST( tile->tx_route.src_ip==site_ip4_addr );
  FD_TEST( 0==memcmp( tile->tx_route.mac_addrs+0, "\x01\x23\x45\x67\x89\xab", 6 ) );
  verify_balances( tile, stem, mock, frame_track );

  /* TX packet targeting default gateway */
  memset( &tile->tx_route, 0, sizeof(tile->tx_route) );
  tx_sig = fd_disco_netmux_sig( 0U, 0, FD_IP4_ADDR( 1,1,1,1 ), DST_PROTO_OUTGOING, 0UL );
  FD_TEST( 0==before_frag( tile, 0UL, tx_seq, tx_sig ) );
  FD_TEST( tile->tx_route.if_idx==IF_IDX_ETH0 );
  FD_TEST( tile->tx_route.src_ip==public_ip4_addr );
  FD_TEST( 0==memcmp( tile->tx_route.mac_addrs+0, "\xff\x23\x45\x67\x89\xab", 6 ) );
  uchar * tx_packet = fd_chunk_to_laddr( wksp, tx_chunk );
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
    uchar        data[2];
  } const tx_pkt_templ = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 30 ),
      .daddr       = FD_IP4_ADDR( 1,1,1,1 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 10 ),
      .net_sport = fd_ushort_bswap( 1 ),
      .net_dport = fd_ushort_bswap( 2 )
    },
    .data = { 0x11, 0x22 }
  };
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( tile->tx_pending_cnt==1U );
  FD_TEST( !test_tx_wq_cnt( mock, tile ) );
  charge_busy = 0;
  before_credit( tile, stem, &charge_busy );
  FD_TEST( !charge_busy );
  FD_TEST( tile->tx_pending_cnt==1U );
  before_credit( tile, stem, &charge_busy );
  FD_TEST( charge_busy );
  FD_TEST( tile->tx_pending_cnt==0U );
  FD_TEST( test_tx_wq_cnt( mock, tile )==1U );
  uint tx_wqe_idx = mock->sq_nic_cons & (tile->hw.qp.tx_depth-1U);
  fd_mlx5_tile_send_wr_t tx_meta = fd_mlx5_tile_tx_meta( tile->hw.qp.tx_user_data[ tx_wqe_idx ] );
  fd_mlx5_tx_wqe_t const * tx_wqe = tile->hw.qp.sq+tx_wqe_idx;
  uint const tx_wr_chunk = tx_meta.chunk;
  FD_TEST( tx_wr_chunk>=test_rx_chunk1( tile, stem ) && tx_wr_chunk<test_tx_chunk1( tile, stem ) );
  FD_TEST( tx_meta.sz==sizeof(tx_pkt_templ) );
  uchar * tx_frame = fd_chunk_to_laddr( tile->umem_base, tx_wr_chunk );
  FD_TEST( 0==memcmp( tx_frame+0, "\xff\x23\x45\x67\x89\xab", 6 ) ); // eth.dst
  FD_TEST( 0==memcmp( tx_frame+6, "\x00\x00\x00\x00\x00\x00", 6 ) ); // eth.src
  FD_TEST( fd_ushort_bswap( FD_LOAD( ushort, tx_frame+12 ) )==FD_ETH_HDR_TYPE_IP ); // eth.net_type
  FD_TEST( FD_LOAD( uchar, tx_frame+14 )==FD_IP4_VERIHL( 4, 5 )   ); // ip4.verihl
  FD_TEST( FD_LOAD( uchar, tx_frame+23 )==FD_IP4_HDR_PROTOCOL_UDP ); // ip4.protocol
  FD_TEST( FD_LOAD( uint,  tx_frame+26 )==public_ip4_addr         ); // ip4.saddr
  FD_TEST( FD_LOAD( uint,  tx_frame+30 )==FD_IP4_ADDR( 1,1,1,1 )  ); // ip4.daddr
  FD_TEST( fd_ip4_hdr_check( tx_frame+14 )==0 );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx_wqe->bytes+32 ) )==sizeof(tx_pkt_templ) );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx_wqe->bytes+36 ) )==tile->hw.qp.lkey );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, tx_wqe->bytes+40 ) )==(ulong)tx_frame );
  tx_chunk = fd_dcache_compact_next( tx_chunk, sizeof(tx_pkt_templ), tx_chunk0, tx_wmark );
  tx_complete_one( mock, tile, FD_MLX5_CQE_REQ );
  verify_balances( tile, stem, mock, frame_track );
  charge_busy = 0;
  before_credit( tile, stem, &charge_busy );
  FD_TEST( tile->metrics.tx_pkt_cnt==1UL );
  FD_TEST( tile->metrics.tx_bytes_total==sizeof(tx_pkt_templ) );
  verify_balances( tile, stem, mock, frame_track );

  /* A full SQ batch is submitted together, followed by a partial batch. */
  for( ulong i=0UL; i<(ulong)batch_size+1UL; i++ ) {
    fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
    during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
    after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );
  }
  FD_TEST( tile->tx_pending_cnt==1U );
  FD_TEST( test_tx_wq_cnt( mock, tile )==batch_size );
  fd_mlx5_tile_tx_flush( tile );
  FD_TEST( tile->tx_pending_cnt==0U );
  FD_TEST( test_tx_wq_cnt( mock, tile )==batch_size+1U );
  verify_balances( tile, stem, mock, frame_track );

  tx_complete_batch( mock, tile, FD_MLX5_CQE_REQ, batch_size );
  tx_complete_one  ( mock, tile, FD_MLX5_CQE_REQ );
  charge_busy = 0;
  before_credit( tile, stem, &charge_busy );
  FD_TEST( charge_busy );
  FD_TEST( !test_tx_cq_cnt( mock, tile ) );
  FD_TEST( tile->metrics.tx_pkt_cnt==2UL+batch_size );
  FD_TEST( tile->metrics.tx_bytes_total==(2UL+batch_size)*sizeof(tx_pkt_templ) );
  verify_balances( tile, stem, mock, frame_track );

  /* Clean up */
  fd_wksp_free_laddr( frame_track_delete( frame_track_leave( frame_track ) ) );
  fd_wksp_free_laddr( tile );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
