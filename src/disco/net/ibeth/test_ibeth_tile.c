/* test_ibeth_tile.c runs parts of the ibeth tile against a mock ibverbs
   queue pair. */

#define FD_TILE_TEST 1
#include "fd_ibeth_tile.c"
#include "../../../disco/topo/fd_topob.h"
#include "../../../waltz/ibverbs/fd_ibverbs_mock.h"

#define SET_NAME frame_track
#include "../../../util/tmpl/fd_set_dynamic.c"

#define WKSP_TAG  1UL
#define MR_LKEY  42UL
#define SHRED_PORT ((ushort)4242)

#define IF_IDX_LO   1U
#define IF_IDX_ETH0 7U
#define IF_IDX_ETH1 8U

/* chunk_to_frame_idx converts a tango chunk index (64 byte stride) to a
   frame index (MTU multiple of 64 bytes). */

static inline ulong
chunk_to_frame_idx( ulong chunk ) {
  return chunk / (FD_NET_MTU / FD_CHUNK_SZ);
}

/* verify_rx_balance verifies that:
   - no frame is allocated twice
   - no frame is allocated out-of-bounds
   - no frame disappeared (memory leak) */

static void
verify_rx_balance( fd_ibeth_tile_t const *      tile,
                   fd_stem_context_t const *    stem,
                   fd_ibverbs_mock_qp_t const * mock,
                   frame_track_t *              frame_track ) {
  ulong const frame_max = frame_track_max( frame_track );
  ulong const rx_frame0 = chunk_to_frame_idx( tile->rx_chunk0 );
  ulong const rx_frame1 = chunk_to_frame_idx( tile->rx_chunk1 );
  FD_TEST( rx_frame0<rx_frame1 && rx_frame1<=frame_max );
  frame_track_range( frame_track, rx_frame0, rx_frame1 );

#define CHECK( chunk ) do {                                            \
    ulong const frame_idx = chunk_to_frame_idx( chunk );               \
    FD_TEST( frame_idx>=rx_frame0 && frame_idx<rx_frame1 );            \
    FD_TEST( frame_track_test( frame_track, frame_idx ) );             \
    frame_track_remove( frame_track, frame_idx );                      \
  } while(0)

  /* RX pending batch */
  FD_TEST( tile->rx_pending_rem <= FD_IBETH_PENDING_MAX );
  ulong const pending_cnt = FD_IBETH_PENDING_MAX - tile->rx_pending_rem;
  for( ulong i=0UL; i<pending_cnt; i++ ) {
    struct ibv_recv_wr const * wr = tile->rx_pending[ FD_IBETH_PENDING_MAX-i-1 ].wr;
    CHECK( wr->wr_id );
    void const * frame = fd_chunk_to_laddr_const( tile->umem_base, wr->wr_id );
    FD_TEST( wr->num_sge==1 );
    FD_TEST( wr->sg_list[0].addr==(ulong)frame );
    FD_TEST( wr->sg_list[0].length==FD_NET_MTU );
  }

  /* RX work queue entries */
  struct ibv_recv_wr * rx_q = mock->rx_q;
  for( fd_ibv_recv_wr_q_iter_t iter = fd_ibv_recv_wr_q_iter_init( rx_q );
       !fd_ibv_recv_wr_q_iter_done( rx_q, iter );
       iter = fd_ibv_recv_wr_q_iter_next( rx_q, iter ) ) {
    struct ibv_recv_wr const * wr = fd_ibv_recv_wr_q_iter_ele_const( rx_q, iter );
    FD_TEST( wr );
    CHECK( wr->wr_id );
    void const * frame = fd_chunk_to_laddr_const( tile->umem_base, wr->wr_id );
    FD_TEST( wr->num_sge==1 );
    FD_TEST( wr->sg_list[0].addr==(ulong)frame );
    FD_TEST( wr->sg_list[0].length==FD_NET_MTU );
  }

  /* Completion queue entries */
  struct ibv_wc * wc_q = mock->wc_q;
  for( fd_ibv_wc_q_iter_t iter = fd_ibv_wc_q_iter_init( wc_q );
       !fd_ibv_wc_q_iter_done( wc_q, iter );
       iter = fd_ibv_wc_q_iter_next( wc_q, iter ) ) {
    struct ibv_wc const * wc = fd_ibv_wc_q_iter_ele_const( wc_q, iter );
    FD_TEST( wc );
    if( wc->opcode == IBV_WC_RECV ) {
      CHECK( wc->wr_id );
    }
  }

  /* Out links */
  ulong const out_cnt = tile->rx_link_cnt;
  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
    fd_frag_meta_t const * mcache = stem->mcaches[ tile->rx_link_out_idx[ out_idx ] ];
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
verify_tx_balance( fd_ibeth_tile_t const *      tile,
                   fd_ibverbs_mock_qp_t const * mock,
                   ulong *                      frame_track ) {
  ulong const frame_max = frame_track_max( frame_track );
  ulong const tx_frame0 = chunk_to_frame_idx( tile->tx_chunk0 );
  ulong const tx_frame1 = chunk_to_frame_idx( tile->tx_chunk1 );
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

  /* TX work queue entries */
  struct ibv_send_wr * tx_q = mock->tx_q;
  for( fd_ibv_send_wr_q_iter_t iter = fd_ibv_send_wr_q_iter_init( tx_q );
       !fd_ibv_send_wr_q_iter_done( tx_q, iter );
       iter = fd_ibv_send_wr_q_iter_next( tx_q, iter ) ) {
    struct ibv_send_wr const * wr = fd_ibv_send_wr_q_iter_ele_const( tx_q, iter );
    FD_TEST( wr );
    CHECK( wr->wr_id );
  }

  /* Completion queue entries */
  struct ibv_wc * wc_q = mock->wc_q;
  for( fd_ibv_wc_q_iter_t iter = fd_ibv_wc_q_iter_init( wc_q );
       !fd_ibv_wc_q_iter_done( wc_q, iter );
       iter = fd_ibv_wc_q_iter_next( wc_q, iter ) ) {
    struct ibv_wc const * wc = fd_ibv_wc_q_iter_ele_const( wc_q, iter );
    FD_TEST( wc );
    if( wc->opcode == IBV_WC_SEND ) {
      CHECK( wc->wr_id );
    }
  }

  /* Check for memory leaks */
  FD_TEST( frame_track_is_null( frame_track ) );

#undef CHECK
}

/* verify_balances ensures that packet frames are correctly allocated
   across rings. */

static void
verify_balances( fd_ibeth_tile_t const *      tile,
                 fd_stem_context_t const *    stem,
                 fd_ibverbs_mock_qp_t const * mock,
                 frame_track_t *              frame_track ) {
  verify_rx_balance( tile, stem, mock, frame_track );
  verify_tx_balance( tile,       mock, frame_track );
}

/* rx_complete_one moves one RX work request to a completion. */

static ulong
rx_complete_one( fd_ibverbs_mock_qp_t * mock,
                 enum ibv_wc_status     status,
                 ulong                  sz ) {
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q ) );
  FD_TEST( fd_ibv_wc_q_avail   ( mock->wc_q ) );
  struct ibv_recv_wr const * wr = fd_ibv_recv_wr_q_pop_head_nocopy( mock->rx_q );
  struct ibv_wc *            wc = fd_ibv_wc_q_push_tail_nocopy    ( mock->wc_q );
  wc->wr_id    = wr->wr_id;
  wc->opcode   = IBV_WC_RECV;
  wc->status   = status;
  wc->byte_len = (uint)sz;
  return wr->wr_id;
}

/* tx_complete_one moves one TX work request to a completion. */

static ulong
tx_complete_one( fd_ibverbs_mock_qp_t * mock,
                 enum ibv_wc_status     status,
                 ulong                  wr_id,
                 ulong                  sz ) {
  FD_TEST( fd_ibv_wc_q_avail( mock->wc_q ) );
  struct ibv_wc * wc = fd_ibv_wc_q_push_tail_nocopy( mock->wc_q );
  wc->wr_id    = wr_id;
  wc->opcode   = IBV_WC_SEND;
  wc->status   = status;
  wc->byte_len = (uint)sz;
  return wr_id;
}

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

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "gigantic"                   );
  ulong const  page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 1UL                          );
  ulong const  numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong const  rxq_depth  = 1024UL;
  ulong const  txq_depth  = 1024UL;
  ulong const  link_depth =  128UL;
  ulong const  cq_depth   = rxq_depth + txq_depth;

  ulong const sge_max = 1UL; /* ibeth tile only uses 1 SGE */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Mock ibverbs queue pair */
  void * mock_mem = fd_wksp_alloc_laddr( wksp, fd_ibverbs_mock_qp_align(), fd_ibverbs_mock_qp_footprint( rxq_depth, txq_depth, cq_depth, sge_max ), WKSP_TAG );
  fd_ibverbs_mock_qp_t * mock = fd_ibverbs_mock_qp_new( mock_mem, rxq_depth, txq_depth, cq_depth, sge_max );
  FD_TEST( mock );

  /* Mock a topology */
  static fd_topo_t topo[1];
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "ibeth", "wksp", "wksp", cpu_idx, 0, 0 );
  topo_tile->ibeth.rx_queue_size = (uint)rxq_depth;
  topo_tile->ibeth.tx_queue_size = (uint)txq_depth;
  topo_tile->ibeth.net.shred_listen_port = SHRED_PORT;

  /* Mock an RX output link */
  fd_topo_link_t * rx_link = fd_topob_link( topo, "net_shred", "wksp", link_depth, 0UL, 1UL );
  void * rx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), WKSP_TAG );
  rx_link->mcache = fd_mcache_join( fd_mcache_new( rx_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( rx_link->mcache );
  topo->objs[ rx_link->mcache_obj_id ].offset = (ulong)rx_mcache_mem - (ulong)wksp;

  /* Allocate tile memory */
  fd_ibeth_tile_t * tile = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( topo_tile ), WKSP_TAG );
  FD_TEST( tile );
  memset( tile, 0, sizeof(fd_ibeth_tile_t) );
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
  topo_tile->ibeth.umem_dcache_obj_id = dcache_obj->id;
  tile->umem_base   = (uchar *)rx_dcache_mem;
  tile->umem_frame0 = rx_dcache;
  tile->umem_sz     = dcache_data_sz;
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

  /* Inject mock ibverbs QP into tile state */
  tile->cq = fd_ibverbs_mock_qp_get_cq_ex( mock );
  tile->qp = fd_ibverbs_mock_qp_get_qp   ( mock );
  tile->mr_lkey = MR_LKEY;

  /* Netbase objects */
  ulong const fib4_max = 8UL;
  void * fib4_local_mem = fd_wksp_alloc_laddr( wksp, fd_fib4_align(), fd_fib4_footprint( fib4_max ), WKSP_TAG );
  void * fib4_main_mem  = fd_wksp_alloc_laddr( wksp, fd_fib4_align(), fd_fib4_footprint( fib4_max ), WKSP_TAG );
  FD_TEST( fd_fib4_new( fib4_local_mem, fib4_max ) );
  FD_TEST( fd_fib4_new( fib4_main_mem,  fib4_max ) );
  fd_topo_obj_t * topo_fib4_local = fd_topob_obj( topo, "fib4", "wksp" );
  fd_topo_obj_t * topo_fib4_main  = fd_topob_obj( topo, "fib4", "wksp" );
  topo_fib4_local->offset = (ulong)fib4_local_mem - (ulong)wksp;
  topo_fib4_main->offset  = (ulong)fib4_main_mem  - (ulong)wksp;
  topo_tile->ibeth.fib4_local_obj_id = topo_fib4_local->id;
  topo_tile->ibeth.fib4_main_obj_id  = topo_fib4_main->id;
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
  topo_tile->ibeth.neigh4_obj_id     = topo_neigh4_hmap->id;
  topo_tile->ibeth.neigh4_ele_obj_id = topo_neigh4_ele->id;
  fd_neigh4_hmap_t neigh4_hmap_[1];
  fd_neigh4_hmap_t * neigh4_hmap = fd_neigh4_hmap_join( neigh4_hmap_, neigh4_hmap_mem, neigh4_ele_mem );
  FD_TEST( neigh4_hmap );

  /* Network configuration */
  tile->main_if_idx = IF_IDX_ETH0;
  uint const public_ip4_addr = FD_IP4_ADDR( 203,0,113,88 ); /* our default source address */
  uint const site_ip4_addr   = FD_IP4_ADDR( 203,0,113,89 ); /* our site address */
  uint const banned_ip4_addr = FD_IP4_ADDR( 7,0,0,1 );      /* blackholed at the route table */
  uint const path2_ip4_addr  = FD_IP4_ADDR( 7,20,0,1 );     /* routed via a different interface */
  uint const neigh1_ip4_addr = FD_IP4_ADDR( 192,168,1,11 ); /* missing a neighbor table entry */
  uint const neigh2_ip4_addr = FD_IP4_ADDR( 192,168,1,12 ); /* can send packets via this guy */
  uint const gw_ip4_addr     = FD_IP4_ADDR( 192,168,1,1 );  /* gateway */
  tile->r.default_address = public_ip4_addr;

  /* Basic routing tables */
  fd_fib4_t * fib_local = fd_fib4_join( fib4_local_mem ); FD_TEST( fib_local );
  fd_fib4_t * fib_main  = fd_fib4_join( fib4_main_mem  ); FD_TEST( fib_main  );
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 127,0,0,1 ), 32, 0U ) = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_LO,
    .ip4_src = FD_IP4_ADDR( 127,0,0,1 ),
    .rtype   = FD_FIB4_RTYPE_LOCAL
  };
  *fd_fib4_append( fib_main, FD_IP4_ADDR( 0,0,0,0 ), 0, 0U ) = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_gw  = gw_ip4_addr
  };
  *fd_fib4_append( fib_main, banned_ip4_addr, 32, 0U ) = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_BLACKHOLE
  };
  *fd_fib4_append( fib_main, path2_ip4_addr, 32, 0U ) = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH1,
    .rtype   = FD_FIB4_RTYPE_UNICAST
  };
  *fd_fib4_append( fib_main, FD_IP4_ADDR( 192,168,1,0 ), 24, 0U ) = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = site_ip4_addr
  };

  /* Neighbor table */
  add_neighbor( neigh4_hmap, neigh2_ip4_addr, 0x01,0x23,0x45,0x67,0x89,0xab );
  add_neighbor( neigh4_hmap, gw_ip4_addr,     0xff,0x23,0x45,0x67,0x89,0xab );

  /* Stem publish context for RX */
  ulong stem_seq[1] = {0};
  ulong cr_avail = ULONG_MAX;
  fd_stem_context_t stem[1] = {{
    .mcaches  = &rx_link->mcache,
    .seqs     = stem_seq,
    .depths   = &link_depth,
    .cr_avail = &cr_avail,
    .cr_decrement_amount = 0UL
  }};

  /* Attach links to tile */
  fd_topob_tile_out( topo, "ibeth", 0UL, "net_shred", 0UL );
  fd_topob_tile_in( topo, "ibeth", 0UL, "wksp", "shred_net", 0UL, 0, 1 );

  /* Initialize tile state (assigns frames) */
  rxq_assign_all( tile, topo, topo_tile );
  unprivileged_init( topo, topo_tile );
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q )==rxq_depth );

  /* Allocate bit set tracking frames */
  ulong const chunk_max = fd_ulong_max( tile->rx_chunk1, tile->tx_chunk1 );
  ulong const frame_max = chunk_to_frame_idx( chunk_max );
  void * frame_track_mem = fd_wksp_alloc_laddr( wksp, frame_track_align(), frame_track_footprint( frame_max ), 1UL );
  frame_track_t * frame_track = frame_track_join( frame_track_new( frame_track_mem, frame_max ) );
  FD_TEST( frame_track );

  /* Verify initial assignment */
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q )==rxq_depth );
  FD_TEST( fd_ibv_send_wr_q_cnt( mock->tx_q )==0UL       );
  FD_TEST( fd_ibv_wc_q_cnt     ( mock->wc_q )==0UL       );
  FD_TEST( tile->rx_pending_rem==FD_IBETH_PENDING_MAX    );
  FD_TEST( stem_seq[0]==0UL );

  /* Trickle a few failed CQEs (should fill pending batch) */
  for( ulong i=1UL; i<FD_IBETH_PENDING_MAX; i++ ) { /* one less than max */
    rx_complete_one( mock, IBV_WC_GENERAL_ERR, 0UL );
  }
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q )==rxq_depth-FD_IBETH_PENDING_MAX+1 );
  FD_TEST( fd_ibv_wc_q_cnt( mock->wc_q )==FD_IBETH_PENDING_MAX-1 );
  verify_balances( tile, stem, mock, frame_track );
  int poll_in     = 1;
  int charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==1 );
  FD_TEST( tile->rx_pending_rem==1 );
  verify_balances( tile, stem, mock, frame_track );

  /* No op */
  charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==0 );

  /* Flush pending batch */
  rx_complete_one( mock, IBV_WC_GENERAL_ERR, 0UL ); /* flushes batch */
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( tile->rx_pending_rem==FD_IBETH_PENDING_MAX    );
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q )==rxq_depth );
  FD_TEST( fd_ibv_wc_q_cnt     ( mock->wc_q )==0UL       );
  FD_TEST( stem_seq[0]==0UL );

  /* Poll a couple times, empty CQ */
  for( ulong i=0UL; i<1024UL; i++ ) {
    int poll_in = 1;
    int charge_busy = 0;
    after_credit( tile, stem, &poll_in, &charge_busy );
    FD_TEST( !charge_busy );
  }

  /* RX packet undersz */
  ulong rx_seq = 0UL;
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_complete_one( mock, IBV_WC_SUCCESS, 0UL );
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
  ulong   rx_chunk  = rx_complete_one( mock, IBV_WC_SUCCESS, sizeof(rx_pkt_templ) );
  uchar * rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_eq( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_seq++;

  /* RX packet with different dst port */
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_chunk  = rx_complete_one( mock, IBV_WC_SUCCESS, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_dport ),
            fd_ushort_bswap( 9999 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

  /* RX packet with unsupported IP version */
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_chunk  = rx_complete_one( mock, IBV_WC_SUCCESS, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( uchar, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.verihl ),
            FD_IP4_VERIHL( 6,5 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

  /* RX packet with invalid Ethertype */
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_packet = fd_chunk_to_laddr( tile->umem_base, rx_complete_one( mock, IBV_WC_SUCCESS, 64UL ) );
  fd_memset( rx_packet, 0, FD_NET_MTU );
  fd_eth_hdr_t eth_hdr = { .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP ) };
  FD_STORE( fd_eth_hdr_t, rx_packet, eth_hdr );
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );

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
  memset( &tile->r.tx_op, 0, sizeof(tile->r.tx_op) );
  ulong tx_sig = fd_disco_netmux_sig( 0U, 0, neigh2_ip4_addr, DST_PROTO_OUTGOING, 0UL );
  FD_TEST( 0==before_frag( tile, 0UL, tx_seq, tx_sig ) );
  FD_TEST( tile->r.tx_op.if_idx==IF_IDX_ETH0 );
  FD_TEST( tile->r.tx_op.src_ip==site_ip4_addr );
  FD_TEST( 0==memcmp( tile->r.tx_op.mac_addrs+0, "\x01\x23\x45\x67\x89\xab", 6 ) );
  verify_balances( tile, stem, mock, frame_track );

  /* TX packet targeting default gateway */
  memset( &tile->r.tx_op, 0, sizeof(tile->r.tx_op) );
  tx_sig = fd_disco_netmux_sig( 0U, 0, FD_IP4_ADDR( 1,1,1,1 ), DST_PROTO_OUTGOING, 0UL );
  FD_TEST( 0==before_frag( tile, 0UL, tx_seq, tx_sig ) );
  FD_TEST( tile->r.tx_op.if_idx==IF_IDX_ETH0 );
  FD_TEST( tile->r.tx_op.src_ip==public_ip4_addr );
  FD_TEST( 0==memcmp( tile->r.tx_op.mac_addrs+0, "\xff\x23\x45\x67\x89\xab", 6 ) );
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
  FD_TEST( fd_ibv_send_wr_q_cnt( mock->tx_q )==1UL );
  struct ibv_send_wr tx_wr = fd_ibv_send_wr_q_pop_head( mock->tx_q );
  FD_TEST( tx_wr.wr_id >= tile->tx_chunk0 && tx_wr.wr_id < tile->tx_chunk1 );
  uchar * tx_frame = fd_chunk_to_laddr( tile->umem_base, tx_wr.wr_id );
  FD_TEST( 0==memcmp( tx_frame+0, "\xff\x23\x45\x67\x89\xab", 6 ) ); // eth.dst
  FD_TEST( 0==memcmp( tx_frame+6, "\x00\x00\x00\x00\x00\x00", 6 ) ); // eth.src
  FD_TEST( fd_ushort_bswap( FD_LOAD( ushort, tx_frame+12 ) )==FD_ETH_HDR_TYPE_IP ); // eth.net_type
  FD_TEST( FD_LOAD( uchar, tx_frame+14 )==FD_IP4_VERIHL( 4, 5 )   ); // ip4.verihl
  FD_TEST( FD_LOAD( uchar, tx_frame+23 )==FD_IP4_HDR_PROTOCOL_UDP ); // ip4.protocol
  FD_TEST( FD_LOAD( uint,  tx_frame+26 )==public_ip4_addr         ); // ip4.saddr
  FD_TEST( FD_LOAD( uint,  tx_frame+30 )==FD_IP4_ADDR( 1,1,1,1 )  ); // ip4.daddr
  FD_TEST( fd_ip4_hdr_check( tx_frame+14 )==0 );
  FD_TEST( tx_wr.num_sge==1 );
  FD_TEST( tx_wr.opcode==IBV_WR_SEND );
  FD_TEST( tx_wr.sg_list[0].addr==(ulong)tx_frame );
  FD_TEST( tx_wr.sg_list[0].length==sizeof(tx_pkt_templ) );
  FD_TEST( tx_wr.sg_list[0].lkey==tile->mr_lkey );
  fd_ibv_sge_p_ele_release( mock->sge_pool, (fd_ibv_mock_sge_t *)tx_wr.sg_list );
  tx_chunk = fd_dcache_compact_next( tx_chunk, sizeof(tx_pkt_templ), tx_chunk0, tx_wmark );
  tx_complete_one( mock, IBV_WC_SUCCESS, tx_wr.wr_id, sizeof(tx_pkt_templ) );
  verify_balances( tile, stem, mock, frame_track );
  charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  verify_balances( tile, stem, mock, frame_track );

  /* Clean up */
  fd_wksp_free_laddr( frame_track_delete( frame_track_leave( frame_track ) ) );
  fd_wksp_free_laddr( tile );
  fd_wksp_free_laddr( fd_ibverbs_mock_qp_delete( mock ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
