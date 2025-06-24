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
    FD_TEST( tile->rx_link_out_idx[ out_idx ] );
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

static void
rx_complete_one( fd_ibverbs_mock_qp_t * mock,
                 enum ibv_wc_status     status ) {
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q ) );
  FD_TEST( fd_ibv_wc_q_avail   ( mock->wc_q ) );
  struct ibv_recv_wr const * wr = fd_ibv_recv_wr_q_pop_head_nocopy( mock->rx_q );
  struct ibv_wc *            wc = fd_ibv_wc_q_push_tail_nocopy    ( mock->wc_q );
  wc->wr_id  = wr->wr_id;
  wc->opcode = IBV_WC_RECV;
  wc->status = status;
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

  /* Mock an output link */
  fd_topo_link_t * topo_link = fd_topob_link( topo, "net_shred", "wksp", link_depth, 0UL, 1UL );
  void * mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), WKSP_TAG );
  topo_link->mcache = fd_mcache_join( fd_mcache_new( mcache_mem, 128UL, 0UL, 0UL ) );
  topo->objs[ topo_link->mcache_obj_id ].offset = (ulong)mcache_mem - (ulong)wksp;

  /* Allocate tile memory */
  fd_ibeth_tile_t * tile = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( topo_tile ), WKSP_TAG );
  FD_TEST( tile );
  memset( tile, 0, sizeof(fd_ibeth_tile_t) );
  topo->objs[ topo_tile->tile_obj_id ].offset = (ulong)tile - (ulong)wksp;
  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->tile_obj_id )==tile );
  FD_TEST( topo_link->mcache );

  /* UMEM */
  ulong const dcache_depth   = rxq_depth+txq_depth+link_depth;
  ulong const dcache_data_sz = fd_dcache_req_data_sz( FD_NET_MTU, dcache_depth, 1UL, 1 );
  FD_TEST( dcache_data_sz );
  void *  dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), WKSP_TAG );
  uchar * dcache     = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
  fd_topo_obj_t * dcache_obj = fd_topob_obj( topo, "dcache", "wksp" );
  topo->objs[ dcache_obj->id ].offset = (ulong)dcache_mem - (ulong)wksp;
  topo_tile->ibeth.umem_dcache_obj_id = dcache_obj->id;
  tile->umem_base   = (uchar *)dcache_mem;
  tile->umem_frame0 = dcache;
  tile->umem_sz     = dcache_data_sz;
  tile->umem_chunk0 = (uint)fd_laddr_to_chunk( wksp, dcache );
  tile->umem_wmark  = (uint)fd_dcache_compact_wmark( wksp, dcache, FD_NET_MTU );

  /* Inject mock ibverbs QP into tile state */
  tile->cq = fd_ibverbs_mock_qp_get_cq( mock );
  tile->qp = fd_ibverbs_mock_qp_get_qp( mock );
  tile->mr_lkey = MR_LKEY;

  /* Netbase objects */
  ulong const fib4_max = 2UL;
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

  /* Stem publish context for RX */
  ulong stem_seq[1] = {0};
  ulong cr_avail = ULONG_MAX;
  fd_stem_context_t stem[1] = {{
    .mcaches  = &topo_link->mcache,
    .seqs     = stem_seq,
    .depths   = &link_depth,
    .cr_avail = &cr_avail,
    .cr_decrement_amount = 0UL
  }};

  /* Initialize tile state (assigns frames) */
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
  FD_TEST( stem_seq[0]==0UL );

  /* Trickle a few failed CQEs (should fill pending batch) */
  for( ulong i=0; i<4; i++ ) { /* one less than max */
    rx_complete_one( mock, IBV_WC_GENERAL_ERR );
  }
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q )==rxq_depth-4 );
  FD_TEST( fd_ibv_wc_q_cnt( mock->wc_q )==4 );
  int poll_in     = 1;
  int charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==1 );
  verify_balances( tile, stem, mock, frame_track );

  /* No op */
  charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==0 );

  /* Flush pending batch */
  rx_complete_one( mock, IBV_WC_GENERAL_ERR ); /* flushes batch */
  after_credit( tile, stem, &poll_in, &charge_busy );
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

  /* Clean up */
  fd_wksp_free_laddr( frame_track_delete( frame_track_leave( frame_track ) ) );
  fd_wksp_free_laddr( tile );
  fd_wksp_free_laddr( fd_ibverbs_mock_qp_delete( mock ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
