/* test_ibeth_tile.c runs parts of the ibeth tile against a mock ibverbs
   queue pair. */

#define FD_TILE_TEST 1
#include "fd_ibeth_tile.c"
#include "../../../disco/topo/fd_topob.h"
#include "../../../waltz/ibverbs/fd_ibverbs_mock.h"

#define WKSP_TAG  1UL
#define MR_LKEY  42UL
#define SHRED_PORT ((ushort)4242)

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

  /* Post initial RX descriptors */
  unprivileged_init( topo, topo_tile );
  FD_TEST( fd_ibv_recv_wr_q_cnt( mock->rx_q )==rxq_depth );

  /* Poll a couple times, empty CQ */
  for( ulong i=0UL; i<1024UL; i++ ) {
    int poll_in = 1;
    int charge_busy = 0;
    after_credit( tile, stem, &poll_in, &charge_busy );
    FD_TEST( !charge_busy );
  }

  /* Clean up */
  fd_wksp_free_laddr( tile );
  fd_wksp_free_laddr( fd_ibverbs_mock_qp_delete( mock ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
