/* test_ibeth_tile.c runs parts of the ibeth tile against a mock ibverbs 
   queue pair. */

#define FD_TILE_TEST 1
#include "fd_ibeth_tile.c"
#include "../../../waltz/ibverbs/fd_ibverbs_mock.h"

#define WKSP_TAG  1UL
#define MR_LKEY  42UL

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "gigantic"                   );
  ulong const  page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 1UL                          );
  ulong const  numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong const  rx_depth = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-depth",    NULL, 1024UL                       );
  ulong const  tx_depth = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-depth",    NULL, 1024UL                       );
  ulong const  cq_depth = rx_depth + tx_depth;

  ulong const sge_max = 1UL; /* ibeth tile only uses 1 SGE */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Mock ibverbs queue pair */
  void * mock_mem = fd_wksp_alloc_laddr( wksp, fd_ibverbs_mock_qp_align(), fd_ibverbs_mock_qp_footprint( rx_depth, tx_depth, cq_depth, sge_max ), WKSP_TAG );
  fd_ibverbs_mock_qp_t * mock = fd_ibverbs_mock_qp_new( mock_mem, rx_depth, tx_depth, cq_depth, sge_max );
  FD_TEST( mock );

  /* Allocate tile memory */
  fd_topo_tile_t topo_tile = {
    .ibeth = {
      .rx_queue_size = (uint)rx_depth,
      .tx_queue_size = (uint)tx_depth,
    }
  };
  fd_ibeth_tile_t * tile = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( &topo_tile ), WKSP_TAG );
  FD_TEST( tile );
  memset( tile, 0, sizeof(fd_ibeth_tile_t) );

  /* Inject mock ibverbs QP into tile state */
  tile->cq = fd_ibverbs_mock_qp_get_cq( mock );
  tile->qp = fd_ibverbs_mock_qp_get_qp( mock );
  tile->mr_lkey = MR_LKEY;

  /* Clean up */
  fd_wksp_free_laddr( tile );
  fd_wksp_free_laddr( fd_ibverbs_mock_qp_delete( mock ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
