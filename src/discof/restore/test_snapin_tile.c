#include "test/fd_snapin_test_topo.h"
#include "fd_snapin_tile_private.h"
#include "utils/fd_ssctrl.h"

#include "../../disco/topo/fd_topob.h"
#include "../../app/platform/fd_file_util.h"

static fd_topo_t *
test_snapin_init_topo( fd_wksp_t * wksp ) {
  fd_topo_t * topo = fd_wksp_alloc_laddr( wksp, alignof(fd_topo_t), sizeof(fd_topo_t), 1UL );
  FD_TEST( topo );

  topo = fd_topob_new( topo, "snapin" );
  FD_TEST( topo );

  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "snapin" );
  topo_wksp->wksp = wksp;

  fd_topob_tile( topo, "snapin", "snapin", "snapin", 0UL, 0, 0 );

  fd_restore_create_link( wksp, topo, "snapdc_in",    "snapin",  LINK_DEPTH, USHORT_MAX,                     0, 1 );
  fd_restore_create_link( wksp, topo, "snapin_manif", "snapin",  4UL,        sizeof(fd_snapshot_manifest_t), 1, 0 );
  fd_restore_create_link( wksp, topo, "snapin_ct",    "snapin",  LINK_DEPTH, 0UL,                            1, 0 );

  fd_topob_tile_in ( topo, "snapin", 0UL, "snapin", "snapdc_in",    0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_manif", 0UL                                     );
  fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_ct",    0UL                                     );
  return topo;
}

static void
test_snapin_fini( fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[i];
    fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( link->mcache ) ) );
    fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( link->dcache ) ) );
  }
}

static void
test_slot_verification( fd_snapin_test_topo_t * snapin,
                        fd_topo_t *             topo,
                        fd_wksp_t *             wksp ) {
  fd_snapin_test_topo_init( fd_snapin_test_topo_join( fd_snapin_test_topo_new( snapin ) ),
                            topo,
                            wksp,
                            "snapin" );
  fd_ssctrl_init_t * init_msg = fd_chunk_to_laddr( snapin->in_dc_out.mem, snapin->in_dc_out.chunk );
  init_msg->file = 1;
  init_msg->zstd = 1;
  init_msg->addr.addr = FD_IP4_ADDR( 35, 123, 172, 228 );
  init_msg->addr.port = fd_ushort_bswap( 8899 );
  init_msg->is_https = 0;
  init_msg->slot = 42UL;

  fd_snapin_test_topo_fini( snapin );
}

/* TODO: add more unit tests */
int main( int     argc,
    char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 12UL;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  FD_TEST( wksp );

  fd_snapin_test_topo_t snapin;
  fd_topo_t * topo = test_snapin_init_topo( wksp );
  test_slot_verification( &snapin, topo, wksp );
  test_snapin_fini( topo );

  fd_wksp_delete( wksp );
  return 0;
}