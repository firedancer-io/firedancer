#include "fd_restore_test_topo.h"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL
#define IN_DEPTH 8UL

FD_FN_CONST ulong
fd_restore_test_topo_align( void ) {
  return alignof(fd_restore_test_topo_t);
}

FD_FN_CONST ulong
fd_restore_test_topo_footprint( void ) {
  return sizeof(fd_restore_test_topo_t);
}

void *
fd_restore_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_restore_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_restore_test_topo_t * restore = FD_SCRATCH_ALLOC_APPEND( l, fd_restore_test_topo_align(), fd_restore_test_topo_footprint() );
  fd_memset( restore, 0, sizeof(fd_restore_test_topo_t) );

  FD_COMPILER_MFENCE();
  restore->magic = FD_RESTORE_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)restore;
}

fd_restore_test_topo_t *
fd_restore_test_topo_join( void * shrestore ) {
  if( FD_UNLIKELY( !shrestore ) ) {
    FD_LOG_WARNING(( "NULL shrestore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shrestore, fd_restore_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shrestore" ));
    return NULL;
  }

  fd_restore_test_topo_t * restore = (fd_restore_test_topo_t *)shrestore;

  if( FD_UNLIKELY( restore->magic!=FD_RESTORE_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return restore;
}

static void
fd_restore_test_topo_create_link( fd_wksp_t * wksp,
                                  fd_topo_t * topo,
                                  char const * link_name,
                                  char const * wksp_name,
                                  ulong       depth,
                                  ulong       mtu,
                                  int         permit_no_consumers ) {
  fd_topo_link_t * link = fd_topob_link( topo, link_name, wksp_name, depth, mtu, 1UL );
  void * mcache = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( IN_DEPTH, 0UL ), WKSP_TAG );
  FD_TEST( fd_mcache_new( mcache, IN_DEPTH, 0UL, 0UL ) );
  topo->objs[ link->mcache_obj_id ].offset = fd_wksp_gaddr_fast( wksp, mcache );

  ulong const in_data_sz = fd_dcache_req_data_sz( mtu, IN_DEPTH, 0UL, 1 );
  void * dcache = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( in_data_sz, 0UL ), WKSP_TAG );
  FD_TEST( fd_dcache_new( dcache, in_data_sz, 0UL ) );
  topo->objs[ link->dcache_obj_id ].offset = fd_wksp_gaddr_fast( wksp, dcache );

  link->mcache = fd_mcache_join( mcache );
  link->dcache = fd_dcache_join( dcache );
  link->permit_no_consumers = !!permit_no_consumers;
}

void
fd_restore_test_topo_init( fd_restore_test_topo_t * restore,
                           fd_wksp_t *              wksp ) {
  fd_topo_t * topo = fd_wksp_alloc_laddr( wksp, alignof(fd_topo_t), sizeof(fd_topo_t), WKSP_TAG );
  FD_TEST( topo );

  restore->topo = fd_topob_new( topo, "restore" );
  FD_TEST( restore->topo );

  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "restore" );
  topo_wksp->wksp = wksp;

  /* make each tile */
  fd_topob_tile( topo, "snapct", "restore", "snapct", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapld", "restore", "snapld", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapdc", "restore", "snapdc", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapin", "restore", "snapin", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapla", "restore", "snapla", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapls", "restore", "snapls", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapwh", "restore", "snapwh", 0UL, 0, 0 );
  fd_topob_tile( topo, "snapwr", "restore", "snapwr", 0UL, 0, 0 );

  /* make links - depth constant at 128UL */
  fd_restore_test_topo_create_link( wksp, topo, "snapct_ld",    "restore", IN_DEPTH, 280UL,       0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapld_dc",    "restore", IN_DEPTH, USHORT_MAX,  0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapdc_in",    "restore", IN_DEPTH, USHORT_MAX,  0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapin_manif", "restore", IN_DEPTH, 518874272UL, 0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapct_repr",  "restore", IN_DEPTH, 0UL,         1 );
  fd_restore_test_topo_create_link( wksp, topo, "snapin_wh",    "restore", IN_DEPTH, 16UL<<20,    0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapwh_wr",    "restore", IN_DEPTH, 0UL,         0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapla_ls",    "restore", IN_DEPTH, 2048UL,      0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapin_ls",    "restore", IN_DEPTH, 10485848UL,  0 );
  fd_restore_test_topo_create_link( wksp, topo, "snapls_ct",    "restore", IN_DEPTH, 0UL,         0 );

  /* setup tile inputs and outputs */
  fd_topob_tile_in ( topo, "snapct", 0UL, "restore", "snapls_ct",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "snapct", 0UL, "restore", "snapld_dc",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapct", 0UL,           "snapct_ld",   0UL                                     );
  fd_topob_tile_out( topo, "snapct", 0UL,           "snapct_repr", 0UL                                     );

  fd_topob_tile_in ( topo, "snapld", 0UL, "restore", "snapct_ld",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapld", 0UL,           "snapld_dc",   0UL                                     );

  fd_topob_tile_in ( topo, "snapdc", 0UL, "restore", "snapld_dc",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL,           "snapdc_in",   0UL                                     );

  fd_topob_tile_in ( topo, "snapin", 0UL, "restore", "snapdc_in",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_ls",   0UL                                     );
  fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_manif",0UL                                    );
  fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_wh",   0UL                                     );

  fd_topob_tile_in ( topo, "snapla", 0UL, "restore", "snapdc_in",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapla", 0UL,           "snapla_ls",   0UL                                     );

  fd_topob_tile_in ( topo, "snapls", 0UL, "restore", "snapin_ls",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "snapls", 0UL, "restore", "snapla_ls",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapls", 0UL,           "snapls_ct",   0UL                                     );

  fd_topob_tile_in ( topo, "snapwh", 0UL, "restore", "snapin_wh",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapwh", 0UL,           "snapwh_wr",   0UL                                     );

  fd_topob_tile_in ( topo, "snapwr", 0UL, "restore", "snapwh_wr",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /* initialize each tile's test topo */
  fd_snapct_test_topo_init( &restore->snapct, topo, wksp );
  fd_snapld_test_topo_init( &restore->snapld, topo, wksp );
  fd_snapdc_test_topo_init( &restore->snapdc, topo, wksp );
  fd_snapin_test_topo_init( &restore->snapin, topo, wksp );
  fd_snapla_test_topo_init( &restore->snapla, topo, wksp );
  fd_snapls_test_topo_init( &restore->snapls, topo, wksp );
  fd_snapwh_test_topo_init( &restore->snapwh, topo, wksp );
  fd_snapwr_test_topo_init( &restore->snapwr, topo, wksp );
}

void
fd_restore_test_topo_fini( fd_restore_test_topo_t * restore ) {
  fd_snapct_test_topo_fini( &restore->snapct );
  fd_snapld_test_topo_fini( &restore->snapld );
  fd_snapdc_test_topo_fini( &restore->snapdc );
  fd_snapin_test_topo_fini( &restore->snapin );
  fd_snapla_test_topo_fini( &restore->snapla );
  fd_snapls_test_topo_fini( &restore->snapls );
  fd_snapwh_test_topo_fini( &restore->snapwh );
  fd_snapwr_test_topo_fini( &restore->snapwr );
  fd_wksp_free_laddr( restore->topo );
}
