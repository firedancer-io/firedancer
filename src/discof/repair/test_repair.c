#include "fd_repair_tile.c"

void test_store_chain( fd_wksp_t * wksp ) {
  ulong  fec_max     = 8;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 1UL ) );
  FD_TEST( store );
  fd_hash_t mr1 = { { 1 } };
  fd_hash_t mr2 = { { 2 } };
  fd_hash_t mr3 = { { 3 } };
  fd_hash_t mr4 = { { 4 } };
  fd_hash_t mr5 = { { 5 } };
  fd_hash_t mr6 = { { 6 } };
  fd_hash_t hash_null = { 0 };
  fd_store_insert( store, 0, &mr1, &hash_null );
  fd_store_insert( store, 0, &mr2, &mr1 );
  fd_store_insert( store, 0, &mr4, &mr3 );
  fd_store_insert( store, 0, &mr3, &mr2 );
  fd_store_insert( store, 0, &mr5, &mr4 );
  fd_store_insert( store, 0, &mr6, &mr5 );
  /* No store link needed */

  FD_TEST( fd_repair_fec_range_query( store, &mr6, &mr1 ) );
  FD_TEST( !fd_repair_fec_range_query( store, &mr5, &mr6 ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_store_chain( wksp );
  fd_halt();
  return 0;
}
