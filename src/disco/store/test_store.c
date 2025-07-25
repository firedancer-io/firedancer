#include "fd_store.h"

/* test_simple defines the following store in which there is only a
   single FEC set per slot.

         slot 0
           |
         slot 1
         /    \
    slot 2    |
       |    slot 3
    slot 4    |
            slot 5
              |
            slot 6
*/

void
test_simple( fd_wksp_t * wksp ) {
  ulong  fec_max     = 8;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 0UL ) );
  FD_TEST( store                  );
  fd_store_pool_t pool = fd_store_pool( store );
  FD_TEST( pool.ele );
  FD_TEST( pool.ele_max == fec_max );
  FD_TEST( pool.pool );
  FD_TEST( fd_store_map( store ) );

  fd_hash_t mr0 = { { 0 } };
  fd_hash_t mr1 = { { 1 } };
  fd_hash_t mr2 = { { 2 } };
  fd_hash_t mr3 = { { 3 } };
  fd_hash_t mr4 = { { 4 } };
  fd_hash_t mr5 = { { 5 } };
  fd_hash_t mr6 = { { 6 } };
  fd_store_insert( store, &mr0 );
  fd_store_insert( store, &mr1 );
  fd_store_insert( store, &mr2 );
  fd_store_insert( store, &mr4 );
  fd_store_insert( store, &mr3 );
  fd_store_insert( store, &mr5 );
  fd_store_insert( store, &mr6 );

  fd_store_fec_t const * fec0 = fd_store_query_const( store, &mr0 );
  fd_store_fec_t const * fec1 = fd_store_query_const( store, &mr1 );
  fd_store_fec_t const * fec2 = fd_store_query_const( store, &mr2 );
  fd_store_fec_t const * fec3 = fd_store_query_const( store, &mr3 );
  fd_store_fec_t const * fec4 = fd_store_query_const( store, &mr4 );
  fd_store_fec_t const * fec5 = fd_store_query_const( store, &mr5 );
  fd_store_fec_t const * fec6 = fd_store_query_const( store, &mr6 );

  fd_store_link( store, &mr1, &mr0 );
  fd_store_link( store, &mr2, &mr1 );
  fd_store_link( store, &mr4, &mr2 );
  fd_store_link( store, &mr3, &mr1 );
  fd_store_link( store, &mr5, &mr3 );
  fd_store_link( store, &mr6, &mr5 );

  FD_TEST( fd_store_parent( &pool, fec4 ) == fec2 ) ;
  FD_TEST( fd_store_parent( &pool, fec2 ) == fec1 ) ;
  FD_TEST( fd_store_parent( &pool, fec1 ) == fec0 ) ;

  FD_TEST( fd_store_parent( &pool, fec6 ) == fec5 ) ;
  FD_TEST( fd_store_parent( &pool, fec5 ) == fec3 ) ;
  FD_TEST( fd_store_parent( &pool, fec3 ) == fec1 ) ;
  FD_TEST( fd_store_parent( &pool, fec1 ) == fec0 ) ;

  FD_TEST( fd_store_child( &pool, fec0 ) == fec1 ) ;
  FD_TEST( fd_store_child( &pool, fec1 ) == fec2 ) ;
  FD_TEST( fd_store_child( &pool, fec2 ) == fec4 ) ;
  FD_TEST( fd_store_child( &pool, fec3 ) == fec5 ) ;
  FD_TEST( fd_store_child( &pool, fec5 ) == fec6 ) ;

  FD_TEST( fd_store_sibling( &pool, fd_store_child( &pool, fec1 ) ) == fec3 ) ;

  fd_store_publish( store, &mr2 );
  fd_store_fec_t * root = fd_store_root( store );
  FD_TEST( root == fec2 );
  FD_TEST( root->parent == fd_store_pool_idx_null() );
  FD_TEST( fd_store_parent( &pool, fec4 ) == fec2 );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_publish( fd_wksp_t * wksp ) {
  ulong  fec_max     = 16;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 0UL ) );
  FD_TEST( store                  );
  fd_store_pool_t pool = fd_store_pool( store );
  FD_TEST( pool.ele );
  FD_TEST( pool.ele_max == fec_max );
  FD_TEST( pool.pool );
  FD_TEST( fd_store_map ( store ) );

  fd_hash_t mr0  = { { 0, 0xa } };
  fd_hash_t mr1a = { { 1, 0xa } };
  fd_hash_t mr1b = { { 1, 0xb } };
  fd_hash_t mr2a = { { 2, 0xa } };
  fd_hash_t mr2b = { { 2, 0xb } };
  fd_hash_t mr2c = { { 2, 0xc } };
  fd_hash_t mr3a = { { 3, 0xa } };
  fd_hash_t mr4a = { { 4, 0xa } };
  fd_hash_t mr4b = { { 4, 0xb } };
  fd_hash_t mr4c = { { 4, 0xc } };
  fd_hash_t mr4d = { { 4, 0xd } };
  fd_hash_t mr5a = { { 5, 0xa } };
  fd_hash_t mr5b = { { 5, 0xb } };
  fd_hash_t mr6a = { { 6, 0xa } };
  FD_TEST( fd_store_insert( store, &mr0 ) );
  FD_TEST( fd_store_insert( store, &mr1a ) );
  FD_TEST( fd_store_insert( store, &mr1b ) );
  FD_TEST( fd_store_insert( store, &mr2a ) );
  FD_TEST( fd_store_insert( store, &mr2b ) );
  FD_TEST( fd_store_insert( store, &mr2c ) );
  FD_TEST( fd_store_insert( store, &mr3a ) );
  FD_TEST( fd_store_insert( store, &mr4a ) );
  FD_TEST( fd_store_insert( store, &mr4b ) );
  FD_TEST( fd_store_insert( store, &mr4c ) );
  FD_TEST( fd_store_insert( store, &mr4d ) );
  FD_TEST( fd_store_insert( store, &mr5a ) );
  FD_TEST( fd_store_insert( store, &mr5b ) );
  FD_TEST( fd_store_insert( store, &mr6a ) );

  fd_store_link( store, &mr1a, &mr0 );
  fd_store_link( store, &mr1b, &mr1a );

  fd_store_link( store, &mr2a, &mr1b );
  fd_store_link( store, &mr2b, &mr2a );
  fd_store_link( store, &mr2c, &mr2b );
  fd_store_link( store, &mr4a, &mr2c );
  fd_store_link( store, &mr4b, &mr4a );
  fd_store_link( store, &mr4c, &mr4b );
  fd_store_link( store, &mr4d, &mr4c );

  fd_store_link( store, &mr3a, &mr1b );
  fd_store_link( store, &mr5a, &mr3a );
  fd_store_link( store, &mr5b, &mr5a );
  fd_store_link( store, &mr6a, &mr5b );

  fd_store_print( store );

  // fd_store_publish( store, &mr6a );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  // test_simple( wksp );
  test_publish( wksp );

  fd_halt();
  return 0;
}
