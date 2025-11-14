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
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 1UL ) );
  FD_TEST( store                  );
  fd_store_pool_t pool = fd_store_pool( store );
  FD_TEST( pool.ele );
  FD_TEST( pool.ele_max == fec_max );
  FD_TEST( pool.pool );
  FD_TEST( fd_store_map( store ) );

  fd_store_exacq( store );

  fd_hash_t mr0 = { { 0 } };
  fd_hash_t mr1 = { { 1 } };
  fd_hash_t mr2 = { { 2 } };
  fd_hash_t mr3 = { { 3 } };
  fd_hash_t mr4 = { { 4 } };
  fd_hash_t mr5 = { { 5 } };
  fd_hash_t mr6 = { { 6 } };
  fd_store_insert( store, 0, &mr0 );
  fd_store_insert( store, 0, &mr1 );
  fd_store_insert( store, 0, &mr2 );
  fd_store_insert( store, 0, &mr4 );
  fd_store_insert( store, 0, &mr3 );
  fd_store_insert( store, 0, &mr5 );
  fd_store_insert( store, 0, &mr6 );

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

  FD_TEST( fd_store_parent( store, fec4 ) == fec2 ) ;
  FD_TEST( fd_store_parent( store, fec2 ) == fec1 ) ;
  FD_TEST( fd_store_parent( store, fec1 ) == fec0 ) ;

  FD_TEST( fd_store_parent( store, fec6 ) == fec5 ) ;
  FD_TEST( fd_store_parent( store, fec5 ) == fec3 ) ;
  FD_TEST( fd_store_parent( store, fec3 ) == fec1 ) ;
  FD_TEST( fd_store_parent( store, fec1 ) == fec0 ) ;

  FD_TEST( fd_store_child( store, fec0 ) == fec1 ) ;
  FD_TEST( fd_store_child( store, fec1 ) == fec2 ) ;
  FD_TEST( fd_store_child( store, fec2 ) == fec4 ) ;
  FD_TEST( fd_store_child( store, fec3 ) == fec5 ) ;
  FD_TEST( fd_store_child( store, fec5 ) == fec6 ) ;

  FD_TEST( fd_store_sibling( store, fd_store_child( store, fec1 ) ) == fec3 ) ;

  fd_store_publish( store, &mr2 );
  fd_store_fec_t * root = fd_store_root( store );
  FD_TEST( root == fec2 );
  FD_TEST( root->parent == fd_store_pool_idx_null() );
  FD_TEST( fd_store_parent( store, fec4 ) == fec2 );

  fd_store_exrel( store );

  fd_store_clear( store );
  FD_TEST( fd_store_root( store ) == NULL );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_mr( fd_wksp_t * wksp ) {
  ulong  fec_max     = 16;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 2UL ) );
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

  fd_store_exacq( store );

  FD_TEST( fd_store_insert( store, 0, &mr0 ) );
  FD_TEST( fd_store_query_const( store, &mr0 ) );

  FD_TEST( fd_store_insert( store, 0, &mr1a ) );
  FD_TEST( fd_store_query_const( store, &mr1a ) );

  FD_TEST( fd_store_insert( store, 0, &mr1b ) );
  FD_TEST( fd_store_query_const( store, &mr1b ) );

  FD_TEST( fd_store_insert( store, 0, &mr2a ) );
  FD_TEST( fd_store_query_const( store, &mr2a ) );

  FD_TEST( fd_store_insert( store, 0, &mr2b ) );
  FD_TEST( fd_store_query_const( store, &mr2b ) );

  FD_TEST( fd_store_insert( store, 0, &mr2c ) );
  FD_TEST( fd_store_query_const( store, &mr2c ) );

  FD_TEST( fd_store_insert( store, 0, &mr3a ) );
  FD_TEST( fd_store_query_const( store, &mr3a ) );

  FD_TEST( fd_store_insert( store, 0, &mr4a ) );
  FD_TEST( fd_store_query_const( store, &mr4a ) );

  FD_TEST( fd_store_insert( store, 0, &mr4b ) );
  FD_TEST( fd_store_query_const( store, &mr4b ) );

  FD_TEST( fd_store_insert( store, 0, &mr4c ) );
  FD_TEST( fd_store_query_const( store, &mr4c ) );

  FD_TEST( fd_store_insert( store, 0, &mr4d ) );
  FD_TEST( fd_store_query_const( store, &mr4d ) );

  FD_TEST( fd_store_insert( store, 0, &mr5a ) );
  FD_TEST( fd_store_query_const( store, &mr5a ) );

  FD_TEST( fd_store_insert( store, 0, &mr5b ) );
  FD_TEST( fd_store_query_const( store, &mr5b ) );

  FD_TEST( fd_store_insert( store, 1, &mr6a ) );
  FD_TEST( fd_store_query_const( store, &mr6a ) );

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

  fd_store_publish( store, &mr6a );
  FD_TEST( 0==memcmp( &fd_store_root( store )->key, &mr6a, sizeof(fd_hash_t) ) );

  fd_store_exrel( store );

  fd_store_clear( store );
  FD_TEST( fd_store_root( store ) == NULL );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_map_function( fd_wksp_t * wksp ) {
  ulong  fec_max     = 16;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 2UL ) );
  fd_store_pool_t  pool = fd_store_pool( store );
  fd_store_fec_t * fec0 = fd_store_fec0( store );
  fd_store_map_t * map  = fd_store_map( store );
  FD_TEST( store );
  ulong part_sz = fec_max / store->part_cnt;

  fd_store_key_t key1 = { .mr = { { 0 } }, .part = 0 };
  fd_store_key_t key2 = { .mr = { { 0 } }, .part = 1 };

  FD_TEST( fd_store_map_key_eq( &key1, &key2 ) );
  FD_TEST( fd_store_map_key_hash( &key1, part_sz ) != fd_store_map_key_hash( &key2, part_sz ) );

  fd_store_exacq( store );
  fd_store_insert( store, key1.part, &key1.mr );
  fd_store_insert( store, key2.part, &key2.mr ); /* will fail, mr already exists.*/

  /* at this point there are two merkle root = 0 keys in the map, but they live in different partitions */
  /* the store_query APIs should return the same fec_t *, but the store_map_ele_query APIs should return different fec_t * */

  FD_TEST( fd_store_map_ele_query ( map, &key1, NULL, fec0 ) );
  FD_TEST( !fd_store_map_ele_query( map, &key2, NULL, fec0 ) );
  FD_TEST( fd_store_query( store, &key1.mr ) == fd_store_query( store, &key2.mr ) );

  /* purposefully collide a bunch of keys with key1 */
  fd_store_key_t collide1 = { .mr = { .ul = { 0, 20, 0, 0 } }, .part = 0 };
  fd_store_key_t collide2 = { .mr = { .ul = { 0, 30, 0, 0 } }, .part = 0 };
  fd_store_insert( store, collide1.part, &collide1.mr );
  fd_store_insert( store, collide2.part, &collide2.mr );

  FD_TEST( fd_store_map_ele_query_const( map, &collide1, NULL, fec0 ) );
  FD_TEST( fd_store_map_ele_query_const( map, &collide2, NULL, fec0 ) );
  FD_TEST( fd_store_map_ele_query_const( map, &key1, NULL, fec0 ) );

  /* verify they all belong on the same private_chain_idx */
  ulong seed = map->seed;
  FD_TEST( seed == fec_max / store->part_cnt );
  ulong private_chain_idx = fd_store_map_private_chain_idx( &key1, seed, fec_max );
  FD_TEST( fd_store_map_private_chain_idx( &collide1, seed, fec_max ) == private_chain_idx );
  FD_TEST( fd_store_map_private_chain_idx( &collide2, seed, fec_max ) == private_chain_idx );

  /* not only that, the next pointer should be chaining them together */
  fd_store_fec_t const * fec1 = fd_store_map_ele_query_const( map, &key1,     NULL, fec0 );
  fd_store_fec_t const * fec2 = fd_store_map_ele_query_const( map, &collide1, NULL, fec0 );
  fd_store_fec_t const * fec3 = fd_store_map_ele_query_const( map, &collide2, NULL, fec0 );

  FD_TEST( fec3->next == fd_store_pool_idx( &pool, fec2 ) );
  FD_TEST( fec2->next == fd_store_pool_idx( &pool, fec1 ) );
  FD_TEST( fec1->next == ULONG_MAX );

  /* do a  query / const and non-const */
  FD_TEST( fd_store_query_const( store, &collide1.mr ) );
  fd_store_query( store, &collide2.mr )->parent = 20; /* random */

  /* verify order of the fec_t in the chain is still the same */
  FD_TEST( fd_store_map_ele_query( map, &key1,     NULL, fec0 ) == fec1 );
  FD_TEST( fd_store_map_ele_query( map, &collide1, NULL, fec0 ) == fec2 );
  FD_TEST( fd_store_map_ele_query( map, &collide2, NULL, fec0 ) == fec3 );

  /* verify the fec_t in the chain is still the same */
  FD_TEST( fec3->next == fd_store_pool_idx( &pool, fec2 ) );
  FD_TEST( fec2->next == fd_store_pool_idx( &pool, fec1 ) );
  FD_TEST( fec1->next == ULONG_MAX );

  fd_store_exrel( store );
}

static ulong      tile_go;
static ulong      num_insert = 10;
static fd_store_t * store;

static int
shred_tile_insert( int argc, char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_NOTICE(( "shred_tile_insert called on tile %lu", fd_tile_idx() ));

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  ulong tile_idx = fd_tile_idx();
  for( ulong i = 1; i < num_insert; i++ ) {
    fd_hash_t mr = { .ul = { (i << 16) | tile_idx } };
    fd_rwlock_read( &store->lock );
    FD_LOG_NOTICE(( "inserting %lu at tile %lu", i, tile_idx ));
    fd_store_insert( store, (uint)tile_idx, &mr );
    fd_rwlock_unread( &store->lock );
  }
  return 0;
}

void
test_para( fd_wksp_t * wksp ) {
  ulong  fec_max     = 64;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max ), 1UL );

  // Use actual available tile count, capped at our desired max
  ulong available_tiles = fd_tile_cnt();

  store = fd_store_join( fd_store_new( mem, fec_max, available_tiles ) );
  FD_TEST( store );

  FD_LOG_NOTICE(( "Testing concurrent acquire / release on %lu tiles ", available_tiles ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile_go ) = 0;
  FD_COMPILER_MFENCE();

  for( ulong tile_idx=1UL; tile_idx<available_tiles; tile_idx++ ) {
    fd_tile_exec_new( tile_idx, shred_tile_insert, 0, NULL );
  }

  fd_log_sleep( (long)0.1e9 );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile_go ) = 1;
  FD_COMPILER_MFENCE();

  for( ulong tile_idx=1UL; tile_idx<available_tiles; tile_idx++ ) {
    fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );
  }

  for( ulong tile_idx=1UL; tile_idx<available_tiles; tile_idx++ ) {
    for( ulong i = 1; i < num_insert; i++ ) {
      fd_hash_t mr = { .ul = { (i << 16) | tile_idx } };
      fd_rwlock_read( &store->lock );
      FD_TEST( fd_store_query( store, &mr ) );
      fd_rwlock_unread( &store->lock );
    }
  }

  FD_TEST( fd_store_verify( store ) == 0 );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  //test_simple( wksp );
  test_mr( wksp );
  test_map_function( wksp );
  test_para( wksp );

  fd_halt();
  return 0;
}
