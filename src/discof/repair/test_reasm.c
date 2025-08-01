#include "fd_reasm.h"
#include "fd_reasm_private.h"
#include "../../disco/fd_disco_base.h"

#define PRINT_MAP(name)                                                              \
  do {                                                                               \
    name##_t * name = reasm->name;                                                   \
    fd_reasm_fec_t * pool = reasm->pool;                                             \
    FD_LOG_NOTICE(( #name ));                                                        \
    for( name##_iter_t iter = name##_iter_init(       name, pool );                  \
                             !name##_iter_done( iter, name, pool );                  \
                       iter = name##_iter_next( iter, name, pool ) ) {               \
      fd_reasm_fec_t const * fec = name##_iter_ele_const( iter, name, pool );        \
      FD_LOG_NOTICE(( "(%lu, %u)", fec->slot, fec->fec_set_idx ));                   \
    }                                                                                \
  } while(0)

void
test_fec_ordering( fd_wksp_t * wksp ){
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_reasm_fec_t * pool = reasm->pool;
  // ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  orphaned_t * orphaned = reasm->orphaned;
  subtrees_t * subtrees = reasm->subtrees;

  /* Receive (0, 64) -> (1, 32) -> (1, 0) -> (2, 0) -> (3, 64) -> (2, 32) -> (3, 32) -> (3, 0) */

  fd_hash_t mrnull[1] = {{{ 0 }}};
  fd_hash_t mr0_64[1] = {{{ 1 }}};
  fd_hash_t mr1_00[1] = {{{ 2 }}};
  fd_hash_t mr1_32[1] = {{{ 3 }}};
  fd_hash_t mr2_00[1] = {{{ 4 }}};
  fd_hash_t mr2_32[1] = {{{ 5 }}};
  fd_hash_t mr3_00[1] = {{{ 6 }}};
  fd_hash_t mr3_32[1] = {{{ 7 }}};
  fd_hash_t mr3_64[1] = {{{ 8 }}};

  fd_reasm_fec_t * f0_64 = fd_reasm_insert( reasm, mr0_64, mrnull, 0, 64, 1, 32, 0, 1 );
  FD_TEST( frontier_ele_query( frontier, &f0_64->key, NULL, pool ) == f0_64 );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, mr1_32, mr1_00, 1, 32, 1, 32, 0, 1 );
  FD_TEST( subtrees_ele_query( subtrees, &f1_32->key, NULL, pool ) == f1_32 );

  fd_reasm_fec_t * f1_00 = fd_reasm_insert( reasm, mr1_00, mr0_64, 1, 0, 1, 32, 0, 0 );
  FD_TEST( ancestry_ele_query( ancestry, &f1_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f0_64->key, NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f2_00 = fd_reasm_insert( reasm, mr2_00, mr1_32, 2, 0, 1, 32, 0, 0 );
  FD_TEST( frontier_ele_query( frontier, &f2_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f3_64 = fd_reasm_insert( reasm, mr3_64, mr3_32, 3, 64, 2, 32, 0, 1 );
  FD_TEST( subtrees_ele_query( subtrees, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f2_32 = fd_reasm_insert( reasm, mr2_32, mr2_00, 2, 32, 1, 32, 0, 1 );
  FD_TEST( frontier_ele_query( frontier, &f2_32->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f2_00->key, NULL, pool ) );

  fd_reasm_fec_t * f3_32 = fd_reasm_insert( reasm, mr3_32, mr3_00, 3, 32, 2, 32, 0, 0 );
  FD_TEST( subtrees_ele_query( subtrees, &f3_32->key, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f3_0 = fd_reasm_insert( reasm, mr3_00, mr1_32, 3, 0, 2, 32, 0, 0 );
  FD_TEST( ancestry_ele_query( ancestry, &f3_0->key,  NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f2_32->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f3_32->key, NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f3_64->key, NULL, pool ) );

  fd_hash_t order[7] = {
      f1_00->key,
      f1_32->key,
      f2_00->key,
      f2_32->key,
      f3_0->key,
      f3_32->key,
      f3_64->key,
  };
  fd_reasm_fec_t * fec = NULL; ulong i = 0;
  while( FD_LIKELY( fec = fd_reasm_out( reasm ) ) ) { FD_TEST( 0==memcmp( &fec->key, &order[i], sizeof(fd_hash_t) ) ); i++; }
  FD_TEST( i==sizeof(order) / sizeof(fd_hash_t) );

  // fd_reasm_fec_t actual[1];
  // fd_fec_out_t expected[1];

  // /* Chained merkle root conflict for first FEC of slot 4 (doesn't chain
  //    correctly off last FEC of slot 3).

  //    (3, 64) formerly in the frontier now expected to be in the ancestry
  //    because (4, 0) is a child. But since (4, 0) is an invalid child, it
  //    shouldn't actually be inserted into the frontier. */

  // fd_hash_t hash9 [1] = { { { 9 } } };
  // fd_hash_t hash42[1] = { { { 42 } } };
  // fd_reasm_fec_t * f4_0 = fd_reasm_insert( chainer, hash9, hash42, 4, 0, 1, 32, 0, 1  /* invalid chained merkle root */ );
  // FD_TEST( !frontier_ele_query( chainer, &f4_0->key , NULL, pool) );
  // FD_TEST( ancestry_ele_query( chainer, &f3_64->key, NULL, pool ) );
  // FD_TEST( fd_reasm_out_cnt( chainer ) == 1 );
  // fd_reasm_fec_t * out = fd_reasm_out_next( chainer );
  // // *expected = (fd_fec_out_t){ .err = FD_REASM_ERR_MERKLE, 4, 0 };
  // // FD_TEST( 0 == memcmp( actual, expected, sizeof(fd_fec_out_t) ) );

  // /* Equivocating FEC (slot 3, fec_set_idx 0) that chains off slot 2
  //    instead of slot 1 (parent_off = 1 instead of 2) with the correct
  //    chained merkle root. */

  // fd_reasm_fec_t * f3_0_eqvoc = fd_reasm_insert( chainer, hash9, mr2_32, 3, 0, 32, 0, 0, 1,  );
  // FD_TEST( !f3_0_eqvoc );
  // FD_TEST( fd_reasm_out_cnt( chainer ) == 1 );
  // *actual   = fd_reasm_out_pop_head( chainer );
  // // *expected = (fd_fec_out_t){ .err = FD_REASM_ERR_UNIQUE, 3, 0 };
  // // FD_TEST( 0 == memcmp( actual, expected, sizeof(fd_fec_out_t) ) );

  // /* TODO more robust testing */

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );
}

// void
// test_single_fec( fd_wksp_t * wksp ){
//   ulong fec_max = 32;

//   void * mem = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
//   FD_TEST( mem );
//   fd_reasm_t * chainer = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );

//   fd_hash_t mr_root[1] = {{{ 1 }}};
//   fd_hash_t mr1_0  [1] = {{{ 2 }}};
//   fd_hash_t mr2_0  [1] = {{{ 4 }}};
//   fd_hash_t mr3_0  [1] = {{{ 6 }}};

//   /* Receive (0, 64) -> (1, 0) -> (3, 0) -> (2, 0)
//      single FEC slots */
//   ulong keys[3] = { 1UL << 32 | 0,
//                     2UL << 32 | 0,
//                     3UL << 32 | 0 };

//   fd_reasm_fec_t * f0_64 = fd_reasm_init( chainer, 0, mr_root );
//   FD_TEST( frontier_ele_query( chainer, f0_64->key , NULL, pool) == f0_64 );

//   fd_reasm_fec_t * f1_0 = fd_reasm_insert( chainer, 1, 0, 32, 1, 1, 1, mr1_0, mr_root );
//   FD_TEST( frontier_ele_query( chainer, f1_0->key ), NULL, pool );
//   FD_TEST( !ancestry_ele_query( chainer, f1_0->key ), NULL, pool );
//   FD_TEST( !fd_reasm_orphaned_query( chainer, f1_0->key ) );

//   fd_reasm_fec_t * f3_0 = fd_reasm_insert( chainer, 3, 0, 32, 1, 1, 1, mr3_0, mr2_0 );
//   FD_TEST( !frontier_ele_query( chainer, f3_0->key ), NULL, pool );
//   FD_TEST( !ancestry_ele_query( chainer, f3_0->key ), NULL, pool );
//   FD_TEST( fd_reasm_orphaned_query( chainer, f3_0->key ) );

//   FD_TEST( frontier_ele_query( chainer, f1_0->key ), NULL, pool );

//   fd_reasm_fec_t * f2_0 = fd_reasm_insert( chainer, 2, 0, 32, 1, 1, 1, mr2_0, mr1_0 );
//   FD_TEST( !frontier_ele_query( chainer, f2_0->key ), NULL, pool );
//   FD_TEST( ancestry_ele_query( chainer, f2_0->key ), NULL, pool );
//   FD_TEST( !fd_reasm_orphaned_query( chainer, f2_0->key ) );

//   FD_TEST( frontier_ele_query( chainer, f3_0->key ), NULL, pool );
//   FD_TEST( !ancestry_ele_query( chainer, f3_0->key ), NULL, pool );
//   FD_TEST( !fd_reasm_orphaned_query( chainer, f3_0->key ) );

//   ulong i = 0;
//   while ( !fd_reasm_out_empty( chainer ) ) {
//     fd_fec_out_t out = fd_reasm_out_pop_head( chainer );
//     ulong        key = out.slot << 32 | out.fec_set_idx;
//     // FD_LOG_NOTICE(( "%lu: (%lu, %u) %lu %lu", i, out.slot, out.fec_set_idx, key, keys[i] ));
//     FD_TEST( out.err == FD_REASM_SUCCESS );
//     FD_TEST( key == keys[i] );
//     i++;
//   }

//   fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( chainer ) ) );

// }

// void
// test_publish( fd_wksp_t * wksp ){
//   ulong fec_max = 32;

//   void * mem = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
//   FD_TEST( mem );
//   fd_reasm_t * chainer = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );

//   fd_hash_t mr_root[1] = {{{ 1 }}};
//   fd_reasm_fec_t * f0_64 = fd_reasm_init( chainer, 1, mr_root );

//   FD_TEST( frontier_ele_query( chainer, f0_64->key , NULL, pool) == f0_64 );

//   /* Typical startup behavior, turbine orphan FECs added */
//   fd_reasm_insert( chainer, 10, 0, 32, 1, 1, 1, mr_root, mr_root );
//   fd_reasm_insert( chainer, 9, 0, 32, 1, 1, 1, mr_root, mr_root );

//   /* simulating no FECs chained, but a new root is published */
//   ulong new_root = 2UL << 32 | 0;
//   fd_reasm_publish( chainer, 2 );

//   FD_TEST( frontier_ele_query( chainer, new_root ) , NULL, pool);

//   /* Chain off of root slot for a bit */
//   fd_reasm_insert( chainer, 3, 0, 32, 1, 1, 1, mr_root, mr_root );
//   fd_reasm_insert( chainer, 4, 0, 32, 1, 1, 1, mr_root, mr_root );
//   ulong new_frontier = 4UL << 32 | 0;
//   FD_TEST( frontier_ele_query( chainer, new_frontie, NULL, poolr ) );

//   /* Publish to ancestor */
//   fd_reasm_publish( chainer, 3 );
//   FD_TEST( frontier_ele_query( chainer, new_frontie, NULL, poolr ) );

//   /* Make a tree

//   3 - 4 - 8 - 9 - 10
//     \ 5 - 6 - 7

//   */

//   fd_reasm_insert( chainer, 5, 0, 32, 1, 1, 2, mr_root, mr_root );
//   fd_reasm_insert( chainer, 6, 0, 32, 1, 1, 1, mr_root, mr_root );
//   fd_reasm_insert( chainer, 7, 0, 32, 1, 1, 1, mr_root, mr_root );
//   fd_reasm_insert( chainer, 8, 0, 32, 1, 1, 4, mr_root, mr_root );

//   ulong frontier_cnt = frontier_cnt( chainer );
//   ulong frontier_keys[2] = { 7UL << 32 | 0, 10UL << 32 | 0 };
//   FD_TEST( frontier_cnt == sizeof(frontier_keys) / sizeof(ulong) );
//   for( ulong i = 0; i < sizeof(frontier_keys) / sizeof(ulong); i++ ){
//     FD_TEST( frontier_ele_query( chainer, frontier_ke, NULL, poolys[i] ) );
//   }

//   /* Publish down the tree */
//   fd_reasm_publish( chainer, 4 );
//   new_frontier = 10UL << 32 | 0;
//   FD_TEST( frontier_ele_query( chainer, new_frontie, NULL, poolr ) );

//   FD_TEST( fd_reasm_query( chainer, 4, 0 ) );
//   FD_TEST( !fd_reasm_query( chainer, 5, 0 ) );
//   FD_TEST( !fd_reasm_query( chainer, 6, 0 ) );
//   FD_TEST( !fd_reasm_query( chainer, 7, 0 ) );
//   FD_TEST( fd_reasm_query( chainer, 8, 0 ) );
//   FD_TEST( fd_reasm_query( chainer, 9, 0 ) );
//   FD_TEST( fd_reasm_query( chainer, 10, 0 ) );

//   fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( chainer ) ) );
// }

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_fec_ordering( wksp );
  // test_single_fec( wksp );
  // test_publish( wksp );

  ulong sig = fd_disco_repair_replay_sig( 3508496, 1, 32, 128 );
  FD_TEST( fd_disco_repair_replay_sig_slot( sig ) == 3508496 );
  FD_TEST( fd_disco_repair_replay_sig_parent_off( sig ) == 1 );
  FD_TEST( fd_disco_repair_replay_sig_data_cnt( sig ) == 32 );
  FD_TEST( fd_disco_repair_replay_sig_slot_complete( sig ) == 1 );

  fd_halt();
  return 0;
}
