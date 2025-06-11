#include "fd_forest.h"

#include <stdarg.h>

/*
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

fd_forest_t *
setup_preorder( fd_forest_t * forest ) {
  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 4, 2, 0, 0 );
  fd_forest_data_shred_insert( forest, 4, 2, 31, 1 );
  fd_forest_data_shred_insert( forest, 3, 2, 0, 0 );
  fd_forest_data_shred_insert( forest, 3, 2, 31, 1 );
  fd_forest_data_shred_insert( forest, 5, 2, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 2, 31, 1 );
  fd_forest_data_shred_insert( forest, 6, 1, 0, 0 );
  FD_TEST( !fd_forest_verify( forest ) );
  // fd_forest_print( forest );
  return forest;
}

/*
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
test_publish( fd_wksp_t * wksp ) {
  ulong publish_test_cases[2] = {

  /*
        slot 2
          |
        slot 4
  */

    2,

  /*
         slot 3
           |
         slot 5
           |
         slot 6
  */

    3 };

  for( ulong i = 0; i < sizeof(publish_test_cases) / sizeof(ulong); i++ ) {
    ulong ele_max = 8UL;
    void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
    FD_TEST( mem );
    fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

    FD_TEST( forest );

    forest = setup_preorder( forest );
    fd_forest_print( forest );
    fd_forest_publish( forest, publish_test_cases[i] );
    FD_TEST( !fd_forest_verify( forest ) );

    fd_wksp_free_laddr( fd_forest_delete( fd_forest_leave( fd_forest_fini( forest ) ) ) );
  }
}

void
test_publish_incremental( fd_wksp_t * wksp ){
  /* as the name suggests. tests the complications introduced by loading
     two incremental snapshots */

  ulong ele_max = 32UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  /* 1. Try publishing to a slot that doesnt exist

      0          10 -> 11

   */

  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 11, 1, 0, 0, 1, 1 );

  ulong new_root = 1;
  fd_forest_publish( forest, new_root );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &new_root, NULL, fd_forest_pool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 0 ) );

  /* 2. Try publishing to a slot on the frontier

    1 -> 2 -> 3       10 -> 11

  */

  fd_forest_data_shred_insert( forest, 2, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 3, 1, 0, 0, 1, 1 );

  ulong frontier = 3;
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier, NULL, fd_forest_pool( forest ) ) );
  fd_forest_publish( forest, frontier );
  FD_TEST( fd_forest_root_slot( forest ) == frontier );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier, NULL, fd_forest_pool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 1 ) );
  FD_TEST( !fd_forest_query( forest, 2 ) );
  FD_TEST( fd_forest_query( forest, 10 ) );
  FD_TEST( fd_forest_query( forest, 11 ) );

  /* 3. Try publishing to a slot in ancestry but in front of the frontier

      frontier    new_root
    3 -> 4 -> 5 -> 6 -> 7      10 -> 11

  */

  fd_forest_data_shred_insert( forest, 4, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 6, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 7, 1, 0, 0, 0, 0 );

  frontier = 4;
  new_root = 6;
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier, NULL, fd_forest_pool( forest ) ) );
  fd_forest_publish( forest, new_root );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  frontier = 7;
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier, NULL, fd_forest_pool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 3 ) );
  FD_TEST( !fd_forest_query( forest, 4 ) );
  FD_TEST( !fd_forest_query( forest, 5 ) );

  /* 4. Try publishing to an orphan slot

  6 -> 7       10 -> 11
               8 -> 9 (should get pruned)
  */

  fd_forest_data_shred_insert( forest, 9, 1, 0, 0, 0, 0 );

  new_root = 10;
  frontier = 11;

  fd_forest_publish( forest, new_root);
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier, NULL, fd_forest_pool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 6 ) );
  FD_TEST( !fd_forest_query( forest, 7 ) );
  FD_TEST( !fd_forest_query( forest, 8 ) );
  FD_TEST( !fd_forest_query( forest, 9 ) );
  FD_TEST( fd_forest_query( forest, 10 ) );
  FD_TEST( fd_forest_query( forest, 11 ) );

  /* 5. Try publishing to an orphan slot that is not a "head" of orphans
                            (publish)
    10 -> 11         14 -> 15 -> 16

  */

  fd_forest_data_shred_insert( forest, 14, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 15, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 16, 1, 0, 0, 0, 0 );

  new_root = 15;
  frontier = 16;
  fd_forest_publish( forest, new_root );
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier, NULL, fd_forest_pool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 10 ) );
  FD_TEST( !fd_forest_query( forest, 11 ) );
  FD_TEST( !fd_forest_query( forest, 14 ) );
}
#define SORT_NAME        sort
#define SORT_KEY_T       ulong
#include "../../util/tmpl/fd_sort.c"

ulong * frontier_arr( fd_wksp_t * wksp, fd_forest_t * forest ) {
  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );
  fd_forest_ele_t const *      pool     = fd_forest_pool_const( forest );
  ulong                        cnt      = fd_forest_pool_used( pool );

  FD_TEST( !fd_forest_frontier_verify( fd_forest_frontier_const( forest ), fd_forest_pool_max( pool ), pool ) );
  ulong * arr = fd_wksp_alloc_laddr( wksp, 8, cnt, 42UL );

  ulong i = 0;
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool );
       !fd_forest_frontier_iter_done( iter, frontier, pool );
       iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_ele_t const * ele = fd_forest_frontier_iter_ele_const( iter, frontier, pool );
    arr[i++] = ele->slot;
    FD_TEST( i < cnt );
  }
  for( ulong j = i; j < cnt; j++ ) arr[j] = ULONG_MAX;
  return sort_inplace( arr, cnt );
}

void test_out_of_order( fd_wksp_t * wksp ) {
  ulong ele_max = 8UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 6, 1, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 2, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 0, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0 );
  fd_forest_data_shred_insert( forest, 3, 2, 0, 0 );

  // fd_forest_print( forest );
  ulong * arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 1 );
  FD_TEST( arr[1] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  for( uint i = 1; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 1, 1, i, 0 );
  }
  fd_forest_data_shred_insert( forest, 1, 1, 31, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 3 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  for( uint i = 1; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 3, 2, i, 0 );
  }
  fd_forest_data_shred_insert( forest, 3, 2, 31, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 5 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  for( uint i = 1; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 5, 2, i, 0 );
  }
  fd_forest_data_shred_insert( forest, 5, 2, 31, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 4, 2, 0, 0 );
  for( uint i = 1; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 2, 1, i, 0 );
  }
  fd_forest_data_shred_insert( forest, 2, 1, 31, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  for( uint i = 1; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 6, 1, i, 0 );
  }
  fd_forest_data_shred_insert( forest, 6, 1, 31, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  for( uint i = 1; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 4, 2, i, 0 );
  }
  fd_forest_data_shred_insert( forest, 4, 2, 31, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  // for( ulong i = 0; i < 7; i++ ) {
  //   FD_LOG_NOTICE(( "i %lu %lu", i, arr[i] ));
  // }
  // preorder( forest, fd_forest_pool_ele( fd_forest_pool( forest ), forest->root ) );

  fd_wksp_free_laddr( fd_forest_delete( fd_forest_leave( fd_forest_fini( forest ) ) ) );
}

void
test_forks( fd_wksp_t * wksp ){

  ulong ele_max = 32UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  // these slots all have 1 fec set
  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 3, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 4, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 10, 1, 31, 1 ); /* orphan */

  /* Frontier should be slot 1. */
  int cnt = 0;
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       !fd_forest_frontier_iter_done( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       iter = fd_forest_frontier_iter_next( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) ) ) {
    fd_forest_ele_t * ele = fd_forest_frontier_iter_ele( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
    cnt++;
    FD_LOG_NOTICE(( "slot %lu, fec_set_idx %u", ele->slot, ele->fec_set_idx ));
  }

  ulong key = ( 1UL << 32 ) | 0 ;
  FD_TEST(  fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &key, NULL, fd_forest_pool( forest ) ) );

  FD_TEST( cnt == 1 );
  // advance frontier to slot 3
  for( uint i = 0; i < 31; i++ ) {
    fd_forest_data_shred_insert( forest, 1, 1, i, 0 );
    fd_forest_data_shred_insert( forest, 2, 1, i, 0 );
  }


  key = 3UL << 32 | 0;
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &key, NULL, fd_forest_pool( forest ) ) );

  // add a new fork off slot 1
  fd_forest_data_shred_insert( forest, 5, 4, 31, 1 );

  fd_forest_print( forest );

  key = 5UL << 32 | 0;
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &key, NULL, fd_forest_pool( forest ) ) );

  cnt = 0;
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       !fd_forest_frontier_iter_done( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       iter = fd_forest_frontier_iter_next( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) ) ) {
    fd_forest_ele_t * ele = fd_forest_frontier_iter_ele( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
    cnt++;
    (void) ele;
  }
  FD_TEST( cnt == 2 );

  // add a fork off of the orphan
  fd_forest_data_shred_insert( forest, 11, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 12, 4, 63, 1 );

  cnt = 0;
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       !fd_forest_frontier_iter_done( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       iter = fd_forest_frontier_iter_next( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) ) ) {
    fd_forest_ele_t * ele = fd_forest_frontier_iter_ele( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
    cnt++;
    (void) ele;
  }
  FD_TEST( cnt == 2 );

  fd_forest_print( forest );

}

void
test_multi_fec_slots( fd_wksp_t * wksp ){
  ulong ele_max = 32UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 1023, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 64, 0 );
  fd_forest_data_shred_insert( forest, 3, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 4, 1, 511, 0 );
  fd_forest_data_shred_insert( forest, 10, 1, 31, 0 ); /* orphan */


  fd_forest_print( forest );
  ulong key = ( 9UL << 32 ) | UINT_MAX;
  FD_TEST( fd_forest_orphaned_ele_query_const( fd_forest_orphaned( forest ), &key, NULL, fd_forest_pool( forest ) ) );
  key = ( 2UL << 32 ) | UINT_MAX;
  FD_TEST( fd_forest_orphaned_ele_query_const( fd_forest_orphaned( forest ), &key, NULL, fd_forest_pool( forest ) ) );

  for( uint i = 0; i < 1023; i+=32 ) {
    FD_TEST( fd_forest_query_const(  forest, 1, i ) );
  }
  for( uint i = 0; i < 64; i+=32 ) {
    FD_TEST( fd_forest_query_const(  forest, 2, i ) );
  }

  fd_forest_data_shred_insert( forest, 9, 1, 31, 1);
  fd_forest_data_shred_insert( forest, 2, 1, 95, 1);
  fd_forest_print( forest );
  key = ( 8UL << 32 ) | UINT_MAX;
  FD_TEST( fd_forest_orphaned_ele_query_const( fd_forest_orphaned( forest ), &key, NULL, fd_forest_pool( forest ) ) );
}

void
test_imitate_startup( fd_wksp_t * wksp ){
#define FOR( start, end ) for( uint i = start; i <= end; i++ )

  ulong ele_max = 512UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 340704);
fd_forest_data_shred_insert( forest, 341052, 5, 0, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 10, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 1, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 3, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 20, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 27, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 26, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 5, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 21, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 6, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 24, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 8, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 7, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 13, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 17, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 22, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 18, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 14, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 25, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 28, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 19, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 12, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 0, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 1, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 2, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 3, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 4, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 5, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 6, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 7, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 8, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 9, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 10, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 11, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 12, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 13, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 14, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 15, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 16, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 17, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 18, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 19, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 20, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 21, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 22, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 23, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 24, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 25, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 26, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 27, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 28, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 29, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 30, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 31, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 31, 0);
fd_forest_data_shred_insert( forest, 341047, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341046, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341045, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341044, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341043, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341042, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341041, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341040, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341039, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341038, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341037, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341036, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341035, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341034, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341033, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341032, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341031, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341030, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341029, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341028, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341027, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341026, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341025, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341024, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341023, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341022, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341021, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341020, 1, 63, 1);
fd_forest_data_shred_insert( forest, 341052, 5, 32, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 33, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 34, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 36, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 39, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 52, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 47, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 41, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 48, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 35, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 38, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 57, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 61, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 43, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 54, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 49, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 45, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 44, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 58, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 63, 1);
fd_forest_data_shred_insert( forest, 341052, 5, 62, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 56, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 32, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 33, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 34, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 35, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 36, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 37, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 38, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 39, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 40, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 41, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 42, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 43, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 44, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 45, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 46, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 47, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 48, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 49, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 50, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 51, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 52, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 53, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 54, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 55, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 56, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 57, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 58, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 59, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 60, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 61, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 62, 0);
fd_forest_data_shred_insert( forest, 341052, 5, 63, 1);
__asm__("int $3");
fd_forest_data_shred_insert( forest, 341052, 5, 63, 1);

  FD_TEST( !fd_forest_verify( forest ) );
  fd_forest_print( forest );
}

void
test_large_print_tree( fd_wksp_t * wksp ){
   /*[330090532, 330090539] ── [330090544, 330090583] ── [330090588, 330090851] ── [330090856, 330090859] ── [330090864, 330091003] ── [330091008]
                                                                                                                       └── [330091004, 330091007] ── [330091010, 330091048]
                                                                        └── [330090852, 330090855]*/
  ulong ele_max = 512UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 330090532 );

  for( ulong slot = 330090533; slot <= 330090539; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 31, 1 );
  }

  fd_forest_data_shred_insert( forest, 330090544, 5, 31, 1 );

  for( ulong slot = 330090545; slot <= 330090583; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 63, 1 );
  }

  fd_forest_data_shred_insert( forest, 330090588, 5, 63, 1 );
  for( ulong slot = 330090589; slot <= 330090855; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 127, 1 );
  }
  fd_forest_data_shred_insert( forest, 330090856, 5, 127, 1 );
  for( ulong slot = 330090857; slot <= 330090859; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 127, 1 );
  }
  fd_forest_data_shred_insert( forest, 330090864, 5,  255, 1 );
  for( ulong slot = 330090865; slot <= 330091007; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 31, 1 );
  }
  fd_forest_data_shred_insert( forest, 330091008, 5, 31, 1 );

  fd_forest_data_shred_insert( forest, 330091010, 3, 31, 1 );
  for( ulong slot = 330091011; slot <= 330091048; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 31, 1 );
  }

  FD_TEST( !fd_forest_verify( forest ) );
  fd_forest_print( forest );

}

struct iter_order {
  ulong slot;
  uint  idx;
};
typedef struct iter_order iter_order_t;

void
test_linear_forest_iterator( fd_wksp_t * wksp ) {
  /* Repar forest iterator for a linear chain (expected behavior for
     start up) */
  ulong ele_max = 512UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  /*
  slot  complete_idx   received
  0          31
  1          31            1
  2          31            2
  3          31            3
  4          31            4
  5          31            5

  expected iterator order:
  (slot 1, idx 0), (slot 2, idx 0), (slot 2, idx 1), (slot 3, idx UINT_MAX), (slot 4, idx UINT_MAX),
  (slot 5, idx 0), (slot 5, idx 1), (slot 5, idx 2), (slot 5, idx 3), (slot 5, idx 4)
  */
  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 1, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 2, 0 );
  fd_forest_data_shred_insert( forest, 3, 1, 3, 0 );
  fd_forest_data_shred_insert( forest, 4, 1, 4, 0 );
  fd_forest_data_shred_insert( forest, 5, 1, 31, 1 );
  fd_forest_data_shred_insert( forest, 5, 1, 5, 0 );

  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  ulong i = 0;
  ulong last_slot_rq = 0;
  ulong last_idx_rq = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, iter.ele_idx );
    FD_LOG_NOTICE(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    last_slot_rq = ele->slot;
    last_idx_rq = iter.shred_idx;
    i++;
  }
  FD_TEST( i == 31 );
  FD_TEST( last_slot_rq == 2 );
  FD_TEST( last_idx_rq == UINT_MAX );
  FD_LOG_DEBUG(("success"));
}

//void
//test_branched_forest_iterator( fd_wksp_t * wksp ) {
  ///* Repair forest iterator for a branched chain (expected behavior for
     //regular turbine) */
  //ulong ele_max = 512UL;
  //void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  //FD_TEST( mem );
  //fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

   ///*

         //slot 0
           //|
         //slot 1
         ///
    //slot 2    |
       //|    slot 3
    //slot 4    |
            //slot 5

  //slot  complete_idx   recieved
  //0          1
  //1          1            1
  //2          2            2
  //3          3            0
  //4          4            3
  //5          5            5

  //expected iterator order:
  //(slot 1, idx 0), (slot 2, idx 0), (slot 2, idx 1), (slot 3, idx UINT_MAX), (slot 4, idx UINT_MAX),
  //(slot 5, idx 0), (slot 5, idx 1), (slot 5, idx 2), (slot 5, idx 3), (slot 5, idx 4)
  //*/
  //fd_forest_init( forest, 0 );
  //fd_forest_data_shred_insert( forest, 1, 1, 1, 1 );
  //fd_forest_data_shred_insert( forest, 2, 1, 2, 1 );
  //fd_forest_data_shred_insert( forest, 3, 2, 0, 0 );
  //fd_forest_data_shred_insert( forest, 4, 2, 3, 0 );
  //fd_forest_data_shred_insert( forest, 5, 2, 5, 1 );

  ///* This is deterministic. With only one frontier, we will try to DFS
  //the left most fork */
  //iter_order_t inital_expected[4] = {
    //{ 1, 0 }, { 2, 0 }, { 2, 1 }, { 4, UINT_MAX },
  //};
  //int i = 0;
  //for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    //fd_forest_ele_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    //FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    //FD_TEST( ele->slot == inital_expected[i].slot );
    //FD_TEST( iter.shred_idx == inital_expected[i].idx );
    //i++;
  //}
  //FD_TEST( i == sizeof(inital_expected) / sizeof(iter_order_t) );

  //FD_LOG_DEBUG(("advancing frontier"));
  ///* Now frontier advances to the point where we have two things in the
     //frontier */
  //ulong curr_ver =  fd_fseq_query( fd_forest_ver_const( forest ) );
  //fd_forest_data_shred_insert( forest, 1, 1, 0, 0 );
  //// slot one is complete, so we should now have two things in the frontier

  //FD_TEST( curr_ver < fd_fseq_query( fd_forest_ver_const( forest ) ) );
  //curr_ver = fd_fseq_query( fd_forest_ver_const( forest ) );

  //iter_order_t expected[9] = {
    //{ 2, 0 }, { 2, 1 }, { 4, UINT_MAX }, { 3, UINT_MAX },
    //{ 5, 0 }, { 5, 1 }, { 5, 2 }, { 5, 3 }, { 5, 4 }
  //};

  //i = 0;
  //for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    //fd_forest_ele_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    //FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    //FD_TEST( ele->slot == expected[i].slot );
    //FD_TEST( iter.shred_idx == expected[i].idx );
    //i++;
  //}
  //FD_TEST( i == sizeof(expected) / sizeof(iter_order_t) );

  //FD_LOG_DEBUG(("adding data shred middle of iteration"));

  //FD_TEST( curr_ver == fd_fseq_query( fd_forest_ver_const( forest ) ) );

  ///* Lets do a data shred insert in the middle that affects the frontier */
  //i = 0;
  //for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    //fd_forest_ele_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    //FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    //i++;
    //if( i == 2 ) {
      ///* insert a data shred in the middle of the iteration */
      //fd_forest_data_shred_insert( forest, 3, 2, 3, 1 );
      //FD_TEST( curr_ver < fd_fseq_query( fd_forest_ver_const( forest ) ) );
      //curr_ver = fd_fseq_query( fd_forest_ver_const( forest ) );
    //}
  //}
  //FD_TEST( curr_ver == fd_fseq_query( fd_forest_ver_const( forest ) ) );
  //FD_TEST( i == 2 ); // iteration gets cut off
//}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_publish( wksp );
  //test_out_of_order( wksp );
  //test_forks( wksp );
  //test_multi_fec_slots( wksp );
  //test_large_print_tree( wksp);
  //test_linear_forest_iterator( wksp );

  //test_imitate_startup( wksp );
  //test_branched_forest_iterator( wksp );

  fd_halt();
  return 0;
}
