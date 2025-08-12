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
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 4, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 3, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 6, 1, 0, 0, 0, 0 );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_forest_print( forest );
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
    fd_forest_publish( setup_preorder( forest ), publish_test_cases[i] );
    FD_TEST( !fd_forest_verify( forest ) );
    fd_forest_print( forest );

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
  fd_forest_data_shred_insert( forest, 6, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 3, 2, 0, 0, 0, 0 );

  fd_forest_print( forest );
  ulong * arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 1 );
  FD_TEST( arr[1] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 1, 1, 1, 0, 1, 1 );
  fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 3 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 3, 2, 1, 0, 1, 1 );
  fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 5 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 5, 2, 1, 0, 1, 1 );
  fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 4, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 1, 0, 1, 1 );
  fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 6, 1, 1, 0, 1, 1 );
  fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 4, 2, 1, 0, 0, 0 ); /* shred complete arrives before */
  fd_forest_data_shred_insert( forest, 4, 2, 2, 0, 1, 1 );
  fd_forest_print( forest );
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

  // these slots all have 2 shreds, 0,1
  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 3, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 4, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 10, 1, 1, 0, 1, 1 ); /* orphan */

  /* Frontier should be slot 1. */
  ulong key = 1 ;
  FD_TEST(  fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &key, NULL, fd_forest_pool( forest ) ) );

  int cnt = 0;
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       !fd_forest_frontier_iter_done( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
       iter = fd_forest_frontier_iter_next( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) ) ) {
    fd_forest_ele_t * ele = fd_forest_frontier_iter_ele( iter, fd_forest_frontier( forest ), fd_forest_pool( forest ) );
    cnt++;
    (void) ele;
  }

  FD_TEST( cnt == 1 );
  // advance frontier to slot 3
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 0, 0, 0, 0 );

  key = 3;
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &key, NULL, fd_forest_pool( forest ) ) );

  // add a new fork off slot 1
  fd_forest_data_shred_insert( forest, 5, 4, 1, 0, 1, 1 );

  fd_forest_print( forest );

  key = 5;
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
  fd_forest_data_shred_insert( forest, 11, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 12, 4, 1, 0, 1, 1 );

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
test_print_tree( fd_wksp_t *wksp ){
  ulong ele_max = 512UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 1568376 );
  fd_forest_data_shred_insert( forest, 1568377, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568378, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568379, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568380, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568381, 2, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568382, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568383, 4, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568384, 5, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568385, 5, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 1568386, 6, 0, 0, 1, 1 );

  for( ulong i = 1568387; i < 1568400; i++ ){
    FD_TEST( fd_forest_data_shred_insert( forest, i, 1, 0, 0, 1, 1) );
  }

  FD_TEST( !fd_forest_verify( forest ) );
  fd_forest_print( forest );

  /*[330090532, 330090539] ── [330090544, 330090583] ── [330090588, 330090851] ── [330090856, 330090859] ── [330090864, 330091003] ── [330091008]
                                                                                                                       └── [330091004, 330091007] ── [330091010, 330091048]
                                                                        └── [330090852, 330090855]*/

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
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
  }

  fd_forest_data_shred_insert( forest, 330090544, 5, 0, 0, 1, 1 );

  for( ulong slot = 330090545; slot <= 330090583; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
  }

  fd_forest_data_shred_insert( forest, 330090588, 5, 0, 0, 1, 1 );
  for( ulong slot = 330090589; slot <= 330090855; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
  }
  fd_forest_data_shred_insert( forest, 330090856, 5, 0, 0, 1, 1 );
  for( ulong slot = 330090857; slot <= 330090859; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
  }
  fd_forest_data_shred_insert( forest, 330090864, 5, 0, 0, 1, 1 );
  for( ulong slot = 330090865; slot <= 330091007; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
  }
  fd_forest_data_shred_insert( forest, 330091008, 5, 0, 0, 1, 1 );

  fd_forest_data_shred_insert( forest, 330091010, 3, 0, 0, 1, 1 );
  for( ulong slot = 330091011; slot <= 330091048; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
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
  0          1
  1          1            1
  2          2            2
  3          3            0
  4          4            3
  5          5            5

  expected iterator order:
  (slot 1, idx 0), (slot 2, idx 0), (slot 2, idx 1), (slot 3, idx UINT_MAX), (slot 4, idx UINT_MAX),
  (slot 5, idx 0), (slot 5, idx 1), (slot 5, idx 2), (slot 5, idx 3), (slot 5, idx 4)
  */
  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 2, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 3, 1, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 4, 1, 3, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 1, 5, 0, 1, 1 );

  iter_order_t expected[10] = {
    { 1, 0 }, { 2, 0 }, { 2, 1 }, { 3, UINT_MAX }, { 4, UINT_MAX },
    { 5, 0 }, { 5, 1 }, { 5, 2 }, { 5, 3 }, { 5, 4 }
  };

  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  ulong i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, iter.ele_idx );
    FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    FD_TEST( ele->slot == expected[i].slot );
    FD_TEST( iter.shred_idx == expected[i].idx );
    i++;
  }
  FD_TEST( i == sizeof(expected) / sizeof(iter_order_t) );
  FD_LOG_DEBUG(("success"));
}

void
test_branched_forest_iterator( fd_wksp_t * wksp ) {
  /* Repair forest iterator for a branched chain (expected behavior for
     regular turbine) */
  ulong ele_max = 512UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

   /*

         slot 0
           |
         slot 1
         /    \
    slot 2    |
       |    slot 3
    slot 4    |
            slot 5

  slot  complete_idx   received
  0          1
  1          1            1
  2          2            2
  3          3            0
  4          4            3
  5          5            5

  expected iterator order:
  (slot 1, idx 0), (slot 2, idx 0), (slot 2, idx 1), (slot 3, idx UINT_MAX), (slot 4, idx UINT_MAX),
  (slot 5, idx 0), (slot 5, idx 1), (slot 5, idx 2), (slot 5, idx 3), (slot 5, idx 4)
  */
  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 1, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 2, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 3, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 4, 2, 3, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 5, 2, 5, 0, 1, 1 );

  /* This is deterministic. With only one frontier, we will try to DFS
  the left most fork */
  iter_order_t inital_expected[4] = {
    { 1, 0 }, { 2, 0 }, { 2, 1 }, { 4, UINT_MAX },
  };
  int i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_ele_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    FD_TEST( ele->slot == inital_expected[i].slot );
    FD_TEST( iter.shred_idx == inital_expected[i].idx );
    i++;
  }
  FD_TEST( i == sizeof(inital_expected) / sizeof(iter_order_t) );

  FD_LOG_DEBUG(("advancing frontier"));
  /* Now frontier advances to the point where we have two things in the
     frontier */
  ulong curr_ver =  fd_fseq_query( fd_forest_ver_const( forest ) );
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0, 0, 0 );
  // slot one is complete, so we should now have two things in the frontier

  FD_TEST( curr_ver < fd_fseq_query( fd_forest_ver_const( forest ) ) );
  curr_ver = fd_fseq_query( fd_forest_ver_const( forest ) );

  iter_order_t expected[9] = {
    { 2, 0 }, { 2, 1 }, { 4, UINT_MAX }, { 3, UINT_MAX },
    { 5, 0 }, { 5, 1 }, { 5, 2 }, { 5, 3 }, { 5, 4 }
  };

  i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_ele_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    FD_TEST( ele->slot == expected[i].slot );
    FD_TEST( iter.shred_idx == expected[i].idx );
    i++;
  }
  FD_TEST( i == sizeof(expected) / sizeof(iter_order_t) );

  FD_LOG_DEBUG(("adding data shred middle of iteration"));

  FD_TEST( curr_ver == fd_fseq_query( fd_forest_ver_const( forest ) ) );

  /* Lets do a data shred insert in the middle that affects the frontier */
  i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_ele_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    i++;
    if( i == 2 ) {
      /* insert a data shred in the middle of the iteration */
      fd_forest_data_shred_insert( forest, 3, 2, 3, 0, 1, 1 );
      FD_TEST( curr_ver < fd_fseq_query( fd_forest_ver_const( forest ) ) );
      curr_ver = fd_fseq_query( fd_forest_ver_const( forest ) );
    }
  }
  FD_TEST( curr_ver == fd_fseq_query( fd_forest_ver_const( forest ) ) );
  FD_TEST( i == 2 ); // iteration gets cut off
}

void
test_frontier( fd_wksp_t * wksp ) {
  /* bug where we added ele to frontier but didn't remove from ancestry*/
  ulong ele_max = 8;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 0 );
  fd_forest_data_shred_insert( forest, 1, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 2, 1, 0, 0, 1, 1 );
  fd_forest_data_shred_insert( forest, 3, 1, 0, 0, 0, 0 ); /* new frontier */

  ulong frontier_slot = 3;
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier_slot, NULL, fd_forest_pool( forest ) ) );

  /* frontier chaining from slot 1 */
  fd_forest_data_shred_insert( forest, 4, 3, 0, 0, 0, 0 ); /* new frontier */
  frontier_slot = 4;
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier_slot, NULL, fd_forest_pool( forest ) ) );
  FD_TEST( !fd_forest_ancestry_ele_query( fd_forest_ancestry( forest ), &frontier_slot, NULL, fd_forest_pool( forest ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_publish( wksp );
  test_publish_incremental( wksp );
  test_out_of_order( wksp );
  test_forks( wksp );
  test_print_tree( wksp );
  // test_large_print_tree( wksp);
  test_linear_forest_iterator( wksp );
  test_branched_forest_iterator( wksp );
  test_frontier( wksp );

  fd_halt();
  return 0;
}
