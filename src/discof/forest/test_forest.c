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

fd_forest_blk_t *
fd_forest_blk_data_shred_insert( fd_forest_t * forest, ulong slot, ulong parent_slot, uint shred_idx, uint fec_set_idx, int data_complete FD_PARAM_UNUSED, int slot_complete ) {
  fd_forest_blk_insert( forest, slot, parent_slot );
  return fd_forest_data_shred_insert( forest, slot, parent_slot, shred_idx, fec_set_idx, slot_complete, 0, SHRED_SRC_REPAIR );
}

fd_forest_blk_t *
fd_forest_blk_fec_insert( fd_forest_t * forest, ulong slot, ulong parent_slot, uint last_shred_idx, uint fec_set_idx, int slot_complete ) {
  fd_forest_blk_insert( forest, slot, parent_slot );
  return fd_forest_fec_insert( forest, slot, parent_slot, last_shred_idx, fec_set_idx, slot_complete, 0 );
}

fd_forest_t *
setup_preorder( fd_forest_t * forest ) {
  fd_forest_init( forest, 0 );
  fd_forest_blk_data_shred_insert( forest, 1, 0, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 2, 1, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 4, 2, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 3, 1, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 5, 3, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 6, 5, 0, 0, 0, 0 );
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
  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  //fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );
  fd_forest_consumed_t * consumed = fd_forest_consumed( forest );
  fd_forest_cns_t *      conspool = fd_forest_conspool( forest );
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );

  /* 1. Try publishing to a slot that doesnt exist

      0          10? -> 11

   */

  fd_forest_init( forest, 0 );
  fd_forest_blk_data_shred_insert( forest, 11, 10, 0, 0, 1, 1 );

  ulong new_root = 1;
  ulong _11 = 11;
  fd_forest_publish( forest, new_root );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  FD_TEST( fd_forest_consumed_ele_query( consumed, &new_root, NULL, conspool ) );
  FD_TEST( fd_forest_frontier_ele_query( frontier, &new_root, NULL, pool ) || fd_forest_ancestry_ele_query( ancestry, &new_root, NULL, pool ) );
  FD_TEST( fd_forest_subtrees_ele_query( subtrees, &_11, NULL, pool ) );
  FD_TEST( !fd_forest_query( forest, 0 ) );
  FD_TEST( !fd_forest_query( forest, 10 ) );


  /* 2. Try publishing to a slot on the frontier
              v
    1 -> 2 -> 3       10? -> 11

  */

  fd_forest_blk_fec_insert( forest, 2, 1, 0, 0, 1 );
  fd_forest_blk_fec_insert( forest, 3, 2, 0, 0, 1 );

  ulong front_slot = 3;
  fd_forest_print( forest );
  FD_TEST( fd_forest_consumed_ele_query( consumed, &front_slot, NULL, conspool ) );
  FD_TEST( fd_forest_frontier_ele_query( frontier, &front_slot, NULL, pool ) );
  fd_forest_publish( forest, front_slot );
  FD_TEST( fd_forest_root_slot( forest ) == front_slot );
  FD_TEST( fd_forest_consumed_ele_query( consumed, &front_slot, NULL, conspool ) );
  FD_TEST( !fd_forest_query( forest, 1 ) );
  FD_TEST( !fd_forest_query( forest, 2 ) );
  FD_TEST( !fd_forest_query( forest, 10 ) );
  FD_TEST( fd_forest_query( forest, 11 ) );

  /* 3. Try publishing to a slot in ancestry but in front of the frontier

      frontier    new_root
    3 -> 4 -> 5 -> 6 -> 7      10 -> 11

  */

  fd_forest_blk_data_shred_insert( forest, 4, 3, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 5, 4, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 6, 5, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 7, 6, 0, 0, 0, 0 );
  FD_TEST( !fd_forest_verify( forest ) );

  front_slot = 4;
  new_root = 6;
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &front_slot, NULL, fd_forest_conspool( forest ) ) );
  fd_forest_publish( forest, new_root );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  front_slot = 7;
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &front_slot, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 3 ) );
  FD_TEST( !fd_forest_query( forest, 4 ) );
  FD_TEST( !fd_forest_query( forest, 5 ) );

  /* 4. Try publishing to an orphan slot

  6 -> 7       10 -> 11
               8 -> 9 (should get pruned)
  */

  fd_forest_blk_data_shred_insert( forest, 9, 8, 0, 0, 0, 0 );

  new_root = 10;
  front_slot = 11;

  fd_forest_publish( forest, new_root );
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &front_slot, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 6 ) );
  FD_TEST( !fd_forest_query( forest, 7 ) );
  FD_TEST( !fd_forest_query( forest, 8 ) );
  FD_TEST( !fd_forest_query( forest, 9 ) );
  FD_TEST( fd_forest_ancestry_ele_query( ancestry, &new_root, NULL, pool ) );
  FD_TEST( fd_forest_frontier_ele_query( frontier, &front_slot, NULL, pool ) );

  /* 5. Try publishing to an orphan slot that is not a "head" of orphans
                            (publish)
    10 -> 11         14 -> 15 -> 16

  */

  fd_forest_blk_data_shred_insert( forest, 14, 13, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 15, 14, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 16, 15, 0, 0, 0, 0 );

  new_root = 15;
  front_slot = 16;
  fd_forest_publish( forest, new_root );
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_root_slot( forest ) == new_root );
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &front_slot, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( !fd_forest_query( forest, 10 ) );
  FD_TEST( !fd_forest_query( forest, 11 ) );
  FD_TEST( !fd_forest_query( forest, 14 ) );
}
#define SORT_NAME        sort
#define SORT_KEY_T       ulong
#include "../../util/tmpl/fd_sort.c"

ulong * consumed_arr( fd_wksp_t * wksp, fd_forest_t * forest ) {
  fd_forest_consumed_t const * consumed = fd_forest_consumed_const( forest );
  fd_forest_cns_t const *      conspool = fd_forest_conspool_const( forest );
  fd_forest_blk_t const *      pool     = fd_forest_pool_const( forest );
  ulong                        cnt      = fd_forest_pool_used( pool );

  FD_TEST( !fd_forest_frontier_verify( fd_forest_frontier_const( forest ), fd_forest_pool_max( pool ), pool ) );
  ulong * arr = fd_wksp_alloc_laddr( wksp, 8, cnt, 42UL );

  ulong i = 0;
  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( consumed, conspool );
       !fd_forest_consumed_iter_done( iter, consumed, conspool );
       iter = fd_forest_consumed_iter_next( iter, consumed, conspool ) ) {
    fd_forest_cns_t const * ele = fd_forest_consumed_iter_ele_const( iter, consumed, conspool );
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
  fd_forest_blk_data_shred_insert( forest, 6, 5, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 5, 3, 0, 0, 0, 0 );

  fd_forest_print( forest );

  fd_forest_blk_data_shred_insert( forest, 2, 1, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 1, 0, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 3, 1, 0, 0, 0, 0 );

  fd_forest_print( forest );
  ulong * arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 1 );
  FD_TEST( arr[1] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_blk_data_shred_insert( forest, 1, 0, 1, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 1, 0, 1, 0, 1    );
  fd_forest_print( forest );
  arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 3 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_blk_data_shred_insert( forest, 3, 1, 1, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 3, 1, 1, 0, 1    );
  fd_forest_print( forest );
  arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 5 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_blk_data_shred_insert( forest, 5, 3, 1, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 5, 3, 1, 0, 1    );
  fd_forest_print( forest );
  arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_blk_data_shred_insert( forest, 4, 2, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 2, 1, 1, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 2, 1, 1, 0, 1    );
  fd_forest_print( forest );
  arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_blk_data_shred_insert( forest, 6, 5, 1, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 6, 5, 1, 0, 1    );
  fd_forest_print( forest );
  arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_blk_data_shred_insert( forest, 4, 2, 1, 0, 0, 0 ); /* shred complete arrives before */
  //fd_forest_blk_data_shred_insert( forest, 4, 2, 2, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 4, 2, 2, 0, 1    );
  fd_forest_print( forest );
  arr = consumed_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );


  fd_forest_print( forest );
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
  fd_forest_blk_data_shred_insert( forest, 1, 0, 1, 0, 0, 1 );
  fd_forest_blk_data_shred_insert( forest, 2, 1, 1, 0, 0, 1 );
  fd_forest_blk_data_shred_insert( forest, 3, 2, 1, 0, 0, 1 );
  fd_forest_blk_data_shred_insert( forest, 4, 3, 1, 0, 0, 1 );
  fd_forest_blk_data_shred_insert( forest, 10, 9, 1, 0, 0, 1 ); /* orphan */

  /* Frontier should be slot 1. */
  ulong key = 1 ;
  FD_TEST(  fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &key, NULL, fd_forest_conspool( forest ) ) );

  int cnt = 0;
  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
       !fd_forest_consumed_iter_done( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
       iter = fd_forest_consumed_iter_next( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) ) ) {
    fd_forest_cns_t * ele = fd_forest_consumed_iter_ele( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
    cnt++;
    (void) ele;
  }

  FD_TEST( cnt == 1 );
  // advance frontier to slot 3
  //fd_forest_blk_data_shred_insert( forest, 1, 0, 0, 0, 0, 0 );
  fd_forest_blk_fec_insert       ( forest, 1, 0, 1, 0, 1    );
  //fd_forest_blk_data_shred_insert( forest, 2, 1, 0, 0, 0, 0 );
  fd_forest_blk_fec_insert       ( forest, 2, 1, 1, 0, 1    );

  key = 3;
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &key, NULL, fd_forest_conspool( forest ) ) );

  // add a new fork off slot 1
  fd_forest_blk_data_shred_insert( forest, 5, 1, 1, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 5, 1, 1, 0, 1    );

  fd_forest_print( forest );

  key = 5;
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &key, NULL, fd_forest_conspool( forest ) ) );

  cnt = 0;
  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
       !fd_forest_consumed_iter_done( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
       iter = fd_forest_consumed_iter_next( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) ) ) {
    fd_forest_cns_t * ele = fd_forest_consumed_iter_ele( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
    cnt++;
    (void) ele;
  }
  FD_TEST( cnt == 2 );

  // add a fork off of the orphan
  fd_forest_blk_data_shred_insert( forest, 11, 10, 1, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 12, 8, 1, 0, 1, 1 );

  cnt = 0;
  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
       !fd_forest_consumed_iter_done( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
       iter = fd_forest_consumed_iter_next( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) ) ) {
    fd_forest_cns_t * ele = fd_forest_consumed_iter_ele( iter, fd_forest_consumed( forest ), fd_forest_conspool( forest ) );
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
  fd_forest_blk_data_shred_insert( forest, 1568377, 1568376, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568378, 1568377, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568379, 1568378, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568380, 1568379, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568381, 1568379, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568382, 1568381, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568383, 1568379, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568384, 1568379, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568385, 1568380, 0, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 1568386, 15683806, 0, 0, 1, 1 );

  for( ulong i = 1568387; i < 1568400; i++ ){
    FD_TEST( fd_forest_blk_data_shred_insert( forest, i, i-1, 0, 0, 1, 1) );
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
    fd_forest_blk_data_shred_insert( forest, slot, slot-1, 0, 0, 1, 1 );
  }

  fd_forest_blk_data_shred_insert( forest, 330090544, 330090539, 0, 0, 1, 1 );

  for( ulong slot = 330090545; slot <= 330090583; slot++ ){
    fd_forest_blk_data_shred_insert( forest, slot, slot - 1, 0, 0, 1, 1 );
  }

  fd_forest_blk_data_shred_insert( forest, 330090588, 330090588 - 5, 0, 0, 1, 1 );
  for( ulong slot = 330090589; slot <= 330090855; slot++ ){
    fd_forest_blk_data_shred_insert( forest, slot, slot -1, 0, 0, 1, 1 );
  }
  fd_forest_blk_data_shred_insert( forest, 330090856, 330090588 - 5, 0, 0, 1, 1 );
  for( ulong slot = 330090857; slot <= 330090859; slot++ ){
    fd_forest_blk_data_shred_insert( forest, slot, slot - 1, 0, 0, 1, 1 );
  }
  fd_forest_blk_data_shred_insert( forest, 330090864, 330090864 - 5, 0, 0, 1, 1 );
  for( ulong slot = 330090865; slot <= 330091007; slot++ ){
    fd_forest_blk_data_shred_insert( forest, slot, slot - 1, 0, 0, 1, 1 );
  }
  fd_forest_blk_data_shred_insert( forest, 330091008, 330091008 - 5, 0, 0, 1, 1 );

  fd_forest_blk_data_shred_insert( forest, 330091010, 330091010 - 5, 0, 0, 1, 1 );
  for( ulong slot = 330091011; slot <= 330091048; slot++ ){
    fd_forest_blk_data_shred_insert( forest, slot, slot - 1, 0, 0, 1, 1 );
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
  fd_forest_blk_data_shred_insert( forest, 1, 0, 1, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 2, 1, 2, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 3, 2, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 4, 3, 3, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 5, 4, 5, 0, 1, 1 );

  iter_order_t expected[10] = {
    { 1, 0 }, { 2, 0 }, { 2, 1 }, { 3, UINT_MAX }, { 4, UINT_MAX },
    { 5, 0 }, { 5, 1 }, { 5, 2 }, { 5, 3 }, { 5, 4 }
  };

  fd_forest_blk_t const * pool = fd_forest_pool_const( forest );
  ulong i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_blk_t const * ele = fd_forest_pool_ele_const( pool, iter.ele_idx );
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
  fd_forest_blk_data_shred_insert( forest, 1, 0, 1, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 2, 1, 2, 0, 1, 1 );
  fd_forest_blk_data_shred_insert( forest, 3, 1, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 4, 2, 3, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, 5, 3, 5, 0, 1, 1 );

  /* This is deterministic. With only one frontier, we will try to DFS
  the left most fork */
  iter_order_t inital_expected[4] = {
    { 1, 0 }, { 2, 0 }, { 2, 1 }, { 4, UINT_MAX },
  };
  int i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_blk_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
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
  fd_forest_blk_data_shred_insert( forest, 1, 0, 0, 0, 0, 0 );
  fd_forest_blk_fec_insert       ( forest, 1, 0, 1, 0, 1    );
  // slot one is complete, so we should now have two things in the frontier

  FD_TEST( curr_ver < fd_fseq_query( fd_forest_ver_const( forest ) ) );
  curr_ver = fd_fseq_query( fd_forest_ver_const( forest ) );

  iter_order_t expected[9] = {
    { 2, 0 }, { 2, 1 }, { 4, UINT_MAX }, { 3, UINT_MAX },
    { 5, 0 }, { 5, 1 }, { 5, 2 }, { 5, 3 }, { 5, 4 }
  };

  i = 0;
  for( fd_forest_iter_t iter = fd_forest_iter_init( forest ); !fd_forest_iter_done( iter, forest ); iter = fd_forest_iter_next( iter, forest ) ) {
    fd_forest_blk_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
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
    fd_forest_blk_t const * ele = fd_forest_pool_ele_const( fd_forest_pool_const( forest ), iter.ele_idx );
    FD_LOG_DEBUG(( "iter: slot %lu, idx %u", ele->slot, iter.shred_idx ));
    i++;
    if( i == 2 ) {
      /* insert a data shred in the middle of the iteration */
      fd_forest_blk_data_shred_insert( forest, 3, 1, 3, 0, 1, 1 );
      FD_TEST( curr_ver < fd_fseq_query( fd_forest_ver_const( forest ) ) );
      curr_ver = fd_fseq_query( fd_forest_ver_const( forest ) );
    }
  }
  FD_TEST( curr_ver == fd_fseq_query( fd_forest_ver_const( forest ) ) );
  FD_TEST( i == 2 ); // iteration gets cut off
}

void
test_frontier( fd_wksp_t * wksp ) {
  /* bug where we added ele to frontier but didn't remove from ancestry */
  ulong ele_max = 8;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 0 );
  fd_forest_blk_data_shred_insert( forest, 1, 0, 0, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 1, 0, 0, 0, 1    );
  fd_forest_blk_data_shred_insert( forest, 2, 1, 0, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 2, 1, 0, 0, 1    );
  fd_forest_blk_data_shred_insert( forest, 3, 2, 0, 0, 0, 0 ); /* new frontier */

  ulong frontier_slot = 3;
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST( fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &frontier_slot, NULL, fd_forest_pool( forest ) ) );

  /* frontier chaining from slot 1 */
  fd_forest_blk_data_shred_insert( forest, 4, 1, 0, 0, 0, 0 ); /* new frontier */
  frontier_slot = 4;
  FD_TEST( !fd_forest_verify( forest ) );
  FD_TEST(  fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &frontier_slot, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( !fd_forest_ancestry_ele_query( fd_forest_ancestry( forest ), &frontier_slot, NULL, fd_forest_pool( forest ) ) );
}

void
test_invalid_frontier_insert( fd_wksp_t * wksp ) {

  /* We had a gnarly race where suppose we were executing at the head of
     turbine, caught up, and suddenly got dropped from turbine for a
     bit. Let's say we were at slot 100, and we executed it fully, but
     from our POV it looks like there aren't any new shreds coming in.
     Soon we get added back to the turbine tree, and slot 109 comes in.
     slot 109 is a child of 108, and we don't know yet that slot 108 is
     a child of 100.  In the old forest paradigm, 108 would have been
     created by 109 getting created. Then we have another slot 101
     arrive, and 101 would chain successfully to 100, and the frontier
     would advance to 101.  But NOW slot 108 arrives, and chains off of
     100.  But the original !query(slot)->acquire->insert that catches
     that 108 would need to be added to the frontier as well would
     *never get called*, because 108  ALREADY EXISTED.
  */
  ulong ele_max = 8;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 0 );
  fd_forest_blk_data_shred_insert( forest, 100, 0, 0, 0, 1, 1 );
  fd_forest_blk_fec_insert       ( forest, 100, 0, 0, 0,    1 );

  /* turbine pause, state: [100] */

  fd_forest_blk_data_shred_insert( forest, 109, 108, 0, 0, 0, 0 );

  ulong _109 = 109;
  FD_TEST( fd_forest_subtrees_ele_query( fd_forest_subtrees( forest ), &_109, NULL, fd_forest_pool( forest ) ) );

  fd_forest_blk_data_shred_insert( forest, 101, 100, 0, 0, 0, 0 );

  /* turbine resume, state: [100, 101]         [109] */
  FD_TEST( fd_forest_subtrees_ele_query( fd_forest_subtrees( forest ), &_109, NULL, fd_forest_pool( forest ) ) );

  fd_forest_blk_data_shred_insert( forest, 108, 100, 0, 0, 0, 0 );

  FD_TEST( !fd_forest_subtrees_ele_query( fd_forest_subtrees( forest ), &_109, NULL, fd_forest_pool( forest ) ) );

  /* turbine resume, state: [100, 101] -  [108, 109]*/

  fd_forest_print( forest );
  FD_TEST( !fd_forest_verify( forest ) );
  ulong _101 = 101;
  ulong _108 = 108;
  FD_TEST( fd_forest_consumed_ele_query ( fd_forest_consumed( forest ), &_101, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( fd_forest_consumed_ele_query ( fd_forest_consumed( forest ), &_108, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( !fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_109, NULL, fd_forest_conspool( forest ) ) );

  fd_forest_print( forest );

}

void
test_fec_clear( fd_wksp_t * wksp ) {
  ulong ele_max = 8;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_forest_t * forest = fd_forest_join( fd_forest_new( mem, ele_max, 42UL /* seed */ ) );

  fd_forest_init( forest, 0 );

  /* simulate block 1 getting completed with 2 FEC sets */

  ulong _1 = 1;
  ulong _2 = 2;
  ulong _3 = 3;

  fd_forest_blk_data_shred_insert( forest, _2, _1, 0, 0, 0, 0 );

  fd_forest_blk_fec_insert( forest, _1, 0, 31, 0,  0 );
  fd_forest_blk_fec_insert( forest, _1, 0, 63, 32, 1 );

  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_2, NULL, fd_forest_conspool( forest ) ) );

  /* something funky happened in fec_resolver, sending a clear msg for
     something that was completed already */
  fd_forest_fec_clear( forest, _1, 0, 17 );
  /* but its ok because consumed should be unaffected */
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_2, NULL, fd_forest_conspool( forest ) ) );

  fd_forest_blk_fec_insert( forest, _3, _2, 32, 0, 1 ); /* despite being completed, we are still stuck at slot 2 */
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_2, NULL, fd_forest_conspool( forest ) ) );

  /* receiving all the shreds for slot 2 but not the fec completes does
     not advance the frontier */
  fd_forest_blk_data_shred_insert( forest, _2, _1, 0, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, _2, _1, 1, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, _2, _1, 2, 0, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, _2, _1, 3, 3, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, _2, _1, 4, 3, 0, 0 );
  fd_forest_blk_data_shred_insert( forest, _2, _1, 5, 3, 0, 1 );
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_2, NULL, fd_forest_conspool( forest ) ) );

  /* receiving 1 fec for slot 2 does not complete the slot */
  fd_forest_blk_fec_insert( forest, _2, _1, 2, 0, 0 );
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_2, NULL, fd_forest_conspool( forest ) ) );
  /* finally complete */
  fd_forest_blk_fec_insert( forest, _2, _1, 5, 3, 1 );
  FD_TEST( fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_3, NULL, fd_forest_conspool( forest ) ) );
  FD_TEST( !fd_forest_consumed_ele_query( fd_forest_consumed( forest ), &_2, NULL, fd_forest_conspool( forest ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_invalid_frontier_insert( wksp );
  test_publish( wksp );
  test_publish_incremental( wksp );
  test_out_of_order( wksp );
  test_forks( wksp );
  test_print_tree( wksp );
  // test_large_print_tree( wksp);
  test_linear_forest_iterator( wksp );
  test_branched_forest_iterator( wksp );
  test_frontier( wksp );
  test_fec_clear( wksp );

  fd_halt();
  return 0;
}
