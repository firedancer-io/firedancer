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
    fd_forest_publish( setup_preorder( forest ), publish_test_cases[i] );
    FD_TEST( !fd_forest_verify( forest ) );
    // fd_forest_print( forest );

    fd_wksp_free_laddr( fd_forest_delete( fd_forest_leave( fd_forest_fini( forest ) ) ) );
  }
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

  // fd_forest_print( forest );
  ulong * arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 1 );
  FD_TEST( arr[1] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 1, 1, 1, 0, 1, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 3 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 3, 2, 1, 0, 1, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 5 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 5, 2, 1, 0, 1, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 4, 2, 0, 0, 0, 0 );
  fd_forest_data_shred_insert( forest, 2, 1, 1, 0, 1, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 6, 1, 1, 0, 1, 1 );
  // fd_forest_print( forest );
  arr = frontier_arr( wksp, forest );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_forest_verify( forest ) );
  fd_wksp_free_laddr( arr );

  fd_forest_data_shred_insert( forest, 4, 2, 1, 0, 0, 0 ); /* shred complete arrives before */
  fd_forest_data_shred_insert( forest, 4, 2, 2, 0, 1, 1 );
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
    //fd_forest_shred_complete( forest, i, 0 );
  }

  //fd_forest_shred_complete( forest,  1568377, 0 ); /* shred complete arrives before */
  //fd_forest_shred_complete( forest,  1568378, 0 );
  //fd_forest_shred_complete( forest,  1568379, 0 );
  //fd_forest_shred_complete( forest,  1568380, 0 );
  //fd_forest_shred_complete( forest,  1568381, 0 );
  //fd_forest_shred_complete( forest,  1568382, 0 );
  //fd_forest_shred_complete( forest,  1568383, 0 );
  //fd_forest_shred_complete( forest,  1568384, 0 );
  //fd_forest_shred_complete( forest,  1568385, 0 );
  //fd_forest_shred_complete( forest,  1568386, 0 );
//
  FD_TEST( !fd_forest_verify( forest ) );
  // fd_forest_print( forest );

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
    //fd_forest_shred_complete( forest, slot, 0 );
  }

  fd_forest_data_shred_insert( forest, 330090544, 5, 0, 0, 1, 1 );

  for( ulong slot = 330090545; slot <= 330090583; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
    //fd_forest_shred_complete( forest, slot, 0 );
  }

  fd_forest_data_shred_insert( forest, 330090588, 5, 0, 0, 1, 1 );
  for( ulong slot = 330090589; slot <= 330090855; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
    //fd_forest_shred_complete( forest, slot, 0 );
  }
  fd_forest_data_shred_insert( forest, 330090856, 5, 0, 0, 1, 1 );
  for( ulong slot = 330090857; slot <= 330090859; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
    //fd_forest_shred_complete( forest, slot, 0 );
  }
  fd_forest_data_shred_insert( forest, 330090864, 5, 0, 0, 1, 1 );
  for( ulong slot = 330090865; slot <= 330091007; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
    //fd_forest_shred_complete( forest, slot, 0 );
  }
  fd_forest_data_shred_insert( forest, 330091008, 5, 0, 0, 1, 1 );

  fd_forest_data_shred_insert( forest, 330091010, 3, 0, 0, 1, 1 );
  for( ulong slot = 330091011; slot <= 330091048; slot++ ){
    fd_forest_data_shred_insert( forest, slot, 1, 0, 0, 1, 1 );
    //fd_forest_shred_complete( forest, slot, 0 );
  }

  FD_TEST( !fd_forest_verify( forest ) );
  // fd_forest_print( forest );

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
  test_out_of_order( wksp );
  // test_print_tree( wksp );
  // test_large_print_tree( wksp);

  fd_halt();
  return 0;
}
