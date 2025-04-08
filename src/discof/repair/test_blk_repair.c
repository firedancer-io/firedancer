#include "fd_blk_repair.h"

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

fd_blk_repair_t *
setup_preorder( fd_blk_repair_t * blk_repair ) {
  fd_blk_repair_init( blk_repair, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 1, 1, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 2, 1, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 4, 2, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 3, 2, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 5, 2, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 6, 1, 0 );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  return blk_repair;
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
    void * mem = fd_wksp_alloc_laddr( wksp, fd_blk_repair_align(), fd_blk_repair_footprint( ele_max ), 1UL );
    FD_TEST( mem );
    fd_blk_repair_t * blk_repair = fd_blk_repair_join( fd_blk_repair_new( mem, ele_max, 42UL /* seed */ ) );

    FD_TEST( blk_repair );
    fd_blk_repair_publish( setup_preorder( blk_repair ), publish_test_cases[i] );
    FD_TEST( !fd_blk_repair_verify( blk_repair ) );
    fd_blk_repair_print( blk_repair );

    fd_wksp_free_laddr( fd_blk_repair_delete( fd_blk_repair_leave( fd_blk_repair_fini( blk_repair ) ) ) );
  }
}

#define SORT_NAME        sort
#define SORT_KEY_T       ulong
#include "../../util/tmpl/fd_sort.c"

ulong * frontier_arr( fd_wksp_t * wksp, fd_blk_repair_t * blk_repair ) {
  fd_blk_frontier_t const * frontier = fd_blk_frontier_const( blk_repair );
  fd_blk_ele_t const *      pool     = fd_blk_pool_const( blk_repair );
  ulong                     cnt      = fd_blk_pool_used( pool );

  FD_TEST( !fd_blk_frontier_verify( fd_blk_frontier_const( blk_repair ), fd_blk_pool_max( pool ), pool ) );
  ulong * arr = fd_wksp_alloc_laddr( wksp, 8, cnt, 42UL );

  ulong i = 0;
  for( fd_blk_frontier_iter_t iter = fd_blk_frontier_iter_init( frontier, pool );
       !fd_blk_frontier_iter_done( iter, frontier, pool );
       iter = fd_blk_frontier_iter_next( iter, frontier, pool ) ) {
    fd_blk_ele_t const * ele = fd_blk_frontier_iter_ele_const( iter, frontier, pool );
    arr[i++] = ele->slot;
    FD_TEST( i < cnt );
  }
  for( ulong j = i; j < cnt; j++ ) arr[j] = ULONG_MAX;
  return sort_inplace( arr, cnt );
}

void test_out_of_order( fd_wksp_t * wksp ) {
  ulong ele_max = 8UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_blk_repair_align(), fd_blk_repair_footprint( ele_max ), 1UL );
  FD_TEST( mem );
  fd_blk_repair_t * blk_repair = fd_blk_repair_join( fd_blk_repair_new( mem, ele_max, 42UL /* seed */ ) );

  fd_blk_repair_init( blk_repair, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 6, 1, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 5, 2, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 2, 1, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 1, 1, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 3, 2, 0 );
  fd_blk_repair_data_shred_insert( blk_repair, 4, 2, 0 );

  fd_blk_repair_shred_complete( blk_repair, 1, 0 );
  ulong * arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == 0 );
  FD_TEST( arr[1] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  fd_blk_repair_shred_complete( blk_repair, 0, 0 );
  arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 3 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  fd_blk_repair_shred_complete( blk_repair, 3, 0 );
  arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 5 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  fd_blk_repair_shred_complete( blk_repair, 5, 0 );
  arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == 2 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  fd_blk_repair_data_shred_insert( blk_repair, 2, 1, 1 );
  fd_blk_repair_shred_complete( blk_repair, 2, 1 ); /* shred complete arrives after */
  arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == 6 );
  FD_TEST( arr[2] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  fd_blk_repair_shred_complete( blk_repair, 6, 0 );
  arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == 4 );
  FD_TEST( arr[1] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  fd_blk_repair_shred_complete( blk_repair, 4, 1 ); /* shred complete arrives before */
  fd_blk_repair_data_shred_insert( blk_repair, 4, 2, 1 );
  arr = frontier_arr( wksp, blk_repair );
  FD_TEST( arr[0] == ULONG_MAX );
  FD_TEST( !fd_blk_repair_verify( blk_repair ) );
  fd_blk_repair_print( blk_repair );
  fd_wksp_free_laddr( arr );

  // for( ulong i = 0; i < 7; i++ ) {
  //   FD_LOG_NOTICE(( "i %lu %lu", i, arr[i] ));
  // }
  // preorder( blk_repair, fd_blk_pool_ele( fd_blk_pool( blk_repair ), blk_repair->root ) );

  fd_wksp_free_laddr( fd_blk_repair_delete( fd_blk_repair_leave( fd_blk_repair_fini( blk_repair ) ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  // test_publish( wksp );
  test_out_of_order( wksp );

  fd_halt();
  return 0;
}
