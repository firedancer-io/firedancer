#include "fd_list.h"

#define MAX 4

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      FD_SHMEM_HUGE_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
  FD_TEST( wksp );

  void *      mem  = fd_wksp_alloc_laddr( wksp, fd_list_align(), fd_list_footprint( 2 ), 42UL );
  fd_list_t * list = fd_list_join( fd_list_new( mem, 4 ) );
  fd_list_t * sentinel = fd_list_sentinel( list );

  fd_list_t * curr = fd_list_head( list );
  for ( ulong i = 1; i <= MAX; i++ ) {
    curr->tag = i;
    curr      = fd_list_next(curr);
  }

  ulong n = 0;
  curr    = fd_list_head( list );
  while ( curr->tag != 0 ) {
    n++;
    curr = fd_list_next(curr);
  }
  FD_TEST( n == MAX );

  /* 1 -> 2 -> 3 -> 4 => 2 -> 3 -> 4 */
  fd_list_t * pop = fd_list_pop_front( list );
  FD_TEST( pop->tag == 1 );
  FD_TEST( fd_list_head( list )->tag == 2 );

  ulong i = 1;
  curr    = fd_list_head( list );
  while ( curr != sentinel ) {
    FD_TEST( curr->tag == i + 1 );
    curr = fd_list_next(curr);
    i++;
  }

  /* 2 -> 3 -> 4 => 2 -> 3 -> 4 -> 1 */
  fd_list_push_back( list, pop );
  FD_TEST( fd_list_head( list )->tag == 2 );
  FD_TEST( fd_list_tail( list )->tag == 1 );

  /* 2 -> 3 -> 4 -> 1 => 2 -> 3 -> 1 -> 4 */
  fd_list_t * remove = fd_list_remove( fd_list_prev(fd_list_tail( list )) );
  fd_list_insert( fd_list_tail( list ), remove );

  /* 2 -> 3 -> 1 -> 4 => 1 -> 2 -> 3 -> 4 */
  remove = fd_list_remove( fd_list_next(fd_list_next(fd_list_head( list ))) );
  fd_list_insert( sentinel, remove );

  /* 1 -> 2 -> 3 -> 4 => NULL  */
  i = 1;
  while ( ( curr = fd_list_pop_front( list ) ) != NULL ) {
    FD_TEST( curr->tag == i );
    i++;
  }
  FD_TEST( i == MAX );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
